package buzz

import (
	"context"
	"sync"
	"time"
)

type DeliveryStatus string

const (
	StatusPrepared  DeliveryStatus = "prepared"
	StatusPublished DeliveryStatus = "published"
	StatusRetry     DeliveryStatus = "retry"
	StatusPoison    DeliveryStatus = "poison"
)

type Delivery struct {
	Record      CommittedFact
	EventID     string
	RootEventID string
	Wire        []byte
	Status      DeliveryStatus
	Attempts    int
	LastError   string
	Superseded  []SupersededProjection
}

// SupersededProjection retains immutable evidence for an event that stock
// Buzz proved expired and absent before a fresh projection event replaced it.
// Ambiguous events are never added here and are never re-signed.
type SupersededProjection struct {
	EventID      string
	RootEventID  string
	Wire         []byte
	Attempts     int
	LastError    string
	SupersededAt time.Time
	Reason       string
}

type LagState struct {
	Checkpoint    uint64
	HighWatermark uint64
	Pending       int
	Poisoned      int
}

// State is the durable projector state. Records retain exact prepared Buzz
// bytes, case roots, retries, poison outcomes, and lag independently of the
// read-only PostgreSQL authority source.
type State struct {
	Checkpoint    uint64
	HighWatermark uint64
	CaseRoots     map[string]string
	Records       map[uint64]Delivery
	Lag           LagState
}

type Store interface {
	Load(ctx context.Context) (State, error)
	Save(ctx context.Context, state State) error
}

type MemoryStore struct {
	mu    sync.RWMutex
	state State
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{state: normalizeState(State{})}
}

func (s *MemoryStore) Load(_ context.Context) (State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state), nil
}

func (s *MemoryStore) Save(_ context.Context, state State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = cloneState(normalizeState(state))
	return nil
}

func (s *MemoryStore) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

func normalizeState(state State) State {
	if state.CaseRoots == nil {
		state.CaseRoots = make(map[string]string)
	}
	if state.Records == nil {
		state.Records = make(map[uint64]Delivery)
	}
	state.recalculateLag()
	return state
}

func cloneState(state State) State {
	copy := State{
		Checkpoint: state.Checkpoint, HighWatermark: state.HighWatermark,
		CaseRoots: make(map[string]string, len(state.CaseRoots)),
		Records:   make(map[uint64]Delivery, len(state.Records)),
		Lag:       state.Lag,
	}
	for caseID, root := range state.CaseRoots {
		copy.CaseRoots[caseID] = root
	}
	for sequence, delivery := range state.Records {
		delivery.Record.Raw = append([]byte(nil), delivery.Record.Raw...)
		delivery.Wire = append([]byte(nil), delivery.Wire...)
		delivery.Superseded = append([]SupersededProjection(nil), delivery.Superseded...)
		for index := range delivery.Superseded {
			delivery.Superseded[index].Wire = append([]byte(nil), delivery.Superseded[index].Wire...)
		}
		copy.Records[sequence] = delivery
	}
	return copy
}

func (s *State) recordFailure(sequence uint64, err error, maxAttempts int) {
	delivery := s.Records[sequence]
	delivery.Attempts++
	delivery.LastError = err.Error()
	if delivery.Attempts >= maxAttempts {
		delivery.Status = StatusPoison
	} else {
		delivery.Status = StatusRetry
	}
	s.Records[sequence] = delivery
}

func (s *State) recalculateLag() {
	s.Lag = LagState{Checkpoint: s.Checkpoint, HighWatermark: s.HighWatermark}
	for _, delivery := range s.Records {
		switch delivery.Status {
		case StatusRetry:
			s.Lag.Pending++
		case StatusPoison:
			s.Lag.Poisoned++
		}
	}
}

func (s State) caseDelivery(caseID string) (Delivery, bool) {
	root, ok := s.CaseRoots[caseID]
	if !ok {
		return Delivery{}, false
	}
	for _, delivery := range s.Records {
		if delivery.EventID == root {
			return delivery, true
		}
	}
	return Delivery{}, false
}
