package sspedge

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/avivsinai/snagline/internal/deliverystream"
)

type JournalMessage interface {
	Metadata() (JournalMetadata, error)
	Subject() string
	Data() []byte
	DoubleAck(context.Context) error
	Nak() error
}
type JournalMetadata struct {
	Stream           string
	Sequence         uint64
	DeliverySeq      int64
	TenantID, EdgeID string
	EdgeGeneration   int64
}
type Verifier interface {
	Verify(context.Context, JournalDelivery) (*VerifiedProjection, error)
}
type VerificationError struct {
	Reason    string
	Permanent bool
	Err       error
}

func (e *VerificationError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Reason
}
func (e *VerificationError) Unwrap() error { return e.Err }
func Permanent(reason string, err error) error {
	return &VerificationError{Reason: reason, Permanent: true, Err: err}
}
func Transient(err error) error { return &VerificationError{Err: err} }

type ProcessOutcome string

const (
	ProcessAccepted               ProcessOutcome = "accepted"
	ProcessRejected               ProcessOutcome = "rejected"
	ProcessQuarantined            ProcessOutcome = "quarantined"
	ProcessDuplicate              ProcessOutcome = "duplicate"
	ProcessRetrying               ProcessOutcome = "retrying"
	ProcessReconciliationRequired ProcessOutcome = "reconciliation_required"
)

var ErrConsumerHalted = errors.New("sspedge: journal consumer halted")

type ReconcileBatch struct {
	Deliveries                     []JournalDelivery
	HighWatermark, CompleteThrough int64
}
type Reconciler interface {
	FetchAfter(context.Context, EdgeIdentity, int64) (ReconcileBatch, error)
}
type ReconcileResult struct {
	Applied                        int
	HighWatermark, CompleteThrough int64
	Resumed                        bool
}

type JournalConsumer struct {
	db         *DB
	verifier   Verifier
	identity   EdgeIdentity
	reconciler Reconciler
	mu         sync.RWMutex
	halted     bool
}

func NewJournalConsumer(db *DB, verifier Verifier, identity EdgeIdentity, reconciler Reconciler) (*JournalConsumer, error) {
	if db == nil || verifier == nil || identity.validate() != nil {
		return nil, errors.New("sspedge: invalid journal consumer")
	}
	state, err := db.DeliveryState(context.Background(), identity)
	if err != nil {
		return nil, err
	}
	if state.Mode != DeliveryModeActive && state.Mode != DeliveryModeReconciliationRequired {
		return nil, errors.New("sspedge: invalid persisted delivery mode")
	}
	return &JournalConsumer{
		db:         db,
		verifier:   verifier,
		identity:   identity,
		reconciler: reconciler,
		halted:     state.Mode == DeliveryModeReconciliationRequired,
	}, nil
}
func (c *JournalConsumer) Halted() bool {
	if c == nil {
		return true
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.halted
}
func (c *JournalConsumer) setHalted(v bool) { c.mu.Lock(); c.halted = v; c.mu.Unlock() }
func (c *JournalConsumer) halt()            { c.setHalted(true) }

func (c *JournalConsumer) Process(ctx context.Context, msg JournalMessage, now time.Time) (ProcessOutcome, error) {
	if c == nil || msg == nil {
		return "", errors.New("sspedge: nil journal consumer or message")
	}
	outcome, err := c.Handle(ctx, msg, now)
	if err != nil {
		if errors.Is(err, ErrConsumerHalted) {
			return "", err
		}
		return c.retry(msg)
	}
	if err := msg.DoubleAck(ctx); err != nil {
		return "", err
	}
	return outcome, nil
}

// Handle validates and durably applies one delivery without acknowledging its
// carrier. Transport adapters own ACK/NAK ordering; Process remains the
// compatibility wrapper for callers that already provide JournalMessage.
func (c *JournalConsumer) Handle(ctx context.Context, msg JournalMessage, now time.Time) (ProcessOutcome, error) {
	if c == nil || msg == nil {
		return "", errors.New("sspedge: nil journal consumer or message")
	}
	if c.Halted() {
		return "", ErrConsumerHalted
	}
	meta, err := msg.Metadata()
	if err != nil {
		return "", err
	}
	d := JournalDelivery{Stream: meta.Stream, Sequence: meta.Sequence, DeliverySeq: meta.DeliverySeq, TenantID: meta.TenantID, EdgeID: meta.EdgeID, EdgeGeneration: meta.EdgeGeneration, Subject: msg.Subject(), Raw: append([]byte(nil), msg.Data()...)}
	if d.DeliverySeq <= 0 {
		return "", errors.New("sspedge: delivery sequence must be positive")
	}
	if d.TenantID != c.identity.TenantID || d.EdgeID != c.identity.EdgeID || d.EdgeGeneration != c.identity.Generation {
		// A delivery sequence belongs to its declared generation. A foreign
		// identity is a reconciliation trigger, but cannot raise this
		// generation's authoritative high watermark.
		if err := c.db.RequireReconciliation(ctx, c.identity, 0, "delivery_identity_mismatch", now); err != nil {
			return "", err
		}
		c.halt()
		return ProcessReconciliationRequired, nil
	}
	outcome, err := c.apply(ctx, d, now, false)
	if err != nil {
		return "", err
	}
	return c.outcome(outcome)
}
func (c *JournalConsumer) apply(ctx context.Context, d JournalDelivery, now time.Time, reconciling bool) (ApplyOutcome, error) {
	p, err := c.verifier.Verify(ctx, d)
	if err != nil {
		var v *VerificationError
		if errors.As(err, &v) && v.Permanent {
			if reconciling {
				return c.db.applyReconciled(ctx, d, VerdictRejected, v.Reason, nil, now)
			}
			return c.db.ApplyVerified(ctx, d, VerdictRejected, v.Reason, nil, now)
		}
		return "", err
	}
	if !routeMatches(d.Subject, c.identity, p) {
		if reconciling {
			return c.db.applyReconciled(ctx, d, VerdictRejected, "route_mismatch", p, now)
		}
		return c.db.ApplyVerified(ctx, d, VerdictRejected, "route_mismatch", p, now)
	}
	if reconciling {
		return c.db.applyReconciled(ctx, d, VerdictAccepted, "", p, now)
	}
	return c.db.ApplyVerified(ctx, d, VerdictAccepted, "", p, now)
}
func (c *JournalConsumer) outcome(o ApplyOutcome) (ProcessOutcome, error) {
	switch o {
	case ApplyAccepted:
		return ProcessAccepted, nil
	case ApplyRejected:
		return ProcessRejected, nil
	case ApplyDuplicate:
		return ProcessDuplicate, nil
	case ApplyQuarantined:
		c.halt()
		return ProcessQuarantined, nil
	case ApplyReconciliationRequired:
		c.halt()
		return ProcessReconciliationRequired, nil
	default:
		return "", errors.New("sspedge: unknown apply outcome")
	}
}
func (c *JournalConsumer) retry(msg JournalMessage) (ProcessOutcome, error) {
	if err := msg.Nak(); err != nil {
		return "", err
	}
	return ProcessRetrying, nil
}

func (c *JournalConsumer) Reconcile(ctx context.Context, now time.Time) (ReconcileResult, error) {
	if c == nil || !c.Halted() {
		return ReconcileResult{}, errors.New("sspedge: reconciliation not required")
	}
	if c.reconciler == nil {
		return ReconcileResult{}, errors.New("sspedge: reconciler is required")
	}
	state, err := c.db.DeliveryState(ctx, c.identity)
	if err != nil {
		return ReconcileResult{}, err
	}
	batch, err := c.reconciler.FetchAfter(ctx, c.identity, state.LastContiguousSeq)
	if err != nil {
		return ReconcileResult{}, err
	}
	result := ReconcileResult{HighWatermark: batch.HighWatermark, CompleteThrough: batch.CompleteThrough}
	if batch.HighWatermark < state.HighWatermark || batch.CompleteThrough < state.LastContiguousSeq || batch.CompleteThrough > batch.HighWatermark {
		return result, errors.New("sspedge: invalid reconciliation bounds")
	}
	if int64(len(batch.Deliveries)) != batch.CompleteThrough-state.LastContiguousSeq {
		return result, errors.New("sspedge: reconciliation range does not match complete boundary")
	}
	expected := state.LastContiguousSeq + 1
	for _, d := range batch.Deliveries {
		if d.TenantID != c.identity.TenantID || d.EdgeID != c.identity.EdgeID || d.EdgeGeneration != c.identity.Generation || d.DeliverySeq != expected {
			return result, errors.New("sspedge: non-contiguous reconciliation delivery")
		}
		expected++
	}
	for _, d := range batch.Deliveries {
		o, err := c.apply(ctx, d, now, true)
		if err != nil {
			return result, err
		}
		if o == ApplyReconciliationRequired || o == ApplyQuarantined {
			return result, errors.New("sspedge: reconciliation delivery halted")
		}
		result.Applied++
	}
	state, err = c.db.DeliveryState(ctx, c.identity)
	if err != nil {
		return result, err
	}
	if state.LastContiguousSeq != batch.CompleteThrough {
		return result, errors.New("sspedge: reconciliation incomplete through declared boundary")
	}
	if batch.CompleteThrough == batch.HighWatermark {
		if err := c.db.CompleteReconciliation(ctx, c.identity, batch.CompleteThrough, batch.HighWatermark, now); err != nil {
			return result, err
		}
		c.setHalted(false)
		result.Resumed = true
	}
	return result, nil
}

func routeMatches(subject string, id EdgeIdentity, p *VerifiedProjection) bool {
	if p == nil {
		return false
	}
	edgeToken := EdgeRoutingToken(id.EdgeID, id.Generation)
	if subject != edgeDeliverySubject(id) {
		return false
	}
	switch p.Family {
	case FamilyCase:
		if p.Case == nil || p.Case.IssuerEdgeID != id.EdgeID || p.Case.IssuerEdgeGeneration != id.Generation || p.Case.RouteKind != "domain" || p.Case.RouteToken != RoutingToken(p.Case.Domain) || p.Case.SourceToken != edgeToken {
			return false
		}
		return true
	case FamilyAdvice:
		if p.Advice == nil || p.Advice.IssuerEdgeID != id.EdgeID || p.Advice.IssuerEdgeGeneration != id.Generation || p.Advice.RouteKind != "edge" || p.Advice.RouteToken != edgeToken {
			return false
		}
		return true
	default:
		return false
	}
}
func RoutingToken(opaque string) string { return deliverystream.RoutingToken(opaque) }
func EdgeRoutingToken(edgeID string, generation int64) string {
	if generation <= 0 {
		return ""
	}
	return deliverystream.EdgeToken(edgeID, uint64(generation))
}
func edgeDeliverySubject(id EdgeIdentity) string {
	if id.validate() != nil {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s",
		deliverystream.SubjectPrefix,
		deliverystream.RoutingToken(id.TenantID),
		deliverystream.DestinationEdge,
		deliverystream.EdgeToken(id.EdgeID, uint64(id.Generation)),
	)
}
