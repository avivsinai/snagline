// Package buzz projects committed SSP records to stock Buzz through an
// outbound-only relay boundary. It has no inbound relay, cursor, wake, or
// reconciliation API: Buzz is a disposable collaboration projection, never
// SSP authority.
package buzz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/avivsinai/snagline/internal/ssp"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/google/uuid"
)

const (
	stockBuzzMessageKind = 9
	defaultMaxAttempts   = 20
)

// FactSource is the projector's read-only PostgreSQL-authority view of
// committed SSP facts.
// It deliberately has no acknowledge, delete, seek, or mutation operation.
type FactSource interface {
	ReadAfter(ctx context.Context, after uint64, limit int) ([]CommittedFact, error)
}

type CommittedFact struct {
	Sequence   uint64
	EnvelopeID string
	Commitment string
	Raw        []byte
}

// CommittedVerifier is the narrow verified-decode boundary. Implementations
// must verify the exact committed raw bytes before returning an envelope.
type CommittedVerifier interface {
	VerifyCommitted(ctx context.Context, raw []byte) (ssp.Envelope, error)
}

// DomainChannels is external operator-owned routing. Registry content and
// Buzz channel membership never select a projection channel.
type DomainChannels interface {
	ChannelForDomain(ctx context.Context, domain string) (string, error)
}

type DigestSigner interface {
	PublicKey() string
	SignDigest(ctx context.Context, digest [sha256.Size]byte) (string, error)
}

// RelayClient intentionally exposes only stock Buzz's outbound event publish.
type RelayClient interface {
	Publish(ctx context.Context, wire []byte) error
}

type ProjectorConfig struct {
	Source            FactSource
	Verifier          CommittedVerifier
	Channels          DomainChannels
	Store             Store
	Signer            DigestSigner
	CaseMentionPubKey string
	Relay             RelayClient
	Clock             func() time.Time
	MaxAttempts       int
}

type Projector struct {
	source            FactSource
	verifier          CommittedVerifier
	channels          DomainChannels
	store             Store
	signer            DigestSigner
	caseMentionPubKey string
	relay             RelayClient
	clock             func() time.Time
	maxAttempts       int
	mu                sync.Mutex
}

func NewProjector(config ProjectorConfig) (*Projector, error) {
	if config.Source == nil || config.Verifier == nil || config.Channels == nil || config.Store == nil || config.Signer == nil || config.Relay == nil {
		return nil, errors.New("collab buzz: source, verifier, channels, store, signer, and relay are required")
	}
	if len(config.CaseMentionPubKey) != 64 || strings.ToLower(config.CaseMentionPubKey) != config.CaseMentionPubKey || config.CaseMentionPubKey == config.Signer.PublicKey() {
		return nil, errors.New("collab buzz: case mention pubkey is invalid")
	}
	pubkey, err := hex.DecodeString(config.CaseMentionPubKey)
	if err != nil || len(pubkey) != schnorr.PubKeyBytesLen {
		return nil, errors.New("collab buzz: case mention pubkey is invalid")
	}
	if _, err := schnorr.ParsePubKey(pubkey); err != nil {
		return nil, errors.New("collab buzz: case mention pubkey is invalid")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	maxAttempts := config.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultMaxAttempts
	}
	return &Projector{
		source: config.Source, verifier: config.Verifier, channels: config.Channels,
		store: config.Store, signer: config.Signer, caseMentionPubKey: config.CaseMentionPubKey, relay: config.Relay,
		clock: clock, maxAttempts: maxAttempts,
	}, nil
}

type ProjectResult struct {
	Processed int
	Published int
	Lag       LagState
}

// Project advances only through records that have either been persisted and
// published, or are non-projecting registry records. A Buzz failure leaves
// the committed SSP source untouched and keeps the exact prepared Buzz bytes
// durable for a byte-identical retry.
func (p *Projector) Project(ctx context.Context, limit int) (ProjectResult, error) {
	if p == nil {
		return ProjectResult{}, errors.New("collab buzz: nil projector")
	}
	if limit <= 0 {
		return ProjectResult{}, errors.New("collab buzz: positive project limit is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	state, err := p.store.Load(ctx)
	if err != nil {
		return ProjectResult{}, err
	}
	state = normalizeState(state)
	records, err := p.source.ReadAfter(ctx, state.Checkpoint, limit)
	if err != nil {
		return ProjectResult{Lag: state.Lag}, err
	}
	result := ProjectResult{}
	for _, record := range records {
		if record.Sequence <= state.Checkpoint || len(record.Raw) == 0 {
			return ProjectResult{Processed: result.Processed, Published: result.Published, Lag: state.Lag}, errors.New("collab buzz: invalid authority fact")
		}
		if record.Sequence > state.HighWatermark {
			state.HighWatermark = record.Sequence
		}
		published, err := p.projectRecord(ctx, &state, record)
		result.Processed++
		if err != nil {
			state.recalculateLag()
			if saveErr := p.store.Save(ctx, state); saveErr != nil {
				return ProjectResult{Processed: result.Processed, Published: result.Published, Lag: state.Lag}, saveErr
			}
			return ProjectResult{Processed: result.Processed, Published: result.Published, Lag: state.Lag}, err
		}
		if published {
			result.Published++
		}
		state.Checkpoint = record.Sequence
		state.recalculateLag()
		if err := p.store.Save(ctx, state); err != nil {
			return ProjectResult{Processed: result.Processed, Published: result.Published, Lag: state.Lag}, err
		}
	}
	return ProjectResult{Processed: result.Processed, Published: result.Published, Lag: state.Lag}, nil
}

func (p *Projector) projectRecord(ctx context.Context, state *State, record CommittedFact) (bool, error) {
	entry := state.Records[record.Sequence]
	if entry.Record.Sequence == 0 {
		entry.Record = record
		state.Records[record.Sequence] = entry
	}
	// A record becomes a durable parked projection after exhausting its retry
	// budget. The next run advances past that disposable projection while
	// retaining its exact evidence and error for operators. PostgreSQL facts
	// and edge delivery are unaffected.
	if entry.Status == StatusPoison {
		return false, nil
	}
	if len(entry.Wire) != 0 {
		if err := p.relay.Publish(ctx, append([]byte(nil), entry.Wire...)); err != nil {
			if errors.Is(err, ErrPreparedExpiredAbsent) {
				return p.supersedeExpiredAbsent(ctx, state, record, entry)
			}
			state.recordFailure(record.Sequence, err, p.maxAttempts)
			return false, fmt.Errorf("collab buzz: publish prepared record %d: %w", record.Sequence, err)
		}
		entry.Status = StatusPublished
		entry.LastError = ""
		state.Records[record.Sequence] = entry
		return true, nil
	}

	envelope, err := p.verifier.VerifyCommitted(ctx, append([]byte(nil), record.Raw...))
	if err != nil {
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: verify committed record %d: %w", record.Sequence, err)
	}
	if envelope.ID != record.EnvelopeID {
		err = errors.New("authority fact metadata conflicts with committed bytes")
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: reject committed record %d: %w", record.Sequence, err)
	}

	switch envelope.Schema {
	case ssp.FamilyCase:
		return p.prepareAndPublishCase(ctx, state, record, envelope)
	case ssp.FamilyAdvice:
		return p.prepareAndPublishAdvice(ctx, state, record, envelope)
	default:
		err := fmt.Errorf("unsupported SSP family %q", envelope.Schema)
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, err
	}
}

func (p *Projector) supersedeExpiredAbsent(ctx context.Context, state *State, record CommittedFact, current Delivery) (bool, error) {
	var oldEvent nostrEvent
	if err := json.Unmarshal(current.Wire, &oldEvent); err != nil ||
		oldEvent.ID != current.EventID || oldEvent.Kind != stockBuzzMessageKind ||
		oldEvent.Content == "" {
		return false, errors.New("collab buzz: invalid persisted projection evidence")
	}
	channel, err := stockEventChannel(oldEvent)
	if err != nil {
		return false, err
	}
	var card collaborationCard
	if err := json.Unmarshal([]byte(oldEvent.Content), &card); err != nil || card.CaseID == "" ||
		(card.Family != ssp.FamilyCase && card.Family != ssp.FamilyAdvice) {
		return false, errors.New("collab buzz: invalid persisted collaboration card")
	}
	if card.Family == ssp.FamilyAdvice && state.CaseRoots[card.CaseID] != current.RootEventID {
		return false, errors.New("collab buzz: persisted advice root conflicts with case root")
	}
	prepared, err := p.prepare(ctx, channel, current.RootEventID, oldEvent.Content)
	if err != nil {
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, err
	}
	history := append([]SupersededProjection(nil), current.Superseded...)
	history = append(history, SupersededProjection{
		EventID: current.EventID, RootEventID: current.RootEventID,
		Wire: append([]byte(nil), current.Wire...), Attempts: current.Attempts,
		LastError: current.LastError, SupersededAt: p.clock().UTC(),
		Reason: "expired_absent",
	})
	replacement := Delivery{
		Record: record, EventID: prepared.ID, RootEventID: current.RootEventID,
		Wire: append([]byte(nil), prepared.Wire...), Status: StatusPrepared,
		Superseded: history,
	}
	state.Records[record.Sequence] = replacement
	if card.Family == ssp.FamilyCase {
		if state.CaseRoots[card.CaseID] != oldEvent.ID {
			return false, errors.New("collab buzz: persisted case root conflicts with prepared event")
		}
		state.CaseRoots[card.CaseID] = prepared.ID
	}
	// Persistence precedes the first publish of the replacement. A crash can
	// therefore retry only these exact new bytes while retaining old evidence.
	if err := p.store.Save(ctx, *state); err != nil {
		return false, fmt.Errorf("collab buzz: persist superseding event: %w", err)
	}
	if err := p.relay.Publish(ctx, append([]byte(nil), prepared.Wire...)); err != nil {
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: publish superseding event: %w", err)
	}
	replacement = state.Records[record.Sequence]
	replacement.Status = StatusPublished
	state.Records[record.Sequence] = replacement
	return true, nil
}

type caseBody struct {
	Domain               string `json:"domain"`
	IssuerEdgeID         string `json:"issuer_edge_id"`
	IssuerEdgeGeneration int64  `json:"issuer_edge_generation"`
	Summary              string `json:"summary"`
	PublicSummary        string `json:"public_summary"`
	ContextManifest      string `json:"context_manifest"`
}

type adviceBody struct {
	CaseCommitment string `json:"case_commitment"`
	Text           string `json:"text"`
	PublicSummary  string `json:"public_summary"`
}

func (p *Projector) prepareAndPublishCase(ctx context.Context, state *State, record CommittedFact, envelope ssp.Envelope) (bool, error) {
	var body caseBody
	if err := decodeExactBody(envelope.Body, &body); err != nil || body.Domain == "" || body.IssuerEdgeGeneration <= 0 || body.Summary == "" || body.PublicSummary == "" {
		if err == nil {
			err = errors.New("case projection fields are required")
		}
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: decode case: %w", err)
	}
	channel, err := p.channels.ChannelForDomain(ctx, body.Domain)
	if err != nil || channel == "" {
		if err == nil {
			err = errors.New("operator channel mapping is missing")
		}
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: case channel: %w", err)
	}
	content, err := renderCard(envelope, record.Commitment, body.PublicSummary, "")
	if err != nil {
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, err
	}
	prepared, err := p.prepare(ctx, channel, "", content)
	if err != nil {
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, err
	}
	// This state update is the persistence barrier: both the immutable Buzz
	// wire and its case root are saved before the first relay call.
	state.Records[record.Sequence] = Delivery{Record: record, Wire: prepared.Wire, EventID: prepared.ID, Status: StatusPrepared}
	state.CaseRoots[envelope.CaseID] = prepared.ID
	if err := p.store.Save(ctx, *state); err != nil {
		return false, fmt.Errorf("collab buzz: persist prepared case: %w", err)
	}
	if err := p.relay.Publish(ctx, append([]byte(nil), prepared.Wire...)); err != nil {
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: publish case: %w", err)
	}
	delivery := state.Records[record.Sequence]
	delivery.Status = StatusPublished
	state.Records[record.Sequence] = delivery
	return true, nil
}

func (p *Projector) prepareAndPublishAdvice(ctx context.Context, state *State, record CommittedFact, envelope ssp.Envelope) (bool, error) {
	var body adviceBody
	if err := decodeExactBody(envelope.Body, &body); err != nil || body.Text == "" || body.PublicSummary == "" {
		if err == nil {
			err = errors.New("advice projection fields are required")
		}
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: decode advice: %w", err)
	}
	root, ok := state.CaseRoots[envelope.CaseID]
	if !ok {
		err := errors.New("case root is not prepared")
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: advice root: %w", err)
	}
	caseDelivery, ok := state.caseDelivery(envelope.CaseID)
	if !ok {
		err := errors.New("case delivery is missing")
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: advice case: %w", err)
	}
	channel := eventChannel(caseDelivery.Wire)
	if channel == "" {
		err := errors.New("prepared case has no channel")
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: advice channel: %w", err)
	}
	content, err := renderCard(envelope, record.Commitment, "", body.PublicSummary)
	if err != nil {
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, err
	}
	prepared, err := p.prepare(ctx, channel, root, content)
	if err != nil {
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, err
	}
	state.Records[record.Sequence] = Delivery{Record: record, Wire: prepared.Wire, EventID: prepared.ID, RootEventID: root, Status: StatusPrepared}
	if err := p.store.Save(ctx, *state); err != nil {
		return false, fmt.Errorf("collab buzz: persist prepared advice: %w", err)
	}
	if err := p.relay.Publish(ctx, append([]byte(nil), prepared.Wire...)); err != nil {
		state.recordFailure(record.Sequence, err, p.maxAttempts)
		return false, fmt.Errorf("collab buzz: publish advice: %w", err)
	}
	delivery := state.Records[record.Sequence]
	delivery.Status = StatusPublished
	state.Records[record.Sequence] = delivery
	return true, nil
}

func decodeExactBody(raw []byte, target any) error {
	decoder := json.NewDecoder(bytesReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("multiple body values")
	}
	return nil
}

// bytesReader keeps the strict decoder local and avoids exposing raw input APIs.
func bytesReader(raw []byte) *strings.Reader { return strings.NewReader(string(raw)) }

type preparedEvent struct {
	ID   string
	Wire []byte
}

type nostrEvent struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

func (p *Projector) prepare(ctx context.Context, channel, root, content string) (preparedEvent, error) {
	if !utf8.ValidString(content) || content == "" {
		return preparedEvent{}, errors.New("collab buzz: collaboration card is not UTF-8")
	}
	parsedChannel, err := uuid.Parse(channel)
	if err != nil || parsedChannel.String() != channel {
		return preparedEvent{}, errors.New("collab buzz: operator channel mapping must be a canonical UUID")
	}
	tags := [][]string{{"h", channel}}
	if root == "" {
		tags = append(tags, []string{"p", p.caseMentionPubKey})
	}
	if root != "" {
		tags = append(tags, []string{"e", root, "", "reply"})
	}
	event := nostrEvent{PubKey: p.signer.PublicKey(), CreatedAt: p.clock().UTC().Unix(), Kind: stockBuzzMessageKind, Tags: tags, Content: content}
	digest, err := nostrDigest(event)
	if err != nil {
		return preparedEvent{}, err
	}
	event.ID = hex.EncodeToString(digest[:])
	signature, err := p.signer.SignDigest(ctx, digest)
	if err != nil {
		return preparedEvent{}, fmt.Errorf("collab buzz: sign prepared event: %w", err)
	}
	event.Sig = signature
	wire, err := marshalNostrEvent(event)
	if err != nil {
		return preparedEvent{}, err
	}
	return preparedEvent{ID: event.ID, Wire: wire}, nil
}

type collaborationCard struct {
	Family     string `json:"family"`
	CaseID     string `json:"case_id"`
	EnvelopeID string `json:"envelope_id"`
	Commitment string `json:"commitment"`
	Summary    string `json:"summary,omitempty"`
	Advice     string `json:"advice,omitempty"`
}

func renderCard(envelope ssp.Envelope, commitment, summary, advice string) (string, error) {
	card := collaborationCard{Family: envelope.Schema, CaseID: envelope.CaseID, EnvelopeID: envelope.ID, Commitment: commitment}
	switch envelope.Schema {
	case ssp.FamilyCase:
		card.Summary = boundedCardText(summary, 1024)
	case ssp.FamilyAdvice:
		card.Advice = boundedCardText(advice, 1024)
	default:
		return "", fmt.Errorf("collab buzz: no collaboration card for %q", envelope.Schema)
	}
	encoded, err := json.Marshal(card)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func boundedCardText(value string, limit int) string {
	if len([]rune(value)) <= limit {
		return value
	}
	return string([]rune(value)[:limit])
}

func nostrDigest(event nostrEvent) ([sha256.Size]byte, error) {
	serialized, err := marshalNostrJSON([]any{0, event.PubKey, event.CreatedAt, event.Kind, event.Tags, event.Content})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	serialized = unescapeNostrLineSeparators(serialized)
	return sha256.Sum256(serialized), nil
}

func marshalNostrEvent(event nostrEvent) ([]byte, error) {
	return marshalNostrJSON(event)
}

func marshalNostrJSON(value any) ([]byte, error) {
	var wire strings.Builder
	encoder := json.NewEncoder(&wire)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(wire.String(), "\n")), nil
}

// Go escapes U+2028/U+2029 even with HTML escaping disabled, while stock
// Buzz's rust-nostr/serde_json event-ID input emits their UTF-8 bytes.
func unescapeNostrLineSeparators(serialized []byte) []byte {
	var normalized []byte
	for i := 0; i < len(serialized); i++ {
		if serialized[i] != '\\' || i+5 >= len(serialized) ||
			serialized[i+1] != 'u' || serialized[i+2] != '2' ||
			serialized[i+3] != '0' || serialized[i+4] != '2' ||
			(serialized[i+5] != '8' && serialized[i+5] != '9') ||
			jsonBackslashEscaped(serialized, i) {
			if normalized != nil {
				normalized = append(normalized, serialized[i])
			}
			continue
		}
		if normalized == nil {
			normalized = make([]byte, 0, len(serialized))
			normalized = append(normalized, serialized[:i]...)
		}
		normalized = append(normalized, 0xe2, 0x80, 0xa8+serialized[i+5]-'8')
		i += 5
	}
	if normalized == nil {
		return serialized
	}
	return normalized
}

func jsonBackslashEscaped(serialized []byte, at int) bool {
	count := 0
	for i := at - 1; i >= 0 && serialized[i] == '\\'; i-- {
		count++
	}
	return count%2 != 0
}

func eventChannel(wire []byte) string {
	var event nostrEvent
	if json.Unmarshal(wire, &event) != nil {
		return ""
	}
	for _, tag := range event.Tags {
		if len(tag) == 2 && tag[0] == "h" {
			return tag[1]
		}
	}
	return ""
}
