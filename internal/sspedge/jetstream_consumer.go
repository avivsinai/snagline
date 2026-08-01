package sspedge

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/avivsinai/snagline/internal/deliverystream"
	"github.com/avivsinai/snagline/internal/ssp"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	defaultJetStreamFetchWait = 5 * time.Second
	maxJetStreamFetchWait     = 30 * time.Second
)

var ErrNoJournalMessage = errors.New("sspedge: no journal message available")

type pullFetcher interface {
	Fetch(int, ...jetstream.FetchOpt) (jetstream.MessageBatch, error)
}

type JetStreamPullConfig struct {
	JetStream jetstream.JetStream
	Request   deliverystream.ConsumerRequest
	Handler   *JournalConsumer
	FetchWait time.Duration
}

// JetStreamPullConsumer is a destination-scoped delivery accelerator. It
// provisions stock explicit-ack JetStream state, but completeness and recovery
// remain exclusively in AuthorityReconciler/PostgreSQL.
type JetStreamPullConsumer struct {
	consumer  pullFetcher
	handler   *JournalConsumer
	identity  EdgeIdentity
	spec      deliverystream.ConsumerSpec
	fetchWait time.Duration
}

func NewJetStreamPullConsumer(ctx context.Context, config JetStreamPullConfig) (*JetStreamPullConsumer, error) {
	if config.JetStream == nil || config.Handler == nil {
		return nil, errors.New("sspedge: JetStream and journal handler are required")
	}
	id := config.Handler.identity
	if err := id.validate(); err != nil {
		return nil, err
	}
	request := config.Request
	if request.Destination != deliverystream.DestinationEdge ||
		request.EdgeGeneration > math.MaxInt64 ||
		request.TenantID != id.TenantID ||
		request.EdgeID != id.EdgeID ||
		int64(request.EdgeGeneration) != id.Generation {
		return nil, errors.New("sspedge: JetStream consumer identity does not match journal handler")
	}
	fetchWait := config.FetchWait
	if fetchWait == 0 {
		fetchWait = defaultJetStreamFetchWait
	}
	if fetchWait < 0 || fetchWait > maxJetStreamFetchWait {
		return nil, errors.New("sspedge: JetStream fetch wait must be at most 30 seconds")
	}
	spec, err := deliverystream.EnsureConsumer(ctx, config.JetStream, request)
	if err != nil {
		return nil, err
	}
	if spec.Stream != deliverystream.StreamName || spec.FilterSubject != edgeDeliverySubject(id) {
		return nil, errors.New("sspedge: ensured JetStream consumer does not match edge delivery route")
	}
	consumer, err := config.JetStream.Consumer(ctx, spec.Stream, spec.Durable)
	if err != nil {
		return nil, err
	}
	return &JetStreamPullConsumer{
		consumer: consumer, handler: config.Handler, identity: id,
		spec: spec, fetchWait: fetchWait,
	}, nil
}

// HandleNext fetches at most one wake. The handler must durably commit before
// DoubleAck. Any pre-ACK mapping or handling failure is negatively
// acknowledged for redelivery.
func (c *JetStreamPullConsumer) HandleNext(ctx context.Context, now time.Time) (ProcessOutcome, error) {
	if c == nil || c.consumer == nil || c.handler == nil {
		return "", errors.New("sspedge: nil JetStream pull consumer")
	}
	if c.handler.Halted() {
		return "", ErrConsumerHalted
	}
	batch, err := c.consumer.Fetch(1, jetstream.FetchMaxWait(c.fetchWait))
	if err != nil {
		if errors.Is(err, nats.ErrTimeout) {
			return "", ErrNoJournalMessage
		}
		return "", err
	}
	message, ok := <-batch.Messages()
	if !ok {
		if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) {
			return "", err
		}
		return "", ErrNoJournalMessage
	}
	wrapped := &jetStreamJournalMessage{message: message, identity: c.identity}
	outcome, err := c.handler.Handle(ctx, wrapped, now)
	if err != nil {
		if nakErr := wrapped.Nak(); nakErr != nil {
			return "", fmt.Errorf("sspedge: handle delivery: %w; NAK failed: %v", err, nakErr)
		}
		if errors.Is(err, ErrConsumerHalted) {
			return "", err
		}
		return ProcessRetrying, nil
	}
	if err := wrapped.DoubleAck(ctx); err != nil {
		return "", fmt.Errorf("sspedge: DoubleAck committed delivery: %w", err)
	}
	return outcome, nil
}

// Halted reports the durable handler gate without exposing the handler itself.
func (c *JetStreamPullConsumer) Halted() bool {
	return c == nil || c.handler == nil || c.handler.Halted()
}

// Reconcile delegates one bounded PostgreSQL-authority recovery pass to the
// journal handler. JetStream remains only the wake/delivery accelerator.
func (c *JetStreamPullConsumer) Reconcile(ctx context.Context, now time.Time) (ReconcileResult, error) {
	if c == nil || c.handler == nil {
		return ReconcileResult{}, errors.New("sspedge: nil JetStream pull consumer")
	}
	return c.handler.Reconcile(ctx, now)
}

type jetStreamJournalMessage struct {
	message  jetstream.Msg
	identity EdgeIdentity
}

var _ JournalMessage = (*jetStreamJournalMessage)(nil)

func (m *jetStreamJournalMessage) Metadata() (JournalMetadata, error) {
	if m == nil || m.message == nil {
		return JournalMetadata{}, errors.New("sspedge: nil JetStream message")
	}
	metadata, err := m.message.Metadata()
	if err != nil {
		return JournalMetadata{}, err
	}
	if metadata == nil ||
		metadata.Stream != deliverystream.StreamName ||
		metadata.Sequence.Stream == 0 ||
		m.message.Subject() != edgeDeliverySubject(m.identity) ||
		len(m.message.Data()) == 0 ||
		len(m.message.Data()) > ssp.MaxEnvelopeBytes {
		return JournalMetadata{}, errors.New("sspedge: invalid JetStream delivery metadata")
	}
	headers := m.message.Headers()
	if values := headers.Values(deliverystream.HeaderOutboxID); len(values) != 1 || values[0] == "" {
		return JournalMetadata{}, errors.New("sspedge: invalid outbox header")
	}
	if _, err := positiveUintHeader(headers, deliverystream.HeaderFactSequence); err != nil {
		return JournalMetadata{}, err
	}
	deliverySequence, err := positiveIntHeader(headers, deliverystream.HeaderDeliverySequence)
	if err != nil {
		return JournalMetadata{}, err
	}
	edgeGeneration, err := positiveIntHeader(headers, deliverystream.HeaderEdgeGeneration)
	if err != nil {
		return JournalMetadata{}, err
	}
	return JournalMetadata{
		Stream: metadata.Stream, Sequence: metadata.Sequence.Stream,
		DeliverySeq: deliverySequence,
		TenantID:    m.identity.TenantID, EdgeID: m.identity.EdgeID,
		EdgeGeneration: edgeGeneration,
	}, nil
}

func (m *jetStreamJournalMessage) Subject() string { return m.message.Subject() }
func (m *jetStreamJournalMessage) Data() []byte    { return m.message.Data() }
func (m *jetStreamJournalMessage) DoubleAck(ctx context.Context) error {
	return m.message.DoubleAck(ctx)
}
func (m *jetStreamJournalMessage) Nak() error { return m.message.Nak() }

func positiveIntHeader(headers nats.Header, name string) (int64, error) {
	values := headers.Values(name)
	if len(values) != 1 {
		return 0, fmt.Errorf("sspedge: %s must appear exactly once", name)
	}
	value, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || value <= 0 || strconv.FormatInt(value, 10) != values[0] {
		return 0, fmt.Errorf("sspedge: %s must be a canonical positive integer", name)
	}
	return value, nil
}

func positiveUintHeader(headers nats.Header, name string) (uint64, error) {
	values := headers.Values(name)
	if len(values) != 1 {
		return 0, fmt.Errorf("sspedge: %s must appear exactly once", name)
	}
	value, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != values[0] {
		return 0, fmt.Errorf("sspedge: %s must be a canonical positive integer", name)
	}
	return value, nil
}
