// Package deliverystream accelerates bounded, at-least-once SSP delivery from the
// PostgreSQL outbox. PostgreSQL remains the sole semantic authority.
package deliverystream

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/avivsinai/snagline/internal/ssp"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	StreamName    = "SNAGLINE_SSP_DELIVERY"
	SubjectPrefix = "snagline.ssp.delivery.v1"

	// ProductionReplicas is fixed because this is the production delivery
	// stream, not a caller-selectable durability class.
	ProductionReplicas = 3
	DefaultMaxAge      = 7 * 24 * time.Hour
	DefaultMaxBytes    = int64(1 << 30)

	HeaderOutboxID         = "Snagline-Outbox-ID"
	HeaderFactSequence     = "Snagline-Fact-Sequence"
	HeaderDeliverySequence = "Snagline-Delivery-Sequence"
	HeaderEdgeGeneration   = "Snagline-Edge-Generation"

	DefaultAckWait    = 30 * time.Second
	DefaultMaxDeliver = 20
)

// DestinationKind identifies the intended delivery recipient. It is not an
// SSP family: the payload remains the exact bytes persisted by the outbox.
type DestinationKind string

const (
	DestinationDomain DestinationKind = "domain"
	DestinationEdge   DestinationKind = "edge"
)

// StreamConfig is intentionally fixed and bounded. A discarded delivery
// message is recovered from PostgreSQL rather than treated as data loss.
func StreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:       StreamName,
		Subjects:   []string{SubjectPrefix + ".>"},
		Retention:  jetstream.LimitsPolicy,
		Discard:    jetstream.DiscardOld,
		MaxAge:     DefaultMaxAge,
		MaxBytes:   DefaultMaxBytes,
		MaxMsgSize: ssp.MaxEnvelopeBytes,
		Storage:    jetstream.FileStorage,
		Replicas:   ProductionReplicas,
		Duplicates: DefaultMaxAge,
	}
}

// EnsureStream creates the one delivery stream. It holds no authoritative SSP
// history and is never used to decide delivery completeness.
func EnsureStream(ctx context.Context, js jetstream.JetStream) error {
	if js == nil {
		return fmt.Errorf("SSP delivery JetStream is required")
	}
	_, err := js.CreateOrUpdateStream(ctx, StreamConfig())
	return err
}

// PublishRequest is the narrow projection of one immutable PostgreSQL outbox
// row needed to wake a destination. The fact and delivery sequences are
// authoritative PostgreSQL facts carried as metadata, never broker positions.
type PublishRequest struct {
	OutboxID         string
	Destination      DestinationKind
	TenantID         string
	DomainID         string
	EdgeID           string
	EdgeGeneration   uint64
	RawSSP           []byte
	FactSequence     uint64
	DeliverySequence uint64
}

// PublishResult reports only JetStream's duplicate acknowledgement. It does
// not expose a broker sequence because broker progress is not completeness.
type PublishResult struct {
	Duplicate bool
}

// Publish writes the exact outbox SSP bytes with an idempotency key derived
// solely from the immutable outbox ID.
func Publish(ctx context.Context, js jetstream.JetStream, request PublishRequest) (PublishResult, error) {
	if js == nil {
		return PublishResult{}, fmt.Errorf("SSP delivery JetStream is required")
	}
	subject, err := SubjectFor(request)
	if err != nil {
		return PublishResult{}, err
	}
	message := nats.NewMsg(subject)
	message.Data = request.RawSSP
	message.Header.Set(HeaderOutboxID, request.OutboxID)
	message.Header.Set(HeaderFactSequence, strconv.FormatUint(request.FactSequence, 10))
	if request.Destination == DestinationEdge {
		message.Header.Set(HeaderDeliverySequence, strconv.FormatUint(request.DeliverySequence, 10))
		message.Header.Set(HeaderEdgeGeneration, strconv.FormatUint(request.EdgeGeneration, 10))
	}
	ack, err := js.PublishMsg(ctx, message,
		jetstream.WithMsgID(MessageID(request.OutboxID)),
		jetstream.WithExpectStream(StreamName),
	)
	if err != nil {
		return PublishResult{}, err
	}
	return PublishResult{Duplicate: ack.Duplicate}, nil
}

// SubjectFor derives a safe subject from a delivery request. Opaque values are
// hashed before becoming a subject token.
func SubjectFor(request PublishRequest) (string, error) {
	if err := validatePublishRequest(request); err != nil {
		return "", err
	}
	return destinationSubject(request.Destination, request.TenantID, request.DomainID, request.EdgeID, request.EdgeGeneration)
}

// MessageID is deterministic for an immutable outbox ID and never uses an SSP
// envelope identifier or a broker sequence as its idempotency key.
func MessageID(outboxID string) string {
	return "outbox:" + RoutingToken(outboxID)
}

// RoutingToken derives a safe NATS token for one opaque identifier.
func RoutingToken(opaque string) string {
	return hashLengthPrefixed([]byte(opaque))
}

// EdgeToken binds an edge identifier to its positive generation. In
// particular, an edge ID by itself is never a delivery routing token.
func EdgeToken(edgeID string, generation uint64) string {
	var generationBytes [8]byte
	binary.BigEndian.PutUint64(generationBytes[:], generation)
	return hashLengthPrefixed([]byte(edgeID), generationBytes[:])
}

func hashLengthPrefixed(values ...[]byte) string {
	hasher := sha256.New()
	var length [8]byte
	for _, value := range values {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write(value)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func destinationSubject(destination DestinationKind, tenantID, domainID, edgeID string, edgeGeneration uint64) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("SSP delivery tenant ID is required")
	}
	tenantToken := RoutingToken(tenantID)
	switch destination {
	case DestinationDomain:
		if domainID == "" {
			return "", fmt.Errorf("SSP domain delivery requires a domain ID")
		}
		return strings.Join([]string{SubjectPrefix, tenantToken, string(DestinationDomain), RoutingToken(domainID)}, "."), nil
	case DestinationEdge:
		if edgeID == "" || edgeGeneration == 0 {
			return "", fmt.Errorf("SSP edge delivery requires an edge ID and positive generation")
		}
		return strings.Join([]string{SubjectPrefix, tenantToken, string(DestinationEdge), EdgeToken(edgeID, edgeGeneration)}, "."), nil
	default:
		return "", fmt.Errorf("unsupported SSP delivery destination %q", destination)
	}
}

func validatePublishRequest(request PublishRequest) error {
	if request.OutboxID == "" {
		return fmt.Errorf("SSP delivery outbox ID is required")
	}
	if request.FactSequence == 0 {
		return fmt.Errorf("SSP delivery fact sequence must be positive")
	}
	switch request.Destination {
	case DestinationEdge:
		if request.DeliverySequence == 0 {
			return fmt.Errorf("SSP edge delivery sequence must be positive")
		}
	case DestinationDomain:
		if request.DeliverySequence != 0 {
			return fmt.Errorf("SSP %s wake must not carry an edge delivery sequence", request.Destination)
		}
	}
	if len(request.RawSSP) == 0 || len(request.RawSSP) > ssp.MaxEnvelopeBytes {
		return fmt.Errorf("SSP delivery raw bytes must be between 1 and %d bytes", ssp.MaxEnvelopeBytes)
	}
	_, err := destinationSubject(request.Destination, request.TenantID, request.DomainID, request.EdgeID, request.EdgeGeneration)
	return err
}

// ConsumerRequest identifies one destination-scoped at-least-once consumer.
// A consumer may accelerate a wake, but its filter and progress are never a
// statement that PostgreSQL delivery is complete.
type ConsumerRequest struct {
	Durable        string
	Destination    DestinationKind
	TenantID       string
	DomainID       string
	EdgeID         string
	EdgeGeneration uint64
	AckWait        time.Duration
	MaxDeliver     int
}

type ConsumerSpec struct {
	Stream        string
	Durable       string
	FilterSubject string
}

// EnsureConsumer provisions an explicit-ack consumer for one delivery route.
func EnsureConsumer(ctx context.Context, js jetstream.JetStream, request ConsumerRequest) (ConsumerSpec, error) {
	if js == nil {
		return ConsumerSpec{}, fmt.Errorf("SSP delivery JetStream is required")
	}
	if !validDurable(request.Durable) {
		return ConsumerSpec{}, fmt.Errorf("invalid SSP delivery durable %q", request.Durable)
	}
	filter, err := destinationSubject(request.Destination, request.TenantID, request.DomainID, request.EdgeID, request.EdgeGeneration)
	if err != nil {
		return ConsumerSpec{}, err
	}
	ackWait := request.AckWait
	if ackWait <= 0 {
		ackWait = DefaultAckWait
	}
	maxDeliver := request.MaxDeliver
	if maxDeliver <= 0 {
		maxDeliver = DefaultMaxDeliver
	}
	spec := ConsumerSpec{Stream: StreamName, Durable: request.Durable, FilterSubject: filter}
	_, err = js.CreateOrUpdateConsumer(ctx, StreamName, jetstream.ConsumerConfig{
		Name:          spec.Durable,
		Durable:       spec.Durable,
		DeliverPolicy: jetstream.DeliverNewPolicy,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       ackWait,
		MaxDeliver:    maxDeliver,
		ReplayPolicy:  jetstream.ReplayInstantPolicy,
		FilterSubject: spec.FilterSubject,
	})
	if err != nil {
		return ConsumerSpec{}, err
	}
	return spec, nil
}

func validDurable(durable string) bool {
	if durable == "" || len(durable) > 64 {
		return false
	}
	for _, character := range durable {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
