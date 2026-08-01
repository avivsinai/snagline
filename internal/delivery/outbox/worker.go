// Package outbox drains leased transactional-outbox rows into an
// at-least-once delivery publisher. The source database remains authoritative.
package outbox

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avivsinai/snagline/internal/deliverystream"
)

const (
	MaxBatchSize  = 1000
	MaxLease      = time.Hour
	MaxRetryDelay = 24 * time.Hour

	ReasonPublishFailed = "publish_failed"
	ReasonMalformedItem = "malformed_item"
)

type EventKind string

const (
	EventCase   EventKind = "case"
	EventAdvice EventKind = "advice"
)

type DestinationKind string

const (
	DestinationDomainDispatch DestinationKind = "domain_dispatch"
	DestinationEdgeDelivery   DestinationKind = "edge_delivery"
)

// Item contains an authority_outbox row, its lease fence, and the immutable
// route metadata joined by the Source while claiming it.
type Item struct {
	ID                string
	LeaseToken        string
	TenantID          string
	EventKind         EventKind
	EntityID          string
	DestinationKind   DestinationKind
	DestinationKey    string
	Raw               []byte
	AuthorityRevision int64

	DomainID         string
	EdgeID           string
	EdgeGeneration   int64
	DeliverySequence int64
}

// Source owns transactional claiming and lease-fenced closure. Implementations
// must reject stale lease tokens in MarkPublished and Release.
type Source interface {
	Claim(ctx context.Context, workerID string, limit int, lease time.Duration) ([]Item, error)
	MarkPublished(ctx context.Context, itemID, leaseToken string) error
	Release(ctx context.Context, itemID, leaseToken string, retryAt time.Time, redactedReason string) error
}

// PublishRequest is the adapter boundary for the exact values accepted by the
// SSP delivery publisher.
type PublishRequest = deliverystream.PublishRequest

// Publisher returns nil only after the delivery system acknowledges publish.
// That acknowledgement is not a semantic receipt or proof of completeness.
type Publisher interface {
	Publish(ctx context.Context, request PublishRequest) error
}

type PublisherFunc func(context.Context, PublishRequest) error

func (publish PublisherFunc) Publish(ctx context.Context, request PublishRequest) error {
	return publish(ctx, request)
}

// Worker performs one bounded claim/publish/close pass.
type Worker struct {
	Source     Source
	Publisher  Publisher
	WorkerID   string
	Limit      int
	Lease      time.Duration
	RetryDelay time.Duration
	Now        func() time.Time
}

func (worker Worker) RunOnce(ctx context.Context) error {
	if err := worker.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	items, err := worker.Source.Claim(ctx, worker.WorkerID, worker.Limit, worker.Lease)
	if err != nil {
		return fmt.Errorf("claim authority outbox: %w", err)
	}
	if len(items) > worker.Limit {
		return fmt.Errorf("authority outbox source returned %d items for limit %d", len(items), worker.Limit)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	var runErrors []error
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(runErrors, err)...)
		}
		request, err := publishRequest(item)
		if err != nil {
			runErrors = append(runErrors, fmt.Errorf("malformed outbox item %q: %w", item.ID, err))
			if releaseErr := worker.release(ctx, item, ReasonMalformedItem); releaseErr != nil {
				runErrors = append(runErrors, releaseErr)
			}
			continue
		}
		if err := worker.Publisher.Publish(ctx, request); err != nil {
			runErrors = append(runErrors, fmt.Errorf("publish outbox item %q: %w", item.ID, err))
			if ctxErr := ctx.Err(); ctxErr != nil {
				return errors.Join(append(runErrors, ctxErr)...)
			}
			if releaseErr := worker.release(ctx, item, ReasonPublishFailed); releaseErr != nil {
				runErrors = append(runErrors, releaseErr)
			}
			continue
		}
		if err := worker.Source.MarkPublished(ctx, item.ID, item.LeaseToken); err != nil {
			runErrors = append(runErrors, fmt.Errorf("mark outbox item %q published: %w", item.ID, err))
			if ctxErr := ctx.Err(); ctxErr != nil {
				return errors.Join(append(runErrors, ctxErr)...)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		runErrors = append(runErrors, err)
	}
	return errors.Join(runErrors...)
}

func (worker Worker) validate() error {
	switch {
	case worker.Source == nil:
		return errors.New("outbox source is required")
	case worker.Publisher == nil:
		return errors.New("outbox publisher is required")
	case strings.TrimSpace(worker.WorkerID) == "":
		return errors.New("outbox worker ID is required")
	case worker.Limit <= 0 || worker.Limit > MaxBatchSize:
		return fmt.Errorf("outbox limit must be between 1 and %d", MaxBatchSize)
	case worker.Lease <= 0 || worker.Lease > MaxLease:
		return fmt.Errorf("outbox lease must be between 1ns and %s", MaxLease)
	case worker.RetryDelay <= 0 || worker.RetryDelay > MaxRetryDelay:
		return fmt.Errorf("outbox retry delay must be between 1ns and %s", MaxRetryDelay)
	default:
		return nil
	}
}

func (worker Worker) release(ctx context.Context, item Item, reason string) error {
	now := time.Now
	if worker.Now != nil {
		now = worker.Now
	}
	retryAt := now().Add(worker.RetryDelay)
	if err := worker.Source.Release(ctx, item.ID, item.LeaseToken, retryAt, reason); err != nil {
		return fmt.Errorf("release outbox item %q: %w", item.ID, err)
	}
	return nil
}

func publishRequest(item Item) (PublishRequest, error) {
	if err := validateCommonItem(item); err != nil {
		return PublishRequest{}, err
	}
	request := PublishRequest{
		OutboxID:     item.ID,
		TenantID:     item.TenantID,
		RawSSP:       append([]byte(nil), item.Raw...),
		FactSequence: uint64(item.AuthorityRevision),
	}
	switch item.DestinationKind {
	case DestinationDomainDispatch:
		if item.EventKind != EventCase {
			return PublishRequest{}, errors.New("domain dispatch requires a case event")
		}
		if item.DomainID == "" || item.DestinationKey != item.DomainID {
			return PublishRequest{}, errors.New("domain dispatch requires a matching domain route")
		}
		if item.EdgeID != "" || item.EdgeGeneration != 0 || item.DeliverySequence != 0 {
			return PublishRequest{}, errors.New("domain dispatch contains edge delivery metadata")
		}
		request.Destination = deliverystream.DestinationDomain
		request.DomainID = item.DomainID
	case DestinationEdgeDelivery:
		if item.EventKind != EventCase && item.EventKind != EventAdvice {
			return PublishRequest{}, errors.New("edge delivery requires a case or advice event")
		}
		if item.EdgeID == "" || item.EdgeGeneration <= 0 || item.DeliverySequence <= 0 {
			return PublishRequest{}, errors.New("edge delivery requires edge ID, positive generation, and positive sequence")
		}
		if item.DestinationKey != fmt.Sprintf("%s@%d", item.EdgeID, item.EdgeGeneration) {
			return PublishRequest{}, errors.New("edge delivery destination key does not match edge tuple")
		}
		if item.DomainID != "" {
			return PublishRequest{}, errors.New("edge delivery contains domain metadata")
		}
		request.Destination = deliverystream.DestinationEdge
		request.EdgeID = item.EdgeID
		request.EdgeGeneration = uint64(item.EdgeGeneration)
		request.DeliverySequence = uint64(item.DeliverySequence)
	default:
		return PublishRequest{}, fmt.Errorf("unsupported destination kind %q", item.DestinationKind)
	}
	if _, err := deliverystream.SubjectFor(request); err != nil {
		return PublishRequest{}, fmt.Errorf("invalid SSP publish request: %w", err)
	}
	return request, nil
}

func validateCommonItem(item Item) error {
	switch {
	case item.ID == "":
		return errors.New("outbox ID is required")
	case item.LeaseToken == "":
		return errors.New("lease token is required")
	case item.TenantID == "":
		return errors.New("tenant ID is required")
	case item.EntityID == "":
		return errors.New("entity ID is required")
	case item.DestinationKey == "":
		return errors.New("destination key is required")
	case len(item.Raw) == 0:
		return errors.New("raw SSP bytes are required")
	case item.AuthorityRevision <= 0:
		return errors.New("authority revision must be positive")
	}
	switch item.EventKind {
	case EventCase, EventAdvice:
		return nil
	default:
		return fmt.Errorf("unsupported event kind %q", item.EventKind)
	}
}
