package sspedge

import (
	"context"
	"errors"
	"fmt"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/ssp"
)

// EdgeDeliverySource is the narrow read-only PostgreSQL-authority capability
// required for edge recovery.
type EdgeDeliverySource interface {
	ListEdgeDeliveries(context.Context, authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error)
}

// AuthorityReconciler converts one bounded authority page into the exact local
// verifier/store input used by live JetStream delivery. It fabricates no
// broker coordinates: Stream and Sequence stay zero-valued.
type AuthorityReconciler struct {
	source EdgeDeliverySource
	limit  int
}

var _ Reconciler = (*AuthorityReconciler)(nil)

func NewAuthorityReconciler(source EdgeDeliverySource, limit int) (*AuthorityReconciler, error) {
	if source == nil || limit <= 0 || limit > 1000 {
		return nil, errors.New("sspedge: authority reconciler requires a source and 1..1000 limit")
	}
	return &AuthorityReconciler{source: source, limit: limit}, nil
}

func (r *AuthorityReconciler) FetchAfter(ctx context.Context, id EdgeIdentity, after int64) (ReconcileBatch, error) {
	if r == nil || r.source == nil {
		return ReconcileBatch{}, errors.New("sspedge: nil authority reconciler")
	}
	if err := id.validate(); err != nil {
		return ReconcileBatch{}, err
	}
	if after < 0 {
		return ReconcileBatch{}, errors.New("sspedge: reconciliation cursor must not be negative")
	}
	page, err := r.source.ListEdgeDeliveries(ctx, authority.EdgeDeliveryQuery{
		TenantID:       id.TenantID,
		EdgeID:         id.EdgeID,
		EdgeGeneration: id.Generation,
		AfterSequence:  after,
		Limit:          r.limit,
	})
	if err != nil {
		return ReconcileBatch{}, err
	}
	if page.HighWatermark < after ||
		page.CompleteThrough < after ||
		page.CompleteThrough > page.HighWatermark ||
		len(page.Deliveries) > r.limit ||
		int64(len(page.Deliveries)) != page.CompleteThrough-after {
		return ReconcileBatch{}, errors.New("sspedge: invalid authority reconciliation bounds")
	}

	subject := edgeDeliverySubject(id)
	batch := ReconcileBatch{
		Deliveries:      make([]JournalDelivery, 0, len(page.Deliveries)),
		HighWatermark:   page.HighWatermark,
		CompleteThrough: page.CompleteThrough,
	}
	expected := after + 1
	for _, delivery := range page.Deliveries {
		if delivery.Sequence != expected ||
			(delivery.Kind != string(FamilyCase) && delivery.Kind != string(FamilyAdvice)) ||
			delivery.CaseID == "" ||
			delivery.EnvelopeID == "" ||
			delivery.Commitment == "" ||
			delivery.AuthorityRevision <= 0 ||
			len(delivery.Raw) == 0 ||
			len(delivery.Raw) > ssp.MaxEnvelopeBytes {
			return ReconcileBatch{}, fmt.Errorf("sspedge: invalid authority delivery at sequence %d", expected)
		}
		batch.Deliveries = append(batch.Deliveries, JournalDelivery{
			DeliverySeq:    delivery.Sequence,
			TenantID:       id.TenantID,
			EdgeID:         id.EdgeID,
			EdgeGeneration: id.Generation,
			Subject:        subject,
			Raw:            append([]byte(nil), delivery.Raw...),
		})
		expected++
	}
	return batch, nil
}
