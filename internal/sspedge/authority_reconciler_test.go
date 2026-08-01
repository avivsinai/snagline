package sspedge

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/deliverystream"
)

func TestAuthorityReconcilerMapsExactDatabaseDeliveriesToLiveSubject(t *testing.T) {
	id := testIdentity()
	source := &fakeEdgeDeliverySource{page: authority.EdgeDeliveryPage{
		Deliveries: []authority.EdgeDelivery{
			{Sequence: 4, Kind: "case", CaseID: "case-1", EnvelopeID: "case-envelope", Commitment: commitment("a"), Raw: []byte("exact-case"), AuthorityRevision: 10},
			{Sequence: 5, Kind: "advice", CaseID: "case-1", EnvelopeID: "advice-envelope", Commitment: commitment("b"), Raw: []byte("exact-advice"), AuthorityRevision: 11},
		},
		HighWatermark: 6, CompleteThrough: 5,
	}}
	reconciler, err := NewAuthorityReconciler(source, 2)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := reconciler.FetchAfter(context.Background(), id, 3)
	if err != nil {
		t.Fatal(err)
	}
	if source.query != (authority.EdgeDeliveryQuery{
		TenantID: id.TenantID, EdgeID: id.EdgeID, EdgeGeneration: id.Generation,
		AfterSequence: 3, Limit: 2,
	}) {
		t.Fatalf("authority query=%+v", source.query)
	}
	if batch.HighWatermark != 6 || batch.CompleteThrough != 5 || len(batch.Deliveries) != 2 {
		t.Fatalf("batch=%+v", batch)
	}
	wantSubject, err := deliverystream.SubjectFor(deliverystream.PublishRequest{
		OutboxID: "outbox", Destination: deliverystream.DestinationEdge,
		TenantID: id.TenantID, EdgeID: id.EdgeID, EdgeGeneration: uint64(id.Generation),
		RawSSP: []byte("x"), FactSequence: 1, DeliverySequence: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, delivery := range batch.Deliveries {
		if delivery.Stream != "" || delivery.Sequence != 0 ||
			delivery.DeliverySeq != int64(index+4) ||
			delivery.TenantID != id.TenantID ||
			delivery.EdgeID != id.EdgeID ||
			delivery.EdgeGeneration != id.Generation ||
			delivery.Subject != wantSubject {
			t.Fatalf("delivery[%d]=%+v", index, delivery)
		}
	}
	if !bytes.Equal(batch.Deliveries[0].Raw, []byte("exact-case")) ||
		!bytes.Equal(batch.Deliveries[1].Raw, []byte("exact-advice")) {
		t.Fatalf("exact bytes changed: %q/%q", batch.Deliveries[0].Raw, batch.Deliveries[1].Raw)
	}
	source.page.Deliveries[0].Raw[0] = 'X'
	if !bytes.Equal(batch.Deliveries[0].Raw, []byte("exact-case")) {
		t.Fatal("batch retained authority-owned raw byte storage")
	}
}

func TestAuthorityReconcilerRejectsNonContiguousOrDishonestPage(t *testing.T) {
	id := testIdentity()
	for name, page := range map[string]authority.EdgeDeliveryPage{
		"gap": {
			Deliveries:    []authority.EdgeDelivery{{Sequence: 2, Kind: "case", Raw: []byte("case")}},
			HighWatermark: 2, CompleteThrough: 2,
		},
		"complete boundary": {
			Deliveries:    []authority.EdgeDelivery{{Sequence: 1, Kind: "case", Raw: []byte("case")}},
			HighWatermark: 2, CompleteThrough: 2,
		},
		"unknown kind": {
			Deliveries:    []authority.EdgeDelivery{{Sequence: 1, Kind: "registry", Raw: []byte("registry")}},
			HighWatermark: 1, CompleteThrough: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			reconciler, err := NewAuthorityReconciler(&fakeEdgeDeliverySource{page: page}, 10)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reconciler.FetchAfter(context.Background(), id, 0); err == nil {
				t.Fatal("dishonest authority page accepted")
			}
		})
	}
}

func TestAuthorityReconcilerValidatesConstructionAndPropagatesReadFailure(t *testing.T) {
	if got, err := NewAuthorityReconciler(nil, 10); err == nil || got != nil {
		t.Fatalf("nil source=(%v,%v)", got, err)
	}
	if got, err := NewAuthorityReconciler(&fakeEdgeDeliverySource{}, 1001); err == nil || got != nil {
		t.Fatalf("oversize limit=(%v,%v)", got, err)
	}
	want := errors.New("database unavailable")
	reconciler, err := NewAuthorityReconciler(&fakeEdgeDeliverySource{err: want}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.FetchAfter(context.Background(), testIdentity(), 0); !errors.Is(err, want) {
		t.Fatalf("read failure=%v", err)
	}
}

type fakeEdgeDeliverySource struct {
	query authority.EdgeDeliveryQuery
	page  authority.EdgeDeliveryPage
	err   error
}

func (s *fakeEdgeDeliverySource) ListEdgeDeliveries(_ context.Context, query authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error) {
	s.query = query
	return s.page, s.err
}
