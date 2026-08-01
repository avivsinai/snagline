package sspedge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/deliverystream"
)

func TestCarrierGapHaltsAndAcksWithoutProjecting(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case-gap"), nil
	}), id, nil)
	msg := fakeCarrier(id, 2, "case-gap", edgeDeliverySubject(id))
	got, err := c.Process(context.Background(), msg, now)
	if err != nil || got != ProcessReconciliationRequired || msg.acks != 1 || !c.Halted() {
		t.Fatalf("gap=(%q,%v) ack=%d halted=%v", got, err, msg.acks, c.Halted())
	}
	if count(t, db, "ssp_edge_cases") != 0 {
		t.Fatal("gap projected")
	}
}

func TestCarrierGapRemainsHaltedWhenAckFails(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case-gap"), nil
	}), id, nil)
	msg := fakeCarrier(id, 2, "case-gap", edgeDeliverySubject(id))
	msg.ackErr = errors.New("ack unavailable")
	if _, err := c.Process(context.Background(), msg, now); err == nil {
		t.Fatal("gap ack failure was hidden")
	}
	if !c.Halted() {
		t.Fatal("consumer remained active after durably recording a gap")
	}
}

func TestWrongGenerationHaltsIntoReconciliation(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case"), nil
	}), id, nil)
	wrong := id
	wrong.Generation++
	msg := fakeCarrier(wrong, 1, "case", edgeDeliverySubject(wrong))
	got, err := c.Process(context.Background(), msg, now)
	if err != nil || got != ProcessReconciliationRequired || msg.acks != 1 || !c.Halted() {
		t.Fatalf("wrong generation=(%q,%v) ack=%d", got, err, msg.acks)
	}
	state, err := db.DeliveryState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if state.HighWatermark != 0 {
		t.Fatalf("foreign generation contaminated configured watermark: %+v", state)
	}
}

func TestConsumerRestoresPersistedReconciliationHalt(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	if err := db.RequireReconciliation(context.Background(), id, 2, "test_gap", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	c, err := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return nil, errors.New("unexpected verification")
	}), id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Halted() {
		t.Fatal("consumer forgot persisted reconciliation state across restart")
	}
}

func TestReconcileAppliesContiguousAuthoritativeRangeAndResumes(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	reconciler := &fakeReconciler{batch: ReconcileBatch{Deliveries: []JournalDelivery{testDelivery(id, 1, "case"), testDelivery(id, 2, "advice")}, HighWatermark: 2, CompleteThrough: 2}}
	reconciler.batch.Deliveries[0].Subject = edgeDeliverySubject(id)
	reconciler.batch.Deliveries[1].Subject = edgeDeliverySubject(id)
	for i := range reconciler.batch.Deliveries {
		reconciler.batch.Deliveries[i].Stream = ""
		reconciler.batch.Deliveries[i].Sequence = 0
	}
	verifier := verifyFunc(func(_ context.Context, d JournalDelivery) (*VerifiedProjection, error) {
		if d.DeliverySeq == 1 {
			return caseProjection(now, id, "domain/a.*", "case"), nil
		}
		return adviceProjection(now, id, commitment("a")), nil
	})
	c, _ := NewJournalConsumer(db, verifier, id, reconciler)
	gap := fakeCarrier(id, 2, "wake-gap", "opaque")
	if got, _ := c.Process(context.Background(), gap, now); got != ProcessReconciliationRequired {
		t.Fatalf("gap=%q", got)
	}
	result, err := c.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Applied != 2 || result.HighWatermark != 2 || !result.Resumed || c.Halted() {
		t.Fatalf("reconcile=%+v halted=%v", result, c.Halted())
	}
	state, _ := db.DeliveryState(context.Background(), id)
	if state.LastContiguousSeq != 2 || state.Mode != DeliveryModeActive {
		t.Fatalf("state=%+v", state)
	}
	if count(t, db, "ssp_edge_advice") != 1 {
		t.Fatal("reconciliation did not apply advice through exact case path")
	}
	if reconciler.after != 0 || reconciler.identity != id {
		t.Fatalf("reconciler query=(%+v, after=%d)", reconciler.identity, reconciler.after)
	}
}

func TestReconcileDoesNotResumeBeforeServerCompleteThroughHighWatermark(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	r := &fakeReconciler{batch: ReconcileBatch{Deliveries: []JournalDelivery{testDelivery(id, 1, "case")}, HighWatermark: 2, CompleteThrough: 1}}
	r.batch.Deliveries[0].Subject = edgeDeliverySubject(id)
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case"), nil
	}), id, r)
	gap := fakeCarrier(id, 2, "gap", "opaque")
	_, _ = c.Process(context.Background(), gap, now)
	result, err := c.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Resumed || !c.Halted() {
		t.Fatalf("premature resume=%+v", result)
	}
}

func TestReconcileRejectsAuthoritativeHighWatermarkRetreat(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	r := &fakeReconciler{batch: ReconcileBatch{HighWatermark: 1, CompleteThrough: 0}}
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case"), nil
	}), id, r)
	gap := fakeCarrier(id, 2, "gap", "opaque")
	_, _ = c.Process(context.Background(), gap, now)
	if _, err := c.Reconcile(context.Background(), now); err == nil {
		t.Fatal("reconciliation accepted a high watermark below the observed authoritative sequence")
	}
	if !c.Halted() {
		t.Fatal("consumer resumed after high watermark retreat")
	}
}

func TestReconcileRejectsInvalidRangeBeforeApplyingAnyDelivery(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	r := &fakeReconciler{batch: ReconcileBatch{
		Deliveries:    []JournalDelivery{testDelivery(id, 1, "case"), testDelivery(id, 2, "extra")},
		HighWatermark: 2, CompleteThrough: 1,
	}}
	r.batch.Deliveries[0].Subject = edgeDeliverySubject(id)
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case"), nil
	}), id, r)
	gap := fakeCarrier(id, 2, "gap", "opaque")
	_, _ = c.Process(context.Background(), gap, now)
	if _, err := c.Reconcile(context.Background(), now); err == nil {
		t.Fatal("reconciliation accepted deliveries beyond complete_through")
	}
	state, err := db.DeliveryState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastContiguousSeq != 0 || count(t, db, "ssp_edge_cases") != 0 {
		t.Fatalf("invalid reconciliation range partially applied: %+v", state)
	}
}

func TestTransientVerificationNaksWithoutAdvancing(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return nil, Transient(errors.New("registry lag"))
	}), id, nil)
	msg := fakeCarrier(id, 1, "case", "opaque")
	got, err := c.Process(context.Background(), msg, time.Now().UTC())
	if err != nil || got != ProcessRetrying || msg.naks != 1 || msg.acks != 0 {
		t.Fatalf("transient=(%q,%v) a/n=%d/%d", got, err, msg.acks, msg.naks)
	}
}

func TestCaseAndAdviceUseOneGenerationBoundEdgeDeliverySubject(t *testing.T) {
	id := testIdentity()
	now := time.Now().UTC()
	subject := edgeDeliverySubject(id)
	if !routeMatches(subject, id, caseProjection(now, id, "domain/a.*", "case")) {
		t.Fatal("live edge delivery subject did not route a case")
	}
	if !routeMatches(subject, id, adviceProjection(now, id, commitment("a"))) {
		t.Fatal("live edge delivery subject did not route advice")
	}
	oldCaseSubject := "snagline.ssp.v1." + RoutingToken(id.TenantID) + ".route.domain." + RoutingToken("domain/a.*") + ".source." + EdgeRoutingToken(id.EdgeID, id.Generation) + ".case"
	if routeMatches(oldCaseSubject, id, caseProjection(now, id, "domain/a.*", "case")) {
		t.Fatal("obsolete split case subject remained routable")
	}
}

type verifyFunc func(context.Context, JournalDelivery) (*VerifiedProjection, error)

func (f verifyFunc) Verify(c context.Context, d JournalDelivery) (*VerifiedProjection, error) {
	return f(c, d)
}

type fakeMessage struct {
	meta       JournalMetadata
	subject    string
	data       []byte
	acks, naks int
	ackErr     error
}

func (m *fakeMessage) Metadata() (JournalMetadata, error) { return m.meta, nil }
func (m *fakeMessage) Subject() string                    { return m.subject }
func (m *fakeMessage) Data() []byte                       { return m.data }
func (m *fakeMessage) DoubleAck(context.Context) error    { m.acks++; return m.ackErr }
func (m *fakeMessage) Nak() error                         { m.naks++; return nil }
func fakeCarrier(id EdgeIdentity, seq int64, raw, subject string) *fakeMessage {
	return &fakeMessage{meta: JournalMetadata{Stream: deliverystream.StreamName, Sequence: uint64(seq + 20), DeliverySeq: seq, TenantID: id.TenantID, EdgeID: id.EdgeID, EdgeGeneration: id.Generation}, subject: subject, data: []byte(raw)}
}

type fakeReconciler struct {
	batch    ReconcileBatch
	after    int64
	identity EdgeIdentity
	err      error
}

func (r *fakeReconciler) FetchAfter(_ context.Context, id EdgeIdentity, after int64) (ReconcileBatch, error) {
	r.identity = id
	r.after = after
	return r.batch, r.err
}
