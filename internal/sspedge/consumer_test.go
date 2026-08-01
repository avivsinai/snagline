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

func TestConflictingRecordedDeliveryHaltsVisiblyWithoutRetryLoop(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case"), nil
	}), id, nil)
	first := fakeCarrier(id, 1, "case-original-bytes", edgeDeliverySubject(id))
	if got, err := c.Process(context.Background(), first, now); err != nil || got != ProcessAccepted {
		t.Fatalf("first=(%q,%v)", got, err)
	}
	conflict := fakeCarrier(id, 1, "case-conflicting-bytes", edgeDeliverySubject(id))
	got, err := c.Process(context.Background(), conflict, now)
	if err != nil || got != ProcessOutcome("identity_conflict") {
		t.Fatalf("conflict=(%q,%v), want durable identity_conflict outcome", got, err)
	}
	if conflict.acks != 1 || conflict.naks != 0 {
		t.Fatalf("conflict ack/nak=%d/%d, want ACK without a redelivery loop", conflict.acks, conflict.naks)
	}
	if !c.Halted() {
		t.Fatal("consumer did not halt on an authoritative delivery identity conflict")
	}
	state, err := db.DeliveryState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != DeliveryModeReconciliationRequired || state.Reason != "delivery_identity_conflict" {
		t.Fatalf("state=%+v, want persisted visible identity-conflict halt", state)
	}
	restarted, err := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return nil, errors.New("unexpected verification")
	}), id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.Halted() {
		t.Fatal("restart forgot the persisted identity-conflict halt")
	}
}

func TestConflictingRecordedNextDeliveryBytesHaltVisibly(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case"), nil
	}), id, nil)
	first := fakeCarrier(id, 1, "case-original-bytes", edgeDeliverySubject(id))
	if got, err := c.Process(context.Background(), first, now); err != nil || got != ProcessAccepted {
		t.Fatalf("first=(%q,%v)", got, err)
	}
	// Simulate a torn historical state where the delivery row exists but the
	// contiguous state was not advanced, so the recorded row is re-examined as
	// the next expected sequence.
	tearContiguousState(t, db, id)
	outcome, err := db.ApplyVerified(context.Background(), JournalDelivery{
		Stream: deliverystream.StreamName, Sequence: 21, DeliverySeq: 1,
		TenantID: id.TenantID, EdgeID: id.EdgeID, EdgeGeneration: id.Generation,
		Subject: edgeDeliverySubject(id), Raw: []byte("case-conflicting-bytes"),
	}, VerdictAccepted, "", caseProjection(now, id, "domain/a.*", "case"), now)
	if err != nil || outcome != ApplyOutcome("identity_conflict") {
		t.Fatalf("apply=(%q,%v), want identity_conflict outcome", outcome, err)
	}
	state, err := db.DeliveryState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != DeliveryModeReconciliationRequired || state.Reason != "delivery_identity_conflict" {
		t.Fatalf("state=%+v, want persisted visible identity-conflict halt", state)
	}
}

func TestConflictingRecordedNextDeliverySubjectHaltsVisibly(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case"), nil
	}), id, nil)
	first := fakeCarrier(id, 1, "case-original-bytes", edgeDeliverySubject(id))
	if got, err := c.Process(context.Background(), first, now); err != nil || got != ProcessAccepted {
		t.Fatalf("first=(%q,%v)", got, err)
	}
	tearContiguousState(t, db, id)
	outcome, err := db.ApplyVerified(context.Background(), JournalDelivery{
		Stream: deliverystream.StreamName, Sequence: 21, DeliverySeq: 1,
		TenantID: id.TenantID, EdgeID: id.EdgeID, EdgeGeneration: id.Generation,
		Subject: "different-subject", Raw: []byte("case-original-bytes"),
	}, VerdictAccepted, "", caseProjection(now, id, "domain/a.*", "case"), now)
	if err != nil || outcome != ApplyIdentityConflict {
		t.Fatalf("same-bytes/different-subject apply=(%q,%v), want ApplyIdentityConflict", outcome, err)
	}
	state, err := db.DeliveryState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != DeliveryModeReconciliationRequired || state.Reason != "delivery_identity_conflict" {
		t.Fatalf("state=%+v, want persisted visible identity-conflict halt", state)
	}
}

func TestReconcileRepairsRecordedNextDeliveryAndResumes(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	original := fakeCarrier(id, 1, "case-original-bytes", edgeDeliverySubject(id))
	reconciler := &fakeReconciler{batch: ReconcileBatch{
		Deliveries: []JournalDelivery{{
			DeliverySeq: 1, TenantID: id.TenantID, EdgeID: id.EdgeID, EdgeGeneration: id.Generation,
			Subject: edgeDeliverySubject(id), Raw: []byte("case-original-bytes"),
		}},
		HighWatermark: 1, CompleteThrough: 1,
	}}
	c, _ := NewJournalConsumer(db, verifyFunc(func(context.Context, JournalDelivery) (*VerifiedProjection, error) {
		return caseProjection(now, id, "domain/a.*", "case"), nil
	}), id, reconciler)
	if got, err := c.Process(context.Background(), original, now); err != nil || got != ProcessAccepted {
		t.Fatalf("first=(%q,%v)", got, err)
	}
	// Tear the contiguous state, then halt through a real conflicting live
	// delivery at the recorded next sequence.
	tearContiguousState(t, db, id)
	conflict := fakeCarrier(id, 1, "case-conflicting-bytes", edgeDeliverySubject(id))
	if got, err := c.Process(context.Background(), conflict, now); err != nil || got != ProcessIdentityConflict || !c.Halted() {
		t.Fatalf("conflict=(%q,%v) halted=%v", got, err, c.Halted())
	}
	// Authority reconciliation replays the exact recorded delivery; the edge
	// must advance through it and resume without reapplying the projection.
	result, err := c.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatalf("reconcile after identity conflict: %v", err)
	}
	if !result.Resumed || c.Halted() {
		t.Fatalf("reconcile=%+v halted=%v, want resumed", result, c.Halted())
	}
	state, err := db.DeliveryState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastContiguousSeq != 1 || state.Mode != DeliveryModeActive {
		t.Fatalf("state=%+v, want repaired active state through seq 1", state)
	}
	if count(t, db, "ssp_edge_cases") != 1 {
		t.Fatal("reconciliation reapplied or dropped the recorded projection")
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

// tearContiguousState simulates a torn historical commit by rewinding the
// contiguous counter beneath an already-recorded delivery row.
func tearContiguousState(t *testing.T, db *DB, id EdgeIdentity) {
	t.Helper()
	if _, err := db.sqlDB.Exec(`UPDATE ssp_edge_delivery_state SET last_contiguous_seq=0 WHERE tenant_id=? AND edge_id=? AND edge_generation=?`, id.TenantID, id.EdgeID, id.Generation); err != nil {
		t.Fatal(err)
	}
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
