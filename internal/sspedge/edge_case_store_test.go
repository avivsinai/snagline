package sspedge

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/edge"
)

func TestEdgeCaseStoreEncryptsAndReplaysExactPendingBytes(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	createdAt := time.Date(2026, 7, 31, 10, 11, 12, 13, time.UTC)
	pending := edge.PendingCase{
		EnvelopeID: "envelope/a",
		CaseID:     "case/a",
		Commitment: commitment("1"),
		Raw:        []byte(`{"exact":"signed bytes"}`),
		CreatedAt:  createdAt,
	}

	if err := db.SavePendingCase(ctx, pending); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := db.SQL().QueryRowContext(ctx, `SELECT raw_ciphertext FROM ssp_edge_pending_cases WHERE case_id=?`, pending.CaseID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, pending.Raw) {
		t.Fatal("pending SSP wire was stored as plaintext")
	}

	got, exists, err := db.LoadPendingCase(ctx, pending.CaseID)
	if err != nil || !exists {
		t.Fatalf("load = (%+v, %v, %v)", got, exists, err)
	}
	if got.EnvelopeID != pending.EnvelopeID || got.CaseID != pending.CaseID ||
		got.Commitment != pending.Commitment || !got.CreatedAt.Equal(pending.CreatedAt) ||
		!bytes.Equal(got.Raw, pending.Raw) {
		t.Fatalf("loaded pending = %+v", got)
	}
	got.Raw[0] ^= 0xff
	again, _, err := db.LoadPendingCase(ctx, pending.CaseID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Raw, pending.Raw) {
		t.Fatal("LoadPendingCase leaked mutable stored bytes")
	}

	if err := db.SavePendingCase(ctx, pending); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	conflict := pending
	conflict.Raw = []byte(`{"different":"bytes"}`)
	if err := db.SavePendingCase(ctx, conflict); err == nil {
		t.Fatal("conflicting pending bytes were accepted")
	}
	if count(t, db, "ssp_edge_pending_cases") != 1 {
		t.Fatal("pending replay inserted another row")
	}
}

func TestMarkCaseAcceptedRemoteRequiresExactPostgresReceipt(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 31, 11, 12, 13, 14, time.UTC)
	pending := edge.PendingCase{
		EnvelopeID: "envelope/a",
		CaseID:     "case/a",
		Commitment: commitment("1"),
		Raw:        []byte(`{"exact":"signed bytes"}`),
		CreatedAt:  now.Add(-time.Minute),
	}
	if err := db.SavePendingCase(ctx, pending); err != nil {
		t.Fatal(err)
	}

	projection := caseProjection(now, testIdentity(), "domain/a", pending.EnvelopeID)
	projection.Case.CaseID = pending.CaseID
	projection.Commitment = pending.Commitment
	if _, err := db.ApplyVerified(ctx, testDelivery(testIdentity(), 1, "case"), VerdictAccepted, "", projection, now); err != nil {
		t.Fatal(err)
	}
	assertPendingState(t, db, pending.CaseID, "pending", "", 0, "")

	accepted := edge.AcceptedRemoteCase{
		EnvelopeID: pending.EnvelopeID,
		CaseID:     pending.CaseID,
		Commitment: pending.Commitment,
		Receipt: edge.CommitReceipt{
			AuthorityID: "postgres-primary",
			Revision:    41,
			EnvelopeID:  pending.EnvelopeID,
			Commitment:  pending.Commitment,
		},
		AcceptedAt: now,
	}
	mismatch := accepted
	mismatch.Receipt.Commitment = commitment("2")
	if err := db.MarkCaseAcceptedRemote(ctx, mismatch); err == nil {
		t.Fatal("mismatched authority receipt was accepted")
	}
	assertPendingState(t, db, pending.CaseID, "pending", "", 0, "")

	if err := db.MarkCaseAcceptedRemote(ctx, accepted); err != nil {
		t.Fatal(err)
	}
	assertPendingState(t, db, pending.CaseID, "accepted_remote", "postgres-primary", 41, sqlTime(now))
	if err := db.MarkCaseAcceptedRemote(ctx, accepted); err != nil {
		t.Fatalf("exact accepted_remote replay: %v", err)
	}
	conflict := accepted
	conflict.Receipt.Revision++
	if err := db.MarkCaseAcceptedRemote(ctx, conflict); err == nil {
		t.Fatal("conflicting authority receipt replaced accepted_remote evidence")
	}
	assertPendingState(t, db, pending.CaseID, "accepted_remote", "postgres-primary", 41, sqlTime(now))
}

func TestReadModelDecryptsAcceptedCaseAndAdvice(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 31, 12, 13, 14, 15, time.UTC)
	id := testIdentity()
	caseP := caseProjection(now, id, "domain/a", "envelope/a")
	caseP.Case.Summary = "line one\nline two"
	if _, err := db.ApplyVerified(ctx, testDelivery(id, 1, "case"), VerdictAccepted, "", caseP, now); err != nil {
		t.Fatal(err)
	}
	adviceP := adviceProjection(now, id, caseP.Commitment)
	adviceP.Advice.Text = "display-only advice"
	adviceReceivedAt := now.Add(time.Second)
	if _, err := db.ApplyVerified(ctx, testDelivery(id, 2, "advice"), VerdictAccepted, "", adviceP, adviceReceivedAt); err != nil {
		t.Fatal(err)
	}

	gotCase, exists, err := db.GetCase(ctx, caseP.Case.CaseID)
	if err != nil || !exists {
		t.Fatalf("GetCase = (%+v, %v, %v)", gotCase, exists, err)
	}
	if gotCase.EnvelopeID != caseP.EnvelopeID || gotCase.CaseID != caseP.Case.CaseID ||
		gotCase.Commitment != caseP.Commitment || gotCase.Summary != caseP.Case.Summary ||
		gotCase.Registry.RoutingEpoch != caseP.Case.RoutingEpoch ||
		gotCase.Registry.Revision != caseP.Case.RegistryRevision ||
		gotCase.Registry.Hash != caseP.Case.RegistryHash ||
		!gotCase.ExpiresAt.Equal(caseP.Case.ExpiresAt) || !gotCase.Committed {
		t.Fatalf("case view = %+v", gotCase)
	}

	advice, err := db.ListAdvice(ctx, caseP.Case.CaseID)
	if err != nil || len(advice) != 1 {
		t.Fatalf("ListAdvice = (%+v, %v)", advice, err)
	}
	wantAdvice := edge.AdviceView{
		AdviceID:   adviceP.Advice.AdviceID,
		CaseID:     adviceP.Advice.CaseID,
		Text:       adviceP.Advice.Text,
		ReceivedAt: adviceReceivedAt,
	}
	if advice[0] != wantAdvice {
		t.Fatalf("advice view = %+v want %+v", advice[0], wantAdvice)
	}
	presented, exists, err := db.PresentAdvice(ctx, adviceP.Advice.AdviceID)
	if err != nil || !exists || presented != wantAdvice {
		t.Fatalf("PresentAdvice = (%+v, %v, %v)", presented, exists, err)
	}

	if _, exists, err := db.GetCase(ctx, "missing"); err != nil || exists {
		t.Fatalf("missing case = (%v, %v)", exists, err)
	}
	if got, err := db.ListAdvice(ctx, "missing"); err != nil || len(got) != 0 {
		t.Fatalf("missing advice list = (%+v, %v)", got, err)
	}
	if _, exists, err := db.PresentAdvice(ctx, "missing"); err != nil || exists {
		t.Fatalf("missing advice = (%v, %v)", exists, err)
	}
}

func TestReadModelRejectsTamperedCiphertext(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	id := testIdentity()
	caseP := caseProjection(now, id, "domain/a", "envelope/a")
	if _, err := db.ApplyVerified(ctx, testDelivery(id, 1, "case"), VerdictAccepted, "", caseP, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL().ExecContext(ctx, `UPDATE ssp_edge_cases SET payload_ciphertext=x'00' WHERE case_id=?`, caseP.Case.CaseID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.GetCase(ctx, caseP.Case.CaseID); err == nil {
		t.Fatal("tampered case ciphertext was presented")
	}
}

func assertPendingState(t *testing.T, db *DB, caseID, state, authorityID string, revision int64, acceptedAt string) {
	t.Helper()
	var gotState, gotAuthorityID, gotAcceptedAt string
	var gotRevision int64
	if err := db.SQL().QueryRow(
		`SELECT state,COALESCE(authority_id,''),COALESCE(authority_revision,0),COALESCE(accepted_at,'') FROM ssp_edge_pending_cases WHERE case_id=?`,
		caseID,
	).Scan(&gotState, &gotAuthorityID, &gotRevision, &gotAcceptedAt); err != nil {
		t.Fatal(err)
	}
	if gotState != state || gotAuthorityID != authorityID || gotRevision != revision || gotAcceptedAt != acceptedAt {
		t.Fatalf("pending state = (%q,%q,%d,%q)", gotState, gotAuthorityID, gotRevision, gotAcceptedAt)
	}
}
