package sspedge

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/edge"
)

func TestAdviceSpoolEncryptsExactReplayAndRejectsConflict(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	pending := edge.PendingAdvice{
		AdviceID:       "advice/a",
		CaseID:         "case/a",
		CaseCommitment: commitment("1"),
		Commitment:     commitment("2"),
		Raw:            []byte(`{"exact":"signed advice"}`),
		CreatedAt:      time.Date(2026, 7, 31, 13, 14, 15, 16, time.UTC),
	}

	if err := db.SavePendingAdvice(ctx, pending); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := db.SQL().QueryRowContext(ctx, `SELECT raw_ciphertext FROM ssp_edge_pending_advice WHERE case_id=?`, pending.CaseID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, pending.Raw) {
		t.Fatal("pending advice wire was stored as plaintext")
	}
	got, exists, err := db.LoadPendingAdvice(ctx, pending.CaseID)
	if err != nil || !exists {
		t.Fatalf("load = (%+v, %v, %v)", got, exists, err)
	}
	if got.AdviceID != pending.AdviceID || got.CaseID != pending.CaseID ||
		got.CaseCommitment != pending.CaseCommitment || got.Commitment != pending.Commitment ||
		!got.CreatedAt.Equal(pending.CreatedAt) || !bytes.Equal(got.Raw, pending.Raw) {
		t.Fatalf("loaded advice = %+v", got)
	}
	got.Raw[0] ^= 0xff
	again, _, err := db.LoadPendingAdvice(ctx, pending.CaseID)
	if err != nil || !bytes.Equal(again.Raw, pending.Raw) {
		t.Fatal("LoadPendingAdvice leaked mutable stored bytes")
	}
	if err := db.SavePendingAdvice(ctx, pending); err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	conflict := pending
	conflict.AdviceID = "advice/b"
	if err := db.SavePendingAdvice(ctx, conflict); err == nil {
		t.Fatal("second final advice semantic identity was accepted")
	}
	if count(t, db, "ssp_edge_pending_advice") != 1 {
		t.Fatal("pending advice replay inserted another row")
	}
}

func TestMarkAdviceAcceptedRemotePersistsOnlyExactReceipt(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 31, 14, 15, 16, 17, time.UTC)
	pending := edge.PendingAdvice{
		AdviceID:       "advice/a",
		CaseID:         "case/a",
		CaseCommitment: commitment("1"),
		Commitment:     commitment("2"),
		Raw:            []byte(`{"exact":"signed advice"}`),
		CreatedAt:      now.Add(-time.Minute),
	}
	if err := db.SavePendingAdvice(ctx, pending); err != nil {
		t.Fatal(err)
	}
	accepted := edge.AcceptedRemoteAdvice{
		AdviceID:   pending.AdviceID,
		CaseID:     pending.CaseID,
		Commitment: pending.Commitment,
		Receipt: edge.CommitReceipt{
			AuthorityID: "postgres-primary",
			Revision:    42,
			EnvelopeID:  pending.AdviceID,
			Commitment:  pending.Commitment,
		},
		AcceptedAt: now,
	}
	mismatch := accepted
	mismatch.Receipt.EnvelopeID = "advice/b"
	if err := db.MarkAdviceAcceptedRemote(ctx, mismatch); err == nil {
		t.Fatal("mismatched receipt was accepted")
	}
	assertPendingAdviceState(t, db, pending.CaseID, "pending", "", 0, "")

	if err := db.MarkAdviceAcceptedRemote(ctx, accepted); err != nil {
		t.Fatal(err)
	}
	assertPendingAdviceState(t, db, pending.CaseID, "accepted_remote", "postgres-primary", 42, sqlTime(now))
	if err := db.MarkAdviceAcceptedRemote(ctx, accepted); err != nil {
		t.Fatalf("exact receipt replay: %v", err)
	}
	conflict := accepted
	conflict.Receipt.AuthorityID = "other"
	if err := db.MarkAdviceAcceptedRemote(ctx, conflict); err == nil {
		t.Fatal("conflicting receipt replaced accepted_remote evidence")
	}
	assertPendingAdviceState(t, db, pending.CaseID, "accepted_remote", "postgres-primary", 42, sqlTime(now))
}

func assertPendingAdviceState(t *testing.T, db *DB, caseID, state, authorityID string, revision int64, acceptedAt string) {
	t.Helper()
	var gotState, gotAuthorityID, gotAcceptedAt string
	var gotRevision int64
	if err := db.SQL().QueryRow(
		`SELECT state,COALESCE(authority_id,''),COALESCE(authority_revision,0),COALESCE(accepted_at,'') FROM ssp_edge_pending_advice WHERE case_id=?`,
		caseID,
	).Scan(&gotState, &gotAuthorityID, &gotRevision, &gotAcceptedAt); err != nil {
		t.Fatal(err)
	}
	if gotState != state || gotAuthorityID != authorityID || gotRevision != revision || gotAcceptedAt != acceptedAt {
		t.Fatalf("pending advice state = (%q,%q,%d,%q)", gotState, gotAuthorityID, gotRevision, gotAcceptedAt)
	}
}
