package sspedge

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDispatcherTurnStoreEncryptsFullBindingAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir, key := privateStorePaths(t)
	path := filepath.Join(dir, "edge.db")
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	eventID := strings.Repeat("a", 64)
	request := []byte(`{"event_id":"` + eventID + `","submission":{"case_id":"case-🧵","case_commitment":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","text":"confidential\u0000text","public_summary":"public"}}`)
	result := []byte(`{"ok":true,"code":"accepted_remote","advice_id":"advice-1","authority_revision":7}`)
	claimTTL := time.Minute

	db, err := Open(ctx, OpenOptions{Path: path, KeyFilePath: key, Tenant: "tenant/a.*"})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := db.BindDispatcherTurn(ctx, eventID, request, now, time.Hour, claimTTL, 2)
	if err != nil || binding.Completed || binding.InFlight || binding.ClaimToken == "" {
		t.Fatalf("initial bind = (%+v, %v)", binding, err)
	}
	if err := db.CompleteDispatcherTurn(ctx, eventID, request, result, now.Add(time.Second), binding.ClaimToken); err != nil {
		t.Fatal(err)
	}
	var requestCiphertext, resultCiphertext []byte
	if err := db.SQL().QueryRowContext(ctx, `SELECT request_ciphertext,result_ciphertext FROM ssp_edge_dispatcher_turns WHERE event_id=?`, eventID).Scan(&requestCiphertext, &resultCiphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(requestCiphertext, request) || bytes.Contains(resultCiphertext, result) {
		t.Fatal("dispatcher turn request or result was stored as plaintext")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(ctx, OpenOptions{Path: path, KeyFilePath: key, Tenant: "tenant/a.*"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	binding, err = db.BindDispatcherTurn(ctx, eventID, request, now.Add(time.Minute), time.Hour, claimTTL, 2)
	if err != nil || !binding.Completed || !bytes.Equal(binding.Result, result) {
		t.Fatalf("restarted bind = (%+v, %v)", binding, err)
	}
	binding.Result[0] ^= 0xff
	again, err := db.BindDispatcherTurn(ctx, eventID, request, now.Add(2*time.Minute), time.Hour, claimTTL, 2)
	if err != nil || !bytes.Equal(again.Result, result) {
		t.Fatal("completed result leaked mutable stored bytes")
	}
	changed := append([]byte(nil), request...)
	changed[len(changed)-3] = 'X'
	if _, err := db.BindDispatcherTurn(ctx, eventID, changed, now.Add(3*time.Minute), time.Hour, claimTTL, 2); !errors.Is(err, ErrDispatcherTurnMismatch) {
		t.Fatalf("changed request error = %v", err)
	}
	if err := db.CompleteDispatcherTurn(ctx, eventID, request, append(result, 'x'), now.Add(4*time.Minute), strings.Repeat("f", 64)); err == nil {
		t.Fatal("changed completed result was accepted")
	}
}

func TestDispatcherTurnStoreExpiresBeforeCapacityAccounting(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	retention := time.Minute
	claimTTL := 30 * time.Second
	request := []byte(`{"canonical":"request"}`)

	for _, character := range []string{"a", "b"} {
		if _, err := db.BindDispatcherTurn(ctx, strings.Repeat(character, 64), request, now, retention, claimTTL, 2); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.BindDispatcherTurn(ctx, strings.Repeat("c", 64), request, now, retention, claimTTL, 2); !errors.Is(err, ErrDispatcherTurnCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if _, err := db.BindDispatcherTurn(ctx, strings.Repeat("c", 64), request, now.Add(retention), retention, claimTTL, 2); err != nil {
		t.Fatalf("bind after expiry: %v", err)
	}
	if got := count(t, db, "ssp_edge_dispatcher_turns"); got != 1 {
		t.Fatalf("rows after expiry = %d", got)
	}
}

func TestAbandonDispatcherTurnFreesPendingCapacity(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	request := []byte(`{"canonical":"request"}`)
	firstEventID := strings.Repeat("a", 64)
	secondEventID := strings.Repeat("b", 64)

	binding, err := db.BindDispatcherTurn(ctx, firstEventID, request, now, time.Hour, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AbandonDispatcherTurn(ctx, firstEventID, request, binding.ClaimToken); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BindDispatcherTurn(ctx, secondEventID, request, now, time.Hour, time.Minute, 1); err != nil {
		t.Fatalf("capacity was not released: %v", err)
	}
}

func TestAbandonDispatcherTurnRejectsWrongRequest(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	eventID := strings.Repeat("a", 64)
	request := []byte(`{"canonical":"request"}`)

	binding, err := db.BindDispatcherTurn(ctx, eventID, request, now, time.Hour, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AbandonDispatcherTurn(ctx, eventID, []byte(`{"canonical":"other"}`), binding.ClaimToken); !errors.Is(err, ErrDispatcherTurnMismatch) {
		t.Fatalf("wrong request error = %v", err)
	}
	if _, err := db.BindDispatcherTurn(ctx, strings.Repeat("b", 64), request, now, time.Hour, time.Minute, 1); !errors.Is(err, ErrDispatcherTurnCapacity) {
		t.Fatalf("wrong request abandoned its reservation: %v", err)
	}
}

func TestAbandonDispatcherTurnRejectsCompletedBinding(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	eventID := strings.Repeat("a", 64)
	request := []byte(`{"canonical":"request"}`)
	result := []byte(`{"ok":true}`)

	binding, err := db.BindDispatcherTurn(ctx, eventID, request, now, time.Hour, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteDispatcherTurn(ctx, eventID, request, result, now.Add(time.Second), binding.ClaimToken); err != nil {
		t.Fatal(err)
	}
	if err := db.AbandonDispatcherTurn(ctx, eventID, request, binding.ClaimToken); err == nil {
		t.Fatal("completed binding was abandoned")
	}
	binding, err = db.BindDispatcherTurn(ctx, eventID, request, now.Add(2*time.Second), time.Hour, time.Minute, 1)
	if err != nil || !binding.Completed || !bytes.Equal(binding.Result, result) {
		t.Fatalf("completed binding changed after abandon = (%+v, %v)", binding, err)
	}
}

func TestDispatcherTurnClaimPreventsStaleOwnerFromErasingLiveRetry(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	eventID := strings.Repeat("a", 64)
	request := []byte(`{"canonical":"request"}`)
	result := []byte(`{"ok":true}`)

	first, err := db.BindDispatcherTurn(ctx, eventID, request, now, time.Hour, time.Minute, 1)
	if err != nil || first.ClaimToken == "" {
		t.Fatalf("first bind = (%+v, %v)", first, err)
	}
	concurrent, err := db.BindDispatcherTurn(ctx, eventID, request, now.Add(time.Second), time.Hour, time.Minute, 1)
	if err != nil || !concurrent.InFlight || concurrent.ClaimToken != "" {
		t.Fatalf("concurrent bind = (%+v, %v)", concurrent, err)
	}
	second, err := db.BindDispatcherTurn(ctx, eventID, request, now.Add(time.Minute), time.Hour, time.Minute, 1)
	if err != nil || second.ClaimToken == "" || second.ClaimToken == first.ClaimToken {
		t.Fatalf("takeover bind = (%+v, %v)", second, err)
	}
	if err := db.AbandonDispatcherTurn(ctx, eventID, request, first.ClaimToken); err == nil {
		t.Fatal("stale owner abandoned live retry")
	}
	if err := db.CompleteDispatcherTurn(ctx, eventID, request, result, now.Add(time.Minute+time.Second), second.ClaimToken); err != nil {
		t.Fatal(err)
	}
	if err := db.AbandonDispatcherTurn(ctx, eventID, request, first.ClaimToken); err == nil {
		t.Fatal("stale owner abandoned completed retry")
	}
	completed, err := db.BindDispatcherTurn(ctx, eventID, request, now.Add(2*time.Minute), time.Hour, time.Minute, 1)
	if err != nil || !completed.Completed || !bytes.Equal(completed.Result, result) {
		t.Fatalf("completed bind = (%+v, %v)", completed, err)
	}
}

func TestReleaseDispatcherTurnClaimKeepsReservationButAllowsImmediateRetry(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	eventID := strings.Repeat("d", 64)
	request := []byte(`{"canonical":"request"}`)

	first, err := db.BindDispatcherTurn(ctx, eventID, request, now, time.Hour, time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ReleaseDispatcherTurnClaim(ctx, eventID, request, first.ClaimToken); err != nil {
		t.Fatal(err)
	}
	if got := count(t, db, "ssp_edge_dispatcher_turns"); got != 1 {
		t.Fatalf("release removed reservation; rows=%d", got)
	}
	second, err := db.BindDispatcherTurn(ctx, eventID, request, now.Add(time.Second), time.Hour, time.Minute, 1)
	if err != nil || second.ClaimToken == "" || second.ClaimToken == first.ClaimToken || second.InFlight {
		t.Fatalf("immediate retry bind = (%+v, %v)", second, err)
	}
	if err := db.ReleaseDispatcherTurnClaim(ctx, eventID, request, first.ClaimToken); err == nil {
		t.Fatal("stale owner released live retry")
	}
}
