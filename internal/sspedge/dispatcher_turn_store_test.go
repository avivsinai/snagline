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

	db, err := Open(ctx, OpenOptions{Path: path, KeyFilePath: key, Tenant: "tenant/a.*"})
	if err != nil {
		t.Fatal(err)
	}
	if binding, err := db.BindDispatcherTurn(ctx, eventID, request, now, time.Hour, 2); err != nil || binding.Completed {
		t.Fatalf("initial bind = (%+v, %v)", binding, err)
	}
	if err := db.CompleteDispatcherTurn(ctx, eventID, request, result, now.Add(time.Second)); err != nil {
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
	binding, err := db.BindDispatcherTurn(ctx, eventID, request, now.Add(time.Minute), time.Hour, 2)
	if err != nil || !binding.Completed || !bytes.Equal(binding.Result, result) {
		t.Fatalf("restarted bind = (%+v, %v)", binding, err)
	}
	binding.Result[0] ^= 0xff
	again, err := db.BindDispatcherTurn(ctx, eventID, request, now.Add(2*time.Minute), time.Hour, 2)
	if err != nil || !bytes.Equal(again.Result, result) {
		t.Fatal("completed result leaked mutable stored bytes")
	}
	changed := append([]byte(nil), request...)
	changed[len(changed)-3] = 'X'
	if _, err := db.BindDispatcherTurn(ctx, eventID, changed, now.Add(3*time.Minute), time.Hour, 2); !errors.Is(err, ErrDispatcherTurnMismatch) {
		t.Fatalf("changed request error = %v", err)
	}
	if err := db.CompleteDispatcherTurn(ctx, eventID, request, append(result, 'x'), now.Add(4*time.Minute)); err == nil {
		t.Fatal("changed completed result was accepted")
	}
}

func TestDispatcherTurnStoreExpiresBeforeCapacityAccounting(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	retention := time.Minute
	request := []byte(`{"canonical":"request"}`)

	for _, character := range []string{"a", "b"} {
		if _, err := db.BindDispatcherTurn(ctx, strings.Repeat(character, 64), request, now, retention, 2); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.BindDispatcherTurn(ctx, strings.Repeat("c", 64), request, now, retention, 2); !errors.Is(err, ErrDispatcherTurnCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if _, err := db.BindDispatcherTurn(ctx, strings.Repeat("c", 64), request, now.Add(retention), retention, 2); err != nil {
		t.Fatalf("bind after expiry: %v", err)
	}
	if got := count(t, db, "ssp_edge_dispatcher_turns"); got != 1 {
		t.Fatalf("rows after expiry = %d", got)
	}
}
