//go:build !cgo

package sspedge

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenFailsClosedWithoutCGO(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "edge.key")
	key := make([]byte, StoreKeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(dir, "edge.db")

	db, err := Open(context.Background(), OpenOptions{
		Path: databasePath, KeyFilePath: keyPath, Tenant: "tenant/a.*",
	})
	if db != nil {
		_ = db.Close()
		t.Fatal("Open returned a database without CGO")
	}
	if err == nil || !strings.Contains(err.Error(), "CGO") {
		t.Fatalf("Open error = %v, want explicit CGO failure", err)
	}
	if _, err := os.Lstat(databasePath); !os.IsNotExist(err) {
		t.Fatalf("non-CGO Open touched database path: %v", err)
	}
}
