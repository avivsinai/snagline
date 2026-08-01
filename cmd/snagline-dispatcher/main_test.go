package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRefusesRuntimeUnavailableWithoutClaimingAdviceAccepted(t *testing.T) {
	dir := t.TempDir()
	descriptor := filepath.Join(dir, "key.json")
	if err := os.WriteFile(descriptor, []byte(`{"key_path":"/tmp/dispatcher.pem"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := run([]string{"--key-descriptor", descriptor, "--case-id", "case-1", "--case-commitment", "sha256:" + repeat("a", 64), "--text", "confidential inert detail", "--public-summary", "inert"}, func(keyDescriptor) (dispatcherAPI, error) { return nil, errors.New("not wired") }, &out)
	if code == 0 || bytes.Contains(out.Bytes(), []byte("inert")) {
		t.Fatalf("code=%d output=%s", code, out.String())
	}
}

func TestReadKeyDescriptorAcceptsOwnerOnlyReadFile(t *testing.T) {
	descriptor := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(descriptor, []byte(`{"key_path":"/tmp/dispatcher.pem"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(descriptor, 0o400); err != nil {
		t.Fatal(err)
	}
	got, err := readKeyDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyPath != "/tmp/dispatcher.pem" {
		t.Fatalf("key path = %q", got.KeyPath)
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
