//go:build darwin || linux || freebsd || openbsd || netbsd

package securefile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrivateExactUsesOpenedPrivateRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	want := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPrivateExact(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("key mismatch")
	}
	got[0] ^= 1
	if want[0] != 7 {
		t.Fatal("returned key aliased test input")
	}
}

func TestReadPrivateExactRejectsUnsafeTargetsAndWrongLength(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid")
	if err := os.WriteFile(valid, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "link")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(dir, "public")
	if err := os.WriteFile(public, bytes.Repeat([]byte{1}, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", dir, symlink, public, short} {
		if _, err := ReadPrivateExact(path, 32); err == nil {
			t.Fatalf("accepted unsafe key path %q", path)
		}
	}
}

func TestBoundedReadersSeparatePublicAndPrivatePermissions(t *testing.T) {
	dir := t.TempDir()
	public := filepath.Join(dir, "public.pem")
	if err := os.WriteFile(public, []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadRegularBounded(public, 16); err != nil || string(got) != "public" {
		t.Fatalf("ReadRegularBounded = %q, %v", got, err)
	}
	if _, err := ReadPrivateBounded(public, 16); err == nil {
		t.Fatal("private reader accepted group/world-readable file")
	}
	private := filepath.Join(dir, "private.pem")
	if err := os.WriteFile(private, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPrivateBounded(private, 16); err != nil || string(got) != "private" {
		t.Fatalf("ReadPrivateBounded = %q, %v", got, err)
	}
}
