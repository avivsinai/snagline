package provision

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// custodyTempDir returns a temporary directory with every symlink already
// resolved. A custody path refuses a symlinked ancestor outright rather than
// resolving it, and on macOS t.TempDir() sits under /var, which is itself a
// symlink to /private/var — a test that handed t.TempDir() straight to
// WriteTo would be exercising the platform's own system symlinks instead of
// the case it means to cover.
func custodyTempDir(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestGenerateSigningKeyWriteAndLoadRoundTripSameKey(t *testing.T) {
	generated, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	wantPublic, err := generated.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(custodyTempDir(t), "signing.pem")
	if err := generated.WriteTo(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o777 != 0o600 {
		t.Fatalf("signing key file mode = %o, want 0600", info.Mode()&0o777)
	}

	loaded, err := LoadSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	gotPublic, err := loaded.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPublic, wantPublic) {
		t.Fatal("loaded signing key does not match the generated key's public key")
	}
}

func TestWriteSigningKeyRefusesToOverwriteAnExistingPath(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(custodyTempDir(t), "signing.pem")
	if err := os.WriteFile(path, []byte("pre-existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := key.WriteTo(path); err == nil {
		t.Fatal("WriteTo silently overwrote an existing path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "pre-existing" {
		t.Fatal("WriteTo modified the pre-existing file despite failing")
	}
}

func TestWriteSigningKeyRefusesASymlinkTarget(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := custodyTempDir(t)
	realTarget := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(realTarget, []byte("do-not-touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "signing.pem")
	if err := os.Symlink(realTarget, link); err != nil {
		t.Fatal(err)
	}
	if err := key.WriteTo(link); err == nil {
		t.Fatal("WriteTo followed a symlink instead of failing closed")
	}
	raw, err := os.ReadFile(realTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "do-not-touch" {
		t.Fatal("WriteTo wrote through the symlink into the link target")
	}
}

func TestWriteSigningKeyRejectsRelativePath(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := key.WriteTo("relative-signing.pem"); err == nil {
		t.Fatal("WriteTo accepted a relative path")
	}
}

func TestWriteSigningKeyRejectsANonCleanPath(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := custodyTempDir(t)
	// "<dir>/nested/../signing.pem" and "<dir>/signing.pem" name the same
	// file only if nothing on the way is a symlink — the very thing the walk
	// refuses to assume. Cleaning such a path lexically and then walking the
	// result would open something the caller did not name, so it is rejected
	// outright rather than normalized.
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Built by concatenation, not filepath.Join, which would clean the ".."
	// away before WriteTo ever saw it.
	nonClean := dir + "/nested/../signing.pem"
	if err := key.WriteTo(nonClean); err == nil {
		t.Fatal("WriteTo accepted a non-clean path containing \"..\"")
	}
	if _, err := os.Lstat(filepath.Join(dir, "signing.pem")); err == nil {
		t.Fatal("WriteTo created a file from a rejected non-clean path")
	}
}

func TestLoadedSigningKeyHasNoPrivateMaterialToWrite(t *testing.T) {
	generated, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(custodyTempDir(t), "signing.pem")
	if err := generated.WriteTo(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(custodyTempDir(t), "reexport.pem")
	if err := loaded.WriteTo(otherPath); err == nil {
		t.Fatal("a signing key obtained via LoadSigningKey wrote out private material")
	}
	if _, err := os.Lstat(otherPath); err == nil {
		t.Fatal("WriteTo created a file despite refusing to persist a loaded key")
	}
}

func TestWriteToRefusesASecondWriteToADifferentPath(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := custodyTempDir(t)
	first := filepath.Join(dir, "first.pem")
	second := filepath.Join(dir, "second.pem")

	if err := key.WriteTo(first); err != nil {
		t.Fatal(err)
	}
	if err := key.WriteTo(second); err == nil {
		t.Fatal("a second WriteTo to a different path succeeded after the first")
	}
	if _, err := os.Lstat(second); err == nil {
		t.Fatal("the refused second write still created a file")
	}
}

func TestWriteToRefusesASecondWriteFromACopiedValue(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := custodyTempDir(t)
	first := filepath.Join(dir, "first.pem")
	second := filepath.Join(dir, "second.pem")

	// A plain Go copy of the struct value must observe the same one-write
	// custody state as the original, so the copy cannot be used to bypass
	// the write-once invariant.
	copied := key
	if err := key.WriteTo(first); err != nil {
		t.Fatal(err)
	}
	if err := copied.WriteTo(second); err == nil {
		t.Fatal("writing from a copy of an already-written key succeeded")
	}
	if _, err := os.Lstat(second); err == nil {
		t.Fatal("the refused copy-write still created a file")
	}
}

func TestWriteToAllowsExactlyOneWinnerUnderConcurrentWrites(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := custodyTempDir(t)
	const attempts = 8
	var successes atomic.Int32
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			path := filepath.Join(dir, fmt.Sprintf("signing-%d.pem", i))
			if err := key.WriteTo(path); err == nil {
				successes.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("concurrent WriteTo calls produced %d successes, want exactly 1", got)
	}
	written := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for range entries {
		written++
	}
	if written != 1 {
		t.Fatalf("concurrent WriteTo calls left %d files on disk, want exactly 1", written)
	}
}

func TestWriteToDoesNotConsumeItsOneWriteOnAFailedAttempt(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := custodyTempDir(t)
	occupied := filepath.Join(dir, "occupied.pem")
	if err := os.WriteFile(occupied, []byte("pre-existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	// It is the first SUCCESSFUL write that spends a key's one point of
	// custody. An attempt that never persisted anything must leave the key
	// writable, or a caller that mistyped a path once could never persist
	// the key it just generated.
	if err := key.WriteTo(occupied); err == nil {
		t.Fatal("WriteTo overwrote an occupied path")
	}
	if err := key.WriteTo(filepath.Join(dir, "signing.pem")); err != nil {
		t.Fatalf("a failed write consumed the key's one write: %v", err)
	}
}

func TestWriteToFailsClosedWhenAnAncestorDirectoryIsASymlink(t *testing.T) {
	base := custodyTempDir(t)
	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(realDir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(base, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Fatal(err)
	}

	// O_NOFOLLOW on the leaf cannot see either of these: the leaf does not
	// exist yet and is not itself a symlink. Only walking the directories
	// refuses them — the immediate parent first, then a grandparent, to show
	// the walk covers arbitrary depth rather than one level.
	for _, target := range []string{
		filepath.Join(linkedDir, "signing.pem"),
		filepath.Join(linkedDir, "keys", "signing.pem"),
	} {
		key, err := GenerateSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := key.WriteTo(target); err == nil {
			t.Fatalf("WriteTo(%q) followed a symlinked ancestor instead of failing closed", target)
		}
	}
	for _, leaked := range []string{
		filepath.Join(realDir, "signing.pem"),
		filepath.Join(realDir, "keys", "signing.pem"),
	} {
		if _, err := os.Lstat(leaked); err == nil {
			t.Fatalf("WriteTo wrote through the symlinked ancestor into %q", leaked)
		}
	}
}

func TestLoadSigningKeyFailsClosedWhenAnAncestorDirectoryIsASymlink(t *testing.T) {
	generated, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	base := custodyTempDir(t)
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realPath := filepath.Join(realDir, "signing.pem")
	if err := generated.WriteTo(realPath); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(base, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadSigningKey(filepath.Join(linkedDir, "signing.pem")); err == nil {
		t.Fatal("LoadSigningKey followed a symlinked parent directory instead of failing closed")
	}
	// The direct path must still load, so the rejection above is about the
	// symlinked ancestor and not an unrelated regression in the read path.
	if _, err := LoadSigningKey(realPath); err != nil {
		t.Fatalf("LoadSigningKey(realPath) = %v, want success", err)
	}
}

func TestLoadSigningKeyFailsClosedOnGroupReadablePermissions(t *testing.T) {
	generated, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(custodyTempDir(t), "signing.pem")
	if err := generated.WriteTo(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(path); err == nil {
		t.Fatal("LoadSigningKey accepted a group-readable signing key file")
	}
}

func TestLoadSigningKeyFailsClosedOnSymlink(t *testing.T) {
	generated, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := custodyTempDir(t)
	real := filepath.Join(dir, "signing.pem")
	if err := generated.WriteTo(real); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(link); err == nil {
		t.Fatal("LoadSigningKey followed a symlink")
	}
}

func TestMarshalVerifyingKeyPEMRoundTripsThroughStandardPKIX(t *testing.T) {
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalVerifyingKeyPEM(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		t.Fatalf("unexpected PEM encoding: block=%#v rest=%q", block, rest)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roundTripped, ok := parsed.(ed25519.PublicKey)
	if !ok || !bytes.Equal(roundTripped, publicKey) {
		t.Fatal("verifying key PEM did not round trip to the same ed25519 public key")
	}
}

func TestMarshalVerifyingKeyPEMRejectsWrongLength(t *testing.T) {
	if _, err := MarshalVerifyingKeyPEM(make([]byte, 16)); err == nil {
		t.Fatal("accepted a public key of the wrong length")
	}
}
