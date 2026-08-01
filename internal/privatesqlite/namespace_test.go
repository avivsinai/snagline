package privatesqlite

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenCreatesPrivateLeafAndRetainsDirectoryDescriptor(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	namespace, err := Open(filepath.Join(dir, "state.sqlite"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer unix.Close(namespace.DirFD)

	info, err := os.Stat(namespace.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("created leaf mode = %v, want private regular 0600", info.Mode())
	}
	var stat unix.Stat_t
	if err := unix.Fstat(namespace.DirFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatalf("retained directory descriptor invalid: stat=%#v err=%v", stat, err)
	}
}

func TestOpenRejectsSymlinkLeafAndNonPrivateDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.sqlite")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.sqlite")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(dir, "link.sqlite")); err == nil {
		t.Fatal("Open() accepted a symlink leaf")
	}

	nonPrivate := t.TempDir()
	if err := os.Chmod(nonPrivate, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(nonPrivate, "state.sqlite")); err == nil {
		t.Fatal("Open() accepted a non-private directory")
	}
}
