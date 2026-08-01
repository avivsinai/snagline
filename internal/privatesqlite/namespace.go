//go:build darwin || linux || freebsd || openbsd || netbsd

// Package privatesqlite establishes the private filesystem namespace required
// before a SQLite driver reopens a database pathname.
package privatesqlite

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Namespace holds the canonical SQLite pathname and an open descriptor for its
// current-user-owned 0700 parent directory. Callers retain DirFD for the store
// lifetime and close it when the store closes.
type Namespace struct {
	Path  string
	DirFD int
}

// Open validates a clean absolute SQLite path, resolves its directory once,
// opens each directory component without following symlinks, and creates or
// verifies a private regular leaf through the retained directory descriptor.
// SQLite receives Path only after this validation; same-UID replacement after
// that handoff remains outside this helper's threat boundary.
func Open(path string) (Namespace, error) {
	if !filepath.IsAbs(path) || path != filepath.Clean(path) {
		return Namespace{}, errors.New("privatesqlite: database path must be absolute and clean")
	}
	dir, base := filepath.Split(path)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return Namespace{}, errors.New("privatesqlite: database path must name a file")
	}
	resolvedDir, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		return Namespace{}, fmt.Errorf("privatesqlite: resolve database directory: %w", err)
	}
	dirFD, err := openNoFollowDirectory(resolvedDir)
	if err != nil {
		return Namespace{}, err
	}
	if err := requirePrivateDirectory(dirFD); err != nil {
		_ = unix.Close(dirFD)
		return Namespace{}, err
	}
	if err := createOrVerifyPrivateLeaf(dirFD, base); err != nil {
		_ = unix.Close(dirFD)
		return Namespace{}, err
	}
	return Namespace{Path: filepath.Join(resolvedDir, base), DirFD: dirFD}, nil
}

func requirePrivateDirectory(dirFD int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(dirFD, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o777 != 0o700 ||
		int(stat.Uid) != os.Getuid() {
		return errors.New("privatesqlite: database directory must be current-user-owned mode 0700")
	}
	return nil
}

func createOrVerifyPrivateLeaf(dirFD int, base string) error {
	leafFD, err := unix.Openat(dirFD, base, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("privatesqlite: open database safely: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(leafFD, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o077 != 0 ||
		int(stat.Uid) != os.Getuid() {
		_ = unix.Close(leafFD)
		return errors.New("privatesqlite: database must be a private current-user-owned regular file")
	}
	return unix.Close(leafFD)
}

func openNoFollowDirectory(path string) (int, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return -1, errors.New("privatesqlite: database directory must be absolute")
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("privatesqlite: open database directory safely: %w", err)
		}
		fd = next
	}
	return fd, nil
}
