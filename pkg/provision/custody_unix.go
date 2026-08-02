//go:build darwin || linux || freebsd || openbsd || netbsd

package provision

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/avivsinai/snagline/internal/securefile"
)

// maxSigningKeyPEMBytes bounds a signing key read, matching the bound
// internal/identity applies when it reads the same file by pathname.
const maxSigningKeyPEMBytes int64 = 64 << 10

// Every syscall performed after the key file is created is indirected
// through a variable. Those are exactly the steps that can fail once a key
// artifact already exists on disk — the branch where custody must count as
// spent even though the write as a whole failed. Injecting them is the only
// way to reach those branches on a healthy filesystem. Nothing outside tests
// reassigns them, and none of them widen this package's public API.
var (
	writeFile = (*os.File).Write
	chmodFile = (*os.File).Chmod
	syncFile  = (*os.File).Sync
	closeFile = (*os.File).Close
	syncDir   = unix.Fsync
)

// writePrivateFile creates path as a new, current-user-only-readable regular
// file containing data, flushed to stable storage. It never overwrites an
// existing path and never follows a symlink, at the leaf or at any directory
// above it: the leaf is created through the descriptor walk below with
// O_EXCL, which fails if anything already exists there (file, directory, or
// symlink, dangling or not), and O_NOFOLLOW.
//
// created reports whether the leaf reached the filesystem. It is true for
// every outcome after the creating open succeeds, failures included, so the
// caller can spend custody at the point of no return rather than at the
// point of success. A post-create failure deliberately leaves the artifact in
// place. POSIX has no conditional unlink primitive: checking an inode and
// then unlinking its name leaves a replacement race. Leaving the artifact is
// the only fail-closed choice; the caller must regenerate, never retry
// elsewhere.
func writePrivateFile(path string, data []byte) (created bool, err error) {
	dirFD, base, err := openCustodyLeaf(path)
	if err != nil {
		return false, err
	}
	defer unix.Close(dirFD)
	dirIdentity, err := identityForFD(dirFD)
	if err != nil {
		return false, fmt.Errorf("provision: identify signing key directory: %w", err)
	}
	leafFD, err := unix.Openat(dirFD, base,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return false, fmt.Errorf("provision: create signing key file: %w", err)
	}
	leafIdentity, err := identityForFD(leafFD)
	if err != nil {
		_ = unix.Close(leafFD)
		return true, fmt.Errorf("provision: identify created signing key file: %w", err)
	}
	if err := fillPrivateFile(os.NewFile(uintptr(leafFD), path), data); err != nil {
		return true, err
	}
	// The contents are durable now; the directory entry naming them is not
	// until the directory itself is flushed. dirFD is the descriptor the
	// component-wise traversal produced, so this flush cannot be redirected
	// by anything that happens to the pathname in the meantime.
	if err := syncDir(dirFD); err != nil {
		return true, fmt.Errorf("provision: flush signing key directory: %w", err)
	}
	if err := verifyNamedLeaf(path, base, dirIdentity, leafIdentity); err != nil {
		return true, err
	}
	return true, nil
}

type filesystemIdentity struct {
	device uint64
	inode  uint64
}

func identityForFD(fd int) (filesystemIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return filesystemIdentity{}, err
	}
	return filesystemIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

// verifyNamedLeaf validates, at the final check, that the exact path the
// caller named resolves to the parent directory and leaf inode created by
// this call. Retaining the original descriptor prevents traversal races while
// writing. A concurrent writer can still alter a pathname after any final
// POSIX check, so callers that require an enduring named-path guarantee must
// provision inside an exclusively controlled directory.
func verifyNamedLeaf(path, wantBase string, wantDir, wantLeaf filesystemIdentity) error {
	dirFD, base, err := openCustodyLeaf(path)
	if err != nil {
		return fmt.Errorf("provision: signing key path changed before completion: %w", err)
	}
	defer unix.Close(dirFD)
	if base != wantBase {
		return errors.New("provision: signing key path changed before completion")
	}
	dirIdentity, err := identityForFD(dirFD)
	if err != nil || dirIdentity != wantDir {
		return errors.New("provision: signing key directory changed before completion")
	}
	leafFD, err := unix.Openat(dirFD, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("provision: signing key path changed before completion: %w", err)
	}
	defer unix.Close(leafFD)
	leafIdentity, err := identityForFD(leafFD)
	if err != nil || leafIdentity != wantLeaf {
		return errors.New("provision: signing key file changed before completion")
	}
	return nil
}

// fillPrivateFile writes data to an already-created key file, pins its mode,
// flushes it to stable storage, and closes it.
func fillPrivateFile(file *os.File, data []byte) (err error) {
	defer func() {
		if closeErr := closeFile(file); err == nil && closeErr != nil {
			err = fmt.Errorf("provision: close signing key file: %w", closeErr)
		}
	}()
	if _, err := writeFile(file, data); err != nil {
		return fmt.Errorf("provision: write signing key file: %w", err)
	}
	if err := chmodFile(file, 0o600); err != nil {
		return fmt.Errorf("provision: enforce signing key file mode: %w", err)
	}
	if err := syncFile(file); err != nil {
		return fmt.Errorf("provision: flush signing key file: %w", err)
	}
	return nil
}

// readPrivateFile returns the contents of a current-user-owned regular file
// at path with no group or other permission bits, reached without following
// a symlink at the leaf or at any directory above it.
func readPrivateFile(path string) ([]byte, error) {
	dirFD, base, err := openCustodyLeaf(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	raw, err := securefile.ReadPrivateAt(dirFD, base, maxSigningKeyPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("provision: read signing key file: %w", err)
	}
	return raw, nil
}

// openCustodyLeaf splits an absolute, already-clean custody path and returns
// an open descriptor for its parent directory plus the leaf name to use
// relative to that descriptor.
func openCustodyLeaf(path string) (int, string, error) {
	if !filepath.IsAbs(path) {
		return -1, "", errors.New("provision: signing key path must be absolute")
	}
	if path != filepath.Clean(path) {
		return -1, "", errors.New("provision: signing key path must be clean, with no \".\", \"..\", or repeated separators")
	}
	dir, base := filepath.Split(path)
	if base == "" || base == "." || base == ".." {
		return -1, "", errors.New("provision: signing key path must name a file")
	}
	dirFD, err := openCustodyDirectory(dir)
	if err != nil {
		return -1, "", err
	}
	return dirFD, base, nil
}

// openCustodyDirectory opens dir by walking it one component at a time from
// the filesystem root, opening each component relative to the previous one
// with O_NOFOLLOW.
//
// A single O_NOFOLLOW open of a full pathname refuses a symlink only at the
// FINAL component; the kernel still follows a symlink at any ancestor. A
// symlinked parent directory therefore redirects both the key write and the
// key read to somewhere the operator never named, which no leaf-level flag
// can detect. Walking descriptor by descriptor is what refuses it, and it is
// the same walk internal/privatesqlite performs before handing a pathname to
// SQLite.
//
// Unlike that walk, custody deliberately does not pre-resolve dir with
// filepath.EvalSymlinks. Resolving first would accept a symlinked ancestor
// as long as its target looked safe, and a private key must land at, and be
// read from, exactly the path the operator named. The cost is that a custody
// path may not traverse a symlink even when the symlink is a legitimate part
// of the platform (macOS /etc, /var, and /tmp are all symlinks); a caller
// there must pass the already-resolved path.
func openCustodyDirectory(dir string) (int, error) {
	clean := filepath.Clean(dir)
	fd, err := unix.Open(string(filepath.Separator),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("provision: open filesystem root: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		next, err := unix.Openat(fd, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("provision: open signing key directory component %q without following symlinks: %w", component, err)
		}
		fd = next
	}
	return fd, nil
}
