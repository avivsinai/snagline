//go:build darwin || linux || freebsd || openbsd || netbsd

// Package securefile reads deployment files from already-validated file
// descriptors. Callers never validate one pathname and reopen another.
package securefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var ErrRejected = errors.New("securefile: private file rejected")

// ReadPrivateExact returns exactly size bytes from a current-user-owned regular
// file with no group or other permissions. Symlinks and nonblocking special
// files are rejected at open time.
func ReadPrivateExact(path string, size int64) ([]byte, error) {
	raw, err := ReadPrivateBounded(path, size)
	if err != nil || int64(len(raw)) != size {
		return nil, ErrRejected
	}
	return raw, nil
}

// ReadPrivateBounded returns at most max bytes from a current-user-owned regular
// file with no group or other permissions.
func ReadPrivateBounded(path string, max int64) ([]byte, error) {
	return readRegularBounded(path, max, true)
}

// ReadRegularBounded returns at most max bytes from a regular file. It is for
// public deployment material such as certificates and verification keys.
func ReadRegularBounded(path string, max int64) ([]byte, error) {
	return readRegularBounded(path, max, false)
}

func readRegularBounded(path string, max int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || max <= 0 {
		return nil, ErrRejected
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRejected
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > max {
		return nil, ErrRejected
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Getuid() || info.Mode().Perm()&0o077 != 0 {
			return nil, ErrRejected
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, ErrRejected
	}
	return raw, nil
}
