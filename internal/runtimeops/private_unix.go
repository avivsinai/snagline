//go:build darwin || linux || freebsd || openbsd || netbsd

package runtimeops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Server owns a private Unix HTTP server.
type Server struct {
	path     string
	listener net.Listener
	http     *http.Server
	once     sync.Once
}

// Start validates and binds the private socket before starting the handler.
// It never falls back to TCP.
func Start(ctx context.Context, path string, config HandlerConfig) (*Server, error) {
	listener, err := ListenUnix(path)
	if err != nil {
		return nil, err
	}
	server := &Server{
		path: path, listener: listener,
		http: &http.Server{Handler: NewHandler(config), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4 << 10},
	}
	go func() { _ = server.http.Serve(listener) }()
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	return server, nil
}

func (s *Server) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var result error
	s.once.Do(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = s.http.Shutdown(shutdown)
		if err := s.listener.Close(); result == nil && !errors.Is(err, net.ErrClosed) {
			result = err
		}
	})
	return result
}

// ListenUnix permits only a socket in an explicitly configured, current-user
// owned 0700 directory. Existing sockets are replaced only when they are
// proven stale and current-user owned; every other existing entry fails closed.
func ListenUnix(path string) (net.Listener, error) {
	canonical, dirFD, base, err := prepareSocketNamespace(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)
	if err := removeStaleSocket(dirFD, base, canonical); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", canonical)
	if err != nil {
		return nil, err
	}
	if err := unix.Fchmodat(dirFD, base, 0o600, 0); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("runtimeops: set private socket permissions: %w", err)
	}
	if err := validateCurrentUserSocket(dirFD, base); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func prepareSocketNamespace(path string) (string, int, string, error) {
	if !filepath.IsAbs(path) || path != filepath.Clean(path) {
		return "", -1, "", errors.New("runtimeops: Unix socket path must be absolute and clean")
	}
	dir, base := filepath.Split(path)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "", -1, "", errors.New("runtimeops: Unix socket path must name a socket")
	}
	resolvedDir, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		return "", -1, "", errors.New("runtimeops: Unix socket parent is unavailable")
	}
	dirFD, err := openNoFollowDirectory(resolvedDir)
	if err != nil {
		return "", -1, "", err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(dirFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o700 || int(stat.Uid) != os.Getuid() {
		_ = unix.Close(dirFD)
		return "", -1, "", errors.New("runtimeops: Unix socket parent must be current-user-owned mode 0700")
	}
	return filepath.Join(resolvedDir, base), dirFD, base, nil
}

func openNoFollowDirectory(path string) (int, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return -1, errors.New("runtimeops: Unix socket parent must be absolute")
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
			return -1, errors.New("runtimeops: Unix socket parent is unavailable")
		}
		fd = next
	}
	return fd, nil
}

func removeStaleSocket(dirFD int, base, path string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(dirFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK || int(stat.Uid) != os.Getuid() {
		return errors.New("runtimeops: refusing to replace an unsafe Unix socket entry")
	}
	probe, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		_ = probe.Close()
		return errors.New("runtimeops: refusing to replace an active Unix socket")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.ENOENT) {
		return errors.New("runtimeops: refusing to replace a Unix socket with unknown liveness")
	}
	if err := unix.Unlinkat(dirFD, base, 0); err != nil {
		return fmt.Errorf("runtimeops: remove stale Unix socket: %w", err)
	}
	return nil
}

func validateCurrentUserSocket(dirFD int, base string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(dirFD, base, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Mode&0o777 != 0o600 || int(stat.Uid) != os.Getuid() {
		return errors.New("runtimeops: created Unix socket is not current-user-owned mode 0600")
	}
	return nil
}
