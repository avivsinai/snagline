package runtimeops

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHandlerReportsLivenessAndOpaqueReadiness(t *testing.T) {
	tracker := NewTracker()
	tracker.MarkInitialized()
	tracker.RecordSuccess(Measurements{Lag: 4, LagKnown: true, Poisoned: 2, PoisonedKnown: true})

	h := NewHandler(HandlerConfig{Role: "delivery", Tracker: tracker, Ready: func(context.Context) error {
		return errors.New("postgres://operator:secret@db.internal/snagline")
	}})

	live := httptest.NewRecorder()
	h.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if live.Code != http.StatusOK || live.Body.String() != "live\n" {
		t.Fatalf("live = %d %q", live.Code, live.Body.String())
	}

	ready := httptest.NewRecorder()
	h.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable || ready.Body.String() != "not_ready\n" {
		t.Fatalf("ready = %d %q", ready.Code, ready.Body.String())
	}
	if strings.Contains(ready.Body.String(), "secret") {
		t.Fatal("readiness leaked dependency detail")
	}

	metrics := httptest.NewRecorder()
	h.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metrics.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", metrics.Code)
	}
	body := metrics.Body.String()
	for _, want := range []string{
		"snagline_runtime_ready{role=\"delivery\"} 0",
		"snagline_runtime_initialized{role=\"delivery\"} 1",
		"snagline_runtime_lag_available{role=\"delivery\"} 1",
		"snagline_runtime_lag{role=\"delivery\"} 4",
		"snagline_runtime_poisoned_available{role=\"delivery\"} 1",
		"snagline_runtime_poisoned{role=\"delivery\"} 2",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "db.internal") {
		t.Fatalf("metrics leaked dependency detail: %s", body)
	}
}

func TestTrackerOmitsUnknownMeasurements(t *testing.T) {
	tracker := NewTracker()
	tracker.RecordError()
	metrics := tracker.Snapshot()
	if metrics.LastError.IsZero() || metrics.LagKnown || metrics.PoisonedKnown {
		t.Fatalf("snapshot = %#v", metrics)
	}
}

func TestHasFreshSuccessRejectsStaleFutureAndSupersededCycles(t *testing.T) {
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	fresh := Snapshot{LastSuccess: now.Add(-time.Minute)}
	if !HasFreshSuccess(fresh, now, 2*time.Minute) {
		t.Fatal("fresh successful cycle was rejected")
	}
	for name, snapshot := range map[string]Snapshot{
		"missing":    {},
		"stale":      {LastSuccess: now.Add(-3 * time.Minute)},
		"future":     {LastSuccess: now.Add(time.Second)},
		"superseded": {LastSuccess: now.Add(-time.Minute), LastError: now.Add(-30 * time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			if HasFreshSuccess(snapshot, now, 2*time.Minute) {
				t.Fatalf("accepted unhealthy snapshot: %#v", snapshot)
			}
		})
	}
	if HasFreshSuccess(fresh, now, 0) {
		t.Fatal("accepted a non-positive freshness window")
	}
}

func TestListenUnixRequiresPrivateCurrentUserNamespace(t *testing.T) {
	dir := testDir(t, 0o700)
	path := filepath.Join(dir, "ops.sock")
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || int(stat.Uid) != os.Getuid() {
		t.Fatalf("socket = mode:%v uid:%d", info.Mode(), stat.Uid)
	}

	unsafe := testDir(t, 0o755)
	if _, err := ListenUnix(filepath.Join(unsafe, "ops.sock")); err == nil {
		t.Fatal("accepted group/world-accessible socket parent")
	}
	if _, err := ListenUnix("relative.sock"); err == nil {
		t.Fatal("accepted relative socket path")
	}

	t.Run("symlink socket", func(t *testing.T) {
		dir := testDir(t, 0o700)
		path := filepath.Join(dir, "ops.sock")
		if err := os.Symlink(filepath.Join(dir, "target"), path); err != nil {
			t.Fatal(err)
		}
		if _, err := ListenUnix(path); err == nil {
			t.Fatal("accepted a symlink socket path")
		}
	})
	t.Run("regular file", func(t *testing.T) {
		dir := testDir(t, 0o700)
		path := filepath.Join(dir, "ops.sock")
		if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ListenUnix(path); err == nil {
			t.Fatal("accepted a regular file socket path")
		}
	})
	t.Run("stale current-user socket", func(t *testing.T) {
		dir := testDir(t, 0o700)
		path := filepath.Join(dir, "ops.sock")
		stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		stale.SetUnlinkOnClose(false)
		if err := stale.Close(); err != nil {
			t.Fatal(err)
		}
		listener, err := ListenUnix(path)
		if err != nil {
			t.Fatalf("did not replace a stale current-user socket: %v", err)
		}
		t.Cleanup(func() { _ = listener.Close() })
	})
	t.Run("active current-user socket", func(t *testing.T) {
		dir := testDir(t, 0o700)
		path := filepath.Join(dir, "ops.sock")
		active, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = active.Close() })
		if _, err := ListenUnix(path); err == nil {
			t.Fatal("replaced an active socket")
		}
	})
}

func TestStartServesOnlyPrivateSurfaceAndStopsWithContext(t *testing.T) {
	dir := testDir(t, 0o700)
	ctx, cancel := context.WithCancel(context.Background())
	server, err := Start(ctx, filepath.Join(dir, "ops.sock"), HandlerConfig{Role: "projector", Ready: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", server.Path())
	}}}
	response, err := client.Get("http://ops/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("ready = %d %s", response.StatusCode, body)
	}
	cancel()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Lstat(server.Path()); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket remained after shutdown")
		}
		time.Sleep(time.Millisecond)
	}
}

func testDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "snagline-runtimeops-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}
