// Package runtimeops provides the intentionally small, private operational
// surface shared by Snagline daemons. It has no authority or transport
// semantics: callers inject bounded readiness probes and record only numeric
// runtime state safe to expose to the current local user.
package runtimeops

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultProbeTimeout = 2 * time.Second

// Readiness is a bounded dependency check. Its error is deliberately never
// serialized: dependency failures can contain credentials or private topology.
type Readiness func(context.Context) error

// Measurements are the optional, observable work-state values a daemon can
// honestly provide. Unknown values are omitted rather than guessed.
type Measurements struct {
	Lag           float64
	LagKnown      bool
	Poisoned      float64
	PoisonedKnown bool
}

// Snapshot is a safe copy of the tracker state.
type Snapshot struct {
	Initialized   bool
	LastSuccess   time.Time
	LastError     time.Time
	Lag           float64
	LagKnown      bool
	Poisoned      float64
	PoisonedKnown bool
}

// Tracker holds in-process observations only. It intentionally neither reads
// a database nor claims that a broker checkpoint is an authority position.
type Tracker struct {
	mu       sync.RWMutex
	snapshot Snapshot
	now      func() time.Time
}

func NewTracker() *Tracker { return &Tracker{now: time.Now} }

func (t *Tracker) MarkInitialized() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.snapshot.Initialized = true
}

func (t *Tracker) RecordSuccess(measurements Measurements) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.snapshot.LastSuccess = t.now().UTC()
	if measurements.LagKnown {
		t.snapshot.Lag = measurements.Lag
		t.snapshot.LagKnown = true
	}
	if measurements.PoisonedKnown {
		t.snapshot.Poisoned = measurements.Poisoned
		t.snapshot.PoisonedKnown = true
	}
}

func (t *Tracker) RecordError() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.snapshot.LastError = t.now().UTC()
}

func (t *Tracker) Snapshot() Snapshot {
	if t == nil {
		return Snapshot{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.snapshot
}

// HasFreshSuccess fails closed when a worker has never completed, completed
// before its latest error, stopped making progress, or the local clock moved
// behind the recorded success. Dependency probes alone cannot detect a stuck
// work loop.
func HasFreshSuccess(snapshot Snapshot, now time.Time, maxAge time.Duration) bool {
	if maxAge <= 0 || snapshot.LastSuccess.IsZero() || snapshot.LastError.After(snapshot.LastSuccess) {
		return false
	}
	age := now.UTC().Sub(snapshot.LastSuccess)
	return age >= 0 && age <= maxAge
}

// HandlerConfig defines an intentionally non-disclosing HTTP surface. Role is
// restricted to shipped daemon names so metrics cannot carry configuration.
type HandlerConfig struct {
	Role         string
	Ready        Readiness
	Tracker      *Tracker
	ProbeTimeout time.Duration
}

// NewHandler creates exactly GET /livez, GET /readyz, and GET /metrics.
func NewHandler(config HandlerConfig) http.Handler {
	role := config.Role
	if !validRole(role) {
		role = "unknown"
	}
	tracker := config.Tracker
	if tracker == nil {
		tracker = NewTracker()
	}
	timeout := config.ProbeTimeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = defaultProbeTimeout
	}
	ready := func(parent context.Context) bool {
		if config.Ready == nil {
			return false
		}
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		return config.Ready(ctx) == nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		writePlain(w, http.StatusOK, "live\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, request *http.Request) {
		if !ready(request.Context()) {
			writePlain(w, http.StatusServiceUnavailable, "not_ready\n")
			return
		}
		writePlain(w, http.StatusOK, "ready\n")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, request *http.Request) {
		writeMetrics(w, role, ready(request.Context()), tracker.Snapshot())
	})
	return mux
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func writeMetrics(w http.ResponseWriter, role string, isReady bool, snapshot Snapshot) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	value := 0
	if isReady {
		value = 1
	}
	label := `{role="` + role + `"}`
	var body strings.Builder
	body.WriteString("# HELP snagline_runtime_ready Whether this daemon can serve its dependencies.\n# TYPE snagline_runtime_ready gauge\n")
	fmt.Fprintf(&body, "snagline_runtime_ready%s %d\n", label, value)
	body.WriteString("# HELP snagline_runtime_initialized Whether this daemon completed its initial dependency construction.\n# TYPE snagline_runtime_initialized gauge\n")
	value = 0
	if snapshot.Initialized {
		value = 1
	}
	fmt.Fprintf(&body, "snagline_runtime_initialized%s %d\n", label, value)
	writeTimestamp(&body, "snagline_runtime_last_success_timestamp_seconds", label, snapshot.LastSuccess)
	writeTimestamp(&body, "snagline_runtime_last_error_timestamp_seconds", label, snapshot.LastError)
	writeKnown(&body, "snagline_runtime_lag_available", label, snapshot.LagKnown)
	if snapshot.LagKnown {
		fmt.Fprintf(&body, "snagline_runtime_lag%s %s\n", label, strconv.FormatFloat(snapshot.Lag, 'f', -1, 64))
	}
	writeKnown(&body, "snagline_runtime_poisoned_available", label, snapshot.PoisonedKnown)
	if snapshot.PoisonedKnown {
		fmt.Fprintf(&body, "snagline_runtime_poisoned%s %s\n", label, strconv.FormatFloat(snapshot.Poisoned, 'f', -1, 64))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body.String()))
}

func writeKnown(body *strings.Builder, name, label string, known bool) {
	value := 0
	if known {
		value = 1
	}
	fmt.Fprintf(body, "%s%s %d\n", name, label, value)
}

func writeTimestamp(body *strings.Builder, name, label string, value time.Time) {
	seconds := int64(0)
	if !value.IsZero() {
		seconds = value.Unix()
	}
	fmt.Fprintf(body, "%s%s %d\n", name, label, seconds)
}

func validRole(role string) bool {
	switch role {
	case "control", "delivery", "edge", "projector":
		return true
	default:
		return false
	}
}
