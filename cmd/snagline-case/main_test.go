package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCaseConfigRejectsBadModeAndSocket(t *testing.T) {
	for _, args := range [][]string{
		{},       // no mode
		{"open"}, // no socket
		{"frobnicate", "--socket=/run/x/edge.sock"},   // bad mode
		{"open", "--socket=relative/edge.sock"},       // non-absolute socket
		{"open", "--socket=/run/../run/x/edge.sock"},  // unclean socket
		{"get", "--socket=/run/x/edge.sock", "extra"}, // stray positional
	} {
		if _, err := parseCaseConfig(args); err == nil {
			t.Fatalf("args %v were accepted", args)
		}
	}
	config, err := parseCaseConfig([]string{"open", "--socket=/run/snagline-edge-a/edge.sock", "--case-id=case-1"})
	if err != nil || config.Mode != "open" || config.CaseID != "case-1" {
		t.Fatalf("valid open config rejected: %#v %v", config, err)
	}
}

func TestRunCaseOpenGetAdviceAgainstMockEdge(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "slcase-cmd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "edge.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"EnvelopeID":"e","CaseID":"case-1","Commitment":"c","AcceptedRemote":true,"Receipt":{"AuthorityID":"a","Revision":1,"EnvelopeID":"e","Commitment":"c"}}`))
	})
	mux.HandleFunc("GET /v1/cases/{caseID}/advice", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"AdviceID":"adv-1","CaseID":"case-1","Text":"inert","ReceivedAt":"2026-08-04T00:00:00Z"}]`))
	})
	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)

	var out bytes.Buffer
	openCfg := caseConfig{Mode: "open", Socket: socket, CaseID: "case-1", Domain: "billing", Summary: "detail", PublicSummary: "blurb", ContextManifest: "sha256:" + strings.Repeat("a", 64), RegistryHash: "sha256:" + strings.Repeat("a", 64), RoutingEpoch: 0, Revision: 0}
	if err := runCase(context.Background(), openCfg, &out); err != nil {
		t.Fatalf("open failed: %v", err)
	}
	var submission map[string]any
	if err := json.Unmarshal(out.Bytes(), &submission); err != nil || submission["CaseID"] != "case-1" {
		t.Fatalf("open output = %s (%v)", out.String(), err)
	}

	out.Reset()
	if err := runCase(context.Background(), caseConfig{Mode: "advice", Socket: socket, CaseID: "case-1"}, &out); err != nil {
		t.Fatalf("advice failed: %v", err)
	}
	if !strings.Contains(out.String(), "adv-1") {
		t.Fatalf("advice output = %s", out.String())
	}
}
