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

func TestParseCaseConfigExposesNoAuthoritySelectingFlags(t *testing.T) {
	for _, args := range [][]string{{}, {"frobnicate"}, {"open", "--socket=/tmp/edge.sock"}, {"get", "--case-id=foreign"}, {"open", "--summary=secret"}, {"advice", "extra"}} {
		if _, err := parseCaseConfig(args); err == nil {
			t.Fatalf("args %v accepted", args)
		}
	}
	for _, mode := range []string{"open", "retry", "get", "advice"} {
		config, err := parseCaseConfig([]string{mode})
		if err != nil || config.Mode != mode {
			t.Fatalf("mode=%s config=%#v err=%v", mode, config, err)
		}
	}
}

func TestReadSessionBindingRequiresPrivateStrictDescriptor(t *testing.T) {
	dir := t.TempDir()
	valid := `{"socket":"/run/snagline-edge-a/edge.sock","case_id":"case-1","domain":"runtime","context_manifest":"` + digest("a") + `","registry":{"routing_epoch":1,"revision":2,"hash":"` + digest("b") + `"}}`
	path := filepath.Join(dir, "session.json")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	binding, err := readSessionBinding(path)
	if err != nil || binding.CaseID != "case-1" || binding.Registry.Revision != 2 {
		t.Fatalf("binding=%#v err=%v", binding, err)
	}
	for name, body := range map[string]string{"unknown field": strings.Replace(valid, `"case_id"`, `"unexpected":true,"case_id"`, 1), "trailing JSON": valid + `{}`, "relative socket": strings.Replace(valid, "/run/snagline-edge-a/edge.sock", "relative.sock", 1), "bad digest": strings.Replace(valid, digest("a"), "sha256:no", 1)} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readSessionBinding(p); err == nil {
				t.Fatal("invalid descriptor accepted")
			}
		})
	}
	public := filepath.Join(dir, "public.json")
	if err := os.WriteFile(public, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSessionBinding(public); err == nil {
		t.Fatal("public descriptor accepted")
	}
}

func TestRunCaseUsesPinnedCaseReadsSummaryFromStdinAndRedactsOutput(t *testing.T) {
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
	var openedCase, openedSummary, readCase string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		openedCase, _ = body["case_id"].(string)
		openedSummary, _ = body["summary"].(string)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(submissionJSON()))
	})
	mux.HandleFunc("GET /v1/cases/{caseID}/advice", func(w http.ResponseWriter, r *http.Request) {
		readCase = r.PathValue("caseID")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"AdviceID":"adv-1","CaseID":"case-1","Text":"CONFIDENTIAL-ADVICE","ReceivedAt":"2026-08-04T00:00:00Z"}]`))
	})
	mux.HandleFunc("GET /v1/cases/{caseID}", func(w http.ResponseWriter, r *http.Request) {
		readCase = r.PathValue("caseID")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"EnvelopeID":"env-1","CaseID":"case-1","Commitment":"` + digest("c") + `","Summary":"CONFIDENTIAL-SUMMARY","Registry":{"RoutingEpoch":1,"Revision":2,"Hash":"` + digest("b") + `"},"ExpiresAt":"2026-08-04T00:00:00Z","Committed":true}`))
	})
	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	descriptor := writeBinding(t, dir, socket)

	var out bytes.Buffer
	input := `{"summary":"CONFIDENTIAL-SUMMARY","public_summary":"safe"}`
	if err := runCase(context.Background(), caseConfig{Mode: "open"}, descriptor, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if openedCase != "case-1" || openedSummary != "CONFIDENTIAL-SUMMARY" {
		t.Fatalf("case=%q summary=%q", openedCase, openedSummary)
	}
	if strings.Contains(out.String(), "CONFIDENTIAL") || !strings.Contains(out.String(), "accepted_remote") {
		t.Fatalf("open output=%s", out.String())
	}

	out.Reset()
	if err := runCase(context.Background(), caseConfig{Mode: "advice"}, descriptor, strings.NewReader("ignored"), &out); err != nil {
		t.Fatal(err)
	}
	if readCase != "case-1" || strings.Contains(out.String(), "CONFIDENTIAL-ADVICE") || !strings.Contains(out.String(), "adv-1") {
		t.Fatalf("case=%q output=%s", readCase, out.String())
	}

	out.Reset()
	if err := runCase(context.Background(), caseConfig{Mode: "get"}, descriptor, strings.NewReader("ignored"), &out); err != nil {
		t.Fatal(err)
	}
	if readCase != "case-1" || strings.Contains(out.String(), "CONFIDENTIAL-SUMMARY") || !strings.Contains(out.String(), "case_status") {
		t.Fatalf("case=%q output=%s", readCase, out.String())
	}
}

func TestRunCaseRejectsMalformedOrInvalidUTF8StdinBeforeCallingEdge(t *testing.T) {
	dir := t.TempDir()
	descriptor := writeBinding(t, dir, filepath.Join(dir, "missing.sock"))
	for name, input := range map[string]string{"unknown": `{"summary":"s","public_summary":"p","extra":true}`, "trailing": `{"summary":"s","public_summary":"p"}{}`, "invalid utf8": string([]byte{'{', '"', 's', 'u', 'm', 'm', 'a', 'r', 'y', '"', ':', '"', 0xff, '"', '}'})} {
		t.Run(name, func(t *testing.T) {
			if err := runCase(context.Background(), caseConfig{Mode: "open"}, descriptor, strings.NewReader(input), ioDiscard{}); err == nil {
				t.Fatal("bad stdin accepted")
			}
		})
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func writeBinding(t *testing.T, dir, socket string) string {
	t.Helper()
	path := filepath.Join(dir, "session.json")
	body := `{"socket":` + quote(socket) + `,"case_id":"case-1","domain":"runtime","context_manifest":"` + digest("a") + `","registry":{"routing_epoch":1,"revision":2,"hash":"` + digest("b") + `"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func digest(c string) string { return "sha256:" + strings.Repeat(c, 64) }
func quote(s string) string  { raw, _ := json.Marshal(s); return string(raw) }
func submissionJSON() string {
	return `{"EnvelopeID":"env-1","CaseID":"case-1","Commitment":"` + digest("c") + `","AcceptedRemote":true,"Receipt":{"AuthorityID":"auth","Revision":3,"EnvelopeID":"env-1","Commitment":"` + digest("c") + `"}}`
}
