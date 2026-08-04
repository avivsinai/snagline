package edgeclient

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// startCaseServer stands up the three case routes over a private Unix socket and
// returns a client bound to it. The handlers assert method and status so the
// test proves the client speaks the exact contract: 202 on open, 200 on reads.
func startCaseServer(t *testing.T, mux *http.ServeMux) *Client {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "slcase-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "edge.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	client, err := New(Config{Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestOpenCaseRequiresAcceptedStatusAndEchoesCaseID(t *testing.T) {
	mux := http.NewServeMux()
	var gotBody map[string]any
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		// The edge accepts a case with 202, not 200.
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"EnvelopeID":"env-1","CaseID":"case-1","Commitment":"c","AcceptedRemote":true,"Receipt":{"AuthorityID":"auth","Revision":3,"EnvelopeID":"env-1","Commitment":"c"}}`))
	})
	client := startCaseServer(t, mux)

	submission, err := client.OpenCase(context.Background(), OpenCaseRequest{
		CaseID: "case-1", Domain: "billing", Summary: "confidential detail",
		PublicSummary: "public blurb", ContextManifest: "sha256:" + repeat64(),
		Registry: RegistryCoordinates{RoutingEpoch: 0, Revision: 3, Hash: "sha256:" + repeat64()},
	})
	if err != nil {
		t.Fatalf("open = %v", err)
	}
	if !submission.AcceptedRemote || submission.CaseID != "case-1" || submission.Receipt.Revision != 3 {
		t.Fatalf("submission = %#v", submission)
	}
	// public_summary and summary must both cross the wire, distinctly.
	if gotBody["public_summary"] != "public blurb" || gotBody["summary"] != "confidential detail" {
		t.Fatalf("request body did not carry both summaries: %#v", gotBody)
	}
}

func TestOpenCaseRejectsA200Response(t *testing.T) {
	// A 200 (rather than the contractual 202) must be treated as a rejection,
	// so a misbehaving or wrong endpoint cannot be read as an accepted case.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"EnvelopeID":"e","CaseID":"case-1","Commitment":"c","AcceptedRemote":true,"Receipt":{"AuthorityID":"a","Revision":1,"EnvelopeID":"e","Commitment":"c"}}`))
	})
	client := startCaseServer(t, mux)
	if _, err := client.OpenCase(context.Background(), validOpen()); err == nil {
		t.Fatal("a 200 open response was accepted; must require 202")
	}
}

func TestOpenCaseRejectsMismatchedCaseID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"EnvelopeID":"e","CaseID":"OTHER","Commitment":"c","AcceptedRemote":true,"Receipt":{"AuthorityID":"a","Revision":1,"EnvelopeID":"e","Commitment":"c"}}`))
	})
	client := startCaseServer(t, mux)
	if _, err := client.OpenCase(context.Background(), validOpen()); err == nil {
		t.Fatal("a response confirming a different case ID was accepted")
	}
}

func TestGetCaseAndListAdviceReadThroughGET(t *testing.T) {
	mux := http.NewServeMux()
	var caseMethod, adviceMethod string
	mux.HandleFunc("GET /v1/cases/{caseID}/advice", func(w http.ResponseWriter, r *http.Request) {
		adviceMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"AdviceID":"adv-1","CaseID":"case-1","Text":"inert advice","ReceivedAt":"2026-08-04T00:00:00Z"}]`))
	})
	mux.HandleFunc("GET /v1/cases/{caseID}", func(w http.ResponseWriter, r *http.Request) {
		caseMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"EnvelopeID":"e","CaseID":"case-1","Commitment":"c","Summary":"s","Registry":{"routing_epoch":0,"revision":1,"hash":"sha256:x"},"ExpiresAt":"2026-08-04T00:00:00Z","Committed":true}`))
	})
	client := startCaseServer(t, mux)

	record, err := client.GetCase(context.Background(), "case-1")
	if err != nil || record.CaseID != "case-1" || !record.Committed {
		t.Fatalf("get = %#v, %v", record, err)
	}
	advice, err := client.ListAdvice(context.Background(), "case-1")
	if err != nil || len(advice) != 1 || advice[0].AdviceID != "adv-1" {
		t.Fatalf("advice = %#v, %v", advice, err)
	}
	if caseMethod != http.MethodGet || adviceMethod != http.MethodGet {
		t.Fatalf("reads must use GET; case=%s advice=%s", caseMethod, adviceMethod)
	}
}

func TestListAdviceRejectsForeignCase(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cases/{caseID}/advice", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"AdviceID":"adv-1","CaseID":"SOMEONE-ELSE","Text":"t","ReceivedAt":"2026-08-04T00:00:00Z"}]`))
	})
	client := startCaseServer(t, mux)
	if _, err := client.ListAdvice(context.Background(), "case-1"); err == nil {
		t.Fatal("advice belonging to a different case was accepted")
	}
}

func validOpen() OpenCaseRequest {
	return OpenCaseRequest{
		CaseID: "case-1", Domain: "billing", Summary: "detail", PublicSummary: "blurb",
		ContextManifest: "sha256:" + repeat64(), Registry: RegistryCoordinates{Hash: "sha256:" + repeat64()},
	}
}

func repeat64() string {
	s := ""
	for i := 0; i < 64; i++ {
		s += "a"
	}
	return s
}
