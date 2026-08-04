package edgeclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestOpenCaseUsesSnakeCaseRequestAndValidatesReceipt(t *testing.T) {
	mux := http.NewServeMux()
	var gotBody map[string]any
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(validSubmissionJSON("case-1")))
	})
	submission, err := startCaseServer(t, mux).OpenCase(context.Background(), validOpen())
	if err != nil || !submission.AcceptedRemote || submission.Receipt.Revision != 3 {
		t.Fatalf("submission=%#v err=%v", submission, err)
	}
	if gotBody["public_summary"] != "blurb" || gotBody["summary"] != "detail" || gotBody["case_id"] != "case-1" {
		t.Fatalf("request=%#v", gotBody)
	}
}

func TestOpenCaseRejectsIncompleteOrMismatchedReceipt(t *testing.T) {
	valid := validSubmissionJSON("case-1")
	tests := map[string]string{
		"not accepted":                strings.Replace(valid, `"AcceptedRemote":true`, `"AcceptedRemote":false`, 1),
		"missing envelope":            strings.Replace(valid, `"EnvelopeID":"env-1"`, `"EnvelopeID":""`, 1),
		"bad commitment":              strings.Replace(valid, digest("c"), "not-a-digest", 1),
		"missing authority":           strings.Replace(valid, `"AuthorityID":"auth"`, `"AuthorityID":""`, 1),
		"zero revision":               strings.Replace(valid, `"Revision":3`, `"Revision":0`, 1),
		"receipt envelope mismatch":   strings.Replace(valid, `"EnvelopeID":"env-1","Commitment":`+quote(digest("c"))+`}}`, `"EnvelopeID":"other","Commitment":`+quote(digest("c"))+`}}`, 1),
		"receipt commitment mismatch": strings.Replace(valid, `"EnvelopeID":"env-1","Commitment":`+quote(digest("c"))+`}}`, `"EnvelopeID":"env-1","Commitment":`+quote(digest("d"))+`}}`, 1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(body))
			})
			if _, err := startCaseServer(t, mux).OpenCase(context.Background(), validOpen()); err == nil {
				t.Fatal("invalid response was trusted")
			}
		})
	}
}

func TestOpenCaseRetriesExactlyOnceAfterLostResponse(t *testing.T) {
	mux := http.NewServeMux()
	openCalls, retryCalls := 0, 0
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, _ *http.Request) {
		openCalls++
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	})
	mux.HandleFunc("POST /v1/cases/case-1/retry", func(w http.ResponseWriter, r *http.Request) {
		retryCalls++
		raw, _ := io.ReadAll(r.Body)
		if len(raw) != 0 {
			t.Fatalf("retry body=%q", raw)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(validSubmissionJSON("case-1")))
	})
	result, err := startCaseServer(t, mux).OpenCase(context.Background(), validOpen())
	if err != nil || !result.AcceptedRemote || openCalls != 1 || retryCalls != 1 {
		t.Fatalf("result=%#v err=%v opens=%d retries=%d", result, err, openCalls, retryCalls)
	}
}

func TestOpenCaseRetriesExactlyOnceAfterTruncatedAcceptedResponse(t *testing.T) {
	mux := http.NewServeMux()
	openCalls, retryCalls := 0, 0
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, _ *http.Request) {
		openCalls++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "999")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"EnvelopeID":`))
	})
	mux.HandleFunc("POST /v1/cases/case-1/retry", func(w http.ResponseWriter, r *http.Request) {
		retryCalls++
		raw, _ := io.ReadAll(r.Body)
		if len(raw) != 0 {
			t.Fatalf("retry body=%q", raw)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(validSubmissionJSON("case-1")))
	})
	result, err := startCaseServer(t, mux).OpenCase(context.Background(), validOpen())
	if err != nil || !result.AcceptedRemote || openCalls != 1 || retryCalls != 1 {
		t.Fatalf("result=%#v err=%v opens=%d retries=%d", result, err, openCalls, retryCalls)
	}
}

func TestOpenCaseDoesNotRetrySemanticRejection(t *testing.T) {
	mux := http.NewServeMux()
	retries := 0
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnprocessableEntity) })
	mux.HandleFunc("POST /v1/cases/case-1/retry", func(w http.ResponseWriter, _ *http.Request) { retries++; w.WriteHeader(http.StatusAccepted) })
	if _, err := startCaseServer(t, mux).OpenCase(context.Background(), validOpen()); err == nil || retries != 0 {
		t.Fatalf("err=%v retries=%d", err, retries)
	}
}

func TestOpenCaseValidatesUTF8RuneBoundsAndExactDigests(t *testing.T) {
	invalidUTF8 := string([]byte{0xff})
	tests := map[string]OpenCaseRequest{
		"invalid UTF-8":       mutateOpen(func(r *OpenCaseRequest) { r.Summary = invalidUTF8 }),
		"too many runes":      mutateOpen(func(r *OpenCaseRequest) { r.PublicSummary = strings.Repeat("界", 1025) }),
		"bad context digest":  mutateOpen(func(r *OpenCaseRequest) { r.ContextManifest = "sha256:" + strings.Repeat("A", 64) }),
		"bad registry digest": mutateOpen(func(r *OpenCaseRequest) { r.Registry.Hash = "sha256:" + strings.Repeat("a", 63) }),
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := (&Client{http: http.DefaultClient}).OpenCase(context.Background(), request); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestOpenCaseAcceptsMultibyteTextAtRuneLimit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(validSubmissionJSON("case-1")))
	})
	request := validOpen()
	request.Summary = strings.Repeat("界", 4096)
	if _, err := startCaseServer(t, mux).OpenCase(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestOpenCaseRequiresAcceptedStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/cases", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validSubmissionJSON("case-1")))
	})
	if _, err := startCaseServer(t, mux).OpenCase(context.Background(), validOpen()); err == nil {
		t.Fatal("200 accepted")
	}
}

func TestGetCaseAndListAdviceDecodeActualPascalCaseWire(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cases/{caseID}/advice", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"AdviceID":"adv-1","CaseID":"case-1","Text":"inert advice","ReceivedAt":"2026-08-04T00:00:00Z"}]`))
	})
	mux.HandleFunc("GET /v1/cases/{caseID}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"EnvelopeID":"env-1","CaseID":"case-1","Commitment":` + quote(digest("c")) + `,"Summary":"secret","Registry":{"RoutingEpoch":0,"Revision":1,"Hash":` + quote(digest("a")) + `},"ExpiresAt":"2026-08-04T00:00:00Z","Committed":true}`))
	})
	client := startCaseServer(t, mux)
	record, err := client.GetCase(context.Background(), "case-1")
	if err != nil || record.Registry.Revision != 1 || record.Summary != "secret" {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	advice, err := client.ListAdvice(context.Background(), "case-1")
	if err != nil || len(advice) != 1 || advice[0].Text != "inert advice" {
		t.Fatalf("advice=%#v err=%v", advice, err)
	}
}

func TestListAdviceRejectsForeignCase(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cases/{caseID}/advice", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"AdviceID":"adv-1","CaseID":"other","Text":"t","ReceivedAt":"2026-08-04T00:00:00Z"}]`))
	})
	if _, err := startCaseServer(t, mux).ListAdvice(context.Background(), "case-1"); err == nil {
		t.Fatal("foreign advice accepted")
	}
}

func validOpen() OpenCaseRequest {
	return OpenCaseRequest{CaseID: "case-1", Domain: "billing", Summary: "detail", PublicSummary: "blurb", ContextManifest: digest("a"), Registry: RegistryCoordinates{RoutingEpoch: 0, Revision: 3, Hash: digest("b")}}
}

func mutateOpen(fn func(*OpenCaseRequest)) OpenCaseRequest { r := validOpen(); fn(&r); return r }
func digest(character string) string                       { return "sha256:" + strings.Repeat(character, 64) }
func quote(value string) string                            { return fmt.Sprintf("%q", value) }
func validSubmissionJSON(caseID string) string {
	return fmt.Sprintf(`{"EnvelopeID":"env-1","CaseID":%q,"Commitment":%q,"AcceptedRemote":true,"Receipt":{"AuthorityID":"auth","Revision":3,"EnvelopeID":"env-1","Commitment":%q}}`, caseID, digest("c"), digest("c"))
}
