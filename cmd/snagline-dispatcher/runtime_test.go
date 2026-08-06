package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/dispatcherruntime"
	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/sspedge"
)

func TestParseDispatcherRuntimeConfigRequiresSecureOneShotInputs(t *testing.T) {
	setValidDispatcherEnvironment(t)
	config, err := parseDispatcherRuntimeConfig([]string{"--case-id", "case-1", "--case-commitment", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--text", "confidential inert detail", "--public-summary", "inert"}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if config.CaseID != "case-1" || config.EnvelopeTTL.String() != "1h0m0s" {
		t.Fatalf("config=%+v", config)
	}
}

func TestParseDispatcherRuntimeConfigReadsCompleteUnicodeRequestFromBoundedStdin(t *testing.T) {
	setValidDispatcherEnvironment(t)
	request := dispatcherruntime.CommandRequest{
		EventID: strings.Repeat("b", 64),
		Submission: dispatcherruntime.Submission{
			CaseID:         "case-🧵\x00",
			CaseCommitment: "sha256:" + strings.Repeat("a", 64),
			Text:           "confidential\x00U0001f680",
			PublicSummary:  "public" + string(rune(0x202e)),
		},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	config, err := parseDispatcherRuntimeConfig([]string{"--request-stdin"}, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if config.EventID != request.EventID || config.CaseID != request.Submission.CaseID || config.Text != request.Submission.Text || config.PublicSummary != request.Submission.PublicSummary {
		t.Fatalf("config=%+v", config)
	}
	invalid := append([]byte(nil), raw...)
	invalid[len(invalid)-2] = 0xff
	if _, err := parseDispatcherRuntimeConfig([]string{"--request-stdin"}, bytes.NewReader(invalid)); err == nil {
		t.Fatal("invalid UTF-8 stdin request was accepted")
	}
}

func TestParseDispatcherRuntimeConfigRejectsPlaintextControlEndpoint(t *testing.T) {
	setValidDispatcherEnvironment(t)
	if _, err := parseDispatcherRuntimeConfig([]string{"--case-id", "case-1", "--case-commitment", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--text", "confidential inert detail", "--public-summary", "inert", "--control-url", "http://control.example"}, strings.NewReader("")); err == nil {
		t.Fatal("accepted plaintext control endpoint")
	}
}

type fakeDispatcherTurnStore struct {
	request, result []byte
	completed       bool
}

func (s *fakeDispatcherTurnStore) BindDispatcherTurn(_ context.Context, _ string, request []byte, _ time.Time, _ time.Duration, _ int) (sspedge.DispatcherTurnBinding, error) {
	if s.request == nil {
		s.request = append([]byte(nil), request...)
		return sspedge.DispatcherTurnBinding{}, nil
	}
	if !bytes.Equal(s.request, request) {
		return sspedge.DispatcherTurnBinding{}, sspedge.ErrDispatcherTurnMismatch
	}
	return sspedge.DispatcherTurnBinding{Completed: s.completed, Result: append([]byte(nil), s.result...)}, nil
}

func (s *fakeDispatcherTurnStore) CompleteDispatcherTurn(_ context.Context, _ string, request, result []byte, _ time.Time) error {
	if !bytes.Equal(s.request, request) {
		return sspedge.ErrDispatcherTurnMismatch
	}
	s.result = append([]byte(nil), result...)
	s.completed = true
	return nil
}

type fakeDispatcherFinalizer struct{ calls int }

func (f *fakeDispatcherFinalizer) FinalizeAdvice(context.Context, edge.FinalizeAdviceRequest) (edge.AdviceSubmission, error) {
	f.calls++
	return edge.AdviceSubmission{EnvelopeID: "advice-1", AcceptedRemote: true, Receipt: edge.CommitReceipt{Revision: 7}}, nil
}

func (f *fakeDispatcherFinalizer) RetryAdvice(context.Context, string) (edge.AdviceSubmission, error) {
	f.calls++
	return edge.AdviceSubmission{}, errors.New("unexpected retry")
}

type lostResponseWriter struct{}

func (lostResponseWriter) Write([]byte) (int, error) { return 0, errors.New("response lost") }

func TestRunDispatcherReturnsDurableIdenticalResultAfterLostResponse(t *testing.T) {
	config := dispatcherRuntimeConfig{EventID: strings.Repeat("c", 64), CaseID: "case-🧵", CaseCommitment: "sha256:" + strings.Repeat("a", 64), Text: "confidential\x00text", PublicSummary: "public"}
	store := &fakeDispatcherTurnStore{}
	finalizer := &fakeDispatcherFinalizer{}
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	if code := runDispatcherTurn(context.Background(), config, finalizer, store, lostResponseWriter{}, now); code == 0 || !store.completed || finalizer.calls != 1 {
		t.Fatalf("first code=%d completed=%v calls=%d", code, store.completed, finalizer.calls)
	}
	first := append([]byte(nil), store.result...)
	var stdout bytes.Buffer
	if code := runDispatcherTurn(context.Background(), config, finalizer, store, &stdout, now.Add(time.Minute)); code != 0 || finalizer.calls != 1 {
		t.Fatalf("retry code=%d calls=%d output=%s", code, finalizer.calls, stdout.String())
	}
	if got := bytes.TrimSuffix(stdout.Bytes(), []byte{'\n'}); !bytes.Equal(got, first) {
		t.Fatalf("retry result=%s stored=%s", got, first)
	}
	changed := config
	changed.Text = "changed"
	stdout.Reset()
	if code := runDispatcherTurn(context.Background(), changed, finalizer, store, &stdout, now.Add(2*time.Minute)); code == 0 || !strings.Contains(stdout.String(), "turn_request_mismatch") || finalizer.calls != 1 {
		t.Fatalf("changed code=%d calls=%d output=%s", code, finalizer.calls, stdout.String())
	}
}

type recoveringDispatcherFinalizer struct {
	finalizeCalls int
	retryCalls    int
}

func (f *recoveringDispatcherFinalizer) FinalizeAdvice(context.Context, edge.FinalizeAdviceRequest) (edge.AdviceSubmission, error) {
	f.finalizeCalls++
	if f.finalizeCalls == 1 {
		return edge.AdviceSubmission{}, errors.New("ambiguous control response")
	}
	return edge.AdviceSubmission{}, edge.ErrAlreadyPending
}

func (f *recoveringDispatcherFinalizer) RetryAdvice(context.Context, string) (edge.AdviceSubmission, error) {
	f.retryCalls++
	return edge.AdviceSubmission{EnvelopeID: "advice-1", AcceptedRemote: true, Receipt: edge.CommitReceipt{Revision: 7}}, nil
}

func TestRunDispatcherRetriesPendingExactAdviceAfterAmbiguousControlResponse(t *testing.T) {
	config := dispatcherRuntimeConfig{EventID: strings.Repeat("d", 64), CaseID: "case-🧵", CaseCommitment: "sha256:" + strings.Repeat("a", 64), Text: "confidential", PublicSummary: "public"}
	store := &fakeDispatcherTurnStore{}
	finalizer := &recoveringDispatcherFinalizer{}
	now := time.Date(2026, 8, 6, 10, 11, 12, 13, time.UTC)
	var stdout bytes.Buffer
	if code := runDispatcherTurn(context.Background(), config, finalizer, store, &stdout, now); code == 0 || store.completed {
		t.Fatalf("ambiguous call code=%d completed=%v output=%s", code, store.completed, stdout.String())
	}
	stdout.Reset()
	if code := runDispatcherTurn(context.Background(), config, finalizer, store, &stdout, now.Add(time.Minute)); code != 0 || !store.completed || finalizer.finalizeCalls != 2 || finalizer.retryCalls != 1 {
		t.Fatalf("retry code=%d completed=%v finalize=%d retry=%d output=%s", code, store.completed, finalizer.finalizeCalls, finalizer.retryCalls, stdout.String())
	}
}

func setValidDispatcherEnvironment(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"SNAGLINE_DISPATCHER_KEY_DESCRIPTOR": "/run/secrets/dispatcher.json", "SNAGLINE_DISPATCHER_TENANT": "tenant-a", "SNAGLINE_DISPATCHER_PRINCIPAL_ID": "dispatcher-principal", "SNAGLINE_DISPATCHER_AUTHOR_KEY_ID": "dispatcher-key", "SNAGLINE_DISPATCHER_DB": "/var/lib/snagline/dispatcher.db", "SNAGLINE_DISPATCHER_DB_KEY": "/run/secrets/dispatcher-db.key", "SNAGLINE_DISPATCHER_CONTROL_URL": "https://control.example", "SNAGLINE_DISPATCHER_TLS_CERT": "/run/secrets/dispatcher.crt", "SNAGLINE_DISPATCHER_TLS_KEY": "/run/secrets/dispatcher.key", "SNAGLINE_DISPATCHER_CONTROL_CA": "/run/secrets/control-ca.pem", "SNAGLINE_DISPATCHER_ENVELOPE_TTL": "1h",
	} {
		t.Setenv(key, value)
	}
}
