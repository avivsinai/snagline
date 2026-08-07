package dispatcherruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

var validRequest = Submission{
	CaseID:         "case-1",
	CaseCommitment: "sha256:" + strings.Repeat("a", 64),
	Text:           "Use the inert recovery step.",
	PublicSummary:  "A bounded recovery step is available.",
}

type fakeSubmitter struct {
	mu      sync.Mutex
	calls   []Submission
	entered chan Submission
	release chan struct{}
	events  []string
	result  Result
}

func (f *fakeSubmitter) Submit(_ context.Context, eventID string, input Submission) (Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, input)
	f.events = append(f.events, eventID)
	result := f.result
	f.mu.Unlock()
	if f.entered != nil {
		f.entered <- input
		<-f.release
	}
	if result.Code != "" {
		return result, nil
	}
	return Result{OK: true, Code: "accepted_remote", AdviceID: "advice-1", AuthorityRevision: 7}, nil
}

func requestWithEvent(t *testing.T, server http.Handler, body string, san, eventID string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://runtime.example/v1/submit-inert-advice", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Snagline-Buzz-Event-ID", eventID)
	if san != "" {
		certificate := &x509.Certificate{Raw: []byte{1}, DNSNames: []string{san}}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	}
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	return w
}

func request(t *testing.T, server http.Handler, body string, san string) *httptest.ResponseRecorder {
	return requestWithEvent(t, server, body, san, strings.Repeat("a", 64))
}

func newServer(t *testing.T, submitter Submitter, cap int) http.Handler {
	t.Helper()
	server, err := New(Config{Submitter: submitter, ProxyClientSAN: "dns:snagline-dispatcher-proxy", GlobalConcurrency: cap, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

type blockingBody struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (body blockingBody) Read([]byte) (int, error) {
	body.entered <- struct{}{}
	<-body.release
	return 0, io.EOF
}

func (blockingBody) Close() error { return nil }

func TestServerAcceptsOneExactInertAdviceFromPinnedMutualTLSIdentity(t *testing.T) {
	submitter := &fakeSubmitter{}
	raw, _ := json.Marshal(validRequest)
	w := request(t, newServer(t, submitter, 2), string(raw), "snagline-dispatcher-proxy")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(submitter.calls) != 1 || submitter.calls[0] != validRequest || len(submitter.events) != 1 || submitter.events[0] != strings.Repeat("a", 64) {
		t.Fatalf("calls=%+v events=%+v", submitter.calls, submitter.events)
	}
	if !strings.Contains(w.Body.String(), `"code":"accepted_remote"`) {
		t.Fatalf("body=%s", w.Body.String())
	}
}

func TestServerRejectsMissingOrWrongMutualTLSIdentityBeforeSubmission(t *testing.T) {
	for _, san := range []string{"", "intruder"} {
		submitter := &fakeSubmitter{}
		raw, _ := json.Marshal(validRequest)
		w := request(t, newServer(t, submitter, 2), string(raw), san)
		if w.Code != http.StatusUnauthorized || len(submitter.calls) != 0 {
			t.Fatalf("san=%q status=%d calls=%d", san, w.Code, len(submitter.calls))
		}
	}
}

func TestServerRejectsSchemaAndAuthorityWideningBeforeSubmission(t *testing.T) {
	for _, raw := range []string{
		`{"case_id":"case-1","case_commitment":"sha256:` + strings.Repeat("a", 64) + `","text":"inert","public_summary":"public","destination":"edge-1"}`,
		`{"case_id":"case-1","case_commitment":"sha256:` + strings.Repeat("A", 64) + `","text":"inert","public_summary":"public"}`,
		`{"case_id":"case-1","case_commitment":"sha256:` + strings.Repeat("a", 64) + `","text":"","public_summary":"public"}`,
		string([]byte(`{"case_id":"case-1","case_commitment":"sha256:`+strings.Repeat("a", 64)+`","text":"`)) + string([]byte{0xff}) + `","public_summary":"public"}`,
	} {
		submitter := &fakeSubmitter{}
		w := request(t, newServer(t, submitter, 2), raw, "snagline-dispatcher-proxy")
		if w.Code != http.StatusBadRequest || len(submitter.calls) != 0 {
			t.Fatalf("status=%d calls=%d body=%s", w.Code, len(submitter.calls), w.Body.String())
		}
	}
}

func TestServerAcceptsCanonicalUTF8AtExactRuneAndBodyBoundaries(t *testing.T) {
	submitter := &fakeSubmitter{}
	input := Submission{
		CaseID:         strings.Repeat("\x00", 512),
		CaseCommitment: validRequest.CaseCommitment,
		Text:           strings.Repeat("\x00", 8191) + "🚀",
		PublicSummary:  strings.Repeat("\x00", 1024),
	}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > maxRequestBytes {
		t.Fatalf("marshal exact boundary bytes=%d err=%v", len(raw), err)
	}
	w := request(t, newServer(t, submitter, 2), string(raw), "snagline-dispatcher-proxy")
	if w.Code != http.StatusOK || len(submitter.calls) != 1 || submitter.calls[0] != input {
		t.Fatalf("status=%d calls=%+v body=%s", w.Code, submitter.calls, w.Body.String())
	}
}

func TestValidateSubmissionRejectsOverRuneBoundaries(t *testing.T) {
	for name, input := range map[string]Submission{
		"case":    {CaseID: strings.Repeat("🧵", 513), CaseCommitment: validRequest.CaseCommitment, Text: "x", PublicSummary: "x"},
		"text":    {CaseID: "x", CaseCommitment: validRequest.CaseCommitment, Text: strings.Repeat("🚀", 8193), PublicSummary: "x"},
		"summary": {CaseID: "x", CaseCommitment: validRequest.CaseCommitment, Text: "x", PublicSummary: strings.Repeat("𠀋", 1025)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSubmission(input); err == nil {
				t.Fatal("over-boundary submission was accepted")
			}
		})
	}
}

func TestServerEnforcesPerCaseSingleFlightAndGlobalCap(t *testing.T) {
	submitter := &fakeSubmitter{entered: make(chan Submission, 3), release: make(chan struct{})}
	server := newServer(t, submitter, 2)
	call := func(input Submission, eventCharacter string) chan *httptest.ResponseRecorder {
		result := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			raw, _ := json.Marshal(input)
			result <- requestWithEvent(t, server, string(raw), "snagline-dispatcher-proxy", strings.Repeat(eventCharacter, 64))
		}()
		return result
	}
	first := call(validRequest, "a")
	<-submitter.entered
	same := call(validRequest, "b")
	if w := <-same; w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "case_in_flight") {
		t.Fatalf("same case status=%d body=%s", w.Code, w.Body.String())
	}
	second := call(Submission{CaseID: "case-2", CaseCommitment: validRequest.CaseCommitment, Text: "inert", PublicSummary: "public"}, "c")
	<-submitter.entered
	over := call(Submission{CaseID: "case-3", CaseCommitment: validRequest.CaseCommitment, Text: "inert", PublicSummary: "public"}, "d")
	if w := <-over; w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "runtime_busy") {
		t.Fatalf("over cap status=%d body=%s", w.Code, w.Body.String())
	}
	close(submitter.release)
	if (<-first).Code != http.StatusOK || (<-second).Code != http.StatusOK {
		t.Fatal("accepted calls did not complete")
	}
}

func TestServerRejectsOverCapBeforePathAuthOrBodyDecode(t *testing.T) {
	server := newServer(t, &fakeSubmitter{}, 1)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	first := httptest.NewRequest(http.MethodPost, "https://runtime.example"+SubmitPath, nil)
	first.Body = blockingBody{entered: entered, release: release}
	first.Header.Set("Content-Type", "application/json")
	first.Header.Set("X-Snagline-Buzz-Event-ID", strings.Repeat("a", 64))
	certificate := &x509.Certificate{Raw: []byte{1}, DNSNames: []string{"snagline-dispatcher-proxy"}}
	first.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	firstResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, first)
		firstResult <- response
	}()
	<-entered

	second := httptest.NewRequest(http.MethodGet, "https://runtime.example/other", nil)
	secondResult := httptest.NewRecorder()
	server.ServeHTTP(secondResult, second)
	if secondResult.Code != http.StatusServiceUnavailable || !strings.Contains(secondResult.Body.String(), `"code":"runtime_busy"`) {
		t.Fatalf("status=%d body=%s", secondResult.Code, secondResult.Body.String())
	}

	close(release)
	if response := <-firstResult; response.Code != http.StatusBadRequest {
		t.Fatalf("first status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestServerRejectsEscapedAndEmptyQueryPathsBeforeSubmission(t *testing.T) {
	raw, _ := json.Marshal(validRequest)
	for name, mutate := range map[string]func(*http.Request){
		"escaped path": func(request *http.Request) { request.URL.RawPath = "/v1/%73ubmit-inert-advice" },
		"empty query":  func(request *http.Request) { request.URL.ForceQuery = true },
	} {
		t.Run(name, func(t *testing.T) {
			submitter := &fakeSubmitter{}
			request := httptest.NewRequest(http.MethodPost, "https://runtime.example"+SubmitPath, strings.NewReader(string(raw)))
			mutate(request)
			response := httptest.NewRecorder()
			newServer(t, submitter, 1).ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || len(submitter.calls) != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, len(submitter.calls), response.Body.String())
			}
		})
	}
}

func TestServerMapsDurableFullTurnMismatch(t *testing.T) {
	submitter := &fakeSubmitter{result: Result{OK: false, Code: "turn_request_mismatch"}}
	raw, _ := json.Marshal(validRequest)
	w := requestWithEvent(t, newServer(t, submitter, 2), string(raw), "snagline-dispatcher-proxy", strings.Repeat("f", 64))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "turn_request_mismatch") || len(submitter.calls) != 1 {
		t.Fatalf("status=%d body=%s calls=%d", w.Code, w.Body.String(), len(submitter.calls))
	}
}

func TestServerMapsBoundedTurnConflictsWithoutClaimingAcceptance(t *testing.T) {
	raw, _ := json.Marshal(validRequest)
	for _, code := range []string{"pending_advice_conflict", "turn_in_flight"} {
		t.Run(code, func(t *testing.T) {
			submitter := &fakeSubmitter{result: Result{OK: false, Code: code}}
			w := requestWithEvent(t, newServer(t, submitter, 2), string(raw), "snagline-dispatcher-proxy", strings.Repeat("e", 64))
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"ok":false`) || !strings.Contains(w.Body.String(), code) || strings.Contains(w.Body.String(), "accepted_remote") || len(submitter.calls) != 1 {
				t.Fatalf("status=%d body=%s calls=%d", w.Code, w.Body.String(), len(submitter.calls))
			}
		})
	}
}

func TestServerRequiresVerifiedBuzzTurnHeaderBeforeSubmission(t *testing.T) {
	submitter := &fakeSubmitter{}
	raw, _ := json.Marshal(validRequest)
	w := requestWithEvent(t, newServer(t, submitter, 2), string(raw), "snagline-dispatcher-proxy", "")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_turn_context") || len(submitter.calls) != 0 {
		t.Fatalf("status=%d body=%s calls=%d", w.Code, w.Body.String(), len(submitter.calls))
	}
}

func TestServerRequiresCausalVerifiedLeafAndNoAdditionalSANTypes(t *testing.T) {
	raw, _ := json.Marshal(validRequest)
	validLeaf := &x509.Certificate{Raw: []byte{1}, DNSNames: []string{"snagline-dispatcher-proxy"}}
	uri, err := url.Parse("spiffe://example/proxy")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]*tls.ConnectionState{
		"no verified chains":      {PeerCertificates: []*x509.Certificate{validLeaf}},
		"empty verified chain":    {PeerCertificates: []*x509.Certificate{validLeaf}, VerifiedChains: [][]*x509.Certificate{{}}},
		"different verified leaf": {PeerCertificates: []*x509.Certificate{validLeaf}, VerifiedChains: [][]*x509.Certificate{{{Raw: []byte{2}, DNSNames: []string{"snagline-dispatcher-proxy"}}}}},
		"email SAN":               {PeerCertificates: []*x509.Certificate{{Raw: []byte{1}, DNSNames: []string{"snagline-dispatcher-proxy"}, EmailAddresses: []string{"proxy@example.invalid"}}}},
		"IP SAN":                  {PeerCertificates: []*x509.Certificate{{Raw: []byte{1}, DNSNames: []string{"snagline-dispatcher-proxy"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}}},
		"URI SAN":                 {PeerCertificates: []*x509.Certificate{{Raw: []byte{1}, DNSNames: []string{"snagline-dispatcher-proxy"}, URIs: []*url.URL{uri}}}},
	}
	for name, state := range tests {
		t.Run(name, func(t *testing.T) {
			if len(state.VerifiedChains) == 0 && name != "no verified chains" {
				state.VerifiedChains = [][]*x509.Certificate{{state.PeerCertificates[0]}}
			}
			submitter := &fakeSubmitter{}
			r := httptest.NewRequest(http.MethodPost, "https://runtime.example"+SubmitPath, strings.NewReader(string(raw)))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Snagline-Buzz-Event-ID", strings.Repeat("a", 64))
			r.TLS = state
			w := httptest.NewRecorder()
			newServer(t, submitter, 2).ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized || len(submitter.calls) != 0 {
				t.Fatalf("status=%d calls=%d", w.Code, len(submitter.calls))
			}
		})
	}
}
