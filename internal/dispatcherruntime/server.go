package dispatcherruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	SubmitPath      = "/v1/submit-inert-advice"
	maxRequestBytes = 64 << 10
)

var commitmentPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var eventIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Submission struct {
	CaseID         string `json:"case_id"`
	CaseCommitment string `json:"case_commitment"`
	Text           string `json:"text"`
	PublicSummary  string `json:"public_summary"`
}

type Result struct {
	OK                bool   `json:"ok"`
	Code              string `json:"code"`
	AdviceID          string `json:"advice_id,omitempty"`
	AuthorityRevision int64  `json:"authority_revision,omitempty"`
}

type Submitter interface {
	Submit(context.Context, string, Submission) (Result, error)
}

type Config struct {
	Submitter         Submitter
	ProxyClientSAN    string
	GlobalConcurrency int
	RequestTimeout    time.Duration
}

type Server struct {
	submitter      Submitter
	proxyDNSName   string
	requestTimeout time.Duration
	handlerSlots   chan struct{}

	mu          sync.Mutex
	activeCases map[string]struct{}
}

func New(config Config) (*Server, error) {
	if config.Submitter == nil {
		return nil, errors.New("dispatcher runtime: submitter is required")
	}
	proxyDNSName, ok := strings.CutPrefix(strings.TrimSpace(config.ProxyClientSAN), "dns:")
	if !ok || proxyDNSName == "" || strings.ContainsAny(proxyDNSName, " ,") {
		return nil, errors.New("dispatcher runtime: proxy client SAN must be one exact dns identity")
	}
	if config.GlobalConcurrency < 1 || config.GlobalConcurrency > 16 {
		return nil, errors.New("dispatcher runtime: global concurrency must be between 1 and 16")
	}
	if config.RequestTimeout <= 0 || config.RequestTimeout > time.Minute {
		return nil, errors.New("dispatcher runtime: request timeout must be between zero and one minute")
	}
	return &Server{
		submitter:      config.Submitter,
		proxyDNSName:   proxyDNSName,
		requestTimeout: config.RequestTimeout,
		handlerSlots:   make(chan struct{}, config.GlobalConcurrency),
		activeCases:    make(map[string]struct{}),
	}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	select {
	case s.handlerSlots <- struct{}{}:
		defer func() { <-s.handlerSlots }()
	default:
		writeError(w, http.StatusServiceUnavailable, "runtime_busy")
		return
	}
	if r.URL.Path != SubmitPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if !s.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	eventID := r.Header.Get("X-Snagline-Buzz-Event-ID")
	if !eventIDPattern.MatchString(eventID) {
		writeError(w, http.StatusBadRequest, "invalid_turn_context")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil || len(raw) == 0 || !utf8.Valid(raw) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var submission Submission
	if err := decoder.Decode(&submission); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := ensureEOF(decoder); err != nil || ValidateSubmission(submission) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	status, code := s.acquire(submission)
	if status != 0 {
		writeError(w, status, code)
		return
	}
	defer s.release(submission.CaseID)

	ctx, cancel := context.WithTimeout(r.Context(), s.requestTimeout)
	defer cancel()
	result, err := s.submitter.Submit(ctx, eventID, submission)
	if err != nil {
		writeError(w, http.StatusBadGateway, "submission_failed")
		return
	}
	if !result.OK {
		switch result.Code {
		case "turn_request_mismatch", "pending_advice_conflict", "turn_in_flight":
			writeError(w, http.StatusConflict, result.Code)
		case "replay_guard_full":
			writeError(w, http.StatusServiceUnavailable, result.Code)
		default:
			writeError(w, http.StatusBadGateway, "submission_failed")
		}
		return
	}
	if result.Code != "accepted_remote" || result.AdviceID == "" || result.AuthorityRevision <= 0 {
		writeError(w, http.StatusBadGateway, "submission_failed")
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

func (s *Server) authorized(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	certificate := r.TLS.PeerCertificates[0]
	if verified := r.TLS.VerifiedChains[0][0]; verified != certificate && !certificate.Equal(verified) {
		return false
	}
	return len(certificate.DNSNames) == 1 && certificate.DNSNames[0] == s.proxyDNSName &&
		len(certificate.EmailAddresses) == 0 && len(certificate.IPAddresses) == 0 && len(certificate.URIs) == 0
}

func (s *Server) acquire(submission Submission) (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.activeCases[submission.CaseID]; exists {
		return http.StatusConflict, "case_in_flight"
	}
	s.activeCases[submission.CaseID] = struct{}{}
	return 0, ""
}

func (s *Server) release(caseID string) {
	s.mu.Lock()
	delete(s.activeCases, caseID)
	s.mu.Unlock()
}

func ValidateSubmission(submission Submission) error {
	if !validUTF8Runes(submission.CaseID, 512) {
		return errors.New("invalid case id")
	}
	if !commitmentPattern.MatchString(submission.CaseCommitment) {
		return errors.New("invalid case commitment")
	}
	if !validUTF8Runes(submission.Text, 8192) {
		return errors.New("invalid text")
	}
	if !validUTF8Runes(submission.PublicSummary, 1024) {
		return errors.New("invalid public summary")
	}
	return nil
}

func validUTF8Runes(value string, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= 1 && length <= maximum
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("decode trailing data: %w", err)
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "code": code})
}
