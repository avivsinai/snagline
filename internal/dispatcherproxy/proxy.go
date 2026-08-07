package dispatcherproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/avivsinai/snagline/internal/dispatcherruntime"
)

const (
	SubmitPath       = "/v1/submit-inert-advice"
	maxRequestBytes  = 64 << 10
	maxResponseBytes = 16 << 10
)

var eventIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Config struct {
	UpstreamURL       string
	RuntimeServerName string
	Client            *http.Client
	RequestTimeout    time.Duration
	MaxConcurrency    int
}

type Proxy struct {
	upstream       *url.URL
	client         *http.Client
	requestTimeout time.Duration
	handlerSlots   chan struct{}
}

func New(config Config) (*Proxy, error) {
	runtimeServerName := strings.TrimSpace(config.RuntimeServerName)
	expectedUpstream := "https://" + runtimeServerName + ":8443" + SubmitPath
	upstream, err := url.Parse(config.UpstreamURL)
	if err != nil || runtimeServerName == "" || runtimeServerName != strings.ToLower(runtimeServerName) || config.UpstreamURL != expectedUpstream || upstream.String() != expectedUpstream || upstream.Scheme != "https" || upstream.Opaque != "" || upstream.Hostname() != runtimeServerName || upstream.Port() != "8443" || upstream.Path != SubmitPath || upstream.RawPath != "" || upstream.RawQuery != "" || upstream.ForceQuery || upstream.Fragment != "" || upstream.User != nil {
		return nil, errors.New("dispatcher proxy: fixed runtime URL is required")
	}
	if config.Client == nil || config.RequestTimeout <= 0 || config.RequestTimeout > time.Minute {
		return nil, errors.New("dispatcher proxy: bounded client and timeout are required")
	}
	if config.MaxConcurrency < 1 || config.MaxConcurrency > 16 {
		return nil, errors.New("dispatcher proxy: max concurrency must be between 1 and 16")
	}
	client := *config.Client
	client.CheckRedirect = rejectRedirect
	return &Proxy{upstream: upstream, client: &client, requestTimeout: config.RequestTimeout, handlerSlots: make(chan struct{}, config.MaxConcurrency)}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	select {
	case p.handlerSlots <- struct{}{}:
		defer func() { <-p.handlerSlots }()
	default:
		writeError(w, http.StatusServiceUnavailable, "proxy_busy")
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != SubmitPath || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery || request.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	eventID := request.Header.Get("X-Snagline-Buzz-Event-ID")
	if !eventIDPattern.MatchString(eventID) {
		writeError(w, http.StatusBadRequest, "invalid_turn_context")
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || !utf8.Valid(raw) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var submission dispatcherruntime.Submission
	if err := decoder.Decode(&submission); err != nil || ensureEOF(decoder) != nil || dispatcherruntime.ValidateSubmission(submission) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	body, err := json.Marshal(submission)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "proxy_failed")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), p.requestTimeout)
	defer cancel()
	upstreamRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, p.upstream.String(), bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "proxy_failed")
		return
	}
	upstreamRequest.Header.Set("Content-Type", "application/json")
	upstreamRequest.Header.Set("Accept", "application/json")
	upstreamRequest.Header.Set("X-Snagline-Buzz-Event-ID", eventID)
	response, err := p.client.Do(upstreamRequest)
	if err != nil {
		writeError(w, http.StatusBadGateway, "proxy_failed")
		return
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil || len(responseBody) > maxResponseBytes || !json.Valid(responseBody) {
		writeError(w, http.StatusBadGateway, "invalid_runtime_response")
		return
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(responseBody)
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "code": code})
}
