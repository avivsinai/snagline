package dispatcherproxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/dispatcherruntime"
)

const (
	testRuntimeServerName = "runtime.svc.example"
	testUpstreamURL       = "https://" + testRuntimeServerName + ":8443/v1/submit-inert-advice"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestProxyForwardsOnlyValidatedSubmissionAndTurnContext(t *testing.T) {
	var forwarded *http.Request
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		forwarded = request
		body, _ := io.ReadAll(request.Body)
		if string(body) != `{"case_id":"case-1","case_commitment":"sha256:`+strings.Repeat("a", 64)+`","text":"Use the inert recovery step.","public_summary":"A bounded recovery step is available."}` {
			t.Fatalf("forwarded body=%s", body)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true,"code":"accepted_remote","advice_id":"advice-1","authority_revision":7}`))}, nil
	})}
	proxy, err := New(Config{UpstreamURL: testUpstreamURL, RuntimeServerName: testRuntimeServerName, Client: client, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"case_id":"case-1","case_commitment":"sha256:` + strings.Repeat("a", 64) + `","text":"Use the inert recovery step.","public_summary":"A bounded recovery step is available."}`
	request := httptest.NewRequest(http.MethodPost, SubmitPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Snagline-Buzz-Event-ID", strings.Repeat("b", 64))
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusOK || forwarded == nil || forwarded.URL.Scheme != "https" || forwarded.Header.Get("X-Snagline-Buzz-Event-ID") != strings.Repeat("b", 64) {
		t.Fatalf("status=%d forwarded=%v body=%s", response.Code, forwarded, response.Body.String())
	}
}

func TestProxyForwardsCanonicalUTF8AtExactRuneBoundaries(t *testing.T) {
	input := dispatcherruntime.Submission{
		CaseID:         strings.Repeat("\x00", 512),
		CaseCommitment: "sha256:" + strings.Repeat("a", 64),
		Text:           strings.Repeat("\x00", 8191) + "🚀",
		PublicSummary:  strings.Repeat("\x00", 1024),
	}
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		var got dispatcherruntime.Submission
		if err := json.NewDecoder(request.Body).Decode(&got); err != nil || got != input {
			t.Fatalf("forwarded submission mismatch: err=%v", err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true,"code":"accepted_remote","advice_id":"advice-1","authority_revision":7}`))}, nil
	})}
	proxy, err := New(Config{UpstreamURL: testUpstreamURL, RuntimeServerName: testRuntimeServerName, Client: client, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) > maxRequestBytes {
		t.Fatalf("marshal bytes=%d err=%v", len(body), err)
	}
	request := httptest.NewRequest(http.MethodPost, SubmitPath, strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Snagline-Buzz-Event-ID", strings.Repeat("b", 64))
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)
	if response.Code != http.StatusOK || calls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
}

func TestProxyRejectsInvalidRequestsBeforeUpstream(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, context.Canceled })}
	proxy, err := New(Config{UpstreamURL: testUpstreamURL, RuntimeServerName: testRuntimeServerName, Client: client, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ path, event, body string }{
		{"/other", strings.Repeat("b", 64), `{}`},
		{SubmitPath, "invalid", `{}`},
		{SubmitPath, strings.Repeat("b", 64), `{"case_id":"case-1","case_commitment":"sha256:bad","text":"x","public_summary":"x"}`},
		{SubmitPath, strings.Repeat("b", 64), string([]byte(`{"case_id":"case-1","case_commitment":"sha256:`+strings.Repeat("a", 64)+`","text":"`)) + string([]byte{0xff}) + `","public_summary":"x"}`},
	} {
		request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Snagline-Buzz-Event-ID", test.event)
		proxy.ServeHTTP(httptest.NewRecorder(), request)
	}
	if calls != 0 {
		t.Fatalf("invalid requests reached upstream %d times", calls)
	}
}

func TestProxyRejectsUnknownSubmissionFieldsBeforeUpstream(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, context.Canceled
	})}
	proxy, err := New(Config{UpstreamURL: testUpstreamURL, RuntimeServerName: testRuntimeServerName, Client: client, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"case_id":"case-1","case_commitment":"sha256:` + strings.Repeat("a", 64) + `","text":"Use the inert recovery step.","public_summary":"A bounded recovery step is available.","unexpected_authority":"widened"}`
	request := httptest.NewRequest(http.MethodPost, SubmitPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Snagline-Buzz-Event-ID", strings.Repeat("b", 64))
	response := httptest.NewRecorder()

	proxy.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) || calls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
}

func TestNewRejectsAnyRuntimeURLWidening(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})}
	for name, upstream := range map[string]string{
		"scheme":       "http://" + testRuntimeServerName + ":8443" + SubmitPath,
		"hostname":     "https://attacker.example:8443" + SubmitPath,
		"missing port": "https://" + testRuntimeServerName + SubmitPath,
		"wrong port":   "https://" + testRuntimeServerName + ":443" + SubmitPath,
		"path":         "https://" + testRuntimeServerName + ":8443/other",
		"escaped path": "https://" + testRuntimeServerName + ":8443/v1/%73ubmit-inert-advice",
		"query":        testUpstreamURL + "?redirect=1",
		"empty query":  testUpstreamURL + "?",
		"fragment":     testUpstreamURL + "#fragment",
		"userinfo":     "https://user@" + testRuntimeServerName + ":8443" + SubmitPath,
		"opaque":       "https:" + testRuntimeServerName + ":8443" + SubmitPath,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(Config{UpstreamURL: upstream, RuntimeServerName: testRuntimeServerName, Client: client, RequestTimeout: time.Second}); err == nil {
				t.Fatalf("New accepted widened runtime URL %q", upstream)
			}
		})
	}
}

func TestProxyNeverResendsPostAcross307Or308(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Location": []string{testUpstreamURL}},
					Body:       io.NopCloser(strings.NewReader(`{"ok":false,"code":"redirect_rejected"}`)),
				}, nil
			})}
			proxy, err := New(Config{UpstreamURL: testUpstreamURL, RuntimeServerName: testRuntimeServerName, Client: client, RequestTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			body := `{"case_id":"case-1","case_commitment":"sha256:` + strings.Repeat("a", 64) + `","text":"x","public_summary":"x"}`
			request := httptest.NewRequest(http.MethodPost, SubmitPath, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Snagline-Buzz-Event-ID", strings.Repeat("b", 64))
			response := httptest.NewRecorder()
			proxy.ServeHTTP(response, request)
			if response.Code != status || calls != 1 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
			}
		})
	}
}

func TestProxyRejectsWrongMethodAndPathBeforeUpstream(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, context.Canceled
	})}
	proxy, err := New(Config{UpstreamURL: testUpstreamURL, RuntimeServerName: testRuntimeServerName, Client: client, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"case_id":"case-1","case_commitment":"sha256:` + strings.Repeat("a", 64) + `","text":"Use the inert recovery step.","public_summary":"A bounded recovery step is available."}`
	for _, test := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "wrong method", method: http.MethodGet, path: SubmitPath},
		{name: "wrong path", method: http.MethodPost, path: "/other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Snagline-Buzz-Event-ID", strings.Repeat("b", 64))
			response := httptest.NewRecorder()

			proxy.ServeHTTP(response, request)

			if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("wrong method or path reached upstream %d times", calls)
	}
}
