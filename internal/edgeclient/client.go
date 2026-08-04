// Package edgeclient is the bounded client for Snagline's local edge API.
// It intentionally has no SQLite, SSP, PostgreSQL, NATS, or Buzz access.
package edgeclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	errLocalTransport   = errors.New("edgeclient: local transport failed")
	errAcceptedResponse = errors.New("edgeclient: accepted response was incomplete")
	sha256Commitment    = regexp.MustCompile(`\Asha256:[0-9a-f]{64}\z`)
)

const (
	maxRequestBodyBytes = 64 << 10
	// The response may contain six 8KiB Unicode strings. JSON escaping can
	// expand every source byte, so this is intentionally independent from the
	// small request cap and remains bounded below one MiB.
	maxResponseBodyBytes = 512 << 10
	maxLeaseTTL          = 15 * time.Minute
	// Six bounded deliveries keep one claim and its worst-case JSON escaping
	// below maxResponseBodyBytes.
	maxLimit = 6
)

type Front string

const (
	FrontCLI Front = "cli"
	FrontAMQ Front = "amq"
)

type Delivery struct {
	CaseID     string `json:"case_id"`
	AdviceID   string `json:"advice_id"`
	MessageID  string `json:"message_id"`
	Text       string `json:"text"`
	ClaimToken string `json:"claim_token"`
}

type ClaimRequest struct {
	Front    Front
	Owner    string
	LeaseTTL time.Duration
	Limit    int
}

type AckRequest struct {
	Front                            Front
	MessageID, ClaimToken, ReceiptID string
}

type DeliveryOutcome string

const (
	DeliveryRecorded  DeliveryOutcome = "recorded"
	DeliveryDuplicate DeliveryOutcome = "duplicate"
)

type Config struct{ Socket string }

type Client struct {
	socket string
	http   *http.Client
}

func New(config Config) (*Client, error) {
	if !filepath.IsAbs(config.Socket) || filepath.Clean(config.Socket) != config.Socket {
		return nil, errors.New("edgeclient: Unix socket must be absolute and clean")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &Client{socket: config.Socket, http: &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", config.Socket)
		}},
	}}, nil
}

func (c *Client) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

func (c *Client) Claim(ctx context.Context, request ClaimRequest) ([]Delivery, error) {
	if c == nil || c.http == nil || !validFront(request.Front) || !validBounded(request.Owner, 128) || request.LeaseTTL <= 0 || request.LeaseTTL > maxLeaseTTL || request.LeaseTTL%time.Second != 0 || request.Limit < 1 || request.Limit > maxLimit {
		return nil, errors.New("edgeclient: invalid claim request")
	}
	var response struct {
		Deliveries []Delivery `json:"deliveries"`
	}
	if err := c.call(ctx, "/v1/fronts/"+string(request.Front)+"/claims", struct {
		Owner        string `json:"owner"`
		LeaseSeconds int64  `json:"lease_seconds"`
		Limit        int    `json:"limit"`
	}{request.Owner, int64(request.LeaseTTL / time.Second), request.Limit}, &response); err != nil {
		return nil, err
	}
	if len(response.Deliveries) > request.Limit {
		return nil, errors.New("edgeclient: response exceeds requested claim limit")
	}
	for _, delivery := range response.Deliveries {
		if !validDelivery(delivery) {
			return nil, errors.New("edgeclient: invalid delivery response")
		}
	}
	return response.Deliveries, nil
}

func (c *Client) Ack(ctx context.Context, request AckRequest) (DeliveryOutcome, error) {
	if c == nil || c.http == nil || !validFront(request.Front) || !validBounded(request.MessageID, 512) || !validBounded(request.ClaimToken, 128) || !validBounded(request.ReceiptID, 1024) {
		return "", errors.New("edgeclient: invalid acknowledgement")
	}
	var response struct {
		Outcome DeliveryOutcome `json:"outcome"`
	}
	if err := c.call(ctx, "/v1/fronts/"+string(request.Front)+"/acks", struct {
		MessageID  string `json:"message_id"`
		ClaimToken string `json:"claim_token"`
		ReceiptID  string `json:"receipt_id"`
	}{request.MessageID, request.ClaimToken, request.ReceiptID}, &response); err != nil {
		return "", err
	}
	if response.Outcome != DeliveryRecorded && response.Outcome != DeliveryDuplicate {
		return "", errors.New("edgeclient: invalid acknowledgement response")
	}
	return response.Outcome, nil
}

// call issues a POST and requires HTTP 200. Claim and Ack use it.
func (c *Client) call(ctx context.Context, path string, input, output any) error {
	return c.do(ctx, http.MethodPost, path, input, output, http.StatusOK)
}

// do is the shared request path. GET requests pass a nil input and send no body;
// POST requests marshal input. The response must arrive with exactly
// acceptedStatus, so a case open that returns 202 is not confused with a 200 read.
func (c *Client) do(ctx context.Context, method, path string, input, output any, acceptedStatus int) error {
	var bodyReader io.Reader
	if input != nil {
		body, err := json.Marshal(input)
		if err != nil || len(body) > maxRequestBodyBytes {
			return errors.New("edgeclient: encode request")
		}
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://edge.local"+path, bodyReader)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", errLocalTransport, err)
	}
	defer response.Body.Close()
	if response.StatusCode != acceptedStatus {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBodyBytes+1))
		return fmt.Errorf("edgeclient: local edge rejected request with status %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return markAcceptedResponse(acceptedStatus, errors.New("edgeclient: response content type is not application/json"))
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBodyBytes+1))
	if err != nil || len(raw) > maxResponseBodyBytes {
		return markAcceptedResponse(acceptedStatus, errors.New("edgeclient: response exceeds size limit"))
	}
	if !utf8.Valid(raw) {
		return markAcceptedResponse(acceptedStatus, errors.New("edgeclient: response is not valid UTF-8"))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return markAcceptedResponse(acceptedStatus, errors.New("edgeclient: invalid response"))
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return markAcceptedResponse(acceptedStatus, errors.New("edgeclient: response must contain one JSON value"))
	}
	return nil
}

func markAcceptedResponse(acceptedStatus int, err error) error {
	if acceptedStatus == http.StatusAccepted {
		return fmt.Errorf("%w: %w", errAcceptedResponse, err)
	}
	return err
}

// RegistryCoordinates bind a case to a specific registry generation. They are
// deployment-owned inputs: the edge exposes no route to discover them, so a
// caller must receive them from trusted deployment configuration.
type RegistryCoordinates struct {
	RoutingEpoch int64  `json:"routing_epoch"`
	Revision     int64  `json:"revision"`
	Hash         string `json:"hash"`
}

type registryRequestWire struct {
	RoutingEpoch int64  `json:"routing_epoch"`
	Revision     int64  `json:"revision"`
	Hash         string `json:"hash"`
}

type registryResponseWire struct {
	RoutingEpoch int64  `json:"RoutingEpoch"`
	Revision     int64  `json:"Revision"`
	Hash         string `json:"Hash"`
}

type openCaseRequestWire struct {
	CaseID          string              `json:"case_id"`
	Domain          string              `json:"domain"`
	Summary         string              `json:"summary"`
	PublicSummary   string              `json:"public_summary"`
	ContextManifest string              `json:"context_manifest"`
	Registry        registryRequestWire `json:"registry"`
}

type commitReceiptResponseWire struct {
	AuthorityID string `json:"AuthorityID"`
	Revision    int64  `json:"Revision"`
	EnvelopeID  string `json:"EnvelopeID"`
	Commitment  string `json:"Commitment"`
}

type caseSubmissionResponseWire struct {
	EnvelopeID     string                    `json:"EnvelopeID"`
	CaseID         string                    `json:"CaseID"`
	Commitment     string                    `json:"Commitment"`
	AcceptedRemote bool                      `json:"AcceptedRemote"`
	Receipt        commitReceiptResponseWire `json:"Receipt"`
}

type caseRecordResponseWire struct {
	EnvelopeID string               `json:"EnvelopeID"`
	CaseID     string               `json:"CaseID"`
	Commitment string               `json:"Commitment"`
	Summary    string               `json:"Summary"`
	Registry   registryResponseWire `json:"Registry"`
	ExpiresAt  time.Time            `json:"ExpiresAt"`
	Committed  bool                 `json:"Committed"`
}

type adviceResponseWire struct {
	AdviceID   string    `json:"AdviceID"`
	CaseID     string    `json:"CaseID"`
	Text       string    `json:"Text"`
	ReceivedAt time.Time `json:"ReceivedAt"`
}

// OpenCaseRequest is the bounded input for opening a case. PublicSummary is the
// only field projected to Buzz; Summary stays confidential to the fabric.
type OpenCaseRequest struct {
	CaseID          string
	Domain          string
	Summary         string
	PublicSummary   string
	ContextManifest string
	Registry        RegistryCoordinates
}

// CommitReceipt and CaseSubmission mirror the edge's 202 response for an accepted
// case. Field names match the server's default JSON marshaling.
type CommitReceipt struct {
	AuthorityID string
	Revision    int64
	EnvelopeID  string
	Commitment  string
}

type CaseSubmission struct {
	EnvelopeID     string
	CaseID         string
	Commitment     string
	AcceptedRemote bool
	Receipt        CommitReceipt
}

// CaseRecord mirrors GET /v1/cases/{id}. AdviceView mirrors one advice from
// GET /v1/cases/{id}/advice. Both carry the server's default JSON field names.
type CaseRecord struct {
	EnvelopeID string
	CaseID     string
	Commitment string
	Summary    string
	Registry   RegistryCoordinates
	ExpiresAt  time.Time
	Committed  bool
}

type AdviceView struct {
	AdviceID   string
	CaseID     string
	Text       string
	ReceivedAt time.Time
}

// OpenCase submits a new case. The edge accepts it with 202; anything else is an
// error. The caller supplies registry coordinates from deployment configuration.
func (c *Client) OpenCase(ctx context.Context, request OpenCaseRequest) (CaseSubmission, error) {
	if c == nil || c.http == nil ||
		!validCaseText(request.CaseID, 512) || !validCaseText(request.Domain, 512) ||
		!validCaseText(request.Summary, 4096) || !validCaseText(request.PublicSummary, 1024) ||
		!sha256Commitment.MatchString(request.ContextManifest) || !sha256Commitment.MatchString(request.Registry.Hash) ||
		request.Registry.RoutingEpoch < 0 || request.Registry.Revision < 0 {
		return CaseSubmission{}, errors.New("edgeclient: invalid open-case request")
	}
	wire := openCaseRequestWire{
		CaseID: request.CaseID, Domain: request.Domain, Summary: request.Summary,
		PublicSummary: request.PublicSummary, ContextManifest: request.ContextManifest,
		Registry: registryRequestWire{RoutingEpoch: request.Registry.RoutingEpoch, Revision: request.Registry.Revision, Hash: request.Registry.Hash},
	}
	var response caseSubmissionResponseWire
	if err := c.do(ctx, http.MethodPost, "/v1/cases", wire, &response, http.StatusAccepted); err != nil {
		if errors.Is(err, errLocalTransport) || errors.Is(err, errAcceptedResponse) {
			return c.RetryCase(ctx, request.CaseID)
		}
		return CaseSubmission{}, err
	}
	submission, err := validateCaseSubmission(response, request.CaseID)
	if err != nil {
		return c.RetryCase(ctx, request.CaseID)
	}
	return submission, nil
}

// RetryCase asks the edge to resubmit its already-spooled exact bytes once.
// It accepts no mutable case input beyond the deployment-bound case ID.
func (c *Client) RetryCase(ctx context.Context, caseID string) (CaseSubmission, error) {
	if c == nil || c.http == nil || !validCaseText(caseID, 512) {
		return CaseSubmission{}, errors.New("edgeclient: invalid case identifier")
	}
	var response caseSubmissionResponseWire
	if err := c.do(ctx, http.MethodPost, "/v1/cases/"+url.PathEscape(caseID)+"/retry", nil, &response, http.StatusAccepted); err != nil {
		return CaseSubmission{}, err
	}
	return validateCaseSubmission(response, caseID)
}

// GetCase reads a case record. It performs no mutation.
func (c *Client) GetCase(ctx context.Context, caseID string) (CaseRecord, error) {
	if c == nil || c.http == nil || !validCaseText(caseID, 512) {
		return CaseRecord{}, errors.New("edgeclient: invalid case identifier")
	}
	var wire caseRecordResponseWire
	if err := c.do(ctx, http.MethodGet, "/v1/cases/"+url.PathEscape(caseID), nil, &wire, http.StatusOK); err != nil {
		return CaseRecord{}, err
	}
	if wire.CaseID != caseID || !validCaseText(wire.EnvelopeID, 512) || !sha256Commitment.MatchString(wire.Commitment) ||
		!validCaseText(wire.Summary, 4096) || !sha256Commitment.MatchString(wire.Registry.Hash) || wire.Registry.RoutingEpoch < 0 || wire.Registry.Revision < 0 {
		return CaseRecord{}, errors.New("edgeclient: case record identifier mismatch")
	}
	return CaseRecord{EnvelopeID: wire.EnvelopeID, CaseID: wire.CaseID, Commitment: wire.Commitment, Summary: wire.Summary,
		Registry: RegistryCoordinates{RoutingEpoch: wire.Registry.RoutingEpoch, Revision: wire.Registry.Revision, Hash: wire.Registry.Hash}, ExpiresAt: wire.ExpiresAt, Committed: wire.Committed}, nil
}

// ListAdvice lists the advice recorded for a case. A case receives at most one
// final advice, and may receive none, so an empty list is a valid answer.
func (c *Client) ListAdvice(ctx context.Context, caseID string) ([]AdviceView, error) {
	if c == nil || c.http == nil || !validCaseText(caseID, 512) {
		return nil, errors.New("edgeclient: invalid case identifier")
	}
	var wire []adviceResponseWire
	if err := c.do(ctx, http.MethodGet, "/v1/cases/"+url.PathEscape(caseID)+"/advice", nil, &wire, http.StatusOK); err != nil {
		return nil, err
	}
	advice := make([]AdviceView, 0, len(wire))
	for _, view := range wire {
		if view.CaseID != caseID || !validCaseText(view.AdviceID, 512) || !validCaseText(view.Text, 8192) {
			return nil, errors.New("edgeclient: advice response does not belong to the requested case")
		}
		advice = append(advice, AdviceView{AdviceID: view.AdviceID, CaseID: view.CaseID, Text: view.Text, ReceivedAt: view.ReceivedAt})
	}
	return advice, nil
}

func validFront(front Front) bool { return front == FrontCLI || front == FrontAMQ }

func validBounded(value string, max int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= max
}

func validCaseText(value string, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= 1 && utf8.RuneCountInString(value) <= max
}

func validateCaseSubmission(wire caseSubmissionResponseWire, expectedCaseID string) (CaseSubmission, error) {
	if !wire.AcceptedRemote || wire.CaseID != expectedCaseID || !validCaseText(wire.EnvelopeID, 512) ||
		!sha256Commitment.MatchString(wire.Commitment) || !validCaseText(wire.Receipt.AuthorityID, 512) || wire.Receipt.Revision <= 0 ||
		wire.Receipt.EnvelopeID != wire.EnvelopeID || wire.Receipt.Commitment != wire.Commitment {
		return CaseSubmission{}, errors.New("edgeclient: open-case response is incomplete or mismatched")
	}
	return CaseSubmission{EnvelopeID: wire.EnvelopeID, CaseID: wire.CaseID, Commitment: wire.Commitment, AcceptedRemote: wire.AcceptedRemote,
		Receipt: CommitReceipt{AuthorityID: wire.Receipt.AuthorityID, Revision: wire.Receipt.Revision, EnvelopeID: wire.Receipt.EnvelopeID, Commitment: wire.Receipt.Commitment}}, nil
}

func validDelivery(delivery Delivery) bool {
	return validBounded(delivery.CaseID, 512) && validBounded(delivery.AdviceID, 512) && validBounded(delivery.MessageID, 512) && validBounded(delivery.Text, 8192) && validBounded(delivery.ClaimToken, 128)
}
