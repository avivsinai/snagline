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
	"path/filepath"
	"strings"
	"time"
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

func (c *Client) call(ctx context.Context, path string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil || len(body) > maxRequestBodyBytes {
		return errors.New("edgeclient: encode request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://edge.local"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("edgeclient: local edge unavailable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBodyBytes+1))
		return fmt.Errorf("edgeclient: local edge rejected request with status %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("edgeclient: response content type is not application/json")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBodyBytes+1))
	if err != nil || len(raw) > maxResponseBodyBytes {
		return errors.New("edgeclient: response exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("edgeclient: invalid response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("edgeclient: response must contain one JSON value")
	}
	return nil
}

func validFront(front Front) bool { return front == FrontCLI || front == FrontAMQ }

func validBounded(value string, max int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= max
}

func validDelivery(delivery Delivery) bool {
	return validBounded(delivery.CaseID, 512) && validBounded(delivery.AdviceID, 512) && validBounded(delivery.MessageID, 512) && validBounded(delivery.Text, 8192) && validBounded(delivery.ClaimToken, 128)
}
