// Package controlclient is the strict mTLS client for the SSP control-plane
// boundary. Workload identity is established only by the client certificate;
// this package never serializes it into an HTTP header or JSON payload.
package controlclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/ssp"
)

const defaultRequestTimeout = 10 * time.Second

var ErrRejected = errors.New("controlclient: control plane rejected request")

// Config must contain a fully verified TLS 1.3 client configuration. Workload
// is an assertion of the identity bound to that certificate and is checked
// locally before submission; it is never sent to the server.
type Config struct {
	Endpoint       string
	TLS            *tls.Config
	Workload       edge.WorkloadIdentity
	RequestTimeout time.Duration
}

type Client struct {
	endpoint *url.URL
	http     *http.Client
	workload edge.WorkloadIdentity
}

var _ edge.GatewayClient = (*Client)(nil)

func New(config Config) (*Client, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("controlclient: root HTTPS endpoint without credentials, query, or fragment is required")
	}
	if config.Workload.PrincipalID == "" || (config.Workload.EdgeID == "") != (config.Workload.EdgeGeneration == 0) || config.Workload.EdgeGeneration < 0 {
		return nil, errors.New("controlclient: complete certificate-bound workload identity is required")
	}
	if config.TLS == nil {
		return nil, errors.New("controlclient: TLS configuration is required")
	}
	tlsConfig := config.TLS.Clone()
	if tlsConfig.MinVersion < tls.VersionTLS13 || tlsConfig.InsecureSkipVerify || tlsConfig.RootCAs == nil || len(tlsConfig.Certificates) != 1 {
		return nil, errors.New("controlclient: verified TLS 1.3 with exactly one client certificate and explicit roots is required")
	}
	timeout := config.RequestTimeout
	if timeout == 0 {
		timeout = defaultRequestTimeout
	}
	if timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("controlclient: request timeout must be within one minute")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &Client{endpoint: endpoint, workload: config.Workload, http: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

// Submit implements edge.GatewayClient. It routes only SSP cases and advice
// and forwards their exact signed bytes directly as the request body.
func (c *Client) Submit(ctx context.Context, workload edge.WorkloadIdentity, raw []byte) (edge.CommitReceipt, error) {
	if c == nil || c.http == nil || c.endpoint == nil {
		return edge.CommitReceipt{}, errors.New("controlclient: nil client")
	}
	if workload != c.workload {
		return edge.CommitReceipt{}, errors.New("controlclient: requested workload does not match certificate-bound workload")
	}
	header, err := ssp.ReadHeader(raw)
	if err != nil {
		return edge.CommitReceipt{}, fmt.Errorf("controlclient: read SSP header: %w", err)
	}
	var path string
	switch header.Schema {
	case ssp.FamilyCase:
		path = "/v1/cases"
	case ssp.FamilyAdvice:
		path = "/v1/advice"
	default:
		return edge.CommitReceipt{}, errors.New("controlclient: only case and advice submission are supported")
	}
	var response commitResponse
	if err := c.call(ctx, http.MethodPost, path, raw, &response); err != nil {
		return edge.CommitReceipt{}, err
	}
	if response.AuthorityID == "" || response.Revision <= 0 || response.EnvelopeID != header.ID || response.Commitment == "" {
		return edge.CommitReceipt{}, errors.New("controlclient: incomplete or mismatched commit receipt")
	}
	return edge.CommitReceipt{AuthorityID: response.AuthorityID, Revision: response.Revision, EnvelopeID: response.EnvelopeID, Commitment: response.Commitment}, nil
}

// ListEdgeDeliveries supplies the authority-backed recovery read used by
// sspedge.AuthorityReconciler. The route identity is derived from the fixed
// mTLS workload; tenant is only a local consistency assertion and never sent.
func (c *Client) ListEdgeDeliveries(ctx context.Context, query authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error) {
	if c == nil || c.endpoint == nil || c.workload.EdgeID == "" || query.EdgeID != c.workload.EdgeID || query.EdgeGeneration != c.workload.EdgeGeneration || query.TenantID == "" {
		return authority.EdgeDeliveryPage{}, errors.New("controlclient: invalid certificate-bound edge delivery query")
	}
	query.PrincipalID = c.workload.PrincipalID
	if query.Validate() != nil {
		return authority.EdgeDeliveryPage{}, errors.New("controlclient: invalid certificate-bound edge delivery query")
	}
	path := "/v1/edges/" + url.PathEscape(query.EdgeID) + "/generations/" + strconv.FormatInt(query.EdgeGeneration, 10) + "/deliveries?after_sequence=" + strconv.FormatInt(query.AfterSequence, 10) + "&limit=" + strconv.Itoa(query.Limit)
	var response edgeDeliveriesResponse
	if err := c.call(ctx, http.MethodGet, path, nil, &response); err != nil {
		return authority.EdgeDeliveryPage{}, err
	}
	if response.HighWatermark < query.AfterSequence || response.CompleteThrough < query.AfterSequence || response.CompleteThrough > response.HighWatermark || int64(len(response.Deliveries)) != response.CompleteThrough-query.AfterSequence {
		return authority.EdgeDeliveryPage{}, errors.New("controlclient: invalid authority delivery page")
	}
	result := authority.EdgeDeliveryPage{HighWatermark: response.HighWatermark, CompleteThrough: response.CompleteThrough, Deliveries: make([]authority.EdgeDelivery, 0, len(response.Deliveries))}
	expected := query.AfterSequence + 1
	for _, item := range response.Deliveries {
		if item.Sequence != expected || item.Kind == "" || item.CaseID == "" || item.EnvelopeID == "" || item.Commitment == "" || len(item.Raw) == 0 || item.AuthorityRevision <= 0 {
			return authority.EdgeDeliveryPage{}, errors.New("controlclient: invalid authority delivery")
		}
		result.Deliveries = append(result.Deliveries, authority.EdgeDelivery{Sequence: item.Sequence, Kind: item.Kind, CaseID: item.CaseID, EnvelopeID: item.EnvelopeID, Commitment: item.Commitment, Raw: append([]byte(nil), item.Raw...), AuthorityRevision: item.AuthorityRevision})
		expected++
	}
	return result, nil
}

// ResolveCase returns the control plane's immutable case source. The mTLS
// identity may be either the registered dispatcher or the exact target edge;
// the control service independently authorizes that route from the case-bound
// root-verified registry.
func (c *Client) ResolveCase(ctx context.Context, caseID, commitment string) (authority.CaseRecord, error) {
	if c == nil || caseID == "" || !validCommitment(commitment) {
		return authority.CaseRecord{}, errors.New("controlclient: invalid case query")
	}
	var response caseResponse
	if err := c.call(ctx, http.MethodGet, "/v1/cases/"+url.PathEscape(caseID)+"?commitment="+url.QueryEscape(commitment), nil, &response); err != nil {
		return authority.CaseRecord{}, err
	}
	if response.CaseID != caseID || response.Commitment != commitment || len(response.Raw) == 0 || response.EnvelopeID == "" || response.Domain == "" || response.IssuerEdgeID == "" || response.IssuerEdgeGeneration <= 0 || response.AuthorityRevision <= 0 || response.ExpiresAt.IsZero() {
		return authority.CaseRecord{}, errors.New("controlclient: invalid resolved case")
	}
	return authority.CaseRecord{TenantID: response.TenantID, CaseID: response.CaseID, EnvelopeID: response.EnvelopeID, Commitment: response.Commitment, Raw: append([]byte(nil), response.Raw...), Domain: response.Domain, IssuerEdgeID: response.IssuerEdgeID, IssuerEdgeGeneration: response.IssuerEdgeGeneration, RoutingEpoch: response.RoutingEpoch, RegistryRevision: response.RegistryRevision, RegistryHash: response.RegistryHash, ExpiresAt: response.ExpiresAt, AuthorityRevision: response.AuthorityRevision}, nil
}

// ResolveRegistry returns the exact immutable registry evidence required by
// the edge verifier. Tenant remains an assertion local to the mTLS workload;
// it is never carried in a caller-controlled header or request body.
func (c *Client) ResolveRegistry(ctx context.Context, tenant string, revision int64, commitment string) (authority.RegistryRecord, error) {
	if c == nil || tenant == "" || revision <= 0 || !validCommitment(commitment) {
		return authority.RegistryRecord{}, errors.New("controlclient: invalid registry query")
	}
	var response registryResponse
	path := "/v1/registries/" + strconv.FormatInt(revision, 10) + "?commitment=" + url.QueryEscape(commitment)
	if err := c.call(ctx, http.MethodGet, path, nil, &response); err != nil {
		return authority.RegistryRecord{}, err
	}
	if response.TenantID != tenant || response.Revision != revision || response.Commitment != commitment || response.EnvelopeID == "" || len(response.Raw) == 0 || response.AuthorityRevision <= 0 {
		return authority.RegistryRecord{}, errors.New("controlclient: invalid resolved registry")
	}
	return authority.RegistryRecord{TenantID: response.TenantID, Revision: response.Revision, EnvelopeID: response.EnvelopeID, Commitment: response.Commitment, Raw: append([]byte(nil), response.Raw...), RoutingEpoch: response.RoutingEpoch, PreviousCommitment: response.PreviousCommitment, AuthorityRevision: response.AuthorityRevision}, nil
}

func (c *Client) call(ctx context.Context, method, path string, body []byte, response any) error {
	relative, err := url.Parse(path)
	if err != nil || relative.IsAbs() || relative.Host != "" || !strings.HasPrefix(relative.Path, "/") {
		return errors.New("controlclient: invalid fixed request path")
	}
	endpoint := c.endpoint.ResolveReference(relative)
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("controlclient: build request: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	reply, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("controlclient: request: %w", err)
	}
	defer reply.Body.Close()
	if reply.StatusCode < http.StatusOK || reply.StatusCode >= http.StatusMultipleChoices {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(io.LimitReader(reply.Body, 8<<10)).Decode(&failure)
		return fmt.Errorf("%w: status %d, code %q", ErrRejected, reply.StatusCode, failure.Code)
	}
	decoder := json.NewDecoder(io.LimitReader(reply.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(response); err != nil {
		return fmt.Errorf("controlclient: decode response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("controlclient: response contains multiple JSON values")
	}
	return nil
}

type commitResponse struct {
	AuthorityID string `json:"authority_id"`
	Revision    int64  `json:"revision"`
	EnvelopeID  string `json:"envelope_id"`
	Commitment  string `json:"commitment"`
}
type caseResponse struct {
	TenantID             string    `json:"tenant_id"`
	CaseID               string    `json:"case_id"`
	EnvelopeID           string    `json:"envelope_id"`
	Commitment           string    `json:"commitment"`
	Raw                  []byte    `json:"raw"`
	Domain               string    `json:"domain"`
	IssuerEdgeID         string    `json:"issuer_edge_id"`
	IssuerEdgeGeneration int64     `json:"issuer_edge_generation"`
	RoutingEpoch         int64     `json:"routing_epoch"`
	RegistryRevision     int64     `json:"registry_revision"`
	RegistryHash         string    `json:"registry_hash"`
	ExpiresAt            time.Time `json:"expires_at"`
	AuthorityRevision    int64     `json:"authority_revision"`
}
type deliveryResponse struct {
	Sequence          int64  `json:"sequence"`
	Kind              string `json:"kind"`
	CaseID            string `json:"case_id"`
	EnvelopeID        string `json:"envelope_id"`
	Commitment        string `json:"commitment"`
	Raw               []byte `json:"raw"`
	AuthorityRevision int64  `json:"authority_revision"`
}
type edgeDeliveriesResponse struct {
	Deliveries      []deliveryResponse `json:"deliveries"`
	HighWatermark   int64              `json:"high_watermark"`
	CompleteThrough int64              `json:"complete_through"`
}
type registryResponse struct {
	TenantID           string `json:"tenant_id"`
	Revision           int64  `json:"revision"`
	EnvelopeID         string `json:"envelope_id"`
	Commitment         string `json:"commitment"`
	Raw                []byte `json:"raw"`
	RoutingEpoch       int64  `json:"routing_epoch"`
	PreviousCommitment string `json:"previous_commitment"`
	AuthorityRevision  int64  `json:"authority_revision"`
}

func validCommitment(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if character < '0' || character > '9' && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
