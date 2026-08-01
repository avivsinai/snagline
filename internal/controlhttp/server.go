// Package controlhttp exposes the authenticated SSP control-plane boundary.
// It maps a verified mTLS client certificate to workload identity; request
// headers and request JSON never participate in that identity decision.
package controlhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/controlapi"
	"github.com/avivsinai/snagline/internal/ssp"
)

const (
	defaultMaxBodyBytes   int64 = ssp.MaxEnvelopeBytes
	defaultRequestTimeout       = 10 * time.Second
)

// Admission is controlapi.Service's narrow admission surface.
type Admission interface {
	SubmitRegistry(context.Context, controlapi.WorkloadIdentity, []byte) (authority.CommitReceipt, error)
	Submit(context.Context, controlapi.WorkloadIdentity, []byte) (authority.CommitReceipt, error)
	ResolveCase(context.Context, controlapi.WorkloadIdentity, string, string) (authority.CaseRecord, error)
	ResolveRegistry(context.Context, controlapi.WorkloadIdentity, int64, string) (authority.RegistryRecord, error)
}

type Config struct {
	Tenant           string
	Admission        Admission
	Authority        authority.Store
	ClientIdentities map[string]controlapi.WorkloadIdentity // canonical SAN (for example dns:edge.example)
	MaxBodyBytes     int64
	RequestTimeout   time.Duration
}

type Server struct {
	tenant       string
	admission    Admission
	authority    authority.Store
	identities   map[string]controlapi.WorkloadIdentity
	maxBodyBytes int64
	timeout      time.Duration
}

func New(config Config) (*Server, error) {
	if strings.TrimSpace(config.Tenant) == "" || config.Admission == nil || config.Authority == nil || len(config.ClientIdentities) == 0 {
		return nil, errors.New("controlhttp: tenant, admission, authority, and client identities are required")
	}
	identities := make(map[string]controlapi.WorkloadIdentity, len(config.ClientIdentities))
	for san, identity := range config.ClientIdentities {
		if !validSAN(san) || strings.TrimSpace(identity.PrincipalID) == "" || identity.EdgeGeneration < 0 || (identity.EdgeID == "" && identity.EdgeGeneration != 0) || (identity.EdgeID != "" && identity.EdgeGeneration == 0) {
			return nil, errors.New("controlhttp: each SAN mapping requires a principal and complete edge coordinates when present")
		}
		identities[san] = identity
	}
	maxBody := config.MaxBodyBytes
	if maxBody == 0 {
		maxBody = defaultMaxBodyBytes
	}
	if maxBody <= 0 {
		return nil, errors.New("controlhttp: max body bytes must be positive")
	}
	timeout := config.RequestTimeout
	if timeout == 0 {
		timeout = defaultRequestTimeout
	}
	if timeout <= 0 {
		return nil, errors.New("controlhttp: request timeout must be positive")
	}
	return &Server{tenant: config.Tenant, admission: config.Admission, authority: config.Authority, identities: identities, maxBodyBytes: maxBody, timeout: timeout}, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()
	workload, ok := s.workload(r.TLS)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/registries":
		s.submit(w, r.WithContext(ctx), workload, true)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/cases":
		s.submit(w, r.WithContext(ctx), workload, false)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/advice":
		s.submit(w, r.WithContext(ctx), workload, false)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/cases/"):
		s.resolveCase(w, r.WithContext(ctx), workload)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/registries/"):
		s.resolveRegistry(w, r.WithContext(ctx), workload)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/edges/"):
		s.reconcile(w, r.WithContext(ctx), workload)
	default:
		writeError(w, http.StatusNotFound, "not_found")
	}
}

func (s *Server) resolveRegistry(w http.ResponseWriter, r *http.Request, workload controlapi.WorkloadIdentity) {
	revisionText := strings.TrimPrefix(r.URL.Path, "/v1/registries/")
	if revisionText == "" || strings.Contains(revisionText, "/") {
		writeError(w, http.StatusBadRequest, "invalid_registry_query")
		return
	}
	revision, err := strconv.ParseInt(revisionText, 10, 64)
	commitment := r.URL.Query().Get("commitment")
	if err != nil || revision <= 0 || commitment == "" {
		writeError(w, http.StatusBadRequest, "invalid_registry_query")
		return
	}
	record, err := s.admission.ResolveRegistry(r.Context(), workload, revision, commitment)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, registryResponse(record))
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request, workload controlapi.WorkloadIdentity, registry bool) {
	raw, err := readRaw(r.Body, s.maxBodyBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	var receipt authority.CommitReceipt
	if registry {
		receipt, err = s.admission.SubmitRegistry(r.Context(), workload, raw)
	} else {
		receipt, err = s.admission.Submit(r.Context(), workload, raw)
	}
	if err != nil {
		writeAdmissionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, receiptResponse(receipt))
}

func (s *Server) resolveCase(w http.ResponseWriter, r *http.Request, workload controlapi.WorkloadIdentity) {
	caseID := strings.TrimPrefix(r.URL.Path, "/v1/cases/")
	if caseID == "" || strings.Contains(caseID, "/") {
		writeError(w, http.StatusBadRequest, "invalid_case_query")
		return
	}
	commitment := r.URL.Query().Get("commitment")
	if commitment == "" {
		writeError(w, http.StatusBadRequest, "invalid_case_query")
		return
	}
	record, err := s.admission.ResolveCase(r.Context(), workload, caseID, commitment)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, caseResponse(record))
}

func (s *Server) reconcile(w http.ResponseWriter, r *http.Request, workload controlapi.WorkloadIdentity) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/edges/"), "/")
	if len(parts) != 4 || parts[0] == "" || parts[1] != "generations" || parts[3] != "deliveries" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	generation, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || generation <= 0 || workload.EdgeID != parts[0] || workload.EdgeGeneration != generation {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	after, limit, ok := edgePage(r.URL)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_edge_query")
		return
	}
	page, err := s.authority.ListEdgeDeliveries(r.Context(), authority.EdgeDeliveryQuery{
		TenantID: s.tenant, EdgeID: parts[0], PrincipalID: workload.PrincipalID,
		EdgeGeneration: generation, AfterSequence: after, Limit: limit,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, edgePageResponse(page))
}

func edgePage(u *url.URL) (int64, int, bool) {
	after := int64(0)
	limit := 100
	var err error
	if text := u.Query().Get("after_sequence"); text != "" {
		after, err = strconv.ParseInt(text, 10, 64)
		if err != nil || after < 0 {
			return 0, 0, false
		}
	}
	if text := u.Query().Get("limit"); text != "" {
		limit, err = strconv.Atoi(text)
		if err != nil || limit < 1 || limit > 1000 {
			return 0, 0, false
		}
	}
	return after, limit, true
}

func readRaw(body io.ReadCloser, limit int64) ([]byte, error) {
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, errors.New("invalid bounded body")
	}
	return raw, nil
}

func (s *Server) workload(state *tls.ConnectionState) (controlapi.WorkloadIdentity, bool) {
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return controlapi.WorkloadIdentity{}, false
	}
	var result controlapi.WorkloadIdentity
	found := false
	for _, san := range certificateSANs(state.PeerCertificates[0]) {
		identity, ok := s.identities[san]
		if !ok {
			continue
		}
		if found && identity != result {
			return controlapi.WorkloadIdentity{}, false
		}
		result, found = identity, true
	}
	return result, found
}

func certificateSANs(cert *x509.Certificate) []string {
	values := make([]string, 0, len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses)+len(cert.URIs))
	for _, name := range cert.DNSNames {
		values = append(values, "dns:"+strings.ToLower(name))
	}
	for _, name := range cert.EmailAddresses {
		values = append(values, "email:"+strings.ToLower(name))
	}
	for _, ip := range cert.IPAddresses {
		values = append(values, "ip:"+ip.String())
	}
	for _, uri := range cert.URIs {
		values = append(values, "uri:"+uri.String())
	}
	return values
}

func validSAN(san string) bool {
	for _, prefix := range []string{"dns:", "email:", "ip:", "uri:"} {
		if strings.HasPrefix(san, prefix) && len(san) > len(prefix) {
			return true
		}
	}
	return false
}

func writeAdmissionError(w http.ResponseWriter, err error) {
	if writeTypedControlOutcome(w, err) {
		return
	}
	if errors.Is(err, authority.ErrCaseNotFound) || errors.Is(err, authority.ErrRegistryNotFound) {
		writeError(w, http.StatusUnprocessableEntity, "unprocessable")
		return
	}
	if errors.Is(err, controlapi.ErrRejected) {
		writeError(w, http.StatusBadRequest, "rejected")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "unavailable")
}

// writeTypedControlOutcome renders errors whose type is part of the control
// protocol. Callers choose their own fallback so malformed submissions remain
// distinct from a failed authority read.
func writeTypedControlOutcome(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, controlapi.ErrUnauthorized), errors.Is(err, authority.ErrEdgeNotActive):
		writeError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, "deadline_exceeded")
	case errors.Is(err, controlapi.ErrExpiredInput), errors.Is(err, authority.ErrRegistryHalted):
		writeError(w, http.StatusGone, "gone")
	case errors.Is(err, authority.ErrConflictingCase),
		errors.Is(err, authority.ErrFinalAdviceAlreadySet),
		errors.Is(err, authority.ErrConflictingRegistry),
		errors.Is(err, authority.ErrRegistryRevisionSequence),
		errors.Is(err, authority.ErrRegistryEquivocation),
		errors.Is(err, authority.ErrRegistryRollback),
		errors.Is(err, authority.ErrEdgeGenerationRollback):
		writeError(w, http.StatusConflict, "conflict")
	case errors.Is(err, authority.ErrInvalidRequest),
		errors.Is(err, authority.ErrCaseBinding),
		errors.Is(err, authority.ErrRegistryBinding),
		errors.Is(err, controlapi.ErrInvalidCaseBinding):
		writeError(w, http.StatusUnprocessableEntity, "unprocessable")
	default:
		return false
	}
	return true
}

type commitResponse struct {
	AuthorityID string `json:"authority_id"`
	Revision    int64  `json:"revision"`
	EnvelopeID  string `json:"envelope_id"`
	Commitment  string `json:"commitment"`
}

func receiptResponse(value authority.CommitReceipt) commitResponse {
	return commitResponse{value.AuthorityID, value.Revision, value.EnvelopeID, value.Commitment}
}

type resolvedCaseResponse struct {
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

func caseResponse(value authority.CaseRecord) resolvedCaseResponse {
	return resolvedCaseResponse{value.TenantID, value.CaseID, value.EnvelopeID, value.Commitment, value.Raw, value.Domain, value.IssuerEdgeID, value.IssuerEdgeGeneration, value.RoutingEpoch, value.RegistryRevision, value.RegistryHash, value.ExpiresAt, value.AuthorityRevision}
}

type resolvedRegistryResponse struct {
	TenantID           string `json:"tenant_id"`
	Revision           int64  `json:"revision"`
	EnvelopeID         string `json:"envelope_id"`
	Commitment         string `json:"commitment"`
	Raw                []byte `json:"raw"`
	RoutingEpoch       int64  `json:"routing_epoch"`
	PreviousCommitment string `json:"previous_commitment"`
	AuthorityRevision  int64  `json:"authority_revision"`
}

func registryResponse(value authority.RegistryRecord) resolvedRegistryResponse {
	return resolvedRegistryResponse{value.TenantID, value.Revision, value.EnvelopeID, value.Commitment, value.Raw, value.RoutingEpoch, value.PreviousCommitment, value.AuthorityRevision}
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

func edgePageResponse(value authority.EdgeDeliveryPage) edgeDeliveriesResponse {
	result := edgeDeliveriesResponse{HighWatermark: value.HighWatermark, CompleteThrough: value.CompleteThrough, Deliveries: make([]deliveryResponse, 0, len(value.Deliveries))}
	for _, item := range value.Deliveries {
		result.Deliveries = append(result.Deliveries, deliveryResponse{item.Sequence, item.Kind, item.CaseID, item.EnvelopeID, item.Commitment, item.Raw, item.AuthorityRevision})
	}
	return result
}
func writeStoreError(w http.ResponseWriter, err error) {
	if writeTypedControlOutcome(w, err) {
		return
	}
	if errors.Is(err, authority.ErrCaseNotFound) || errors.Is(err, authority.ErrRegistryNotFound) || errors.Is(err, authority.ErrRegistryHeadNotFound) {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	writeError(w, http.StatusServiceUnavailable, "unavailable")
}
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"code": code})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
