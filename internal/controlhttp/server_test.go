package controlhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/controlapi"
	"github.com/avivsinai/snagline/internal/ssp"
)

func TestServerUsesOnlyVerifiedClientCertificateSANForAdmission(t *testing.T) {
	admission := &fakeAdmission{}
	server, err := New(Config{Tenant: "tenant-a", Admission: admission, Authority: &fakeStore{}, ClientIdentities: map[string]controlapi.WorkloadIdentity{
		"dns:edge.example": {PrincipalID: "edge-principal", EdgeID: "edge-a", EdgeGeneration: 7},
	}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/cases", strings.NewReader(` {"signed":"exact"} `))
	req.Header.Set("X-Principal-ID", "attacker")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"edge.example"}}}, VerifiedChains: [][]*x509.Certificate{{{DNSNames: []string{"edge.example"}}}}}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if admission.workload != (controlapi.WorkloadIdentity{PrincipalID: "edge-principal", EdgeID: "edge-a", EdgeGeneration: 7}) {
		t.Fatalf("workload = %#v", admission.workload)
	}
	if admission.raw != ` {"signed":"exact"} ` {
		t.Fatalf("raw = %q", admission.raw)
	}
}

func TestServerRejectsUnverifiedOrUnknownClientBeforeReadingAdmission(t *testing.T) {
	for _, state := range []*tls.ConnectionState{nil, {PeerCertificates: []*x509.Certificate{{DNSNames: []string{"unknown.example"}}}, VerifiedChains: [][]*x509.Certificate{{{DNSNames: []string{"unknown.example"}}}}}} {
		admission := &fakeAdmission{}
		server, err := New(Config{Tenant: "tenant-a", Admission: admission, Authority: &fakeStore{}, ClientIdentities: map[string]controlapi.WorkloadIdentity{"dns:edge.example": {PrincipalID: "edge"}}})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/cases", strings.NewReader("x"))
		req.TLS = state
		response := httptest.NewRecorder()
		server.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized || admission.called {
			t.Fatalf("status/called = %d/%v", response.Code, admission.called)
		}
		if !strings.Contains(response.Body.String(), `"code":"unauthenticated"`) {
			t.Fatalf("error = %s", response.Body.String())
		}
	}
}

func TestServerReconcilesFromAuthorityAndBoundsRequests(t *testing.T) {
	store := &fakeStore{deliveries: authority.EdgeDeliveryPage{Deliveries: []authority.EdgeDelivery{{Sequence: 2, Raw: []byte("raw")}}, HighWatermark: 2, CompleteThrough: 2}}
	server, err := New(Config{Tenant: "tenant-a", Admission: &fakeAdmission{}, Authority: store, ClientIdentities: map[string]controlapi.WorkloadIdentity{"dns:edge.example": {PrincipalID: "edge", EdgeID: "edge-a", EdgeGeneration: 7}}, MaxBodyBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	req := authenticatedRequest(http.MethodGet, "/v1/edges/edge-a/generations/7/deliveries?after_sequence=1&limit=3")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"high_watermark":2`) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if store.query != (authority.EdgeDeliveryQuery{TenantID: "tenant-a", EdgeID: "edge-a", PrincipalID: "edge", EdgeGeneration: 7, AfterSequence: 1, Limit: 3}) {
		t.Fatalf("query = %#v", store.query)
	}
	req = authenticatedRequest(http.MethodPost, "/v1/cases")
	req.Body = ioNopCloser(strings.NewReader("12345"))
	response = httptest.NewRecorder()
	server.ServeHTTP(response, req)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status = %d", response.Code)
	}
}

func TestServerRejectsReconciliationForInactiveEdgeGeneration(t *testing.T) {
	store := &fakeStore{deliveryErr: authority.ErrEdgeNotActive}
	server, err := New(Config{
		Tenant: "tenant-a", Admission: &fakeAdmission{}, Authority: store,
		ClientIdentities: map[string]controlapi.WorkloadIdentity{
			"dns:edge.example": {PrincipalID: "edge-principal", EdgeID: "edge-a", EdgeGeneration: 7},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/v1/edges/edge-a/generations/7/deliveries?limit=10"))
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"forbidden"`) {
		t.Fatalf("inactive edge response = %d %s, want 403 forbidden", response.Code, response.Body.String())
	}
	if store.query.PrincipalID != "edge-principal" {
		t.Fatalf("authority query principal = %q, want authenticated principal", store.query.PrincipalID)
	}
}

func TestServerResolvesCaseFromAuthority(t *testing.T) {
	store := &fakeStore{}
	admission := &fakeAdmission{}
	server, err := New(Config{Tenant: "tenant-a", Admission: admission, Authority: store, ClientIdentities: map[string]controlapi.WorkloadIdentity{"dns:edge.example": {PrincipalID: "dispatcher"}}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/v1/cases/case-a?commitment=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"raw":"ZXhhY3Qgc2lnbmVkIGJ5dGVz"`) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if admission.workload != (controlapi.WorkloadIdentity{PrincipalID: "dispatcher"}) {
		t.Fatalf("case workload = %#v", admission.workload)
	}
}

func TestServerResolvesExactRegistryForAuthenticatedEdge(t *testing.T) {
	admission := &fakeAdmission{}
	server, err := New(Config{Tenant: "tenant-a", Admission: admission, Authority: &fakeStore{}, ClientIdentities: map[string]controlapi.WorkloadIdentity{
		"dns:edge.example": {PrincipalID: "edge-principal", EdgeID: "edge-a", EdgeGeneration: 7},
	}})
	if err != nil {
		t.Fatal(err)
	}
	commitment := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/v1/registries/12?commitment="+commitment))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"raw":"ZXhhY3QgcmVnaXN0cnkgYnl0ZXM="`) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if admission.registryRevision != 12 || admission.registryCommitment != commitment ||
		admission.workload != (controlapi.WorkloadIdentity{PrincipalID: "edge-principal", EdgeID: "edge-a", EdgeGeneration: 7}) {
		t.Fatalf("registry request = workload %#v revision %d commitment %q", admission.workload, admission.registryRevision, admission.registryCommitment)
	}
}

func TestWriteControlErrorsUsesCanonicalTypedOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		write  func(http.ResponseWriter, error)
		err    error
		status int
		code   string
	}{
		{name: "unauthorized", write: writeAdmissionError, err: controlapi.ErrUnauthorized, status: http.StatusForbidden, code: "forbidden"},
		{name: "inactive edge", write: writeStoreError, err: authority.ErrEdgeNotActive, status: http.StatusForbidden, code: "forbidden"},
		{name: "deadline", write: writeAdmissionError, err: context.DeadlineExceeded, status: http.StatusGatewayTimeout, code: "deadline_exceeded"},
		{name: "conflict", write: writeAdmissionError, err: authority.ErrConflictingCase, status: http.StatusConflict, code: "conflict"},
		{name: "registry rollback", write: writeAdmissionError, err: authority.ErrRegistryRollback, status: http.StatusConflict, code: "conflict"},
		{name: "edge generation rollback", write: writeAdmissionError, err: authority.ErrEdgeGenerationRollback, status: http.StatusConflict, code: "conflict"},
		{name: "expired", write: writeAdmissionError, err: controlapi.ErrExpiredInput, status: http.StatusGone, code: "gone"},
		{name: "semantic validation", write: writeAdmissionError, err: authority.ErrInvalidRequest, status: http.StatusUnprocessableEntity, code: "unprocessable"},
		{name: "missing registry binding", write: writeAdmissionError, err: authority.ErrRegistryNotFound, status: http.StatusUnprocessableEntity, code: "unprocessable"},
		{name: "missing case binding", write: writeAdmissionError, err: authority.ErrCaseNotFound, status: http.StatusUnprocessableEntity, code: "unprocessable"},
		{name: "malformed or rejected", write: writeAdmissionError, err: errors.Join(controlapi.ErrRejected, ssp.ErrDuplicateKey), status: http.StatusBadRequest, code: "rejected"},
		{name: "read not found", write: writeStoreError, err: authority.ErrCaseNotFound, status: http.StatusNotFound, code: "not_found"},
		{name: "unavailable", write: writeStoreError, err: errors.New("authority unavailable"), status: http.StatusServiceUnavailable, code: "unavailable"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			test.write(response, test.err)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("response = %d %s, want %d %q", response.Code, response.Body.String(), test.status, test.code)
			}
		})
	}
}

func TestServerPostDistinguishesRejectedSSPFromUnavailableAuthority(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "authority failure", err: errors.New("postgres commit result unknown"), status: http.StatusServiceUnavailable, code: "unavailable"},
		{name: "malformed SSP", err: errors.Join(controlapi.ErrRejected, ssp.ErrDuplicateKey), status: http.StatusBadRequest, code: "rejected"},
		{name: "missing registry binding", err: authority.ErrRegistryNotFound, status: http.StatusUnprocessableEntity, code: "unprocessable"},
		{name: "missing case binding", err: authority.ErrCaseNotFound, status: http.StatusUnprocessableEntity, code: "unprocessable"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := New(Config{
				Tenant:    "tenant-a",
				Admission: &fakeAdmission{submitErr: test.err},
				Authority: &fakeStore{},
				ClientIdentities: map[string]controlapi.WorkloadIdentity{
					"dns:edge.example": {PrincipalID: "edge-principal", EdgeID: "edge-a", EdgeGeneration: 7},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := authenticatedRequest(http.MethodPost, "/v1/cases")
			request.Body = ioNopCloser(strings.NewReader(`{"id":"case-a"}`))
			response := httptest.NewRecorder()

			server.ServeHTTP(response, request)

			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("response = %d %s, want %d %q", response.Code, response.Body.String(), test.status, test.code)
			}
		})
	}
}

func authenticatedRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"edge.example"}}}, VerifiedChains: [][]*x509.Certificate{{{DNSNames: []string{"edge.example"}}}}}
	return req
}

type fakeAdmission struct {
	called             bool
	workload           controlapi.WorkloadIdentity
	raw                string
	registryRevision   int64
	registryCommitment string
	submitErr          error
}

func (f *fakeAdmission) SubmitRegistry(context.Context, controlapi.WorkloadIdentity, []byte) (authority.CommitReceipt, error) {
	f.called = true
	return authority.CommitReceipt{AuthorityID: "pg", Revision: 1}, nil
}
func (f *fakeAdmission) Submit(_ context.Context, w controlapi.WorkloadIdentity, raw []byte) (authority.CommitReceipt, error) {
	f.called = true
	f.workload = w
	f.raw = string(raw)
	return authority.CommitReceipt{AuthorityID: "pg", Revision: 1}, f.submitErr
}
func (f *fakeAdmission) ResolveCase(_ context.Context, w controlapi.WorkloadIdentity, _, _ string) (authority.CaseRecord, error) {
	f.called = true
	f.workload = w
	return authority.CaseRecord{
		TenantID: "tenant-a", CaseID: "case-a",
		Commitment: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Raw:        []byte("exact signed bytes"),
	}, nil
}
func (f *fakeAdmission) ResolveRegistry(_ context.Context, w controlapi.WorkloadIdentity, revision int64, commitment string) (authority.RegistryRecord, error) {
	f.called = true
	f.workload = w
	f.registryRevision = revision
	f.registryCommitment = commitment
	return authority.RegistryRecord{
		TenantID: "tenant-a", Revision: revision, EnvelopeID: "registry-envelope",
		Commitment: commitment, Raw: []byte("exact registry bytes"), RoutingEpoch: 7,
		AuthorityRevision: 1,
	}, nil
}

type fakeStore struct {
	deliveries  authority.EdgeDeliveryPage
	deliveryErr error
	query       authority.EdgeDeliveryQuery
	caseRecord  authority.CaseRecord
	caseQuery   [3]string
}

func (f *fakeStore) CommitCase(context.Context, authority.CommitCaseRequest) (authority.CommitReceipt, error) {
	return authority.CommitReceipt{}, nil
}
func (f *fakeStore) CommitAdvice(context.Context, authority.CommitAdviceRequest) (authority.CommitReceipt, error) {
	return authority.CommitReceipt{}, nil
}
func (f *fakeStore) CommitRegistry(context.Context, authority.CommitRegistryRequest) (authority.CommitReceipt, error) {
	return authority.CommitReceipt{}, nil
}
func (f *fakeStore) ListEdgeDeliveries(_ context.Context, q authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error) {
	f.query = q
	return f.deliveries, f.deliveryErr
}
func (f *fakeStore) ListProjectionFacts(context.Context, authority.ProjectionFactQuery) (authority.ProjectionFactPage, error) {
	return authority.ProjectionFactPage{}, nil
}
func (f *fakeStore) ResolveCase(_ context.Context, tenant, caseID, commitment string) (authority.CaseRecord, error) {
	f.caseQuery = [3]string{tenant, caseID, commitment}
	return f.caseRecord, nil
}
func (f *fakeStore) ResolveRegistry(context.Context, string, int64, string) (authority.RegistryRecord, error) {
	return authority.RegistryRecord{}, nil
}
func (f *fakeStore) CurrentRegistryHead(context.Context, string) (authority.RegistryHead, error) {
	return authority.RegistryHead{}, nil
}
func ioNopCloser(r *strings.Reader) io.ReadCloser { return io.NopCloser(r) }
