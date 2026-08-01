package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/edge"
)

func TestSubmitUsesMTLSAndForwardsExactBytesWithoutIdentityHeaders(t *testing.T) {
	serverCert, clientCert, roots := testTLS(t)
	raw := testCaseRaw()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.Version != tls.VersionTLS13 {
			t.Fatal("request did not arrive over verified TLS 1.3")
		}
		if got := r.Header.Get("X-Principal-ID"); got != "" || r.Header.Get("X-Edge-ID") != "" || r.Header.Get("X-Edge-Generation") != "" {
			t.Fatalf("identity headers=%v", r.Header)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/cases" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil || string(got) != string(raw) {
			t.Fatalf("body=%q err=%v", got, err)
		}
		_, _ = w.Write([]byte(`{"authority_id":"pg-1","revision":7,"envelope_id":"case-1","commitment":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()

	client, err := New(Config{Endpoint: server.URL, TLS: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, Workload: edge.WorkloadIdentity{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 3}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := client.Submit(context.Background(), edge.WorkloadIdentity{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 3}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.AuthorityID != "pg-1" || receipt.Revision != 7 || receipt.EnvelopeID != "case-1" {
		t.Fatalf("receipt=%+v", receipt)
	}
}

func TestClientRejectsWeakenedTLSOrWorkloadMismatchBeforeRequest(t *testing.T) {
	_, clientCert, roots := testTLS(t)
	for name, config := range map[string]Config{
		"non-https":   {Endpoint: "http://control.invalid", TLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, Workload: edge.WorkloadIdentity{PrincipalID: "edge"}},
		"tls-12":      {Endpoint: "https://control.invalid", TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, Workload: edge.WorkloadIdentity{PrincipalID: "edge"}},
		"skip-verify": {Endpoint: "https://control.invalid", TLS: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, Workload: edge.WorkloadIdentity{PrincipalID: "edge"}},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := New(config); err == nil || got != nil {
				t.Fatalf("New() = %v, %v", got, err)
			}
		})
	}
	client, err := New(Config{Endpoint: "https://control.invalid", TLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, Workload: edge.WorkloadIdentity{PrincipalID: "edge", EdgeID: "edge-1", EdgeGeneration: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Submit(context.Background(), edge.WorkloadIdentity{PrincipalID: "other", EdgeID: "edge-1", EdgeGeneration: 1}, testCaseRaw()); err == nil {
		t.Fatal("mismatched workload reached transport")
	}
}

func TestClientMapsBoundedAuthorityReads(t *testing.T) {
	serverCert, clientCert, roots := testTLS(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/edges/edge-1/generations/2/deliveries" || r.URL.Query().Get("after_sequence") != "3" || r.URL.Query().Get("limit") != "2" {
			t.Fatalf("URL=%s", r.URL.String())
		}
		_, _ = w.Write([]byte(`{"deliveries":[{"sequence":4,"kind":"case","case_id":"case-1","envelope_id":"envelope-1","commitment":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","raw":"eA==","authority_revision":9}],"high_watermark":4,"complete_through":4}`))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	client, err := New(Config{Endpoint: server.URL, TLS: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, Workload: edge.WorkloadIdentity{PrincipalID: "edge", EdgeID: "edge-1", EdgeGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListEdgeDeliveries(context.Background(), authority.EdgeDeliveryQuery{TenantID: "tenant-a", EdgeID: "edge-1", EdgeGeneration: 2, AfterSequence: 3, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Deliveries) != 1 || page.Deliveries[0].Sequence != 4 || string(page.Deliveries[0].Raw) != "x" || page.HighWatermark != 4 {
		t.Fatalf("page=%+v", page)
	}
}

func TestResolveCaseAllowsExactEdgeCertificateAndExactCommitmentQuery(t *testing.T) {
	serverCert, clientCert, roots := testTLS(t)
	commitment := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/cases/case-1" || r.URL.Query().Get("commitment") != commitment {
			t.Fatalf("URL=%s", r.URL.String())
		}
		if r.Header.Get("X-Principal-ID") != "" {
			t.Fatalf("identity header=%v", r.Header)
		}
		_, _ = w.Write([]byte(`{"tenant_id":"tenant-a","case_id":"case-1","envelope_id":"envelope-1","commitment":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","raw":"eA==","domain":"support","issuer_edge_id":"edge-1","issuer_edge_generation":2,"routing_epoch":7,"registry_revision":12,"registry_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expires_at":"2026-08-01T00:00:00Z","authority_revision":9}`))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	client, err := New(Config{Endpoint: server.URL, TLS: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, Workload: edge.WorkloadIdentity{PrincipalID: "edge", EdgeID: "edge-1", EdgeGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := client.ResolveCase(context.Background(), "case-1", commitment)
	if err != nil {
		t.Fatal(err)
	}
	if record.CaseID != "case-1" || record.Commitment != commitment || string(record.Raw) != "x" || record.AuthorityRevision != 9 {
		t.Fatalf("record=%+v", record)
	}
}

func TestResolveRegistryUsesExactRevisionAndCommitment(t *testing.T) {
	serverCert, clientCert, roots := testTLS(t)
	commitment := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/registries/12" || r.URL.Query().Get("commitment") != commitment || r.Header.Get("X-Principal-ID") != "" {
			t.Fatalf("request=%s headers=%v", r.URL, r.Header)
		}
		_, _ = w.Write([]byte(`{"tenant_id":"tenant-a","revision":12,"envelope_id":"registry-12","commitment":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","raw":"eA==","routing_epoch":7,"previous_commitment":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","authority_revision":19}`))
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	client, err := New(Config{Endpoint: server.URL, TLS: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{clientCert}}, Workload: edge.WorkloadIdentity{PrincipalID: "edge", EdgeID: "edge-1", EdgeGeneration: 2}})
	if err != nil {
		t.Fatal(err)
	}
	record, err := client.ResolveRegistry(context.Background(), "tenant-a", 12, commitment)
	if err != nil {
		t.Fatal(err)
	}
	if record.Revision != 12 || record.RoutingEpoch != 7 || string(record.Raw) != "x" || record.AuthorityRevision != 19 {
		t.Fatalf("record=%+v", record)
	}
}

func testTLS(t *testing.T) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey := mustKey(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	makeCert := func(serial int64, dns string, client bool) tls.Certificate {
		key := mustKey(t)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return makeCert(2, "localhost", false), makeCert(3, "edge.test", true), roots
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testCaseRaw() []byte {
	return []byte(`{"schema":"ssp.case.v1","id":"case-1","case_id":"case-1","emitted_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-01T00:00:00Z","routing_epoch":1,"registry_revision":1,"registry_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","author_key_id":"edge-key","signature_alg":"ed25519","body":{},"signature":"placeholder"}`)
}
