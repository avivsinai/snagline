package main

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/deliverystream"
	"github.com/avivsinai/snagline/internal/sspedge"
)

func TestParseEdgeRuntimeConfigRequiresExplicitSecureComposition(t *testing.T) {
	t.Setenv("SNAGLINE_EDGE_SOCKET", "/run/snagline/edge.sock")
	t.Setenv("SNAGLINE_EDGE_OPS_SOCKET", "/run/snagline/edge.ops.sock")
	t.Setenv("SNAGLINE_EDGE_TENANT", "tenant-a")
	t.Setenv("SNAGLINE_EDGE_ID", "edge-a")
	t.Setenv("SNAGLINE_EDGE_GENERATION", "2")
	t.Setenv("SNAGLINE_EDGE_PRINCIPAL_ID", "edge-principal")
	t.Setenv("SNAGLINE_EDGE_AUTHOR_KEY_ID", "edge-key")
	t.Setenv("SNAGLINE_EDGE_SIGNING_KEY", "/run/secrets/edge-key.pem")
	t.Setenv("SNAGLINE_EDGE_REGISTRY_ROOT_KEY", "/run/secrets/registry-root.pem")
	t.Setenv("SNAGLINE_EDGE_REGISTRY_ROOT_KEY_ID", "registry-root-1")
	t.Setenv("SNAGLINE_EDGE_DB", "/var/lib/snagline/edge.db")
	t.Setenv("SNAGLINE_EDGE_DB_KEY", "/run/secrets/edge-db.key")
	t.Setenv("SNAGLINE_EDGE_CONTROL_URL", "https://control.example")
	t.Setenv("SNAGLINE_EDGE_TLS_CERT", "/run/secrets/edge.crt")
	t.Setenv("SNAGLINE_EDGE_TLS_KEY", "/run/secrets/edge.key")
	t.Setenv("SNAGLINE_EDGE_CONTROL_CA", "/run/secrets/control-ca.pem")
	t.Setenv("SNAGLINE_EDGE_NATS_URL", "tls://nats.example:4222")
	t.Setenv("SNAGLINE_EDGE_NATS_CREDENTIALS_FILE", "/run/secrets/nats.creds")
	t.Setenv("SNAGLINE_EDGE_NATS_CA_FILE", "/run/secrets/nats-ca.pem")
	t.Setenv("SNAGLINE_EDGE_ENVELOPE_TTL", "1h")

	config, err := parseEdgeRuntimeConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.EdgeGeneration != 2 || config.EnvelopeTTL.String() != "1h0m0s" || config.OpsSocket != "/run/snagline/edge.ops.sock" {
		t.Fatalf("config=%+v", config)
	}
}

func TestParseEdgeRuntimeConfigRequiresDistinctAbsoluteOpsSocket(t *testing.T) {
	setValidEdgeEnvironment(t)
	if _, err := parseEdgeRuntimeConfig([]string{"--ops-socket=ops.sock"}); err == nil {
		t.Fatal("accepted relative operations socket")
	}
	if _, err := parseEdgeRuntimeConfig([]string{"--ops-socket=/run/snagline/edge.sock"}); err == nil {
		t.Fatal("accepted operations socket shared with edge API")
	}
}

func TestParseEdgeRuntimeConfigRejectsInsecureEndpoints(t *testing.T) {
	setValidEdgeEnvironment(t)
	if _, err := parseEdgeRuntimeConfig([]string{"--control-url", "http://control.example"}); err == nil {
		t.Fatal("accepted plaintext control endpoint")
	}
	if _, err := parseEdgeRuntimeConfig([]string{"--nats-url", "nats://nats.example:4222"}); err == nil {
		t.Fatal("accepted plaintext NATS endpoint")
	}
}

func TestReconcileAuthoritativeBeforeServingCatchesUpFreshEdgeWithoutJetStream(t *testing.T) {
	ctx := context.Background()
	id := sspedge.EdgeIdentity{TenantID: "tenant-a", EdgeID: "edge-a", Generation: 1}
	db := openEdgeRuntimeTestDB(t)
	now := time.Now().UTC()
	delivery := edgeRuntimeDelivery(id, 1)

	source := authorityDeliverySource{page: authority.EdgeDeliveryPage{
		Deliveries:      []authority.EdgeDelivery{{Sequence: 1, Kind: "case", CaseID: "case-1", EnvelopeID: "envelope-1", Commitment: edgeRuntimeCommitment("a"), AuthorityRevision: 1, Raw: delivery.Raw}},
		HighWatermark:   1,
		CompleteThrough: 1,
	}}
	reconciler, err := sspedge.NewAuthorityReconciler(source, 100)
	if err != nil {
		t.Fatal(err)
	}
	verifier := edgeRuntimeVerifyFunc(func(context.Context, sspedge.JournalDelivery) (*sspedge.VerifiedProjection, error) {
		return edgeRuntimeCaseProjection(now, id), nil
	})

	if err := reconcileAuthoritativeEdge(ctx, db, verifier, id, reconciler, now); err != nil {
		t.Fatal(err)
	}
	state, err := db.DeliveryState(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastContiguousSeq != 1 || state.HighWatermark != 1 || state.Mode != sspedge.DeliveryModeActive {
		t.Fatalf("state after authoritative startup reconciliation = %+v", state)
	}
}

func TestEdgeAuthorityReadinessUsesBoundedReadWithoutClaimingCompletion(t *testing.T) {
	ctx := context.Background()
	id := sspedge.EdgeIdentity{TenantID: "tenant-a", EdgeID: "edge-a", Generation: 1}
	db := openEdgeRuntimeTestDB(t)
	source := authorityDeliverySource{page: authority.EdgeDeliveryPage{HighWatermark: 3, CompleteThrough: 0}}
	reconciler, err := sspedge.NewAuthorityReconciler(source, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := edgeAuthorityReadReady(ctx, db, id, reconciler); err != nil {
		t.Fatalf("readiness error = %v", err)
	}
	state, err := db.DeliveryState(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastContiguousSeq != 0 || state.HighWatermark != 0 || state.Mode != sspedge.DeliveryModeActive {
		t.Fatalf("readiness mutated durable delivery state: %+v", state)
	}
}

type edgeRuntimeVerifyFunc func(context.Context, sspedge.JournalDelivery) (*sspedge.VerifiedProjection, error)

func (f edgeRuntimeVerifyFunc) Verify(ctx context.Context, d sspedge.JournalDelivery) (*sspedge.VerifiedProjection, error) {
	return f(ctx, d)
}

type authorityDeliverySource struct{ page authority.EdgeDeliveryPage }

func (s authorityDeliverySource) ListEdgeDeliveries(_ context.Context, query authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error) {
	if query.AfterSequence == 0 {
		return s.page, nil
	}
	return authority.EdgeDeliveryPage{HighWatermark: s.page.HighWatermark, CompleteThrough: s.page.HighWatermark}, nil
}

func openEdgeRuntimeTestDB(t *testing.T) *sspedge.DB {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, sspedge.StoreKeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "edge.key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sspedge.Open(context.Background(), sspedge.OpenOptions{Path: filepath.Join(dir, "edge.db"), KeyFilePath: keyPath, Tenant: "tenant-a"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func edgeRuntimeDelivery(id sspedge.EdgeIdentity, sequence int64) sspedge.JournalDelivery {
	return sspedge.JournalDelivery{
		DeliverySeq: sequence, TenantID: id.TenantID, EdgeID: id.EdgeID, EdgeGeneration: id.Generation,
		Subject: deliverystream.SubjectPrefix + "." + deliverystream.RoutingToken(id.TenantID) + ".edge." + deliverystream.EdgeToken(id.EdgeID, uint64(id.Generation)),
		Raw:     []byte("authoritative delivery"),
	}
}

func edgeRuntimeCaseProjection(now time.Time, id sspedge.EdgeIdentity) *sspedge.VerifiedProjection {
	domain := "domain-a"
	return &sspedge.VerifiedProjection{EnvelopeID: "envelope-1", Commitment: edgeRuntimeCommitment("a"), Family: sspedge.FamilyCase, Case: &sspedge.Case{
		CaseID: "case-1", IssuerEdgeID: id.EdgeID, IssuerEdgeGeneration: id.Generation, Domain: domain,
		RouteKind: "domain", RouteToken: sspedge.RoutingToken(domain), SourceToken: sspedge.EdgeRoutingToken(id.EdgeID, id.Generation),
		RoutingEpoch: 1, RegistryRevision: 1, RegistryHash: edgeRuntimeCommitment("b"), Summary: "summary", ContextManifest: edgeRuntimeCommitment("c"), ExpiresAt: now.Add(time.Hour),
	}}
}

func edgeRuntimeCommitment(last string) string {
	return "sha256:" + "000000000000000000000000000000000000000000000000000000000000000" + last
}

func setValidEdgeEnvironment(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"SNAGLINE_EDGE_SOCKET": "/run/snagline/edge.sock", "SNAGLINE_EDGE_OPS_SOCKET": "/run/snagline/edge.ops.sock", "SNAGLINE_EDGE_TENANT": "tenant-a", "SNAGLINE_EDGE_ID": "edge-a", "SNAGLINE_EDGE_GENERATION": "2", "SNAGLINE_EDGE_PRINCIPAL_ID": "edge-principal", "SNAGLINE_EDGE_AUTHOR_KEY_ID": "edge-key", "SNAGLINE_EDGE_SIGNING_KEY": "/run/secrets/edge-key.pem", "SNAGLINE_EDGE_REGISTRY_ROOT_KEY": "/run/secrets/registry-root.pem", "SNAGLINE_EDGE_REGISTRY_ROOT_KEY_ID": "registry-root-1", "SNAGLINE_EDGE_DB": "/var/lib/snagline/edge.db", "SNAGLINE_EDGE_DB_KEY": "/run/secrets/edge-db.key", "SNAGLINE_EDGE_CONTROL_URL": "https://control.example", "SNAGLINE_EDGE_TLS_CERT": "/run/secrets/edge.crt", "SNAGLINE_EDGE_TLS_KEY": "/run/secrets/edge.key", "SNAGLINE_EDGE_CONTROL_CA": "/run/secrets/control-ca.pem", "SNAGLINE_EDGE_NATS_URL": "tls://nats.example:4222", "SNAGLINE_EDGE_NATS_CREDENTIALS_FILE": "/run/secrets/nats.creds", "SNAGLINE_EDGE_NATS_CA_FILE": "/run/secrets/nats-ca.pem", "SNAGLINE_EDGE_ENVELOPE_TTL": "1h",
	} {
		t.Setenv(key, value)
	}
}

// A failed bind must not put the configured socket pathname into the error, and
// therefore not into the operator log main.go writes. This fixture deliberately
// reaches net.Listen rather than failing earlier in prepareSocketNamespace: the
// parent is a valid current-user-owned 0700 directory, and the basename is long
// enough to exceed the sun_path limit, so net.Listen fails with a *net.OpError
// whose Addr is the full socket path. Without sanitization that path reaches the
// caller verbatim.
func TestServeEdgeSocketBindFailureDoesNotLeakConfiguredPath(t *testing.T) {
	const marker = "tenant-acme-secret-edge-name"
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatalf("chmod parent: %v", err)
	}
	socket := filepath.Join(parent, marker+"-"+strings.Repeat("x", 120)+".sock")

	err := serveEdgeSocket(context.Background(), socket, nil)
	if err == nil {
		t.Fatalf("bind with an overlong socket name unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error leaked the configured socket path: %v", err)
	}
	if strings.Contains(err.Error(), parent) {
		t.Fatalf("error leaked the socket parent directory: %v", err)
	}
	if err.Error() != "edge local API socket unavailable" {
		t.Fatalf("unexpected error text %q", err.Error())
	}
}
