//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/authority/postgres"
	"github.com/avivsinai/snagline/internal/collab/buzz"
	"github.com/avivsinai/snagline/internal/controlapi"
	"github.com/avivsinai/snagline/internal/delivery/outbox"
	"github.com/avivsinai/snagline/internal/deliverystream"
	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/registry"
	"github.com/avivsinai/snagline/internal/ssp"
	"github.com/avivsinai/snagline/internal/sspedge"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestPristineAuthorityEdgeAndBuzzRecovery(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	store, pool := newPristineAuthorityStore(t, ctx)

	trust, registryRaw, edgeKey, dispatcherKey := pristineRegistry(t, now)
	control, err := controlapi.New(controlapi.Config{
		Tenant: "tenant-pristine", Clock: func() time.Time { return now }, Authority: store,
		RegistryTrust: trust, RegistryPublisherPrincipalID: "registry-publisher",
	})
	if err != nil {
		t.Fatal(err)
	}
	registryReceipt, err := control.SubmitRegistry(ctx, controlapi.WorkloadIdentity{PrincipalID: "registry-publisher"}, registryRaw)
	if err != nil {
		t.Fatalf("commit root registry: %v", err)
	}
	registryHash := registryReceipt.Commitment
	caseRaw := pristineCase(t, now, registryHash, edgeKey)
	caseReceipt, err := control.Submit(ctx, controlapi.WorkloadIdentity{PrincipalID: "edge-principal", EdgeID: "edge-pristine", EdgeGeneration: 7}, caseRaw)
	if err != nil {
		t.Fatalf("commit case: %v", err)
	}
	adviceRaw := pristineAdvice(t, now, registryHash, caseReceipt.Commitment, dispatcherKey)
	adviceReceipt, err := control.Submit(ctx, controlapi.WorkloadIdentity{PrincipalID: "dispatcher-principal"}, adviceRaw)
	if err != nil {
		t.Fatalf("commit advice: %v", err)
	}
	if registryReceipt.Revision <= 0 || caseReceipt.Revision <= registryReceipt.Revision || adviceReceipt.Revision <= caseReceipt.Revision ||
		caseReceipt.EnvelopeID != "case-pristine" || adviceReceipt.EnvelopeID != "advice-pristine" {
		t.Fatalf("PostgreSQL commit receipts = registry:%#v case:%#v advice:%#v", registryReceipt, caseReceipt, adviceReceipt)
	}
	var committedCase, committedAdvice []byte
	if err := pool.QueryRow(ctx, `SELECT raw FROM authority_cases WHERE tenant_id=$1 AND case_id=$2`, "tenant-pristine", "case-pristine").Scan(&committedCase); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT raw FROM authority_advice WHERE tenant_id=$1 AND case_id=$2`, "tenant-pristine", "case-pristine").Scan(&committedAdvice); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committedCase, caseRaw) || !bytes.Equal(committedAdvice, adviceRaw) {
		t.Fatal("authority changed the exact signed SSP bytes before issuing its receipt")
	}

	js := newPristineJetStream(t, ctx)
	stream := deliverystream.StreamConfig()
	stream.Replicas = 1 // Embedded test broker: delivery acceleration remains non-authoritative.
	if _, err := js.CreateOrUpdateStream(ctx, stream); err != nil {
		t.Fatalf("create one-replica delivery stream: %v", err)
	}
	edgeDB, databasePath := newPristineEdgeDB(t, ctx)
	edgeID := sspedge.EdgeIdentity{TenantID: "tenant-pristine", EdgeID: "edge-pristine", Generation: 7}
	edgeAuthority := pristineEdgeAuthority{store: store, tenant: edgeID.TenantID, principal: "edge-principal"}
	verifier, err := sspedge.NewAuthorityVerifier(sspedge.AuthorityVerifierConfig{Tenant: edgeID.TenantID, Authority: edgeAuthority, RegistryTrust: trust})
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := sspedge.NewAuthorityReconciler(edgeAuthority, 10)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := sspedge.NewJournalConsumer(edgeDB, verifier, edgeID, reconciler)
	if err != nil {
		t.Fatal(err)
	}
	pull, err := sspedge.NewJetStreamPullConsumer(ctx, sspedge.JetStreamPullConfig{JetStream: js, Request: deliverystream.ConsumerRequest{Durable: "pristine-edge", Destination: deliverystream.DestinationEdge, TenantID: edgeID.TenantID, EdgeID: edgeID.EdgeID, EdgeGeneration: uint64(edgeID.Generation)}, Handler: handler, FetchWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	worker := outbox.Worker{Source: store, Publisher: outbox.JetStreamPublisher{JetStream: js}, WorkerID: "pristine-worker", Limit: 10, Lease: time.Minute, RetryDelay: time.Second, Now: func() time.Time { return now }}
	if err := worker.RunOnce(ctx); err != nil {
		t.Fatalf("publish committed outbox rows: %v", err)
	}
	var published int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authority_outbox WHERE published_at IS NOT NULL`).Scan(&published); err != nil {
		t.Fatal(err)
	}
	if published != 3 { // case -> domain + edge, final advice -> edge
		t.Fatalf("published delivery accelerators = %d, want 3", published)
	}

	if outcome, err := pull.HandleNext(ctx, now); err != nil || outcome != sspedge.ProcessAccepted {
		t.Fatalf("JetStream case delivery = %q, %v", outcome, err)
	}
	// A carrier identity fault halts only the acceleration loop. Reconciliation
	// re-reads the immutable PostgreSQL delivery log, rather than trusting a
	// JetStream cursor, and applies the remaining advice exactly once.
	if outcome, err := handler.Handle(ctx, pristineForeignMessage{}, now); err != nil || outcome != sspedge.ProcessReconciliationRequired || !pull.Halted() {
		t.Fatalf("foreign carrier handling = %q, %v, halted=%v", outcome, err, pull.Halted())
	}
	recovered, err := pull.Reconcile(ctx, now)
	if err != nil || !recovered.Resumed || recovered.Applied != 1 || recovered.CompleteThrough != 2 || pull.Halted() {
		t.Fatalf("PostgreSQL reconciliation = %#v, %v, halted=%v", recovered, err, pull.Halted())
	}
	caseView, found, err := edgeDB.GetCase(ctx, "case-pristine")
	if err != nil || !found || caseView.Commitment != caseReceipt.Commitment || caseView.Summary != "private support summary" || caseView.Registry.Hash != registryHash {
		t.Fatalf("encrypted edge case = %#v, found=%v, err=%v", caseView, found, err)
	}
	adviceViews, err := edgeDB.ListAdvice(ctx, "case-pristine")
	if err != nil || len(adviceViews) != 1 || adviceViews[0].AdviceID != "advice-pristine" || adviceViews[0].Text != "display this inert advice" {
		t.Fatalf("encrypted edge advice = %#v, %v", adviceViews, err)
	}
	var outage atomic.Bool
	outage.Store(true)
	var posts, exactQueries atomic.Int32
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") == "" {
			http.Error(w, "stock Buzz requires authenticated JSON POST", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/events":
			posts.Add(1)
			var event struct {
				ID string `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&event); err != nil || len(event.ID) != 64 {
				http.Error(w, "invalid stock event", http.StatusBadRequest)
				return
			}
			if outage.Load() {
				http.Error(w, `{"message":"outage"}`, http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"event_id":%q,"accepted":true,"message":""}`, event.ID)
		case "/query":
			exactQueries.Add(1)
			var filters []struct {
				IDs      []string `json:"ids"`
				Kinds    []int    `json:"kinds"`
				Channels []string `json:"#h"`
				Limit    int      `json:"limit"`
			}
			if err := json.NewDecoder(r.Body).Decode(&filters); err != nil || len(filters) != 1 || len(filters[0].IDs) != 1 || len(filters[0].Kinds) != 1 || filters[0].Kinds[0] != 9 || len(filters[0].Channels) != 1 || filters[0].Limit != 2 {
				http.Error(w, "invalid stock exact-id query", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(relay.Close)
	buzzSigner, err := buzz.NewPrivateKeySignerBytes(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	client, err := buzz.NewStockRelayClient(buzz.StockRelayConfig{RelayURL: relay.URL, Signer: buzzSigner, Clock: func() time.Time { return now }, AllowInsecureHTTPForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	buzzVerifier, err := buzz.NewAuthorityVerifier(buzz.AuthorityVerifierConfig{TenantID: edgeID.TenantID, Authority: store, RegistryTrust: trust})
	if err != nil {
		t.Fatal(err)
	}
	channels := pristineChannels{"support": "11111111-1111-1111-1111-111111111111"}
	projector, err := buzz.NewProjector(buzz.ProjectorConfig{Source: buzz.AuthoritySource{Store: store, TenantID: edgeID.TenantID}, Verifier: buzzVerifier, Channels: channels, Store: buzz.NewMemoryStore(), Signer: buzzSigner, Relay: client, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Project(ctx, 10); err == nil {
		t.Fatal("Buzz outage unexpectedly succeeded")
	}
	if posts.Load() != 1 || exactQueries.Load() != 1 {
		t.Fatalf("Buzz outage request contract = events:%d query:%d, want exact write plus exact-ID query", posts.Load(), exactQueries.Load())
	}
	if _, err := store.ResolveCase(ctx, edgeID.TenantID, "case-pristine", caseReceipt.Commitment); err != nil {
		t.Fatalf("Buzz outage changed PostgreSQL authority: %v", err)
	}
	caseDuringOutage, found, err := edgeDB.GetCase(ctx, "case-pristine")
	if err != nil || !found || caseDuringOutage.Commitment != caseReceipt.Commitment {
		t.Fatalf("Buzz outage changed edge projection = %#v, found=%v, err=%v", caseDuringOutage, found, err)
	}

	outage.Store(false)
	// A new disposable projector has no memory of the failed attempt. Its
	// recovery succeeds only because it reconstructs both facts from PostgreSQL.
	recoveredProjector, err := buzz.NewProjector(buzz.ProjectorConfig{Source: buzz.AuthoritySource{Store: store, TenantID: edgeID.TenantID}, Verifier: buzzVerifier, Channels: channels, Store: buzz.NewMemoryStore(), Signer: buzzSigner, Relay: client, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := recoveredProjector.Project(ctx, 10)
	if err != nil || result.Published != 2 || result.Processed != 2 {
		t.Fatalf("PostgreSQL-backed Buzz recovery = %#v, %v", result, err)
	}
	if err := edgeDB.Close(); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("private support summary")) || bytes.Contains(stored, []byte("display this inert advice")) {
		t.Fatal("edge SQLite contains projected payload plaintext")
	}
}

func newPristineAuthorityStore(t *testing.T, ctx context.Context) (*postgres.Store, *pgxpool.Pool) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("SNAGLINE_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("SNAGLINE_TEST_POSTGRES_DSN is required for pristine authority integration")
	}
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("snagline_pristine_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); admin.Close() })
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path TO `+schema)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate fresh PostgreSQL authority schema: %v", err)
	}
	store, err := postgres.New(pool, "postgres-pristine")
	if err != nil {
		t.Fatal(err)
	}
	return store, pool
}

func pristineRegistry(t *testing.T, now time.Time) (registry.Trust, []byte, identity.Ed25519SigningKey, identity.Ed25519SigningKey) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	edgePublic, edgePrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dispatcherPublic, dispatcherPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := identity.NewEd25519SigningKey(rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	edgeKey, err := identity.NewEd25519SigningKey(edgePrivate)
	if err != nil {
		t.Fatal(err)
	}
	dispatcherKey, err := identity.NewEd25519SigningKey(dispatcherPrivate)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := registry.NewTrust("registry-root", rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"revision": 1, "routing_epoch": 3, "previous_commitment": nil,
		"domains": []any{map[string]any{"domain": "support", "dispatcher_principal_id": "dispatcher-principal", "issuer_edge_ids": []string{"edge-pristine"}, "specialist_principal_ids": []string{}, "families": []string{ssp.FamilyCase, ssp.FamilyAdvice}, "routing_epoch": 3}},
		"principals": []any{
			map[string]any{"principal_id": "registry-principal", "roles": []string{"registry-authority"}, "ssp_key_ids": []string{"registry-root"}, "edge_ids": []string{}},
			map[string]any{"principal_id": "edge-principal", "roles": []string{"edge"}, "ssp_key_ids": []string{"edge-key"}, "edge_ids": []string{"edge-pristine"}},
			map[string]any{"principal_id": "dispatcher-principal", "roles": []string{"dispatcher"}, "ssp_key_ids": []string{"dispatcher-key"}, "edge_ids": []string{}},
		},
		"edges": []any{map[string]any{"edge_id": "edge-pristine", "generation": 7, "principal_id": "edge-principal"}},
		"keys":  []any{pristineKey("registry-root", rootPublic, "registry-principal", "registry", now), pristineKey("edge-key", edgePublic, "edge-principal", "edge", now), pristineKey("dispatcher-key", dispatcherPublic, "dispatcher-principal", "advice", now)},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ssp.Sign(ssp.Envelope{Schema: ssp.FamilyRegistry, ID: "registry-pristine", EmittedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), RoutingEpoch: 3, RegistryRevision: 1, AuthorKeyID: "registry-root", SignatureAlg: "ed25519", Body: body}, rootKey, now)
	if err != nil {
		t.Fatal(err)
	}
	return trust, raw, edgeKey, dispatcherKey
}

func pristineCase(t *testing.T, now time.Time, registryHash string, key identity.Ed25519SigningKey) []byte {
	t.Helper()
	body := json.RawMessage(`{"domain":"support","issuer_edge_id":"edge-pristine","issuer_edge_generation":7,"summary":"private support summary","context_manifest":"` + pristineDigest("manifest") + `"}`)
	raw, err := ssp.Sign(ssp.Envelope{Schema: ssp.FamilyCase, ID: "case-pristine", CaseID: "case-pristine", EmittedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), RoutingEpoch: 3, RegistryRevision: 1, RegistryHash: registryHash, AuthorKeyID: "edge-key", SignatureAlg: "ed25519", Body: body}, key, now)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pristineAdvice(t *testing.T, now time.Time, registryHash, caseCommitment string, key identity.Ed25519SigningKey) []byte {
	t.Helper()
	body := json.RawMessage(`{"case_commitment":"` + caseCommitment + `","text":"display this inert advice"}`)
	raw, err := ssp.Sign(ssp.Envelope{Schema: ssp.FamilyAdvice, ID: "advice-pristine", CaseID: "case-pristine", EmittedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), RoutingEpoch: 3, RegistryRevision: 1, RegistryHash: registryHash, AuthorKeyID: "dispatcher-key", SignatureAlg: "ed25519", Body: body}, key, now)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pristineKey(id string, public ed25519.PublicKey, principal, usage string, now time.Time) map[string]any {
	return map[string]any{"key_id": id, "public_key": base64.RawURLEncoding.EncodeToString(public), "principal_id": principal, "usage": usage, "not_before": now.Add(-time.Hour).Format(time.RFC3339), "expires_at": now.Add(time.Hour).Format(time.RFC3339)}
}

func pristineDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newPristineJetStream(t *testing.T, ctx context.Context) jetstream.JetStream {
	t.Helper()
	server, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	if !server.ReadyForConnections(5 * time.Second) {
		server.Shutdown()
		t.Fatal("embedded NATS server did not become ready")
	}
	t.Cleanup(server.Shutdown)
	connection, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

func newPristineEdgeDB(t *testing.T, ctx context.Context) (*sspedge.DB, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "edge.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{9}, sspedge.StoreKeyLength), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "edge.sqlite")
	db, err := sspedge.Open(ctx, sspedge.OpenOptions{Path: path, KeyFilePath: keyPath, Tenant: "tenant-pristine"})
	if err != nil {
		t.Fatal(err)
	}
	return db, path
}

type pristineForeignMessage struct{}

// pristineEdgeAuthority binds the direct PostgreSQL test authority to the
// edge's configured tenant, mirroring the tenant-fixed control-client read API.
type pristineEdgeAuthority struct {
	store     *postgres.Store
	tenant    string
	principal string
}

func (a pristineEdgeAuthority) ListEdgeDeliveries(ctx context.Context, query authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error) {
	if query.TenantID != a.tenant {
		return authority.EdgeDeliveryPage{}, fmt.Errorf("unexpected edge tenant %q", query.TenantID)
	}
	query.PrincipalID = a.principal
	return a.store.ListEdgeDeliveries(ctx, query)
}

func (a pristineEdgeAuthority) ResolveCase(ctx context.Context, caseID, commitment string) (authority.CaseRecord, error) {
	return a.store.ResolveCase(ctx, a.tenant, caseID, commitment)
}

func (a pristineEdgeAuthority) ResolveRegistry(ctx context.Context, tenant string, revision int64, commitment string) (authority.RegistryRecord, error) {
	if tenant != a.tenant {
		return authority.RegistryRecord{}, fmt.Errorf("unexpected registry tenant %q", tenant)
	}
	return a.store.ResolveRegistry(ctx, tenant, revision, commitment)
}

func (pristineForeignMessage) Metadata() (sspedge.JournalMetadata, error) {
	return sspedge.JournalMetadata{Stream: deliverystream.StreamName, Sequence: 999, DeliverySeq: 99, TenantID: "tenant-pristine", EdgeID: "other-edge", EdgeGeneration: 7}, nil
}
func (pristineForeignMessage) Subject() string                 { return "foreign" }
func (pristineForeignMessage) Data() []byte                    { return []byte("foreign") }
func (pristineForeignMessage) DoubleAck(context.Context) error { return nil }
func (pristineForeignMessage) Nak() error                      { return nil }

type pristineChannels map[string]string

func (c pristineChannels) ChannelForDomain(_ context.Context, domain string) (string, error) {
	channel, ok := c[domain]
	if !ok {
		return "", fmt.Errorf("missing channel for %q", domain)
	}
	return channel, nil
}
