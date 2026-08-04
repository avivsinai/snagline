package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/controlclient"
	"github.com/avivsinai/snagline/internal/deliverystream"
	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/registry"
	"github.com/avivsinai/snagline/internal/runtimeops"
	"github.com/avivsinai/snagline/internal/securetransport"
	"github.com/avivsinai/snagline/internal/sspedge"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type edgeRuntimeConfig struct {
	Socket, OpsSocket, Tenant, EdgeID, PrincipalID, AuthorKeyID string
	SigningKey, DBPath, DBKey                                   string
	RegistryRootKey, RegistryRootKeyID                          string
	ControlURL, TLSCert, TLSKey, ControlCA                      string
	NATSURL, NATSCredentialsFile, NATSCAFile                    string
	EdgeGeneration                                              int64
	EnvelopeTTL                                                 time.Duration
}

const edgeAuthorityReconcileInterval = 30 * time.Second

func parseEdgeRuntimeConfig(args []string) (edgeRuntimeConfig, error) {
	flags := flag.NewFlagSet("snagline-edge", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socket := flags.String("socket", envEdge("SNAGLINE_EDGE_SOCKET", ""), "absolute Unix socket")
	opsSocket := flags.String("ops-socket", envEdge("SNAGLINE_EDGE_OPS_SOCKET", ""), "absolute private Unix operations socket")
	tenant := flags.String("tenant", envEdge("SNAGLINE_EDGE_TENANT", ""), "SSP tenant")
	edgeID := flags.String("edge-id", envEdge("SNAGLINE_EDGE_ID", ""), "registered edge ID")
	generation := flags.Int64("edge-generation", envEdgeInt64("SNAGLINE_EDGE_GENERATION", 0), "registered positive edge generation")
	principal := flags.String("principal-id", envEdge("SNAGLINE_EDGE_PRINCIPAL_ID", ""), "certificate-bound edge principal")
	author := flags.String("author-key-id", envEdge("SNAGLINE_EDGE_AUTHOR_KEY_ID", ""), "registered edge SSP signing key ID")
	signingKey := flags.String("signing-key", envEdge("SNAGLINE_EDGE_SIGNING_KEY", ""), "Ed25519 PKCS8 private PEM")
	registryRootKey := flags.String("registry-root-key", envEdge("SNAGLINE_EDGE_REGISTRY_ROOT_KEY", ""), "pinned registry Ed25519 public PEM")
	registryRootKeyID := flags.String("registry-root-key-id", envEdge("SNAGLINE_EDGE_REGISTRY_ROOT_KEY_ID", ""), "pinned registry SSP key ID")
	dbPath := flags.String("db", envEdge("SNAGLINE_EDGE_DB", ""), "encrypted edge SQLite path")
	dbKey := flags.String("db-key", envEdge("SNAGLINE_EDGE_DB_KEY", ""), "32-byte encrypted edge SQLite key")
	controlURL := flags.String("control-url", envEdge("SNAGLINE_EDGE_CONTROL_URL", ""), "https control endpoint")
	tlsCert := flags.String("tls-cert", envEdge("SNAGLINE_EDGE_TLS_CERT", ""), "mTLS client certificate")
	tlsKey := flags.String("tls-key", envEdge("SNAGLINE_EDGE_TLS_KEY", ""), "mTLS client key")
	controlCA := flags.String("control-ca", envEdge("SNAGLINE_EDGE_CONTROL_CA", ""), "control root CA")
	natsURL := flags.String("nats-url", envEdge("SNAGLINE_EDGE_NATS_URL", ""), "tls NATS URL")
	natsCredentials := flags.String("nats-credentials-file", envEdge("SNAGLINE_EDGE_NATS_CREDENTIALS_FILE", ""), "NATS credential file")
	natsCA := flags.String("nats-ca-file", envEdge("SNAGLINE_EDGE_NATS_CA_FILE", ""), "NATS root CA")
	ttl := flags.Duration("envelope-ttl", envEdgeDuration("SNAGLINE_EDGE_ENVELOPE_TTL", 0), "positive bounded SSP envelope TTL")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return edgeRuntimeConfig{}, errors.New("invalid edge flags")
	}
	config := edgeRuntimeConfig{Socket: *socket, OpsSocket: *opsSocket, Tenant: *tenant, EdgeID: *edgeID, EdgeGeneration: *generation, PrincipalID: *principal, AuthorKeyID: *author, SigningKey: *signingKey, RegistryRootKey: *registryRootKey, RegistryRootKeyID: *registryRootKeyID, DBPath: *dbPath, DBKey: *dbKey, ControlURL: *controlURL, TLSCert: *tlsCert, TLSKey: *tlsKey, ControlCA: *controlCA, NATSURL: *natsURL, NATSCredentialsFile: *natsCredentials, NATSCAFile: *natsCA, EnvelopeTTL: *ttl}
	return config, config.validate()
}

func (config edgeRuntimeConfig) validate() error {
	if edgeBlank(config.Socket, config.OpsSocket, config.Tenant, config.EdgeID, config.PrincipalID, config.AuthorKeyID, config.SigningKey, config.RegistryRootKey, config.RegistryRootKeyID, config.DBPath, config.DBKey, config.ControlURL, config.TLSCert, config.TLSKey, config.ControlCA, config.NATSURL, config.NATSCredentialsFile, config.NATSCAFile) || config.EdgeGeneration <= 0 || config.EnvelopeTTL <= 0 || config.EnvelopeTTL > 24*time.Hour {
		return errors.New("missing or unbounded edge configuration")
	}
	for _, path := range []string{config.Socket, config.OpsSocket, config.SigningKey, config.RegistryRootKey, config.DBPath, config.DBKey, config.TLSCert, config.TLSKey, config.ControlCA, config.NATSCredentialsFile, config.NATSCAFile} {
		if !filepath.IsAbs(path) || path != filepath.Clean(path) {
			return errors.New("edge paths must be absolute")
		}
	}
	if config.Socket == config.OpsSocket {
		return errors.New("edge and operations sockets must be distinct")
	}
	control, err := url.Parse(config.ControlURL)
	if err != nil || control.Scheme != "https" || control.Host == "" || control.User != nil || control.Path != "" || control.RawQuery != "" || control.Fragment != "" {
		return errors.New("control URL must be a root HTTPS URL without credentials")
	}
	natsURL, err := url.Parse(config.NATSURL)
	if err != nil || natsURL.Scheme != "tls" || natsURL.Host == "" || natsURL.User != nil || natsURL.Path != "" || natsURL.RawQuery != "" || natsURL.Fragment != "" {
		return errors.New("NATS URL must be a root tls URL without credentials")
	}
	return nil
}

func buildEdgeCore(ctx context.Context, config edgeRuntimeConfig) (*edge.Service, *sspedge.DB, *controlclient.Client, error) {
	key, err := identity.LoadEd25519SigningKey(config.SigningKey)
	if err != nil {
		return nil, nil, nil, errors.New("edge signing key unavailable")
	}
	signer, err := edge.NewCaseSigner(key)
	if err != nil {
		return nil, nil, nil, errors.New("edge signing key unavailable")
	}
	tlsConfig, err := securetransport.LoadClientTLS(config.TLSCert, config.TLSKey, config.ControlCA)
	if err != nil {
		return nil, nil, nil, errors.New("control mTLS unavailable")
	}
	client, err := controlclient.New(controlclient.Config{Endpoint: config.ControlURL, TLS: tlsConfig, Workload: edge.WorkloadIdentity{PrincipalID: config.PrincipalID, EdgeID: config.EdgeID, EdgeGeneration: config.EdgeGeneration}})
	if err != nil {
		return nil, nil, nil, errors.New("control client unavailable")
	}
	db, err := sspedge.Open(ctx, sspedge.OpenOptions{Path: config.DBPath, KeyFilePath: config.DBKey, Tenant: config.Tenant})
	if err != nil {
		return nil, nil, nil, errors.New("encrypted edge store unavailable")
	}
	closeDB := true
	defer func() {
		if closeDB {
			_ = db.Close()
		}
	}()
	service, err := edge.NewService(edge.ServiceConfig{EdgeID: config.EdgeID, EdgeGeneration: config.EdgeGeneration, PrincipalID: config.PrincipalID, AuthorKeyID: config.AuthorKeyID, Signer: signer, Store: db, Gateway: client, EnvelopeTTL: config.EnvelopeTTL, NewID: func() (string, error) { return uuid.NewString(), nil }})
	if err != nil {
		return nil, nil, nil, errors.New("edge service unavailable")
	}
	closeDB = false
	return service, db, client, nil
}

func connectEdgeNATS(config edgeRuntimeConfig) (*securetransport.NATSConnection, error) {
	return securetransport.ConnectNATS(securetransport.NATSConfig{URL: config.NATSURL, CredentialsFile: config.NATSCredentialsFile, RootCAFile: config.NATSCAFile, Timeout: 10 * time.Second})
}

// runEdge keeps the local API and JetStream pull loop tied to one cancellation
// context. It completes any persisted reconciliation before binding the local
// API, so local callers never observe an edge advertised as ready mid-repair.
func runEdge(ctx context.Context, config edgeRuntimeConfig) error {
	service, db, client, err := buildEdgeCore(ctx, config)
	if err != nil {
		return err
	}
	defer db.Close()
	verifier, err := buildEdgeVerifier(config, projectionAuthorityClient{client: client, tenant: config.Tenant})
	if err != nil {
		return err
	}
	nc, err := connectEdgeNATS(config)
	if err != nil {
		return errors.New("secure JetStream unavailable")
	}
	defer nc.Close()
	js, err := jetstream.New(nc.Conn)
	if err != nil {
		return errors.New("secure JetStream unavailable")
	}
	identity := sspedge.EdgeIdentity{TenantID: config.Tenant, EdgeID: config.EdgeID, Generation: config.EdgeGeneration}
	reconciler, err := sspedge.NewAuthorityReconciler(client, 100)
	if err != nil {
		return errors.New("authority reconciliation unavailable")
	}
	if err := reconcileAuthoritativeEdge(ctx, db, verifier, identity, reconciler, time.Now().UTC()); err != nil {
		return errors.New("startup authority reconciliation unavailable")
	}
	handler, err := sspedge.NewJournalConsumer(db, verifier, identity, reconciler)
	if err != nil {
		return errors.New("journal consumer unavailable")
	}
	durable := fmt.Sprintf("edge-%s-g%d", deliverystream.RoutingToken(config.EdgeID)[:32], config.EdgeGeneration)
	pull, err := sspedge.NewJetStreamPullConsumer(ctx, sspedge.JetStreamPullConfig{JetStream: js, Request: deliverystream.ConsumerRequest{Durable: durable, Destination: deliverystream.DestinationEdge, TenantID: config.Tenant, EdgeID: config.EdgeID, EdgeGeneration: uint64(config.EdgeGeneration)}, Handler: handler})
	if err != nil {
		return errors.New("secure JetStream consumer unavailable")
	}
	tracker := runtimeops.NewTracker()
	ops, err := runtimeops.Start(ctx, config.OpsSocket, runtimeops.HandlerConfig{Role: "edge", Tracker: tracker, Ready: func(ctx context.Context) error {
		if nc.Conn == nil || nc.Conn.Status() != nats.CONNECTED {
			return errors.New("edge JetStream unavailable")
		}
		return edgeAuthorityReadReady(ctx, db, identity, reconciler)
	}})
	if err != nil {
		return errors.New("private operations surface is unavailable")
	}
	defer ops.Close()
	tracker.MarkInitialized()
	go runEdgeConsumer(ctx, pull, func(ctx context.Context) error {
		return reconcileAuthoritativeEdge(ctx, db, verifier, identity, reconciler, time.Now().UTC())
	})
	return serveEdgeSocket(ctx, config.Socket, edgeLocalAPI{Service: service, db: db})
}

// edgeAuthorityReadReady deliberately performs only the bounded, read-only
// authority check. It does not infer completion from a JetStream cursor and it
// does not apply or acknowledge any authority delivery from a health request.
func edgeAuthorityReadReady(ctx context.Context, db *sspedge.DB, identity sspedge.EdgeIdentity, reconciler sspedge.Reconciler) error {
	if db == nil || reconciler == nil {
		return errors.New("edge authoritative read unavailable")
	}
	state, err := db.DeliveryState(ctx, identity)
	if err != nil || state.Mode != sspedge.DeliveryModeActive {
		return errors.New("edge delivery state unavailable")
	}
	if _, err := reconciler.FetchAfter(ctx, identity, state.LastContiguousSeq); err != nil {
		return errors.New("edge authoritative read unavailable")
	}
	return nil
}

func buildEdgeVerifier(config edgeRuntimeConfig, authority sspedge.ProjectionAuthority) (sspedge.Verifier, error) {
	key, err := identity.LoadEd25519VerifyingKey(config.RegistryRootKey)
	if err != nil {
		return nil, errors.New("pinned registry root unavailable")
	}
	public, err := key.PublicKey()
	if err != nil {
		return nil, errors.New("pinned registry root unavailable")
	}
	trust, err := registry.NewTrust(config.RegistryRootKeyID, public)
	if err != nil {
		return nil, errors.New("pinned registry root unavailable")
	}
	verifier, err := sspedge.NewAuthorityVerifier(sspedge.AuthorityVerifierConfig{Tenant: config.Tenant, Authority: authority, RegistryTrust: trust})
	if err != nil {
		return nil, errors.New("pinned registry verifier unavailable")
	}
	return verifier, nil
}

// projectionAuthorityClient adapts the identity-bound HTTP read surface to
// the verifier's explicit-tenant authority interface. Tenant is checked here
// and still never sent as a client-supplied HTTP identity field.
type projectionAuthorityClient struct {
	client *controlclient.Client
	tenant string
}

func (c projectionAuthorityClient) ListEdgeDeliveries(ctx context.Context, query authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error) {
	if c.client == nil || query.TenantID != c.tenant {
		return authority.EdgeDeliveryPage{}, errors.New("control authority tenant mismatch")
	}
	return c.client.ListEdgeDeliveries(ctx, query)
}
func (c projectionAuthorityClient) ResolveCase(ctx context.Context, caseID, commitment string) (authority.CaseRecord, error) {
	if c.client == nil {
		return authority.CaseRecord{}, errors.New("control authority unavailable")
	}
	return c.client.ResolveCase(ctx, caseID, commitment)
}
func (c projectionAuthorityClient) ResolveRegistry(ctx context.Context, tenant string, revision int64, commitment string) (authority.RegistryRecord, error) {
	if c.client == nil || tenant != c.tenant {
		return authority.RegistryRecord{}, errors.New("control authority tenant mismatch")
	}
	return c.client.ResolveRegistry(ctx, tenant, revision, commitment)
}

func reconcileEdge(ctx context.Context, pull *sspedge.JetStreamPullConsumer) error {
	for pull != nil && pull.Halted() {
		if _, err := pull.Reconcile(ctx, time.Now().UTC()); err != nil {
			return err
		}
	}
	if pull == nil {
		return errors.New("nil JetStream pull consumer")
	}
	return nil
}

// reconcileAuthoritativeEdge starts from the durable local cursor, not the
// broker cursor. It intentionally puts the projection into the existing
// reconciliation state before constructing a fresh consumer so the exact
// PostgreSQL range is verified and committed even when JetStream is healthy
// but has no retained wake for this edge.
func reconcileAuthoritativeEdge(ctx context.Context, db *sspedge.DB, verifier sspedge.Verifier, identity sspedge.EdgeIdentity, reconciler sspedge.Reconciler, now time.Time) error {
	if db == nil || verifier == nil || reconciler == nil || now.IsZero() {
		return errors.New("invalid authority reconciliation dependencies")
	}
	state, err := db.DeliveryState(ctx, identity)
	if err != nil {
		return err
	}
	if err := db.RequireReconciliation(ctx, identity, state.HighWatermark, "authoritative_reconciliation", now); err != nil {
		return err
	}
	consumer, err := sspedge.NewJournalConsumer(db, verifier, identity, reconciler)
	if err != nil {
		return err
	}
	for consumer.Halted() {
		before, err := db.DeliveryState(ctx, identity)
		if err != nil {
			return err
		}
		result, err := consumer.Reconcile(ctx, now)
		if err != nil {
			return err
		}
		if result.Resumed {
			return nil
		}
		after, err := db.DeliveryState(ctx, identity)
		if err != nil {
			return err
		}
		if after.LastContiguousSeq <= before.LastContiguousSeq {
			return errors.New("authority reconciliation made no durable progress")
		}
	}
	return nil
}

func runEdgeConsumer(ctx context.Context, pull *sspedge.JetStreamPullConsumer, periodicReconcile func(context.Context) error) {
	nextAuthorityReconcile := time.Now().Add(edgeAuthorityReconcileInterval)
	for ctx.Err() == nil {
		if pull == nil {
			return
		}
		if pull.Halted() {
			if err := reconcileEdge(ctx, pull); err != nil && ctx.Err() == nil {
				log.Print("snagline-edge: authority reconciliation retrying")
				if !waitEdgeRetry(ctx) {
					return
				}
			}
			continue
		}
		if periodicReconcile != nil && !time.Now().Before(nextAuthorityReconcile) {
			// This runs in the same loop as HandleNext, so no normal carrier
			// delivery can race the transient authoritative reconciliation.
			if err := periodicReconcile(ctx); err != nil && ctx.Err() == nil {
				log.Print("snagline-edge: periodic authority reconciliation retrying")
			}
			nextAuthorityReconcile = time.Now().Add(edgeAuthorityReconcileInterval)
			continue
		}
		if _, err := pull.HandleNext(ctx, time.Now().UTC()); err != nil && !errors.Is(err, sspedge.ErrNoJournalMessage) && !errors.Is(err, context.Canceled) {
			// The consumer either NAKs the delivery or enters reconciliation
			// before this point. Keep retrying without logging broker details.
			log.Print("snagline-edge: journal delivery retrying")
		}
	}
}

func waitEdgeRetry(ctx context.Context) bool {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// Errors leaving this function reach an operator log, so all three exits are
// curated strings like every other runEdge branch. net.Listen bind errors,
// http.Server accept errors, and Shutdown listener-close errors all carry a
// net.OpError whose Addr is the configured socket pathname, so none of them are
// returned verbatim.
func serveEdgeSocket(ctx context.Context, socket string, service edgeAPI) error {
	listener, err := runtimeops.ListenUnix(socket)
	if err != nil {
		return errors.New("edge local API socket unavailable")
	}
	server := &http.Server{Handler: newHandler(service), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("edge local API stopped serving")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return errors.New("edge local API shutdown incomplete")
		}
		return nil
	}
}

func envEdge(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
func envEdgeInt64(name string, fallback int64) int64 {
	value, err := strconv.ParseInt(envEdge(name, ""), 10, 64)
	if envEdge(name, "") == "" {
		return fallback
	}
	if err != nil {
		return 0
	}
	return value
}
func envEdgeDuration(name string, fallback time.Duration) time.Duration {
	value := envEdge(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return parsed
}
func edgeBlank(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}
