package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/avivsinai/snagline/internal/controlclient"
	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/securetransport"
	"github.com/avivsinai/snagline/internal/sspedge"
	"github.com/google/uuid"
)

type dispatcherRuntimeConfig struct {
	DescriptorPath, CaseID, CaseCommitment, Text, PublicSummary string
	Tenant, PrincipalID, AuthorKeyID                            string
	DBPath, DBKey, ControlURL, TLSCert, TLSKey, ControlCA       string
	EnvelopeTTL                                                 time.Duration
}

func parseDispatcherRuntimeConfig(args []string) (dispatcherRuntimeConfig, error) {
	flags := flag.NewFlagSet("snagline-dispatcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	descriptor := flags.String("key-descriptor", envDispatcher("SNAGLINE_DISPATCHER_KEY_DESCRIPTOR", ""), "absolute private key descriptor")
	caseID := flags.String("case-id", "", "case ID")
	commitment := flags.String("case-commitment", "", "exact committed case commitment")
	text := flags.String("text", "", "inert advice text")
	publicSummary := flags.String("public-summary", "", "explicit public advice summary")
	tenant := flags.String("tenant", envDispatcher("SNAGLINE_DISPATCHER_TENANT", ""), "SSP tenant")
	principal := flags.String("principal-id", envDispatcher("SNAGLINE_DISPATCHER_PRINCIPAL_ID", ""), "certificate-bound dispatcher principal")
	author := flags.String("author-key-id", envDispatcher("SNAGLINE_DISPATCHER_AUTHOR_KEY_ID", ""), "registered advice key ID")
	dbPath := flags.String("db", envDispatcher("SNAGLINE_DISPATCHER_DB", ""), "encrypted dispatcher SQLite path")
	dbKey := flags.String("db-key", envDispatcher("SNAGLINE_DISPATCHER_DB_KEY", ""), "32-byte encrypted dispatcher SQLite key")
	controlURL := flags.String("control-url", envDispatcher("SNAGLINE_DISPATCHER_CONTROL_URL", ""), "root HTTPS control endpoint")
	tlsCert := flags.String("tls-cert", envDispatcher("SNAGLINE_DISPATCHER_TLS_CERT", ""), "mTLS client certificate")
	tlsKey := flags.String("tls-key", envDispatcher("SNAGLINE_DISPATCHER_TLS_KEY", ""), "mTLS client key")
	controlCA := flags.String("control-ca", envDispatcher("SNAGLINE_DISPATCHER_CONTROL_CA", ""), "control root CA")
	ttl := flags.Duration("envelope-ttl", envDispatcherDuration("SNAGLINE_DISPATCHER_ENVELOPE_TTL", 0), "positive bounded advice TTL")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return dispatcherRuntimeConfig{}, errors.New("invalid dispatcher flags")
	}
	config := dispatcherRuntimeConfig{DescriptorPath: *descriptor, CaseID: *caseID, CaseCommitment: *commitment, Text: *text, PublicSummary: *publicSummary, Tenant: *tenant, PrincipalID: *principal, AuthorKeyID: *author, DBPath: *dbPath, DBKey: *dbKey, ControlURL: *controlURL, TLSCert: *tlsCert, TLSKey: *tlsKey, ControlCA: *controlCA, EnvelopeTTL: *ttl}
	return config, config.validate()
}

func (config dispatcherRuntimeConfig) validate() error {
	if dispatcherBlank(config.DescriptorPath, config.CaseID, config.CaseCommitment, config.Text, config.PublicSummary, config.Tenant, config.PrincipalID, config.AuthorKeyID, config.DBPath, config.DBKey, config.ControlURL, config.TLSCert, config.TLSKey, config.ControlCA) || !dispatcherCommitment(config.CaseCommitment) || config.EnvelopeTTL <= 0 || config.EnvelopeTTL > 24*time.Hour {
		return errors.New("missing or unbounded dispatcher configuration")
	}
	for _, path := range []string{config.DescriptorPath, config.DBPath, config.DBKey, config.TLSCert, config.TLSKey, config.ControlCA} {
		if !filepath.IsAbs(path) {
			return errors.New("dispatcher paths must be absolute")
		}
	}
	endpoint, err := url.Parse(config.ControlURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("control URL must be a root HTTPS URL without credentials")
	}
	return nil
}

// runDispatcher is one-shot. If an earlier invocation persisted exact advice
// bytes before a lost control response, it retries those bytes instead of
// creating a second final advice envelope.
func runDispatcher(ctx context.Context, config dispatcherRuntimeConfig, stdout io.Writer) int {
	descriptor, err := readKeyDescriptor(config.DescriptorPath)
	if err != nil {
		return writeResult(stdout, commandResult{OK: false, Code: "invalid_key_descriptor"})
	}
	finalizer, db, err := buildDispatcherFinalizer(ctx, config, descriptor)
	if err != nil {
		return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
	}
	defer db.Close()
	result, err := finalizer.FinalizeAdvice(ctx, edge.FinalizeAdviceRequest{CaseID: config.CaseID, CaseCommitment: config.CaseCommitment, Text: config.Text, PublicSummary: config.PublicSummary})
	if errors.Is(err, edge.ErrAlreadyPending) {
		result, err = finalizer.RetryAdvice(ctx, config.CaseID)
	}
	if err != nil || !result.AcceptedRemote {
		return writeResult(stdout, commandResult{OK: false, Code: "advice_not_accepted"})
	}
	return writeResult(stdout, commandResult{OK: true, Code: "accepted_remote", AdviceID: result.EnvelopeID, AuthorityRevision: result.Receipt.Revision})
}

func buildDispatcherFinalizer(ctx context.Context, config dispatcherRuntimeConfig, descriptor keyDescriptor) (*edge.Finalizer, *sspedge.DB, error) {
	key, err := identity.LoadEd25519SigningKey(descriptor.KeyPath)
	if err != nil {
		return nil, nil, errors.New("dispatcher signing key unavailable")
	}
	signer, err := edge.NewAdviceSigner(key)
	if err != nil {
		return nil, nil, errors.New("dispatcher signing key unavailable")
	}
	tlsConfig, err := securetransport.LoadClientTLS(config.TLSCert, config.TLSKey, config.ControlCA)
	if err != nil {
		return nil, nil, errors.New("control mTLS unavailable")
	}
	client, err := controlclient.New(controlclient.Config{Endpoint: config.ControlURL, TLS: tlsConfig, Workload: edge.WorkloadIdentity{PrincipalID: config.PrincipalID}})
	if err != nil {
		return nil, nil, errors.New("control client unavailable")
	}
	db, err := sspedge.Open(ctx, sspedge.OpenOptions{Path: config.DBPath, KeyFilePath: config.DBKey, Tenant: config.Tenant})
	if err != nil {
		return nil, nil, errors.New("encrypted dispatcher store unavailable")
	}
	closeDB := true
	defer func() {
		if closeDB {
			_ = db.Close()
		}
	}()
	reader := authoritativeCaseReader{client: client, caseID: config.CaseID, commitment: config.CaseCommitment}
	finalizer, err := edge.NewFinalizer(edge.FinalizerConfig{PrincipalID: config.PrincipalID, AuthorKeyID: config.AuthorKeyID, Signer: signer, Cases: reader, Spool: db, Gateway: client, EnvelopeTTL: config.EnvelopeTTL, NewID: func() (string, error) { return uuid.NewString(), nil }})
	if err != nil {
		return nil, nil, errors.New("dispatcher finalizer unavailable")
	}
	closeDB = false
	return finalizer, db, nil
}

type authoritativeCaseReader struct {
	client             *controlclient.Client
	caseID, commitment string
}

func (r authoritativeCaseReader) GetCase(ctx context.Context, caseID string) (edge.CaseRecord, bool, error) {
	if r.client == nil || caseID != r.caseID {
		return edge.CaseRecord{}, false, errors.New("dispatcher case query does not match one-shot request")
	}
	record, err := r.client.ResolveCase(ctx, caseID, r.commitment)
	if err != nil {
		return edge.CaseRecord{}, false, err
	}
	return edge.CaseRecord{EnvelopeID: record.EnvelopeID, CaseID: record.CaseID, Commitment: record.Commitment, Registry: edge.RegistryCoordinates{RoutingEpoch: record.RoutingEpoch, Revision: record.RegistryRevision, Hash: record.RegistryHash}, ExpiresAt: record.ExpiresAt, Committed: true}, true, nil
}

func envDispatcher(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
func envDispatcherDuration(name string, fallback time.Duration) time.Duration {
	value := envDispatcher(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return parsed
}
func dispatcherBlank(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}
func dispatcherCommitment(value string) bool {
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
