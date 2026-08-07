package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/avivsinai/snagline/internal/controlclient"
	"github.com/avivsinai/snagline/internal/dispatcherruntime"
	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/securetransport"
	"github.com/avivsinai/snagline/internal/sspedge"
	"github.com/google/uuid"
)

const (
	maxDispatcherCommandRequestBytes = 64 << 10
	dispatcherTurnRetention          = 7 * 24 * time.Hour
	dispatcherTurnClaimTTL           = 2 * time.Minute
	dispatcherTurnCapacity           = 8192
)

type dispatcherRuntimeConfig struct {
	DescriptorPath, EventID, CaseID, CaseCommitment, Text, PublicSummary string
	Tenant, PrincipalID, AuthorKeyID                                     string
	DBPath, DBKey, ControlURL, TLSCert, TLSKey, ControlCA                string
	EnvelopeTTL                                                          time.Duration
}

func parseDispatcherRuntimeConfig(args []string, stdin io.Reader) (dispatcherRuntimeConfig, error) {
	flags := flag.NewFlagSet("snagline-dispatcher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	descriptor := flags.String("key-descriptor", envDispatcher("SNAGLINE_DISPATCHER_KEY_DESCRIPTOR", ""), "absolute private key descriptor")
	requestStdin := flags.Bool("request-stdin", false, "read the complete bounded request as JSON from stdin")
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
	request := dispatcherruntime.CommandRequest{Submission: dispatcherruntime.Submission{CaseID: *caseID, CaseCommitment: *commitment, Text: *text, PublicSummary: *publicSummary}}
	if *requestStdin {
		if *caseID != "" || *commitment != "" || *text != "" || *publicSummary != "" || stdin == nil {
			return dispatcherRuntimeConfig{}, errors.New("stdin dispatcher request cannot be combined with request flags")
		}
		raw, err := io.ReadAll(io.LimitReader(stdin, maxDispatcherCommandRequestBytes+1))
		if err != nil || len(raw) == 0 || len(raw) > maxDispatcherCommandRequestBytes || !utf8.Valid(raw) {
			return dispatcherRuntimeConfig{}, errors.New("invalid stdin dispatcher request")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return dispatcherRuntimeConfig{}, errors.New("invalid stdin dispatcher request")
		}
	} else {
		request.EventID = legacyDispatcherEventID(*caseID)
	}
	config := dispatcherRuntimeConfig{DescriptorPath: *descriptor, EventID: request.EventID, CaseID: request.Submission.CaseID, CaseCommitment: request.Submission.CaseCommitment, Text: request.Submission.Text, PublicSummary: request.Submission.PublicSummary, Tenant: *tenant, PrincipalID: *principal, AuthorKeyID: *author, DBPath: *dbPath, DBKey: *dbKey, ControlURL: *controlURL, TLSCert: *tlsCert, TLSKey: *tlsKey, ControlCA: *controlCA, EnvelopeTTL: *ttl}
	return config, config.validate()
}

func (config dispatcherRuntimeConfig) validate() error {
	request := dispatcherruntime.CommandRequest{EventID: config.EventID, Submission: dispatcherruntime.Submission{CaseID: config.CaseID, CaseCommitment: config.CaseCommitment, Text: config.Text, PublicSummary: config.PublicSummary}}
	if dispatcherBlank(config.DescriptorPath, config.Tenant, config.PrincipalID, config.AuthorKeyID, config.DBPath, config.DBKey, config.ControlURL, config.TLSCert, config.TLSKey, config.ControlCA) || dispatcherruntime.ValidateCommandRequest(request) != nil || config.EnvelopeTTL <= 0 || config.EnvelopeTTL > 24*time.Hour {
		return errors.New("missing or unbounded dispatcher configuration")
	}
	for _, path := range []string{config.DescriptorPath, config.DBPath, config.DBKey, config.TLSCert, config.TLSKey, config.ControlCA} {
		if !filepath.IsAbs(path) {
			return errors.New("dispatcher paths must be absolute")
		}
	}
	endpoint, err := url.Parse(config.ControlURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Opaque != "" || endpoint.Host == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawPath != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
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
	return runDispatcherTurn(ctx, config, finalizer, db, stdout, time.Now().UTC())
}

type dispatcherAdviceFinalizer interface {
	FinalizeAdvice(context.Context, edge.FinalizeAdviceRequest) (edge.AdviceSubmission, error)
	RetryAdvice(context.Context, string) (edge.AdviceSubmission, error)
}

type dispatcherTurnStore interface {
	BindDispatcherTurn(context.Context, string, []byte, time.Time, time.Duration, time.Duration, int) (sspedge.DispatcherTurnBinding, error)
	ReleaseDispatcherTurnClaim(context.Context, string, []byte, string) error
	AbandonDispatcherTurn(context.Context, string, []byte, string) error
	CompleteDispatcherTurn(context.Context, string, []byte, []byte, time.Time, string) error
}

func runDispatcherTurn(ctx context.Context, config dispatcherRuntimeConfig, finalizer dispatcherAdviceFinalizer, store dispatcherTurnStore, stdout io.Writer, now time.Time) int {
	requestBytes, err := json.Marshal(dispatcherruntime.CommandRequest{EventID: config.EventID, Submission: dispatcherruntime.Submission{CaseID: config.CaseID, CaseCommitment: config.CaseCommitment, Text: config.Text, PublicSummary: config.PublicSummary}})
	if err != nil || len(requestBytes) > maxDispatcherCommandRequestBytes {
		return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
	}
	binding, err := store.BindDispatcherTurn(ctx, config.EventID, requestBytes, now, dispatcherTurnRetention, dispatcherTurnClaimTTL, dispatcherTurnCapacity)
	if errors.Is(err, sspedge.ErrDispatcherTurnMismatch) {
		return writeResult(stdout, commandResult{OK: false, Code: "turn_request_mismatch"})
	}
	if errors.Is(err, sspedge.ErrDispatcherTurnCapacity) {
		return writeResult(stdout, commandResult{OK: false, Code: "replay_guard_full"})
	}
	if err != nil {
		return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
	}
	if binding.Completed {
		if !validStoredCommandResult(binding.Result) {
			return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
		}
		return writeCanonicalResult(stdout, binding.Result)
	}
	if binding.InFlight {
		return writeResult(stdout, commandResult{OK: false, Code: "turn_in_flight"})
	}
	if binding.ClaimToken == "" {
		return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
	}
	result, err := finalizer.FinalizeAdvice(ctx, edge.FinalizeAdviceRequest{CaseID: config.CaseID, CaseCommitment: config.CaseCommitment, Text: config.Text, PublicSummary: config.PublicSummary})
	if errors.Is(err, edge.ErrAlreadyPending) {
		result, err = finalizer.RetryAdvice(ctx, config.CaseID)
	}
	if errors.Is(err, edge.ErrPendingAdviceConflict) {
		if store.AbandonDispatcherTurn(ctx, config.EventID, requestBytes, binding.ClaimToken) != nil {
			return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
		}
		return writeResult(stdout, commandResult{OK: false, Code: "pending_advice_conflict"})
	}
	if errors.Is(err, edge.ErrNotFound) || errors.Is(err, edge.ErrNotCommitted) {
		if store.AbandonDispatcherTurn(ctx, config.EventID, requestBytes, binding.ClaimToken) != nil {
			return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
		}
		return writeResult(stdout, commandResult{OK: false, Code: "advice_not_accepted"})
	}
	if err != nil {
		if store.ReleaseDispatcherTurnClaim(ctx, config.EventID, requestBytes, binding.ClaimToken) != nil {
			return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
		}
		return writeResult(stdout, commandResult{OK: false, Code: "advice_not_accepted"})
	}
	if !result.AcceptedRemote || result.EnvelopeID == "" || result.Receipt.Revision <= 0 {
		return writeResult(stdout, commandResult{OK: false, Code: "advice_not_accepted"})
	}
	command := commandResult{OK: true, Code: "accepted_remote", AdviceID: result.EnvelopeID, AuthorityRevision: result.Receipt.Revision}
	resultBytes, err := json.Marshal(command)
	if err != nil || store.CompleteDispatcherTurn(ctx, config.EventID, requestBytes, resultBytes, time.Now().UTC(), binding.ClaimToken) != nil {
		return writeResult(stdout, commandResult{OK: false, Code: "runtime_unavailable"})
	}
	return writeCanonicalResult(stdout, resultBytes)
}

func validStoredCommandResult(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result commandResult
	return decoder.Decode(&result) == nil && decoder.Decode(&struct{}{}) == io.EOF && result.OK && result.Code == "accepted_remote" && result.AdviceID != "" && result.AuthorityRevision > 0
}

func writeCanonicalResult(stdout io.Writer, raw []byte) int {
	if _, err := stdout.Write(append(append([]byte(nil), raw...), '\n')); err != nil {
		return 1
	}
	return 0
}

func legacyDispatcherEventID(caseID string) string {
	digest := sha256.Sum256(append([]byte("snagline/dispatcher/legacy-case/v1\x00"), []byte(caseID)...))
	return hex.EncodeToString(digest[:])
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
