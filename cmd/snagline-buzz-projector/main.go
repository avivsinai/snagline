// snagline-buzz-projector projects committed SSP facts from PostgreSQL to a
// stock Buzz relay. It is deliberately outbound-only: Buzz never supplies
// authority facts, checkpoints, routing, or reconciliation decisions.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/avivsinai/snagline/internal/authority/postgres"
	projectorbuzz "github.com/avivsinai/snagline/internal/collab/buzz"
	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/postgresconfig"
	"github.com/avivsinai/snagline/internal/registry"
	"github.com/avivsinai/snagline/internal/runtimeops"
	"github.com/avivsinai/snagline/internal/securefile"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxConfigBytes              = 64 << 10
	maxProjectorPollInterval    = time.Hour
	maxProjectorRequestTimeout  = time.Minute
	maxProjectorBackoffInterval = time.Hour
)

type projectorConfig struct {
	Tenant              string            `json:"tenant"`
	PostgresDSN         string            `json:"postgres_dsn"`
	AuthorityID         string            `json:"authority_id"`
	ProjectionStatePath string            `json:"projection_state_path"`
	ProjectionKeyFile   string            `json:"projection_key_file"`
	RelayURL            string            `json:"relay_url"`
	PrivateKeyFile      string            `json:"buzz_private_key_file"`
	NIPOAAuthTagFile    string            `json:"buzz_nip_oa_auth_tag_file"`
	TLSCAFile           string            `json:"buzz_tls_ca_file"`
	RegistryRootKeyID   string            `json:"registry_root_key_id"`
	RegistryRootKeyFile string            `json:"registry_root_public_key_file"`
	DomainChannels      map[string]string `json:"domain_channels"`
	PollInterval        string            `json:"poll_interval"`
	BatchSize           int               `json:"batch_size"`
	RequestTimeout      string            `json:"request_timeout"`
	BackoffInitial      string            `json:"backoff_initial"`
	BackoffMax          string            `json:"backoff_max"`
	OpsSocket           string            `json:"ops_socket"`

	pollInterval       time.Duration
	requestTimeout     time.Duration
	backoffInitial     time.Duration
	backoffMax         time.Duration
	postgresPoolConfig *pgxpool.Config
}

func main() {
	configPath := flag.String("config", "", "absolute projector configuration path")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(*configPath) {
		log.Print("snagline-buzz-projector: invalid arguments")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *configPath); err != nil {
		// Errors can originate from a credentialed DSN or signer. Keep output
		// deliberately non-diagnostic so secrets never cross the log boundary.
		log.Print("snagline-buzz-projector: runtime stopped")
		os.Exit(1)
	}
}

func run(parent context.Context, configPath string) error {
	settings, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	return runConfigured(parent, settings)
}

func runConfigured(parent context.Context, settings projectorConfig) error {
	privateKey, err := securefile.ReadPrivateExact(settings.PrivateKeyFile, 32)
	if err != nil {
		return errors.New("buzz projector signer is unavailable")
	}
	defer clearBytes(privateKey)
	signer, err := projectorbuzz.NewPrivateKeySignerBytes(privateKey)
	if err != nil {
		return errors.New("buzz projector signer is unavailable")
	}
	registryTrust, err := loadRegistryTrust(settings)
	if err != nil {
		return errors.New("buzz projector verifier is unavailable")
	}
	projectionKey, err := securefile.ReadPrivateExact(settings.ProjectionKeyFile, 32)
	if err != nil {
		return errors.New("buzz projector projection store key is unavailable")
	}
	defer clearBytes(projectionKey)
	store, err := projectorbuzz.OpenProjectionStore(settings.ProjectionStatePath, projectionKey)
	if err != nil {
		return errors.New("buzz projector projection store is unavailable")
	}
	defer store.Close()

	if settings.postgresPoolConfig == nil {
		return errors.New("buzz projector authority is unavailable")
	}
	pool, err := pgxpool.NewWithConfig(parent, settings.postgresPoolConfig.Copy())
	if err != nil {
		return errors.New("buzz projector authority is unavailable")
	}
	defer pool.Close()
	if err := pool.Ping(parent); err != nil {
		return errors.New("buzz projector authority is unavailable")
	}
	authorityStore, err := postgres.New(pool, settings.AuthorityID)
	if err != nil {
		return errors.New("buzz projector authority is unavailable")
	}
	relay, err := projectorbuzz.NewStockRelayClient(projectorbuzz.StockRelayConfig{
		RelayURL:         settings.RelayURL,
		Signer:           signer,
		NIPOAAuthTagFile: settings.NIPOAAuthTagFile,
		TLSCAFile:        settings.TLSCAFile,
	})
	if err != nil {
		return errors.New("buzz projector relay is unavailable")
	}
	channels, err := newDomainChannelMap(settings.DomainChannels)
	if err != nil {
		return err
	}
	verifier, err := projectorbuzz.NewAuthorityVerifier(projectorbuzz.AuthorityVerifierConfig{
		TenantID: settings.Tenant, Authority: authorityStore, RegistryTrust: registryTrust,
	})
	if err != nil {
		return errors.New("buzz projector verifier is unavailable")
	}
	projector, err := projectorbuzz.NewProjector(projectorbuzz.ProjectorConfig{
		Source:   projectorbuzz.AuthoritySource{Store: authorityStore, TenantID: settings.Tenant},
		Verifier: verifier, Channels: channels, Store: store,
		Signer: signer, Relay: relay,
	})
	if err != nil {
		return errors.New("buzz projector is unavailable")
	}
	tracker := runtimeops.NewTracker()
	ops, err := runtimeops.Start(parent, settings.OpsSocket, runtimeops.HandlerConfig{Role: "projector", Tracker: tracker, Ready: func(ctx context.Context) error {
		return projectorReady(ctx, pool, store, tracker, projectorFreshnessWindow(settings))
	}})
	if err != nil {
		return errors.New("private operations surface is unavailable")
	}
	defer ops.Close()
	tracker.MarkInitialized()
	return projectLoop(parent, projector, settings, tracker)
}

func projectLoop(parent context.Context, projector *projectorbuzz.Projector, settings projectorConfig, tracker *runtimeops.Tracker) error {
	backoff := settings.backoffInitial
	for {
		request, cancel := context.WithTimeout(parent, settings.requestTimeout)
		result, err := projector.Project(request, settings.BatchSize)
		cancel()
		if err != nil {
			tracker.RecordError()
		} else {
			tracker.RecordSuccess(runtimeops.Measurements{Lag: float64(result.Lag.Pending), LagKnown: true, Poisoned: float64(result.Lag.Poisoned), PoisonedKnown: true})
		}
		if parent.Err() != nil {
			return nil
		}
		wait := settings.pollInterval
		if err != nil {
			wait = backoff
			if backoff < settings.backoffMax/2 {
				backoff *= 2
			} else {
				backoff = settings.backoffMax
			}
		} else {
			backoff = settings.backoffInitial
		}
		if err := waitFor(parent, wait); err != nil {
			return nil
		}
	}
}

func projectorReady(ctx context.Context, pool *pgxpool.Pool, store *projectorbuzz.ProjectionStore, tracker *runtimeops.Tracker, freshness time.Duration) error {
	if pool == nil || store == nil || pool.Ping(ctx) != nil {
		return errors.New("buzz projector authority unavailable")
	}
	if _, err := store.Load(ctx); err != nil {
		return errors.New("buzz projector state unavailable")
	}
	if !runtimeops.HasFreshSuccess(tracker.Snapshot(), time.Now(), freshness) {
		return errors.New("buzz projection unavailable")
	}
	return nil
}

func projectorFreshnessWindow(settings projectorConfig) time.Duration {
	return settings.requestTimeout + 2*settings.pollInterval
}

func waitFor(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func loadConfig(path string) (projectorConfig, error) {
	if !filepath.IsAbs(path) {
		return projectorConfig{}, errors.New("buzz projector config must be absolute")
	}
	// The config carries the PostgreSQL DSN and projection topology. Read it
	// through the same descriptor-validated private-file boundary as keys.
	raw, err := securefile.ReadPrivateBounded(path, maxConfigBytes)
	if err != nil || len(raw) == 0 {
		return projectorConfig{}, errors.New("buzz projector config is invalid")
	}
	return parseConfig(raw)
}

func parseConfig(raw []byte) (projectorConfig, error) {
	var settings projectorConfig
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&settings); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return projectorConfig{}, errors.New("buzz projector config is invalid")
	}
	if err := settings.validate(); err != nil {
		return projectorConfig{}, err
	}
	return settings, nil
}

func (settings *projectorConfig) validate() error {
	requireText := func(value string) bool { return value != "" && value == strings.TrimSpace(value) }
	if !requireText(settings.Tenant) || !requireText(settings.PostgresDSN) || !requireText(settings.AuthorityID) ||
		!filepath.IsAbs(settings.ProjectionStatePath) || !filepath.IsAbs(settings.ProjectionKeyFile) ||
		!filepath.IsAbs(settings.PrivateKeyFile) || !filepath.IsAbs(settings.NIPOAAuthTagFile) ||
		(settings.TLSCAFile != "" && !filepath.IsAbs(settings.TLSCAFile)) ||
		!requireText(settings.RegistryRootKeyID) || !filepath.IsAbs(settings.RegistryRootKeyFile) || !filepath.IsAbs(settings.OpsSocket) || settings.OpsSocket != filepath.Clean(settings.OpsSocket) || len(settings.DomainChannels) == 0 ||
		settings.BatchSize < 1 || settings.BatchSize > 1000 {
		return errors.New("buzz projector config is invalid")
	}
	poolConfig, err := postgresconfig.ParsePoolConfig(settings.PostgresDSN)
	if err != nil {
		return errors.New("buzz projector config is invalid")
	}
	settings.postgresPoolConfig = poolConfig
	relayURL, err := url.Parse(settings.RelayURL)
	if err != nil || relayURL.Scheme != "https" || relayURL.Host == "" || relayURL.User != nil ||
		relayURL.RawQuery != "" || relayURL.Fragment != "" || (relayURL.Path != "" && relayURL.Path != "/") ||
		strings.TrimSpace(settings.RelayURL) != settings.RelayURL {
		return errors.New("buzz projector relay must use HTTPS")
	}
	if _, err := newDomainChannelMap(settings.DomainChannels); err != nil {
		return errors.New("buzz projector config is invalid")
	}
	if settings.pollInterval, err = time.ParseDuration(settings.PollInterval); err != nil || settings.pollInterval <= 0 || settings.pollInterval > maxProjectorPollInterval {
		return errors.New("buzz projector config is invalid")
	}
	if settings.requestTimeout, err = time.ParseDuration(settings.RequestTimeout); err != nil || settings.requestTimeout <= 0 || settings.requestTimeout > maxProjectorRequestTimeout {
		return errors.New("buzz projector config is invalid")
	}
	if settings.backoffInitial, err = time.ParseDuration(settings.BackoffInitial); err != nil || settings.backoffInitial <= 0 || settings.backoffInitial > maxProjectorBackoffInterval {
		return errors.New("buzz projector config is invalid")
	}
	if settings.backoffMax, err = time.ParseDuration(settings.BackoffMax); err != nil || settings.backoffMax < settings.backoffInitial || settings.backoffMax > maxProjectorBackoffInterval {
		return errors.New("buzz projector config is invalid")
	}
	return nil
}

type domainChannelMap map[string]string

func newDomainChannelMap(raw map[string]string) (domainChannelMap, error) {
	if len(raw) == 0 {
		return nil, errors.New("buzz projector domain map is required")
	}
	mapping := make(domainChannelMap, len(raw))
	channels := make(map[string]struct{}, len(raw))
	for domain, channel := range raw {
		if domain == "" || domain != strings.TrimSpace(domain) || channel == "" || channel != strings.TrimSpace(channel) {
			return nil, errors.New("buzz projector domain map is invalid")
		}
		parsed, err := uuid.Parse(channel)
		if err != nil || parsed.String() != channel {
			return nil, errors.New("buzz projector channel must be a canonical UUID")
		}
		if _, exists := channels[channel]; exists {
			return nil, errors.New("buzz projector channel must map to exactly one domain")
		}
		channels[channel] = struct{}{}
		mapping[domain] = channel
	}
	return mapping, nil
}

func (m domainChannelMap) ChannelForDomain(_ context.Context, domain string) (string, error) {
	channel, ok := m[domain]
	if !ok {
		return "", fmt.Errorf("buzz projector has no configured channel for domain")
	}
	return channel, nil
}

func loadRegistryTrust(settings projectorConfig) (registry.Trust, error) {
	root, err := identity.LoadEd25519VerifyingKey(settings.RegistryRootKeyFile)
	if err != nil {
		return registry.Trust{}, err
	}
	public, err := root.PublicKey()
	if err != nil {
		return registry.Trust{}, err
	}
	return registry.NewTrust(settings.RegistryRootKeyID, public)
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
