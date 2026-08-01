// snagline-delivery publishes leased PostgreSQL authority-outbox rows to the
// bounded JetStream delivery accelerator. PostgreSQL remains authoritative.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/avivsinai/snagline/internal/authority/postgres"
	"github.com/avivsinai/snagline/internal/delivery/outbox"
	"github.com/avivsinai/snagline/internal/deliverystream"
	"github.com/avivsinai/snagline/internal/postgresconfig"
	"github.com/avivsinai/snagline/internal/runtimeops"
	"github.com/avivsinai/snagline/internal/securefile"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

const (
	defaultBatchSize    = 100
	defaultLease        = time.Minute
	defaultRetryDelay   = 30 * time.Second
	defaultPollInterval = time.Second
	connectionTimeout   = 10 * time.Second
	maxCredentialBytes  = 1 << 20
	maxCAPEMBytes       = 1 << 20
)

type runtimeConfig struct {
	PostgresDSN, AuthorityID, WorkerID, OpsSocket string
	NATSURL, NATSCredentialsFile, NATSCAFile      string
	BatchSize                                     int
	Lease, RetryDelay, PollInterval               time.Duration
	postgresPoolConfig                            *pgxpool.Config
}

func main() {
	config, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "snagline-delivery: invalid configuration")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, config); err != nil {
		fmt.Fprintln(os.Stderr, "snagline-delivery: runtime stopped")
		os.Exit(1)
	}
}

func parseConfig(args []string) (runtimeConfig, error) {
	flags := flag.NewFlagSet("snagline-delivery", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dsn := flags.String("postgres-dsn", env("SNAGLINE_DELIVERY_POSTGRES_DSN", ""), "PostgreSQL DSN")
	authorityID := flags.String("authority-id", env("SNAGLINE_DELIVERY_AUTHORITY_ID", ""), "immutable authority ID")
	workerID := flags.String("worker-id", env("SNAGLINE_DELIVERY_WORKER_ID", ""), "unique worker ID")
	natsURL := flags.String("nats-url", env("SNAGLINE_DELIVERY_NATS_URL", ""), "tls:// NATS URL")
	credentialsFile := flags.String("nats-credentials-file", env("SNAGLINE_DELIVERY_NATS_CREDENTIALS_FILE", ""), "NATS credentials file")
	caFile := flags.String("nats-ca-file", env("SNAGLINE_DELIVERY_NATS_CA_FILE", ""), "NATS CA file")
	batchSize := flags.Int("batch-size", envInt("SNAGLINE_DELIVERY_BATCH_SIZE", defaultBatchSize), "outbox claim batch size")
	lease := flags.Duration("lease", envDuration("SNAGLINE_DELIVERY_LEASE", defaultLease), "outbox lease duration")
	retryDelay := flags.Duration("retry-delay", envDuration("SNAGLINE_DELIVERY_RETRY_DELAY", defaultRetryDelay), "outbox retry delay")
	pollInterval := flags.Duration("poll-interval", envDuration("SNAGLINE_DELIVERY_POLL_INTERVAL", defaultPollInterval), "delay between bounded runs")
	opsSocket := flags.String("ops-socket", env("SNAGLINE_DELIVERY_OPS_SOCKET", ""), "absolute private Unix operations socket")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return runtimeConfig{}, errors.New("invalid flags")
	}
	result := runtimeConfig{PostgresDSN: *dsn, AuthorityID: *authorityID, WorkerID: *workerID, OpsSocket: *opsSocket, NATSURL: *natsURL, NATSCredentialsFile: *credentialsFile, NATSCAFile: *caFile, BatchSize: *batchSize, Lease: *lease, RetryDelay: *retryDelay, PollInterval: *pollInterval}
	if err := result.validate(); err != nil {
		return runtimeConfig{}, err
	}
	return result, nil
}

func (config *runtimeConfig) validate() error {
	if anyBlank(config.PostgresDSN, config.AuthorityID, config.WorkerID, config.OpsSocket, config.NATSURL, config.NATSCredentialsFile, config.NATSCAFile) || !filepath.IsAbs(config.OpsSocket) || config.OpsSocket != filepath.Clean(config.OpsSocket) {
		return errors.New("missing required configuration")
	}
	endpoint, err := url.Parse(config.NATSURL)
	if err != nil || endpoint.Scheme != "tls" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("NATS URL must be a tls URL without embedded credentials")
	}
	if !filepath.IsAbs(config.NATSCredentialsFile) || !filepath.IsAbs(config.NATSCAFile) {
		return errors.New("NATS credential and CA files must be absolute paths")
	}
	poolConfig, err := postgresconfig.ParsePoolConfig(config.PostgresDSN)
	if err != nil {
		return errors.New("PostgreSQL DSN must use authenticated TLS")
	}
	config.postgresPoolConfig = poolConfig
	if config.BatchSize <= 0 || config.BatchSize > outbox.MaxBatchSize || config.Lease <= 0 || config.Lease > outbox.MaxLease || config.RetryDelay <= 0 || config.RetryDelay > outbox.MaxRetryDelay || config.PollInterval <= 0 || config.PollInterval > time.Hour {
		return errors.New("delivery timing or batch configuration is out of bounds")
	}
	return nil
}

func run(ctx context.Context, config runtimeConfig) error {
	if config.postgresPoolConfig == nil {
		return errors.New("PostgreSQL authority is unavailable")
	}
	pool, err := pgxpool.NewWithConfig(ctx, config.postgresPoolConfig.Copy())
	if err != nil {
		return errors.New("PostgreSQL authority is unavailable")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("PostgreSQL authority is unavailable")
	}
	source, err := postgres.New(pool, config.AuthorityID)
	if err != nil {
		return errors.New("PostgreSQL authority is unavailable")
	}
	nc, clearCredentials, err := connectNATS(config)
	if err != nil {
		return errors.New("JetStream delivery is unavailable")
	}
	defer clearCredentials()
	defer nc.Drain()
	js, err := jetstream.New(nc)
	if err != nil {
		return errors.New("JetStream delivery is unavailable")
	}
	if err := deliverystream.EnsureStream(ctx, js); err != nil {
		return errors.New("JetStream delivery stream is unavailable")
	}
	worker := outbox.Worker{Source: source, Publisher: outbox.JetStreamPublisher{JetStream: js}, WorkerID: config.WorkerID, Limit: config.BatchSize, Lease: config.Lease, RetryDelay: config.RetryDelay}
	tracker := runtimeops.NewTracker()
	ops, err := runtimeops.Start(ctx, config.OpsSocket, runtimeops.HandlerConfig{Role: "delivery", Tracker: tracker, Ready: func(ctx context.Context) error {
		return deliveryReady(ctx, pool, nc, js, tracker, deliveryFreshnessWindow(config))
	}})
	if err != nil {
		return errors.New("private operations surface is unavailable")
	}
	defer ops.Close()
	tracker.MarkInitialized()
	return runLoop(ctx, config.PollInterval, func(ctx context.Context) error {
		err := runOnceWithTimeout(ctx, config.Lease, worker.RunOnce)
		if err != nil {
			tracker.RecordError()
			return err
		}
		tracker.RecordSuccess(runtimeops.Measurements{})
		return nil
	})
}

func deliveryReady(ctx context.Context, pool *pgxpool.Pool, nc *nats.Conn, js jetstream.JetStream, tracker *runtimeops.Tracker, freshness time.Duration) error {
	if pool == nil || pool.Ping(ctx) != nil || nc == nil || nc.Status() != nats.CONNECTED || js == nil {
		return errors.New("delivery dependency unavailable")
	}
	if _, err := js.Stream(ctx, deliverystream.StreamName); err != nil {
		return errors.New("delivery stream unavailable")
	}
	if !runtimeops.HasFreshSuccess(tracker.Snapshot(), time.Now(), freshness) {
		return errors.New("delivery worker unavailable")
	}
	return nil
}

func deliveryFreshnessWindow(config runtimeConfig) time.Duration {
	return config.Lease + 2*config.PollInterval
}

func connectNATS(config runtimeConfig) (*nats.Conn, func(), error) {
	auth, clearCredentials, err := loadNATSCredentials(config.NATSCredentialsFile)
	if err != nil {
		return nil, func() {}, err
	}
	caPEM, err := securefile.ReadRegularBounded(config.NATSCAFile, maxCAPEMBytes)
	if err != nil {
		clearCredentials()
		return nil, func() {}, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		clearCredentials()
		return nil, func() {}, errors.New("invalid NATS CA")
	}
	nc, err := nats.Connect(config.NATSURL,
		auth,
		nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}),
		nats.Timeout(connectionTimeout),
	)
	if err != nil {
		clearCredentials()
		return nil, func() {}, err
	}
	return nc, clearCredentials, nil
}

func loadNATSCredentials(path string) (nats.Option, func(), error) {
	raw, err := securefile.ReadPrivateBounded(path, maxCredentialBytes)
	if err != nil {
		return nil, func() {}, err
	}
	defer clear(raw)
	userJWT, err := nkeys.ParseDecoratedJWT(raw)
	if err != nil {
		return nil, func() {}, err
	}
	keyPair, err := nkeys.ParseDecoratedUserNKey(raw)
	if err != nil {
		return nil, func() {}, err
	}
	clearCredentials := func() { keyPair.Wipe() }
	option := nats.UserJWT(
		func() (string, error) { return userJWT, nil },
		func(nonce []byte) ([]byte, error) { return keyPair.Sign(nonce) },
	)
	return option, clearCredentials, nil
}

func runLoop(ctx context.Context, pollInterval time.Duration, runOnce func(context.Context) error) error {
	for {
		if err := runOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Worker errors are either released delivery attempts or unavailable
			// dependencies. The next bounded poll is the retry path; do not log
			// the wrapped error because it can contain credentialed endpoints.
			log.Print("snagline-delivery: delivery attempt failed; retrying")
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func runOnceWithTimeout(parent context.Context, timeout time.Duration, runOnce func(context.Context) error) error {
	if timeout <= 0 || runOnce == nil {
		return errors.New("invalid bounded work cycle")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return runOnce(ctx)
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value := env(name, "")
	if value == "" {
		return fallback
	}
	result, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return result
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := env(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return parsed
}

func anyBlank(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}
