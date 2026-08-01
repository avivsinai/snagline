// snagline-control serves the production SSP control surface over mutually
// authenticated TLS. PostgreSQL commits are authority; this process does not
// treat any transport acknowledgement as an admission result.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/avivsinai/snagline/internal/authority/postgres"
	"github.com/avivsinai/snagline/internal/controlapi"
	"github.com/avivsinai/snagline/internal/controlhttp"
	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/postgresconfig"
	"github.com/avivsinai/snagline/internal/registry"
	"github.com/avivsinai/snagline/internal/runtimeops"
	"github.com/avivsinai/snagline/internal/securefile"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxTLSPEMBytes int64 = 1 << 20

type runtimeConfig struct {
	Environment, Listen, OpsSocket, PostgresDSN, Tenant, AuthorityID string
	RegistryRootKey, RegistryRootKeyID, RegistryPublisherPrincipal   string
	TLSCert, TLSKey, ClientCA                                        string
	ClientMappings                                                   map[string]controlapi.WorkloadIdentity
	postgresPoolConfig                                               *pgxpool.Config
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		config, err := parseMigrationConfig(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "snagline-control migrate: invalid configuration")
			os.Exit(2)
		}
		if err := runMigration(config); err != nil {
			fmt.Fprintln(os.Stderr, "snagline-control migrate: failed")
			os.Exit(1)
		}
		return
	}
	config, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "snagline-control: invalid configuration")
		os.Exit(2)
	}
	if err := serve(config); err != nil {
		fmt.Fprintln(os.Stderr, "snagline-control: stopped")
		os.Exit(1)
	}
}

// migrationConfig is intentionally separate from runtimeConfig. Its DSN must
// identify an owner-level migrator principal; normal control credentials must
// never acquire DDL or role-administration capability.
type migrationConfig struct {
	MigratorPostgresDSN string
	Roles               postgres.RoleConfig
	postgresPoolConfig  *pgxpool.Config
}

func parseMigrationConfig(args []string) (migrationConfig, error) {
	flags := flag.NewFlagSet("snagline-control migrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dsn := flags.String("migrator-postgres-dsn", env("SNAGLINE_MIGRATOR_POSTGRES_DSN", ""), "owner-level PostgreSQL migrator DSN")
	defaults := postgres.DefaultRoleConfig()
	controlRole := flags.String("control-role", env("SNAGLINE_AUTHORITY_CONTROL_ROLE", defaults.ControlRole), "NOLOGIN control authority role")
	deliveryRole := flags.String("delivery-role", env("SNAGLINE_AUTHORITY_DELIVERY_ROLE", defaults.DeliveryRole), "NOLOGIN delivery authority role")
	projectorRole := flags.String("projector-role", env("SNAGLINE_AUTHORITY_PROJECTOR_ROLE", defaults.ProjectorRole), "NOLOGIN projector authority role")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(*dsn) == "" {
		return migrationConfig{}, errors.New("invalid migration flags")
	}
	poolConfig, err := postgresconfig.ParsePoolConfig(*dsn)
	if err != nil {
		return migrationConfig{}, errors.New("invalid migration flags")
	}
	return migrationConfig{
		MigratorPostgresDSN: *dsn,
		Roles: postgres.RoleConfig{
			ControlRole: *controlRole, DeliveryRole: *deliveryRole, ProjectorRole: *projectorRole,
		},
		postgresPoolConfig: poolConfig,
	}, nil
}

func runMigration(config migrationConfig) error {
	if config.postgresPoolConfig == nil {
		return errors.New("PostgreSQL migrator is unavailable")
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config.postgresPoolConfig.Copy())
	if err != nil {
		return errors.New("PostgreSQL migrator is unavailable")
	}
	defer pool.Close()
	if err := pool.Ping(context.Background()); err != nil {
		return errors.New("PostgreSQL migrator is unavailable")
	}
	if err := postgres.Migrate(context.Background(), pool); err != nil {
		return errors.New("authority schema migration failed")
	}
	if err := postgres.ProvisionRoles(context.Background(), pool, config.Roles); err != nil {
		return errors.New("authority role provisioning failed")
	}
	return nil
}

func parseConfig(args []string) (runtimeConfig, error) {
	flags := flag.NewFlagSet("snagline-control", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	environment := flags.String("environment", env("SNAGLINE_CONTROL_ENVIRONMENT", "production"), "deployment environment")
	listen := flags.String("listen", env("SNAGLINE_CONTROL_LISTEN", ":8443"), "HTTPS listen address")
	opsSocket := flags.String("ops-socket", env("SNAGLINE_CONTROL_OPS_SOCKET", ""), "absolute private Unix operations socket")
	dsn := flags.String("postgres-dsn", env("SNAGLINE_CONTROL_POSTGRES_DSN", ""), "PostgreSQL DSN")
	tenant := flags.String("tenant", env("SNAGLINE_CONTROL_TENANT", ""), "SSP tenant")
	authorityID := flags.String("authority-id", env("SNAGLINE_CONTROL_AUTHORITY_ID", ""), "immutable authority ID")
	rootKey := flags.String("registry-root-key", env("SNAGLINE_CONTROL_REGISTRY_ROOT_KEY", ""), "root Ed25519 public PEM")
	rootKeyID := flags.String("registry-root-key-id", env("SNAGLINE_CONTROL_REGISTRY_ROOT_KEY_ID", ""), "registry root SSP key ID")
	publisher := flags.String("registry-publisher-principal", env("SNAGLINE_CONTROL_REGISTRY_PUBLISHER_PRINCIPAL", ""), "registry publisher principal")
	tlsCert := flags.String("tls-cert", env("SNAGLINE_CONTROL_TLS_CERT", ""), "server certificate PEM")
	tlsKey := flags.String("tls-key", env("SNAGLINE_CONTROL_TLS_KEY", ""), "server private key PEM")
	clientCA := flags.String("client-ca", env("SNAGLINE_CONTROL_CLIENT_CA", ""), "trusted client CA PEM")
	mappings := multiFlag{}
	for _, mapping := range strings.Split(env("SNAGLINE_CONTROL_CLIENT_SAN_WORKLOAD", ""), ",") {
		if mapping != "" {
			mappings = append(mappings, mapping)
		}
	}
	flags.Var(&mappings, "client-san-workload", "SAN=principal or SAN=principal|edge_id|generation (repeatable)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return runtimeConfig{}, errors.New("invalid flags")
	}
	result := runtimeConfig{Environment: *environment, Listen: *listen, OpsSocket: *opsSocket, PostgresDSN: *dsn, Tenant: *tenant, AuthorityID: *authorityID, RegistryRootKey: *rootKey, RegistryRootKeyID: *rootKeyID, RegistryPublisherPrincipal: *publisher, TLSCert: *tlsCert, TLSKey: *tlsKey, ClientCA: *clientCA}
	if anyBlank(result.Environment, result.Listen, result.OpsSocket, result.PostgresDSN, result.Tenant, result.AuthorityID, result.RegistryRootKey, result.RegistryRootKeyID, result.RegistryPublisherPrincipal) || !filepath.IsAbs(result.OpsSocket) || result.OpsSocket != filepath.Clean(result.OpsSocket) {
		return runtimeConfig{}, errors.New("missing required configuration")
	}
	poolConfig, err := postgresconfig.ParsePoolConfig(result.PostgresDSN)
	if err != nil {
		return runtimeConfig{}, errors.New("invalid PostgreSQL configuration")
	}
	result.postgresPoolConfig = poolConfig
	result.ClientMappings = make(map[string]controlapi.WorkloadIdentity, len(mappings))
	for _, mapping := range mappings {
		san, identity, err := parseMapping(mapping)
		if err != nil {
			return runtimeConfig{}, err
		}
		if _, exists := result.ClientMappings[san]; exists {
			return runtimeConfig{}, errors.New("duplicate client SAN mapping")
		}
		result.ClientMappings[san] = identity
	}
	if result.Environment == "production" && (anyBlank(result.TLSCert, result.TLSKey, result.ClientCA) || len(result.ClientMappings) == 0) {
		return runtimeConfig{}, errors.New("production requires TLS certificate, key, client CA, and SAN mapping")
	}
	return result, nil
}

func serve(config runtimeConfig) error {
	if config.postgresPoolConfig == nil {
		return errors.New("postgres unavailable")
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config.postgresPoolConfig.Copy())
	if err != nil {
		return errors.New("postgres unavailable")
	}
	defer pool.Close()
	if err := pool.Ping(context.Background()); err != nil {
		return errors.New("postgres unavailable")
	}
	store, err := postgres.New(pool, config.AuthorityID)
	if err != nil {
		return errors.New("authority unavailable")
	}
	root, err := identity.LoadEd25519VerifyingKey(config.RegistryRootKey)
	if err != nil {
		return errors.New("registry root unavailable")
	}
	public, err := root.PublicKey()
	if err != nil {
		return errors.New("registry root unavailable")
	}
	trust, err := registry.NewTrust(config.RegistryRootKeyID, public)
	if err != nil {
		return errors.New("registry root unavailable")
	}
	admission, err := controlapi.New(controlapi.Config{Tenant: config.Tenant, Authority: store, RegistryTrust: trust, RegistryPublisherPrincipalID: config.RegistryPublisherPrincipal})
	if err != nil {
		return errors.New("admission unavailable")
	}
	handler, err := controlhttp.New(controlhttp.Config{Tenant: config.Tenant, Admission: admission, Authority: store, ClientIdentities: config.ClientMappings})
	if err != nil {
		return errors.New("HTTP configuration unavailable")
	}
	tlsConfig, err := tlsConfig(config)
	if err != nil {
		return errors.New("TLS configuration unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tracker := runtimeops.NewTracker()
	ops, err := runtimeops.Start(ctx, config.OpsSocket, runtimeops.HandlerConfig{Role: "control", Tracker: tracker, Ready: func(ctx context.Context) error {
		return controlReady(ctx, pool, store, config.Tenant)
	}})
	if err != nil {
		return errors.New("private operations surface is unavailable")
	}
	defer ops.Close()
	tracker.MarkInitialized()
	server := &http.Server{Addr: config.Listen, Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServeTLS("", "") }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

// controlReady checks the authority actually used by admission. The migration
// ledger must contain exactly the schema this binary implements; an absent,
// stale, newer, or unreadable version fails closed.
func controlReady(ctx context.Context, pool *pgxpool.Pool, store *postgres.Store, tenant string) error {
	if pool == nil || store == nil || pool.Ping(ctx) != nil {
		return errors.New("control authority unavailable")
	}
	var newest, count int
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0), COUNT(*) FROM snagline_schema_migrations`).Scan(&newest, &count); err != nil || newest != 1 || count != 1 {
		return errors.New("control schema unavailable")
	}
	head, err := store.CurrentRegistryHead(ctx, tenant)
	if err != nil || head.Halted {
		return errors.New("control registry unavailable")
	}
	return nil
}

func tlsConfig(config runtimeConfig) (*tls.Config, error) {
	if anyBlank(config.TLSCert, config.TLSKey, config.ClientCA) {
		return nil, errors.New("mTLS is required")
	}
	certPEM, err := securefile.ReadRegularBounded(config.TLSCert, maxTLSPEMBytes)
	if err != nil {
		return nil, err
	}
	keyPEM, err := securefile.ReadPrivateBounded(config.TLSKey, maxTLSPEMBytes)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	caPEM, err := securefile.ReadRegularBounded(config.ClientCA, maxTLSPEMBytes)
	if err != nil {
		return nil, err
	}
	clients := x509.NewCertPool()
	if !clients.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid client CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients}, nil
}

type multiFlag []string

func (f *multiFlag) String() string         { return strings.Join(*f, ",") }
func (f *multiFlag) Set(value string) error { *f = append(*f, value); return nil }
func parseMapping(value string) (string, controlapi.WorkloadIdentity, error) {
	pair := strings.SplitN(value, "=", 2)
	if len(pair) != 2 || pair[0] == "" {
		return "", controlapi.WorkloadIdentity{}, errors.New("invalid client SAN mapping")
	}
	fields := strings.Split(pair[1], "|")
	result := controlapi.WorkloadIdentity{PrincipalID: fields[0]}
	if len(fields) == 3 {
		generation, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || fields[1] == "" || generation <= 0 {
			return "", result, errors.New("invalid client SAN mapping")
		}
		result.EdgeID = fields[1]
		result.EdgeGeneration = generation
	} else if len(fields) != 1 || result.PrincipalID == "" {
		return "", result, errors.New("invalid client SAN mapping")
	}
	return pair[0], result, nil
}
func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
func anyBlank(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}
