package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

const testDeliveryPostgresDSN = "postgresql://delivery@db.example:5432/snagline?sslmode=verify-full&sslrootcert=system"

func TestParseConfigRequiresExplicitSecureRuntimeInputs(t *testing.T) {
	t.Setenv("SNAGLINE_DELIVERY_POSTGRES_DSN", testDeliveryPostgresDSN)
	t.Setenv("SNAGLINE_DELIVERY_AUTHORITY_ID", "authority-1")
	t.Setenv("SNAGLINE_DELIVERY_WORKER_ID", "worker-1")
	t.Setenv("SNAGLINE_DELIVERY_NATS_URL", "tls://nats.example:4222")
	t.Setenv("SNAGLINE_DELIVERY_NATS_CREDENTIALS_FILE", "/run/secrets/nats.creds")
	t.Setenv("SNAGLINE_DELIVERY_NATS_CA_FILE", "/run/secrets/nats-ca.pem")
	t.Setenv("SNAGLINE_DELIVERY_OPS_SOCKET", "/run/snagline/delivery.ops.sock")

	config, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if config.BatchSize != 100 || config.Lease != time.Minute || config.RetryDelay != 30*time.Second || config.PollInterval != time.Second {
		t.Fatalf("parseConfig() defaults = %+v, want bounded production defaults", config)
	}
	if config.postgresPoolConfig == nil {
		t.Fatal("runtime configuration did not retain its validated PostgreSQL connection plan")
	}
}

func TestParseConfigRequiresAbsoluteOpsSocket(t *testing.T) {
	t.Setenv("SNAGLINE_DELIVERY_POSTGRES_DSN", testDeliveryPostgresDSN)
	t.Setenv("SNAGLINE_DELIVERY_AUTHORITY_ID", "authority-1")
	t.Setenv("SNAGLINE_DELIVERY_WORKER_ID", "worker-1")
	t.Setenv("SNAGLINE_DELIVERY_NATS_URL", "tls://nats.example:4222")
	t.Setenv("SNAGLINE_DELIVERY_NATS_CREDENTIALS_FILE", "/run/secrets/nats.creds")
	t.Setenv("SNAGLINE_DELIVERY_NATS_CA_FILE", "/run/secrets/nats-ca.pem")
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("parseConfig accepted a missing operations socket")
	}
	if _, err := parseConfig([]string{"--ops-socket=relative.sock"}); err == nil {
		t.Fatal("parseConfig accepted a relative operations socket")
	}
	config, err := parseConfig([]string{"--ops-socket=/run/snagline/delivery.ops.sock"})
	if err != nil || config.OpsSocket != "/run/snagline/delivery.ops.sock" {
		t.Fatalf("config = %#v, err = %v", config, err)
	}
}

func TestParseConfigRejectsInsecureOrUnboundedDeliveryRuntime(t *testing.T) {
	t.Setenv("SNAGLINE_DELIVERY_POSTGRES_DSN", testDeliveryPostgresDSN)
	t.Setenv("SNAGLINE_DELIVERY_AUTHORITY_ID", "authority-1")
	t.Setenv("SNAGLINE_DELIVERY_WORKER_ID", "worker-1")
	t.Setenv("SNAGLINE_DELIVERY_NATS_URL", "nats://nats.example:4222")
	t.Setenv("SNAGLINE_DELIVERY_NATS_CREDENTIALS_FILE", "/run/secrets/nats.creds")
	t.Setenv("SNAGLINE_DELIVERY_NATS_CA_FILE", "/run/secrets/nats-ca.pem")

	if _, err := parseConfig(nil); err == nil {
		t.Fatal("parseConfig() accepted an insecure NATS URL")
	}
	if _, err := parseConfig([]string{"--nats-url", "tls://nats.example:4222", "--batch-size", "1001"}); err == nil {
		t.Fatal("parseConfig() accepted a batch above the worker claim bound")
	}
	if _, err := parseConfig([]string{"--nats-url", "tls://nats.example:4222", "--poll-interval", "0s"}); err == nil {
		t.Fatal("parseConfig() accepted an unbounded poll interval")
	}
}

func TestParseConfigRejectsInsecurePostgresDSN(t *testing.T) {
	t.Setenv("SNAGLINE_DELIVERY_POSTGRES_DSN", "postgres://authority.example/snagline")
	t.Setenv("SNAGLINE_DELIVERY_AUTHORITY_ID", "authority-1")
	t.Setenv("SNAGLINE_DELIVERY_WORKER_ID", "worker-1")
	t.Setenv("SNAGLINE_DELIVERY_NATS_URL", "tls://nats.example:4222")
	t.Setenv("SNAGLINE_DELIVERY_NATS_CREDENTIALS_FILE", "/run/secrets/nats.creds")
	t.Setenv("SNAGLINE_DELIVERY_NATS_CA_FILE", "/run/secrets/nats-ca.pem")
	t.Setenv("SNAGLINE_DELIVERY_OPS_SOCKET", "/run/snagline/delivery.ops.sock")
	if _, err := parseConfig(nil); err == nil {
		t.Fatal("parseConfig accepted a PostgreSQL DSN without authenticated TLS")
	}
}

func TestRunLoopKeepsPollingAfterReleasedDeliveryFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runs := 0
	err := runLoop(ctx, time.Millisecond, func(context.Context) error {
		runs++
		if runs == 1 {
			return errors.New("publish failed after release")
		}
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("runLoop() error = %v", err)
	}
	if runs != 2 {
		t.Fatalf("runLoop() calls = %d, want 2", runs)
	}
}

func TestDeliveryFreshnessIncludesBoundedWorkAndPollWindows(t *testing.T) {
	config := runtimeConfig{Lease: time.Minute, PollInterval: 5 * time.Second}
	if got := deliveryFreshnessWindow(config); got != 70*time.Second {
		t.Fatalf("freshness window = %s, want 1m10s", got)
	}
}

func TestRunOnceWithTimeoutBoundsStuckWork(t *testing.T) {
	start := time.Now()
	err := runOnceWithTimeout(context.Background(), 10*time.Millisecond, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runOnceWithTimeout() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("bounded work took %s", elapsed)
	}
}

func TestLoadNATSCredentialsRequiresPrivateRegularFile(t *testing.T) {
	keyPair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer keyPair.Wipe()
	seed, err := keyPair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { clear(seed) }()
	credentials := []byte("-----BEGIN NATS USER JWT-----\na.b.c\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n")
	path := filepath.Join(t.TempDir(), "user.creds")
	if err := os.WriteFile(path, credentials, 0o600); err != nil {
		t.Fatal(err)
	}
	option, wipe, err := loadNATSCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if option == nil {
		t.Fatal("missing NATS authentication option")
	}
	wipe()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadNATSCredentials(path); err == nil {
		t.Fatal("accepted group/world-readable NATS credentials")
	}
}
