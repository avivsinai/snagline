package main

import (
	"testing"

	"github.com/avivsinai/snagline/internal/authority/postgres"
)

const testPostgresDSN = "postgresql://service@db.example:5432/snagline?sslmode=verify-full&sslrootcert=system"

func TestParseConfigRequiresMutualTLSAndExplicitSANMappingInProduction(t *testing.T) {
	_, err := parseConfig([]string{"--environment=production", "--postgres-dsn=" + testPostgresDSN, "--tenant=tenant-a", "--authority-id=pg-a", "--registry-root-key=/root.pem", "--registry-root-key-id=root", "--registry-publisher-principal=publisher"})
	if err == nil {
		t.Fatal("production configuration unexpectedly accepted without mTLS material and SAN mapping")
	}
	config, err := parseConfig([]string{"--environment=production", "--postgres-dsn=" + testPostgresDSN, "--tenant=tenant-a", "--authority-id=pg-a", "--registry-root-key=/root.pem", "--registry-root-key-id=root", "--registry-publisher-principal=publisher", "--tls-cert=/server.pem", "--tls-key=/server.key", "--client-ca=/clients.pem", "--client-san-workload=dns:edge.example=edge-principal|edge-a|7", "--ops-socket=/run/snagline/control.ops.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if config.postgresPoolConfig == nil {
		t.Fatal("runtime configuration did not retain its validated PostgreSQL connection plan")
	}
	if got := config.ClientMappings["dns:edge.example"]; got.PrincipalID != "edge-principal" || got.EdgeID != "edge-a" || got.EdgeGeneration != 7 {
		t.Fatalf("mapping = %#v", got)
	}
}

func TestParseConfigRequiresAbsolutePrivateOpsSocket(t *testing.T) {
	args := []string{"--environment=development", "--postgres-dsn=" + testPostgresDSN, "--tenant=tenant-a", "--authority-id=pg-a", "--registry-root-key=/root.pem", "--registry-root-key-id=root", "--registry-publisher-principal=publisher", "--ops-socket=/run/snagline/control.ops.sock"}
	config, err := parseConfig(args)
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if config.OpsSocket != "/run/snagline/control.ops.sock" {
		t.Fatalf("ops socket = %q", config.OpsSocket)
	}
	for _, invalid := range [][]string{
		args[:len(args)-1],
		append(append([]string{}, args[:len(args)-1]...), "--ops-socket=control.ops.sock"),
	} {
		if _, err := parseConfig(invalid); err == nil {
			t.Fatalf("parseConfig accepted invalid ops socket args: %v", invalid)
		}
	}
}

func TestParseMigrationConfigRequiresDedicatedMigratorDSN(t *testing.T) {
	_, err := parseMigrationConfig(nil)
	if err == nil {
		t.Fatal("migration configuration unexpectedly accepted without dedicated migrator DSN")
	}
	config, err := parseMigrationConfig([]string{"--migrator-postgres-dsn=" + testPostgresDSN})
	if err != nil {
		t.Fatal(err)
	}
	if config.MigratorPostgresDSN != testPostgresDSN || config.Roles != postgres.DefaultRoleConfig() {
		t.Fatalf("migration config = %#v", config)
	}
	if config.postgresPoolConfig == nil {
		t.Fatal("migration configuration did not retain its validated PostgreSQL connection plan")
	}
}

func TestParseConfigsRejectInsecurePostgresDSNs(t *testing.T) {
	runtimeArgs := []string{"--environment=development", "--postgres-dsn=postgres://db.example/snagline", "--tenant=tenant-a", "--authority-id=pg-a", "--registry-root-key=/root.pem", "--registry-root-key-id=root", "--registry-publisher-principal=publisher", "--ops-socket=/run/snagline/control.ops.sock"}
	if _, err := parseConfig(runtimeArgs); err == nil {
		t.Fatal("runtime configuration accepted a PostgreSQL DSN without authenticated TLS")
	}
	if _, err := parseMigrationConfig([]string{"--migrator-postgres-dsn=postgres://db.example/snagline"}); err == nil {
		t.Fatal("migration configuration accepted a PostgreSQL DSN without authenticated TLS")
	}
}
