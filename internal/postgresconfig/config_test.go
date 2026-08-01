package postgresconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePoolConfigAcceptsAuthenticatedHostnameVerifyingTLS(t *testing.T) {
	rootCert := writeRootCertificate(t)

	for _, test := range []struct {
		name string
		dsn  string
	}{
		{
			name: "system trust",
			dsn:  "postgres://service:secret@db.example:5432/snagline?sslmode=verify-full&sslrootcert=system",
		},
		{
			name: "explicit root certificate",
			dsn:  "postgresql://service:secret@db.example:5432/snagline?sslmode=verify-full&sslrootcert=" + rootCert,
		},
		{
			name: "verified multi host fallback",
			dsn:  "postgresql://service:secret@db-a.example:5432,db-b.example:5433/snagline?sslmode=verify-full&sslrootcert=system",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := ParsePoolConfig(test.dsn)
			if err != nil {
				t.Fatalf("ParsePoolConfig rejected authenticated TLS DSN: %v", err)
			}
			if config == nil || config.ConnConfig == nil {
				t.Fatalf("ParsePoolConfig config = %#v; want pool and connection config", config)
			}
			assertTLSAttempt(t, "primary", config.ConnConfig.Host, config.ConnConfig.TLSConfig)
			for i, fallback := range config.ConnConfig.Fallbacks {
				if fallback == nil {
					t.Fatalf("fallback %d is nil", i)
				}
				assertTLSAttempt(t, "fallback", fallback.Host, fallback.TLSConfig)
			}
		})
	}
}

func TestParsePoolConfigRejectsDSNsThatCanDowngradeOrBypassTLS(t *testing.T) {
	for _, test := range []struct {
		name string
		dsn  string
	}{
		{name: "empty", dsn: ""},
		{name: "bare URL without TLS parameters", dsn: "postgres://service:secret@db.example/snagline"},
		{name: "non postgres scheme", dsn: "https://service:secret@db.example/snagline?sslmode=verify-full&sslrootcert=system"},
		{name: "key value DSN", dsn: "host=db.example user=service password=secret sslmode=verify-full sslrootcert=system"},
		{name: "disable", dsn: "postgres://service:secret@db.example/snagline?sslmode=disable&sslrootcert=system"},
		{name: "allow", dsn: "postgres://service:secret@db.example/snagline?sslmode=allow&sslrootcert=system"},
		{name: "prefer", dsn: "postgres://service:secret@db.example/snagline?sslmode=prefer&sslrootcert=system"},
		{name: "require", dsn: "postgres://service:secret@db.example/snagline?sslmode=require&sslrootcert=system"},
		{name: "verify CA", dsn: "postgres://service:secret@db.example/snagline?sslmode=verify-ca&sslrootcert=system"},
		{name: "repeated sslmode", dsn: "postgres://service:secret@db.example/snagline?sslmode=verify-full&sslmode=require&sslrootcert=system"},
		{name: "repeated root certificate", dsn: "postgres://service:secret@db.example/snagline?sslmode=verify-full&sslrootcert=system&sslrootcert=/tmp/other.pem"},
		{name: "Unix socket host override", dsn: "postgres://service:secret@db.example/snagline?host=%2Fvar%2Frun%2Fpostgresql&sslmode=verify-full&sslrootcert=system"},
		{name: "mixed TCP and Unix fallback", dsn: "postgres://service:secret@db.example/snagline?host=db.example%2C%2Fvar%2Frun%2Fpostgresql&sslmode=verify-full&sslrootcert=system"},
		{name: "missing root certificate", dsn: "postgres://service:secret@db.example/snagline?sslmode=verify-full"},
		{name: "relative root certificate", dsn: "postgres://service:secret@db.example/snagline?sslmode=verify-full&sslrootcert=ca.pem"},
		{name: "missing host", dsn: "postgres:///snagline?sslmode=verify-full&sslrootcert=system"},
		{name: "missing explicit port", dsn: "postgres://service:secret@db.example/snagline?sslmode=verify-full&sslrootcert=system"},
		{name: "explicit host override", dsn: "postgres://service:secret@db.example:5432/snagline?host=other.example&sslmode=verify-full&sslrootcert=system"},
		{name: "explicit port override", dsn: "postgres://service:secret@db.example:5432/snagline?port=6543&sslmode=verify-full&sslrootcert=system"},
		{name: "service indirection", dsn: "postgres://service:secret@db.example:5432/snagline?service=insecure&sslmode=verify-full&sslrootcert=system"},
		{name: "service file indirection", dsn: "postgres://service:secret@db.example:5432/snagline?servicefile=%2Ftmp%2Fpg_service.conf&sslmode=verify-full&sslrootcert=system"},
		{name: "whitespace", dsn: " postgres://service:secret@db.example/snagline?sslmode=verify-full&sslrootcert=system"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParsePoolConfig(test.dsn)
			if err == nil {
				t.Fatal("ParsePoolConfig accepted an insecure PostgreSQL DSN")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "postgres://") || strings.Contains(err.Error(), "postgresql://") {
				t.Fatalf("ParsePoolConfig leaked DSN credentials in error: %q", err)
			}
		})
	}
}

func TestParsePoolConfigDoesNotLetPGEnvironmentChangeTheExplicitPlan(t *testing.T) {
	serviceFile := filepath.Join(t.TempDir(), "pg_service.conf")
	if err := os.WriteFile(serviceFile, []byte("[insecure]\nhost=service-injected.example\nport=6543\nsslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGSERVICE", "insecure")
	t.Setenv("PGSERVICEFILE", serviceFile)
	t.Setenv("PGHOST", "environment-injected.example")
	t.Setenv("PGPORT", "6544")
	t.Setenv("PGSSLMODE", "disable")
	t.Setenv("PGSSLROOTCERT", "relative-ca.pem")

	config, err := ParsePoolConfig("postgresql://service@db.example:5432/snagline?sslmode=verify-full&sslrootcert=system")
	if err != nil {
		t.Fatal(err)
	}
	assertTLSAttempt(t, "primary", config.ConnConfig.Host, config.ConnConfig.TLSConfig)
	if config.ConnConfig.Host != "db.example" || config.ConnConfig.Port != 5432 {
		t.Fatalf("primary endpoint = %s:%d; want explicit URL endpoint db.example:5432", config.ConnConfig.Host, config.ConnConfig.Port)
	}
	for _, fallback := range config.ConnConfig.Fallbacks {
		assertTLSAttempt(t, "fallback", fallback.Host, fallback.TLSConfig)
	}

	for _, dsn := range []string{
		"postgresql://service@:5432/snagline?sslmode=verify-full&sslrootcert=system",
		"postgresql://service@,/snagline?sslmode=verify-full&sslrootcert=system",
		"postgresql://service@db.example/snagline?sslmode=verify-full&sslrootcert=system",
	} {
		if _, err := ParsePoolConfig(dsn); err == nil {
			t.Fatalf("ParsePoolConfig accepted ambiently completed endpoint %q", dsn)
		}
	}
}

func assertTLSAttempt(t *testing.T, name, host string, config interface {
	Clone() *tls.Config
}) {
	t.Helper()
	if host == "" || strings.HasPrefix(host, "/") {
		t.Fatalf("%s host = %q; want TCP hostname", name, host)
	}
	if config == nil {
		t.Fatalf("%s TLS config is nil", name)
	}
	tlsConfig := config.Clone()
	if tlsConfig.InsecureSkipVerify {
		t.Fatalf("%s TLS config permits unverified certificates", name)
	}
	if tlsConfig.RootCAs == nil {
		t.Fatalf("%s TLS config has no explicit trust roots", name)
	}
	if tlsConfig.ServerName == "" || tlsConfig.ServerName != host {
		t.Fatalf("%s TLS ServerName = %q; want hostname %q", name, tlsConfig.ServerName, host)
	}
}

func writeRootCertificate(t *testing.T) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "postgresconfig-test-root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "postgresconfig-test-root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
