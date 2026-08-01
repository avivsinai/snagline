package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseConfigRejectsUnknownFieldsAndUnsafeRelay(t *testing.T) {
	const channelID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	base := `{
"tenant":"tenant-1","postgres_dsn":"postgresql://projector:secret@db.example:5432/projector?sslmode=verify-full&sslrootcert=system","authority_id":"buzz-projector-1",
"projection_state_path":"/var/lib/snagline/buzz.db","projection_key_file":"/run/secrets/projection.key",
"relay_url":"https://buzz.example","buzz_private_key_file":"/run/secrets/buzz.key",
"registry_root_key_id":"registry-root-1","registry_root_public_key_file":"/run/keys/registry-root-1.pem","domain_channels":{"support.example":"` + channelID + `"},
"poll_interval":"1s","batch_size":10,"request_timeout":"2s","backoff_initial":"100ms","backoff_max":"1s","ops_socket":"/run/snagline/projector.ops.sock"
}`
	settings, err := parseConfig([]byte(base))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if settings.postgresPoolConfig == nil {
		t.Fatal("projector configuration did not retain its validated PostgreSQL connection plan")
	}
	for _, mutated := range []string{
		strings.Replace(base, `"postgres_dsn":"postgresql://projector:secret@db.example:5432/projector?sslmode=verify-full&sslrootcert=system"`, `"postgres_dsn":"postgres://projector:secret@db.example/projector"`, 1),
		strings.Replace(base, `"relay_url":"https://buzz.example"`, `"relay_url":"http://buzz.example"`, 1),
		strings.Replace(base, `"relay_url":"https://buzz.example"`, `"relay_url":"https://"`, 1),
		strings.Replace(base, `"domain_channels":{"support.example":"`+channelID+`"}`, `"domain_channels":{"support.example":"`+channelID+`"},"unknown":true`, 1),
		strings.Replace(base, `"domain_channels":{"support.example":"`+channelID+`"}`, `"domain_channels":{"support.example":"`+channelID+`"},"author_keys":{"edge-key-1":"/run/keys/edge.pem"}`, 1),
		strings.Replace(base, `"domain_channels":{"support.example":"`+channelID+`"}`, `"domain_channels":{"support.example":""}`, 1),
		strings.Replace(base, channelID, strings.ToUpper(channelID), 1),
		strings.Replace(base, channelID, "{"+channelID+"}", 1),
	} {
		if _, err := parseConfig([]byte(mutated)); err == nil {
			t.Fatalf("parseConfig() accepted invalid configuration: %s", mutated)
		}
	}
}

func TestParseConfigRejectsUnboundedProjectorTiming(t *testing.T) {
	const base = `{
"tenant":"tenant-1","postgres_dsn":"postgresql://projector:secret@db.example:5432/projector?sslmode=verify-full&sslrootcert=system","authority_id":"buzz-projector-1",
"projection_state_path":"/var/lib/snagline/buzz.db","projection_key_file":"/run/secrets/projection.key",
"relay_url":"https://buzz.example","buzz_private_key_file":"/run/secrets/buzz.key",
"registry_root_key_id":"registry-root-1","registry_root_public_key_file":"/run/keys/registry-root-1.pem","domain_channels":{"support.example":"11111111-1111-1111-1111-111111111111"},
"poll_interval":"1s","batch_size":10,"request_timeout":"2s","backoff_initial":"100ms","backoff_max":"1s","ops_socket":"/run/snagline/projector.ops.sock"
}`
	for _, mutation := range []struct {
		from string
		to   string
	}{
		{`"poll_interval":"1s"`, `"poll_interval":"2h"`},
		{`"request_timeout":"2s"`, `"request_timeout":"2h"`},
		{`"backoff_initial":"100ms"`, `"backoff_initial":"2h"`},
		{`"backoff_max":"1s"`, `"backoff_max":"2h"`},
	} {
		if _, err := parseConfig([]byte(strings.Replace(base, mutation.from, mutation.to, 1))); err == nil {
			t.Fatalf("accepted unbounded timing mutation %s", mutation.to)
		}
	}
}

func TestProjectorFreshnessIncludesRequestAndPollWindows(t *testing.T) {
	settings := projectorConfig{requestTimeout: 2 * time.Second, pollInterval: 3 * time.Second}
	if got := projectorFreshnessWindow(settings); got != 8*time.Second {
		t.Fatalf("freshness window = %s, want 8s", got)
	}
}

func TestParseConfigRequiresAbsoluteOpsSocket(t *testing.T) {
	config := []byte(`{
"tenant":"tenant-1","postgres_dsn":"postgresql://projector:secret@db.example:5432/projector?sslmode=verify-full&sslrootcert=system","authority_id":"buzz-projector-1",
"projection_state_path":"/var/lib/snagline/buzz.db","projection_key_file":"/run/secrets/projection.key",
"relay_url":"https://buzz.example","buzz_private_key_file":"/run/secrets/buzz.key",
"registry_root_key_id":"registry-root-1","registry_root_public_key_file":"/run/keys/registry-root-1.pem","domain_channels":{"support.example":"11111111-1111-1111-1111-111111111111"},
"poll_interval":"1s","batch_size":10,"request_timeout":"2s","backoff_initial":"100ms","backoff_max":"1s","ops_socket":"/run/snagline/projector.ops.sock"
}`)
	settings, err := parseConfig(config)
	if err != nil || settings.OpsSocket != "/run/snagline/projector.ops.sock" {
		t.Fatalf("settings = %#v, err = %v", settings, err)
	}
	if _, err := parseConfig([]byte(strings.Replace(string(config), `"ops_socket":"/run/snagline/projector.ops.sock"`, `"ops_socket":"relative.sock"`, 1))); err == nil {
		t.Fatal("parseConfig accepted relative operations socket")
	}
	if _, err := parseConfig([]byte(strings.Replace(string(config), `,"ops_socket":"/run/snagline/projector.ops.sock"`, "", 1))); err == nil {
		t.Fatal("parseConfig accepted missing operations socket")
	}
}

func TestParseConfigRejectsRelativePrivateKeyPath(t *testing.T) {
	config := `{
"tenant":"tenant-1","postgres_dsn":"postgresql://projector:secret@db.example:5432/projector?sslmode=verify-full&sslrootcert=system","authority_id":"buzz-projector-1",
"projection_state_path":"/var/lib/snagline/buzz.db","projection_key_file":"/run/secrets/projection.key",
"relay_url":"https://buzz.example","buzz_private_key_file":"buzz.key",
"registry_root_key_id":"registry-root-1","registry_root_public_key_file":"/run/keys/registry-root-1.pem","domain_channels":{"support.example":"11111111-1111-1111-1111-111111111111"},
"poll_interval":"1s","batch_size":10,"request_timeout":"2s","backoff_initial":"100ms","backoff_max":"1s"
}`
	if _, err := parseConfig([]byte(config)); err == nil {
		t.Fatal("parseConfig() accepted a relative private key path")
	}
}

func TestLoadConfigRequiresPrivateRegularFile(t *testing.T) {
	config := []byte(`{
"tenant":"tenant-1","postgres_dsn":"postgresql://projector:secret@db.example:5432/projector?sslmode=verify-full&sslrootcert=system","authority_id":"buzz-projector-1",
"projection_state_path":"/var/lib/snagline/buzz.db","projection_key_file":"/run/secrets/projection.key",
"relay_url":"https://buzz.example","buzz_private_key_file":"/run/secrets/buzz.key",
"registry_root_key_id":"registry-root-1","registry_root_public_key_file":"/run/keys/registry-root-1.pem","domain_channels":{"support.example":"11111111-1111-1111-1111-111111111111"},
"poll_interval":"1s","batch_size":10,"request_timeout":"2s","backoff_initial":"100ms","backoff_max":"1s","ops_socket":"/run/snagline/projector.ops.sock"
}`)
	private := filepath.Join(t.TempDir(), "projector.json")
	if err := os.WriteFile(private, config, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(private); err != nil {
		t.Fatalf("private config rejected: %v", err)
	}
	public := filepath.Join(t.TempDir(), "public.json")
	if err := os.WriteFile(public, config, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(public); err == nil {
		t.Fatal("group/world-readable config accepted")
	}
	link := filepath.Join(t.TempDir(), "config-link.json")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(link); err == nil {
		t.Fatal("symlink config accepted")
	}
}

func TestDomainChannelMapDoesNotNormalizeOrFallBack(t *testing.T) {
	const channelID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mapping, err := newDomainChannelMap(map[string]string{"support.example": channelID})
	if err != nil {
		t.Fatal(err)
	}
	channel, err := mapping.ChannelForDomain(context.Background(), "support.example")
	if err != nil || channel != channelID {
		t.Fatalf("ChannelForDomain() = (%q, %v)", channel, err)
	}
	if _, err := mapping.ChannelForDomain(context.Background(), "SUPPORT.EXAMPLE"); err == nil {
		t.Fatal("ChannelForDomain() accepted a non-exact domain")
	}
	for _, noncanonical := range []string{strings.ToUpper(channelID), "{" + channelID + "}"} {
		if _, err := newDomainChannelMap(map[string]string{"support.example": noncanonical}); err == nil {
			t.Fatalf("newDomainChannelMap() accepted non-canonical UUID %q", noncanonical)
		}
	}
}
