package main

import "testing"

func TestParseDispatcherRuntimeConfigRequiresSecureOneShotInputs(t *testing.T) {
	setValidDispatcherEnvironment(t)
	config, err := parseDispatcherRuntimeConfig([]string{"--case-id", "case-1", "--case-commitment", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--text", "inert"})
	if err != nil {
		t.Fatal(err)
	}
	if config.CaseID != "case-1" || config.EnvelopeTTL.String() != "1h0m0s" {
		t.Fatalf("config=%+v", config)
	}
}

func TestParseDispatcherRuntimeConfigRejectsPlaintextControlEndpoint(t *testing.T) {
	setValidDispatcherEnvironment(t)
	if _, err := parseDispatcherRuntimeConfig([]string{"--case-id", "case-1", "--case-commitment", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--text", "inert", "--control-url", "http://control.example"}); err == nil {
		t.Fatal("accepted plaintext control endpoint")
	}
}

func setValidDispatcherEnvironment(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"SNAGLINE_DISPATCHER_KEY_DESCRIPTOR": "/run/secrets/dispatcher.json", "SNAGLINE_DISPATCHER_TENANT": "tenant-a", "SNAGLINE_DISPATCHER_PRINCIPAL_ID": "dispatcher-principal", "SNAGLINE_DISPATCHER_AUTHOR_KEY_ID": "dispatcher-key", "SNAGLINE_DISPATCHER_DB": "/var/lib/snagline/dispatcher.db", "SNAGLINE_DISPATCHER_DB_KEY": "/run/secrets/dispatcher-db.key", "SNAGLINE_DISPATCHER_CONTROL_URL": "https://control.example", "SNAGLINE_DISPATCHER_TLS_CERT": "/run/secrets/dispatcher.crt", "SNAGLINE_DISPATCHER_TLS_KEY": "/run/secrets/dispatcher.key", "SNAGLINE_DISPATCHER_CONTROL_CA": "/run/secrets/control-ca.pem", "SNAGLINE_DISPATCHER_ENVELOPE_TTL": "1h",
	} {
		t.Setenv(key, value)
	}
}
