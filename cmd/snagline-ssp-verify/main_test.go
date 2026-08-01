package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/ssp"
)

func TestRunRequiresDeterministicNow(t *testing.T) {
	var out bytes.Buffer

	if got := run([]string{
		"--public-key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"--key-id", "key_1",
	}, bytes.NewReader(nil), &out); got != 1 {
		t.Fatalf("exit code = %d, want 1", got)
	}

	if got, want := out.String(), "{\"ok\":false,\"code\":\"missing_now\"}\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestRunRejectsInvalidPublicKeyBeforeReadingInput(t *testing.T) {
	var out bytes.Buffer

	if got := run([]string{
		"--public-key", "not-base64url!",
		"--key-id", "key_1",
		"--now", "2030-01-02T03:04:05Z",
	}, bytes.NewReader([]byte("not an envelope")), &out); got != 1 {
		t.Fatalf("exit code = %d, want 1", got)
	}

	if got, want := out.String(), "{\"ok\":false,\"code\":\"invalid_public_key\"}\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestRunRejectsInvalidNow(t *testing.T) {
	var out bytes.Buffer

	if got := run([]string{
		"--public-key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"--key-id", "key_1",
		"--now", "tomorrow",
	}, bytes.NewReader(nil), &out); got != 1 {
		t.Fatalf("exit code = %d, want 1", got)
	}

	if got, want := out.String(), "{\"ok\":false,\"code\":\"invalid_now\"}\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestRunNowGrammarMatchesSharedCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "ssp", "vectors", "timestamp-v1-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Roles []string `json:"roles"`
		Cases []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			Valid bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	hasCLINowRole := false
	for _, role := range corpus.Roles {
		if role == "cli.now" {
			hasCLINowRole = true
			break
		}
	}
	if !hasCLINowRole {
		t.Fatal("timestamp corpus does not declare cli.now coverage")
	}

	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var out bytes.Buffer
			if got := run([]string{
				"--public-key", "not-base64url!",
				"--key-id", "key_1",
				"--now", tc.Value,
			}, bytes.NewReader(nil), &out); got != 1 {
				t.Fatalf("exit code = %d, want 1", got)
			}
			wantCode := "invalid_now"
			if tc.Valid {
				wantCode = "invalid_public_key"
			}
			want := "{\"ok\":false,\"code\":\"" + wantCode + "\"}\n"
			if got := out.String(); got != want {
				t.Fatalf("output = %q, want %q", got, want)
			}
		})
	}
}

func TestRunVerifiesAtExplicitTime(t *testing.T) {
	wire, encodedPublicKey := signedCaseEnvelope(t)
	var out bytes.Buffer

	if got := run([]string{
		"--public-key", encodedPublicKey,
		"--key-id", "key_1",
		"--now", "2030-01-02T03:04:05Z",
	}, bytes.NewReader(wire), &out); got != 0 {
		t.Fatalf("exit code = %d, want 0; output=%s", got, out.String())
	}

	if got, want := out.String(), "{\"ok\":true,\"code\":\"verified\"}\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestRunReturnsStableVerificationFailure(t *testing.T) {
	wire, encodedPublicKey := signedCaseEnvelope(t)
	wire[len(wire)-2] ^= 1
	var out bytes.Buffer

	if got := run([]string{
		"--public-key", encodedPublicKey,
		"--key-id", "key_1",
		"--now", "2030-01-02T03:04:05Z",
	}, bytes.NewReader(wire), &out); got != 1 {
		t.Fatalf("exit code = %d, want 1", got)
	}

	if got, want := out.String(), "{\"ok\":false,\"code\":\"verification_failed\"}\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func signedCaseEnvelope(t *testing.T) ([]byte, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := identity.NewEd25519SigningKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifyAt := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	wire, err := ssp.Sign(ssp.Envelope{
		Schema:           "ssp.case.v1",
		ID:               "envelope_1",
		CaseID:           "case_1",
		EmittedAt:        verifyAt.Format(time.RFC3339),
		ExpiresAt:        verifyAt.Add(time.Hour).Format(time.RFC3339),
		RoutingEpoch:     1,
		RegistryRevision: 1,
		RegistryHash:     "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		AuthorKeyID:      "key_1",
		SignatureAlg:     "ed25519",
		Body:             []byte(`{"domain":"runtime","issuer_edge_id":"edge_1","issuer_edge_generation":1,"summary":"test case","context_manifest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`),
	}, signingKey, verifyAt)
	if err != nil {
		t.Fatal(err)
	}
	return wire, base64.RawURLEncoding.EncodeToString(publicKey)
}
