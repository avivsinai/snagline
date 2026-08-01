package ssp

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
)

func TestPristineAdviceBindsExactCaseCommitment(t *testing.T) {
	now := time.Date(2026, 7, 30, 20, 0, 0, 0, time.UTC)
	envelope := pristineEnvelope(FamilyAdvice, json.RawMessage(
		`{"case_commitment":"sha256:`+strings.Repeat("c", 64)+`","text":"Inspect the bounded failure and report the next safe step."}`,
	))

	if err := envelope.Validate(now); err != nil {
		t.Fatalf("Validate() rejected pristine advice: %v", err)
	}

	for name, body := range map[string]json.RawMessage{
		"missing case commitment": json.RawMessage(`{"text":"advice"}`),
		"transport root":          json.RawMessage(`{"case_root_ref":"buzz:event","text":"advice","payload_sha256":"sha256:` + strings.Repeat("c", 64) + `"}`),
		"extra payload hash":      json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("c", 64) + `","text":"advice","payload_sha256":"sha256:` + strings.Repeat("d", 64) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := envelope
			candidate.Body = body
			if err := candidate.Validate(now); err == nil {
				t.Fatal("Validate() accepted obsolete or ambiguous advice body")
			}
		})
	}
}

func TestPristineRoutedFamiliesRejectUnsignedProvenance(t *testing.T) {
	now := time.Date(2026, 7, 30, 20, 0, 0, 0, time.UTC)
	envelope := pristineEnvelope(FamilyCase, json.RawMessage(
		`{"domain":"runtime","issuer_edge_id":"edge_7f3a","issuer_edge_generation":1,"summary":"bounded snag","context_manifest":"sha256:`+strings.Repeat("d", 64)+`"}`,
	))
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := identity.NewEd25519SigningKey(private)
	if err != nil {
		t.Fatal(err)
	}
	verifying, err := identity.NewEd25519VerifyingKey(public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Sign(envelope, signing, now)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["provenance"] = json.RawMessage(`{"transport":"buzz","refs":["event-1"]}`)
	withProvenance, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(withProvenance, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, now); err == nil {
		t.Fatal("Verify() accepted unsigned transport provenance")
	}
}

func TestPristineCaseRequiresPositiveIssuerEdgeGeneration(t *testing.T) {
	now := time.Date(2026, 7, 30, 20, 0, 0, 0, time.UTC)
	for _, generation := range []string{"0", "-1", "9007199254740992"} {
		envelope := pristineEnvelope(FamilyCase, json.RawMessage(`{"domain":"runtime","issuer_edge_id":"edge-1","issuer_edge_generation":`+generation+`,"summary":"bounded snag","context_manifest":"sha256:`+strings.Repeat("d", 64)+`"}`))
		if err := envelope.Validate(now); err == nil {
			t.Fatalf("accepted issuer_edge_generation %s", generation)
		}
	}
}

func pristineEnvelope(schema string, body json.RawMessage) Envelope {
	return Envelope{
		Schema:           schema,
		ID:               "envelope-1",
		CaseID:           "case-1",
		EmittedAt:        "2026-07-30T19:59:00Z",
		ExpiresAt:        "2026-07-31T20:00:00Z",
		RoutingEpoch:     4,
		RegistryRevision: 12,
		RegistryHash:     "sha256:" + strings.Repeat("a", 64),
		AuthorKeyID:      "key-1",
		SignatureAlg:     "ed25519",
		Body:             body,
	}
}
