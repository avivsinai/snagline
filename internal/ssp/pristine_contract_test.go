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
		`{"case_commitment":"sha256:`+strings.Repeat("c", 64)+`","text":"Inspect the confidential failure details.","public_summary":"Inspect the bounded failure and report the next safe step."}`,
	))

	if err := envelope.Validate(now); err != nil {
		t.Fatalf("Validate() rejected pristine advice: %v", err)
	}

	for name, body := range map[string]json.RawMessage{
		"old text-only contract":  json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("c", 64) + `","text":"advice"}`),
		"missing case commitment": json.RawMessage(`{"text":"advice","public_summary":"public advice"}`),
		"transport root":          json.RawMessage(`{"case_root_ref":"buzz:event","text":"advice","public_summary":"public advice","payload_sha256":"sha256:` + strings.Repeat("c", 64) + `"}`),
		"extra payload hash":      json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("c", 64) + `","text":"advice","public_summary":"public advice","payload_sha256":"sha256:` + strings.Repeat("d", 64) + `"}`),
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

// TestPristinePublicSummaryContract pins the only text allowed to leave the
// confidential case/advice bodies. Both families must carry exactly one,
// independently authored public_summary string of one through 1024 runes.
func TestPristinePublicSummaryContract(t *testing.T) {
	now := time.Date(2026, 7, 30, 20, 0, 0, 0, time.UTC)
	for _, family := range []string{FamilyCase, FamilyAdvice} {
		t.Run(family, func(t *testing.T) {
			for name, publicSummary := range map[string]string{
				"one rune":   "x",
				"1024 runes": strings.Repeat("界", 1024),
			} {
				t.Run("accepts "+name, func(t *testing.T) {
					envelope := pristineEnvelope(family, pristinePublicSummaryBody(family, `"`+publicSummary+`"`))
					if err := envelope.Validate(now); err != nil {
						t.Fatalf("Validate() rejected %s public_summary: %v", name, err)
					}
				})
			}

			for name, publicSummary := range map[string]string{
				"missing":    "",
				"null":       "null",
				"non-string": "1",
				"empty":      `""`,
				"1025 runes": `"` + strings.Repeat("界", 1025) + `"`,
			} {
				t.Run("rejects "+name, func(t *testing.T) {
					var body json.RawMessage
					if name == "missing" {
						body = pristinePublicSummaryBodyWithoutMember(family)
					} else {
						body = pristinePublicSummaryBody(family, publicSummary)
					}
					envelope := pristineEnvelope(family, body)
					if err := envelope.Validate(now); err == nil {
						t.Fatal("Validate() accepted an absent, malformed, oversized, or aliased public_summary")
					}
				})
			}

			for _, alias := range []string{"publicSummary", "Public_Summary"} {
				t.Run("rejects exact-field alias "+alias, func(t *testing.T) {
					body := strings.Replace(string(pristinePublicSummaryBody(family, `"bounded"`)), `"public_summary"`, `"`+alias+`"`, 1)
					envelope := pristineEnvelope(family, json.RawMessage(body))
					if err := envelope.Validate(now); err == nil {
						t.Fatalf("Validate() accepted public_summary alias %q", alias)
					}
				})
			}
		})
	}
}

func pristinePublicSummaryBody(schema, publicSummary string) json.RawMessage {
	if schema == FamilyCase {
		return json.RawMessage(`{"domain":"runtime","issuer_edge_id":"edge_7f3a","issuer_edge_generation":1,"summary":"confidential snag","public_summary":` + publicSummary + `,"context_manifest":"sha256:` + strings.Repeat("d", 64) + `"}`)
	}
	return json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("c", 64) + `","text":"Inspect the confidential failure details.","public_summary":` + publicSummary + `}`)
}

func pristinePublicSummaryBodyWithoutMember(schema string) json.RawMessage {
	if schema == FamilyCase {
		return json.RawMessage(`{"domain":"runtime","issuer_edge_id":"edge_7f3a","issuer_edge_generation":1,"summary":"confidential snag","context_manifest":"sha256:` + strings.Repeat("d", 64) + `"}`)
	}
	return json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("c", 64) + `","text":"Inspect the confidential failure details."}`)
}

func TestPristineRoutedFamiliesRejectUnsignedProvenance(t *testing.T) {
	now := time.Date(2026, 7, 30, 20, 0, 0, 0, time.UTC)
	envelope := pristineEnvelope(FamilyCase, json.RawMessage(
		`{"domain":"runtime","issuer_edge_id":"edge_7f3a","issuer_edge_generation":1,"summary":"confidential snag","public_summary":"bounded snag","context_manifest":"sha256:`+strings.Repeat("d", 64)+`"}`,
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
		envelope := pristineEnvelope(FamilyCase, json.RawMessage(`{"domain":"runtime","issuer_edge_id":"edge-1","issuer_edge_generation":`+generation+`,"summary":"confidential snag","public_summary":"bounded snag","context_manifest":"sha256:`+strings.Repeat("d", 64)+`"}`))
		if err := envelope.Validate(now); err == nil {
			t.Fatalf("accepted issuer_edge_generation %s", generation)
		}
	}
}

func TestPristineCaseRejectsOldSummaryOnlyContract(t *testing.T) {
	now := time.Date(2026, 7, 30, 20, 0, 0, 0, time.UTC)
	envelope := pristineEnvelope(FamilyCase, json.RawMessage(
		`{"domain":"runtime","issuer_edge_id":"edge_7f3a","issuer_edge_generation":1,"summary":"confidential snag","context_manifest":"sha256:`+strings.Repeat("d", 64)+`"}`,
	))
	if err := envelope.Validate(now); err == nil {
		t.Fatal("Validate() accepted the old summary-only case body")
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
