package ssp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
)

var unicodeNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

// unicodeSignNow sits inside the validity window of the shared strict test
// fixtures, which are dated 2030.
var unicodeSignNow = time.Date(2030, 1, 1, 0, 30, 0, 0, time.UTC)

// TestValidateStringEscapesRejectsMalformedSurrogates covers the parse boundary
// directly. Each input is pure ASCII and valid UTF-8 at the byte level, which is
// exactly why the byte-level guard cannot catch it.
func TestValidateStringEscapesRejectsMalformedSurrogates(t *testing.T) {
	rejected := map[string]string{
		"high then identical high": `{"id":"\uD800\uD800"}`,
		"high then different high": `{"id":"\uD800\uD801"}`,
		"low then high (reversed)": `{"id":"\uDC00\uD800"}`,
		"lone high":                `{"id":"\uD800"}`,
		"lone low":                 `{"id":"\uDC00"}`,
		"lone low mid-string":      `{"id":"a\uDC00b"}`,
		"high at end of string":    `{"id":"a\uD800"}`,
		"high then plain char":     `{"id":"\uD800A"}`,
		"high then non-surrogate":  `{"id":"\uD800\u0041"}`,
		"high then boundary below": `{"id":"\uD800\uDBFF"}`,
		"boundary lone low DFFF":   `{"id":"\uDFFF"}`,
		"boundary lone high DBFF":  `{"id":"\uDBFF"}`,
		"malformed in object key":  `{"\uD800":"v"}`,
		"truncated escape":         `{"id":"\uD80"}`,
		"non-hex escape digit":     `{"id":"\uZZZZ"}`,
	}
	for name, wire := range rejected {
		t.Run(name, func(t *testing.T) {
			if err := validateStringEscapes([]byte(wire)); err == nil {
				t.Fatalf("accepted malformed surrogate escape: %s", wire)
			}
			// rawGuard must refuse it too, since that is the boundary every
			// entry point shares.
			if err := rawGuard([]byte(wire)); err == nil {
				t.Fatalf("rawGuard accepted malformed surrogate escape: %s", wire)
			}
		})
	}
}

// TestValidateStringEscapesAcceptsValidInput is the control set. Without it the
// rejections above could be satisfied by a validator that refuses everything,
// and astral-plane characters must remain expressible.
func TestValidateStringEscapesAcceptsValidInput(t *testing.T) {
	accepted := map[string]string{
		"valid pair":                 `{"id":"\uD800\uDC00"}`,
		"valid pair upper bound":     `{"id":"\uDBFF\uDFFF"}`,
		"valid pair lowercase hex":   `{"id":"\ud83d\ude00"}`,
		"two valid pairs":            `{"id":"\uD800\uDC00\uDBFF\uDFFF"}`,
		"pair surrounded by text":    `{"id":"a\uD83D\uDE00b"}`,
		"non-surrogate escapes":      `{"id":"\u0041\u00e9\uFFFD"}`,
		"escaped backslash then u":   `{"id":"\\uD800"}`,
		"escaped quote":              `{"id":"a\"b"}`,
		"no escapes":                 `{"id":"plain"}`,
		"brace inside string":        `{"id":"{\"nested\":1}"}`,
		"valid pair in object key":   `{"\uD800\uDC00":"v"}`,
		"literal backslash sequence": `{"id":"C:\\path\\uD800"}`,
	}
	for name, wire := range accepted {
		t.Run(name, func(t *testing.T) {
			if err := validateStringEscapes([]byte(wire)); err != nil {
				t.Fatalf("rejected valid input %s: %v", wire, err)
			}
			// Sanity: these must really be valid JSON, or the test is asserting
			// nothing about surrogate handling.
			var into any
			if err := json.Unmarshal([]byte(wire), &into); err != nil {
				t.Fatalf("test input is not valid JSON: %s: %v", wire, err)
			}
		})
	}
}

// TestMalformedSurrogatesNoLongerAliasCanonicalBytes is the security property
// itself: distinct malformed wires must not share canonical signing bytes.
//
// Before this fix, all three inputs below canonicalized to the identical bytes
// {"id":"\ufffd"} — so one Ed25519 signature verified all three and the
// signature no longer identified a single wire. The test asserts they are now
// refused at canonicalization rather than asserting the old aliasing is merely
// improbable.
func TestMalformedSurrogatesNoLongerAliasCanonicalBytes(t *testing.T) {
	aliasing := []string{
		`{"id":"\uD800\uD800"}`,
		`{"id":"\uD800\uD801"}`,
		`{"id":"\uDC00\uD800"}`,
	}
	for _, wire := range aliasing {
		if _, err := canonical([]byte(wire)); err == nil {
			t.Fatalf("canonicalized a malformed-surrogate wire: %s", wire)
		}
	}

	// A valid pair still canonicalizes, and two DIFFERENT valid inputs still
	// produce different bytes, which is what makes the refusals above meaningful.
	first, err := canonical([]byte(`{"id":"\uD800\uDC00"}`))
	if err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
	second, err := canonical([]byte(`{"id":"\uDBFF\uDFFF"}`))
	if err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
	if string(first) == string(second) {
		t.Fatal("two distinct valid inputs produced identical canonical bytes")
	}
}

// TestVerifyRejectsMalformedSurrogatesBeforeSignature proves the refusal happens
// at the parse boundary and not incidentally at signature verification.
//
// The distinction matters: if these wires were rejected only because their
// signatures did not match, the underlying aliasing would still exist and an
// attacker holding a valid signature over the collapsed form could still use it.
// Each case therefore asserts the error is the surrogate error, not a signature
// error, and is produced with an EMPTY key set — verification cannot even be
// attempted, so nothing but the parse boundary can be doing the rejecting.
func TestVerifyRejectsMalformedSurrogatesBeforeSignature(t *testing.T) {
	empty := map[string]identity.Ed25519VerifyingKey{}

	for name, wire := range map[string]string{
		"high high in id":           `{"id":"\uD800\uD800"}`,
		"high different high":       `{"id":"\uD800\uD801"}`,
		"reversed pair":             `{"id":"\uDC00\uD800"}`,
		"lone low in author_key":    `{"author_key_id":"\uDC00"}`,
		"lone high in case_id":      `{"case_id":"\uD800"}`,
		"malformed in schema field": `{"schema":"\uD800\uD800"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify([]byte(wire), empty, unicodeNow)
			if err == nil {
				t.Fatalf("Verify accepted %s", wire)
			}
			message := err.Error()
			if !strings.Contains(message, "surrogate") && !strings.Contains(message, "unicode escape") {
				t.Fatalf("rejected for the wrong reason (%v); the parse boundary must refuse this before signature handling", err)
			}
			if strings.Contains(message, "signature") {
				t.Fatalf("rejected at the signature layer (%v); the aliasing would still exist", err)
			}
		})
	}
}

// TestVerifyRejectsInvalidUnicodePublicSummaryBeforeSignature ensures the
// outbound-safe text cannot use an invalid byte sequence or an unpaired UTF-16
// surrogate to evade the body contract. The signature is deliberately retained
// so rejection must happen before signature verification.
func TestVerifyRejectsInvalidUnicodePublicSummaryBeforeSignature(t *testing.T) {
	_, signing, verifying := strictTestKeys(t)
	keys := map[string]identity.Ed25519VerifyingKey{"key-1": verifying}
	for _, family := range []string{FamilyCase, FamilyAdvice} {
		t.Run(family, func(t *testing.T) {
			var members []string
			if family == FamilyCase {
				members = strictCaseMembers(`{"domain":"runtime","issuer_edge_id":"edge-1","issuer_edge_generation":1,"summary":"confidential help","public_summary":"bounded","context_manifest":"sha256:`+strings.Repeat("b", 64)+`"}`, "")
			} else {
				members = strictAdviceMembers(`{"case_commitment":"sha256:`+strings.Repeat("c", 64)+`","text":"confidential advice","public_summary":"bounded"}`, "")
			}
			valid := signRawMembers(t, signing, members)
			if _, err := Verify(valid, keys, unicodeSignNow); err != nil {
				t.Fatalf("control wire rejected: %v", err)
			}

			for name, publicSummary := range map[string][]byte{
				"invalid UTF-8":           append([]byte(`"public_summary":"`), 0xff, '"'),
				"unpaired high surrogate": []byte(`"public_summary":"\uD800"`),
				"unpaired low surrogate":  []byte(`"public_summary":"\uDC00"`),
			} {
				t.Run(name, func(t *testing.T) {
					wire := bytes.Replace(valid, []byte(`"public_summary":"bounded"`), publicSummary, 1)
					if string(wire) == string(valid) {
						t.Fatal("public_summary substitution did not apply")
					}
					_, err := Verify(wire, keys, unicodeSignNow)
					if err == nil {
						t.Fatal("Verify accepted invalid Unicode in public_summary")
					}
					message := err.Error()
					if !strings.Contains(message, "UTF-8") && !strings.Contains(message, "surrogate") {
						t.Fatalf("Verify rejected for the wrong reason (%v); invalid public_summary Unicode must fail at the parse boundary", err)
					}
					if strings.Contains(message, "signature") {
						t.Fatalf("Verify rejected at the signature layer (%v); invalid public_summary Unicode reached signature handling", err)
					}
				})
			}
		})
	}
}

func TestSignRejectsDistinctInvalidUTF8OpaqueIdentifierAliases(t *testing.T) {
	_, signing, _ := strictTestKeys(t)

	base := Envelope{
		Schema:           "ssp.case.v1",
		ID:               "case-envelope-1",
		CaseID:           "case-1",
		EmittedAt:        "2030-01-01T00:00:00Z",
		ExpiresAt:        "2030-01-01T01:00:00Z",
		RoutingEpoch:     7,
		RegistryRevision: 12,
		RegistryHash:     "sha256:" + strings.Repeat("a", 64),
		AuthorKeyID:      "key-1",
		SignatureAlg:     "ed25519",
		Body:             json.RawMessage(strictCaseBody()),
	}
	for suffixName, suffix := range map[string]string{
		"ed-a0-80": string([]byte{0xED, 0xA0, 0x80}),
		"ed-a0-81": string([]byte{0xED, 0xA0, 0x81}),
	} {
		for field, set := range map[string]func(*Envelope){
			"envelope id":         func(e *Envelope) { e.ID += suffix },
			"case correlation id": func(e *Envelope) { e.CaseID += suffix },
			"author authority id": func(e *Envelope) { e.AuthorKeyID += suffix },
		} {
			t.Run(suffixName+"/"+field, func(t *testing.T) {
				envelope := base
				set(&envelope)
				if wire, err := Sign(envelope, signing, unicodeSignNow); err == nil {
					t.Fatalf("Sign accepted invalid UTF-8 and emitted aliasable wire %q", wire)
				}
			})
		}
	}
}

func TestValidateRejectsInvalidUTF8OpaqueBodyIdentifiers(t *testing.T) {
	_, signing, _ := strictTestKeys(t)
	baseCase := Envelope{Schema: "ssp.case.v1", ID: "case-envelope-1", CaseID: "case-1", EmittedAt: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T01:00:00Z", RoutingEpoch: 7, RegistryRevision: 12, RegistryHash: "sha256:" + strings.Repeat("a", 64), AuthorKeyID: "key-1", SignatureAlg: "ed25519", Body: json.RawMessage(strictCaseBody())}
	baseAdvice := baseCase
	baseAdvice.Schema = "ssp.advice.v1"
	baseAdvice.ID = "advice-envelope-1"
	baseAdvice.Body = json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("c", 64) + `","text":"confidential advice","public_summary":"advice"}`)
	for suffixName, suffix := range map[string]string{"ed-a0-80": string([]byte{0xED, 0xA0, 0x80}), "ed-a0-81": string([]byte{0xED, 0xA0, 0x81})} {
		for name, mutate := range map[string]func(*Envelope){
			"case domain": func(e *Envelope) {
				e.Body = json.RawMessage(`{"domain":"runtime` + suffix + `","issuer_edge_id":"edge-1","issuer_edge_generation":1,"summary":"confidential help","public_summary":"help","context_manifest":"sha256:` + strings.Repeat("b", 64) + `"}`)
			},
			"case issuer edge": func(e *Envelope) {
				e.Body = json.RawMessage(`{"domain":"runtime","issuer_edge_id":"edge-1` + suffix + `","issuer_edge_generation":1,"summary":"confidential help","public_summary":"help","context_manifest":"sha256:` + strings.Repeat("b", 64) + `"}`)
			},
			"advice case commitment": func(e *Envelope) {
				e.Body = json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("c", 64) + suffix + `","text":"confidential advice","public_summary":"advice"}`)
			},
		} {
			t.Run(suffixName+"/"+name, func(t *testing.T) {
				envelope := baseCase
				if strings.HasPrefix(name, "advice") {
					envelope = baseAdvice
				}
				mutate(&envelope)
				if err := envelope.Validate(unicodeSignNow); err == nil {
					t.Fatal("Validate accepted invalid UTF-8 opaque identifier")
				}
				if wire, err := Sign(envelope, signing, unicodeSignNow); err == nil {
					t.Fatalf("Sign accepted invalid UTF-8 opaque identifier and emitted %q", wire)
				}
			})
		}
	}
}

// TestVerifyRejectsSurrogateSubstitutionOnValidSignedWire is the end-to-end
// causal replay, and it is the strongest test in this file.
//
// It starts from a COMPLETE, validly signed envelope whose id contains U+FFFD —
// the exact character that malformed surrogate pairs used to collapse to. The
// signature is then left untouched while only the raw id token is rewritten to a
// malformed high-high pair. Before the parse-boundary fix, that substituted wire
// canonicalized to the same bytes as the original, so the retained signature
// verified it: one signature authenticating two different wires. The test
// requires rejection AT the Unicode boundary specifically, because rejection at
// the signature layer would mean the aliasing still existed and merely happened
// not to be exploitable with this key.
func TestVerifyRejectsSurrogateSubstitutionOnValidSignedWire(t *testing.T) {
	_, signing, verifying := strictTestKeys(t)
	keys := map[string]identity.Ed25519VerifyingKey{"key-1": verifying}

	// A valid signed envelope carrying the replacement character in its id.
	members := strictCaseMembers(strictCaseBody(), "")
	for i, member := range members {
		if strings.HasPrefix(member, `"id":`) {
			members[i] = `"id":"case-�"`
		}
	}
	valid := signRawMembers(t, signing, members)

	// Control: it must verify as-is, or the substitution below proves nothing.
	if _, err := Verify(valid, keys, unicodeSignNow); err != nil {
		t.Fatalf("control wire does not verify: %v\nwire: %s", err, valid)
	}

	// Substitute ONLY the id token, leaving the signature in place.
	for _, malformed := range []string{
		`"id":"case-\uD800\uD800"`,
		`"id":"case-\uD800\uD801"`,
		`"id":"case-\uDC00\uD800"`,
	} {
		substituted := strings.Replace(string(valid), `"id":"case-�"`, malformed, 1)
		if substituted == string(valid) {
			t.Fatalf("substitution did not apply; the test would prove nothing")
		}
		_, err := Verify([]byte(substituted), keys, unicodeSignNow)
		if err == nil {
			t.Fatalf("Verify accepted a surrogate-substituted wire under the original signature: %s", malformed)
		}
		message := err.Error()
		if !strings.Contains(message, "surrogate") {
			t.Fatalf("rejected for the wrong reason (%v); the Unicode boundary must refuse this, not the signature layer", err)
		}
		if strings.Contains(message, "signature") {
			t.Fatalf("rejected at the signature layer (%v); the canonical aliasing would still exist", err)
		}
	}
}
