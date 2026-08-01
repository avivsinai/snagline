package ssp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
)

func TestVerifyRejectsSignedCaseFoldedMembers(t *testing.T) {
	public, signing, verifying := strictTestKeys(t)
	now := strictTestNow()
	base := strictCaseMembers(strictCaseBody(), "")

	tests := []struct {
		name    string
		members []string
	}{
		{
			name:    "envelope alias",
			members: append(append([]string{}, base...), `"Schema":"ssp.case.v1"`),
		},
		{
			name:    "body alias",
			members: strictCaseMembers(`{"domain":"runtime","issuer_edge_id":"edge-1","issuer_edge_generation":1,"summary":"help","Summary":"help","context_manifest":"sha256:`+strings.Repeat("b", 64)+`"}`, ""),
		},
		{
			name:    "forbidden provenance",
			members: strictCaseMembers(strictCaseBody(), `{"transport":"direct"}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := signRawMembers(t, signing, test.members)
			assertSignedWire(t, public, wire)
			if _, err := Verify(wire, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, now); !errors.Is(err, ErrUnknownField) {
				t.Fatalf("Verify error = %v, want exact-member rejection", err)
			}
		})
	}
}

func TestVerifyRejectsSignedCanonicalAliasCollisionsInEitherOrder(t *testing.T) {
	public, signing, verifying := strictTestKeys(t)
	now := strictTestNow()
	base := strictCaseMembers(strictCaseBody(), "")

	tests := map[string][][]string{
		"envelope": {
			append([]string{base[0], `"Schema":"ssp.case.v1"`}, base[1:]...),
			append([]string{`"Schema":"ssp.case.v1"`}, base...),
		},
		"body": {
			strictCaseMembers(`{"domain":"runtime","issuer_edge_id":"edge-1","issuer_edge_generation":1,"summary":"help","Summary":"help","context_manifest":"sha256:`+strings.Repeat("b", 64)+`"}`, ""),
			strictCaseMembers(`{"domain":"runtime","issuer_edge_id":"edge-1","issuer_edge_generation":1,"Summary":"help","summary":"help","context_manifest":"sha256:`+strings.Repeat("b", 64)+`"}`, ""),
		},
		"forbidden provenance": {
			strictCaseMembers(strictCaseBody(), `{"transport":"direct","Transport":"direct"}`),
			strictCaseMembers(strictCaseBody(), `{"Transport":"direct","transport":"direct"}`),
		},
	}
	for level, wires := range tests {
		for order, members := range wires {
			t.Run(level+" order "+strconv.Itoa(order), func(t *testing.T) {
				wire := signRawMembers(t, signing, members)
				assertSignedWire(t, public, wire)
				if _, err := Verify(wire, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, now); !errors.Is(err, ErrUnknownField) {
					t.Fatalf("Verify error = %v, want exact-member rejection", err)
				}
			})
		}
	}
}

func TestVerifyRejectsSignedMissingOrNullAuthorityCoordinates(t *testing.T) {
	public, signing, verifying := strictTestKeys(t)
	now := strictTestNow()
	base := strictCaseMembers(strictCaseBody(), "")

	tests := []struct {
		name    string
		members []string
	}{
		{"missing routing_epoch", withoutMember(base, `"routing_epoch":7`)},
		{"missing registry_revision", withoutMember(base, `"registry_revision":12`)},
		{"null routing_epoch", replaceMember(base, `"routing_epoch":7`, `"routing_epoch":null`)},
		{"null registry_revision", replaceMember(base, `"registry_revision":12`, `"registry_revision":null`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := signRawMembers(t, signing, test.members)
			assertSignedWire(t, public, wire)
			if _, err := Verify(wire, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, now); err == nil {
				t.Fatal("Verify accepted missing or null authority coordinate")
			}
		})
	}
}

func TestVerifyRejectsSignedAdviceOptionalPresenceViolations(t *testing.T) {
	public, signing, verifying := strictTestKeys(t)
	now := strictTestNow()
	for _, body := range []string{
		`{"case_commitment":"sha256:` + strings.Repeat("c", 64) + `","text":"advice","obsolete_field":""}`,
		`{"case_commitment":"sha256:` + strings.Repeat("c", 64) + `","text":"advice","obsolete_field":null}`,
	} {
		wire := signRawMembers(t, signing, strictAdviceMembers(body, ""))
		assertSignedWire(t, public, wire)
		if _, err := Verify(wire, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, now); err == nil {
			t.Fatal("Verify accepted obsolete advice member")
		}
	}
}

func TestVerifyRejectsSignedProvenance(t *testing.T) {
	public, signing, verifying := strictTestKeys(t)
	wire := signRawMembers(t, signing, strictCaseMembers(strictCaseBody(), `{"transport":"direct","refs":null}`))
	assertSignedWire(t, public, wire)
	if _, err := Verify(wire, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, strictTestNow()); err == nil {
		t.Fatal("Verify accepted unsigned provenance")
	}
}

func TestVerifyAcceptsSignedExactSchemaMembers(t *testing.T) {
	public, signing, verifying := strictTestKeys(t)
	wire := signRawMembers(t, signing, strictCaseMembers(strictCaseBody(), ""))
	assertSignedWire(t, public, wire)
	if _, err := Verify(wire, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, strictTestNow()); err != nil {
		t.Fatalf("Verify exact schema members: %v", err)
	}
}

func TestVerifyAcceptsSignedNegativeZeroAuthorityCoordinates(t *testing.T) {
	public, signing, verifying := strictTestKeys(t)
	members := strictCaseMembers(strictCaseBody(), "")
	members = replaceMember(members, `"routing_epoch":7`, `"routing_epoch":0`)
	members = replaceMember(members, `"registry_revision":12`, `"registry_revision":0`)
	signed := signRawMembers(t, signing, members)

	for _, field := range []string{"routing_epoch", "registry_revision"} {
		t.Run(field, func(t *testing.T) {
			zero := []byte(`"` + field + `":0`)
			negativeZero := []byte(`"` + field + `":-0`)
			if count := bytes.Count(signed, zero); count != 1 {
				t.Fatalf("signed wire contains %d %s zero tokens, want 1", count, field)
			}
			wire := bytes.Replace(signed, zero, negativeZero, 1)
			assertSignedWire(t, public, wire)

			envelope, err := Verify(wire, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, strictTestNow())
			if err != nil {
				t.Fatalf("Verify retained-signature -0 alias: %v", err)
			}
			if envelope.RoutingEpoch != 0 || envelope.RegistryRevision != 0 {
				t.Fatalf("Verify decoded authority coordinates as (%d, %d), want (0, 0)", envelope.RoutingEpoch, envelope.RegistryRevision)
			}
		})
	}
}

func TestRequiredNonNegativeIntegerLexicalForm(t *testing.T) {
	tests := []struct {
		token string
		want  int64
		valid bool
	}{
		{token: "-0", valid: true},
		{token: "0", valid: true},
		{token: "9007199254740991", want: 1<<53 - 1, valid: true},
		{token: "-1"},
		{token: "-00"},
		{token: "00"},
		{token: "01"},
		{token: "0.0"},
		{token: "0e0"},
		{token: "9007199254740992"},
	}

	for _, test := range tests {
		t.Run(test.token, func(t *testing.T) {
			got, err := requiredNonNegativeInteger(
				map[string]json.RawMessage{"coordinate": json.RawMessage(test.token)},
				"coordinate",
				"test",
			)
			if test.valid {
				if err != nil {
					t.Fatalf("requiredNonNegativeInteger(%s): %v", test.token, err)
				}
				if got != test.want {
					t.Fatalf("requiredNonNegativeInteger(%s) = %d, want %d", test.token, got, test.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("requiredNonNegativeInteger(%s) unexpectedly succeeded with %d", test.token, got)
			}
		})
	}
}

func strictTestKeys(t *testing.T) (ed25519.PublicKey, identity.Ed25519SigningKey, identity.Ed25519VerifyingKey) {
	t.Helper()
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
	return public, signing, verifying
}

func strictTestNow() time.Time {
	return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}

func strictCaseMembers(body, provenance string) []string {
	members := []string{
		`"schema":"ssp.case.v1"`,
		`"id":"case-envelope-1"`,
		`"case_id":"case-1"`,
		`"emitted_at":"2030-01-01T00:00:00Z"`,
		`"expires_at":"2030-01-01T01:00:00Z"`,
		`"routing_epoch":7`,
		`"registry_revision":12`,
		`"registry_hash":"sha256:` + strings.Repeat("a", 64) + `"`,
		`"author_key_id":"key-1"`,
		`"signature_alg":"ed25519"`,
		`"body":` + body,
	}
	if provenance != "" {
		members = append(members, `"provenance":`+provenance)
	}
	return members
}

func strictAdviceMembers(body, provenance string) []string {
	members := strictCaseMembers(body, provenance)
	members[0] = `"schema":"ssp.advice.v1"`
	members[1] = `"id":"advice-envelope-1"`
	return members
}

func strictCaseBody() string {
	return `{"domain":"runtime","issuer_edge_id":"edge-1","issuer_edge_generation":1,"summary":"help","context_manifest":"sha256:` + strings.Repeat("b", 64) + `"}`
}

func signRawMembers(t *testing.T, signing identity.Ed25519SigningKey, members []string) []byte {
	t.Helper()
	withoutSignature := []byte("{" + strings.Join(members, ",") + "}")
	unsigned, err := stripUnsignedTopLevel(withoutSignature)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonical(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signing.Sign(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return []byte("{" + strings.Join(append(append([]string{}, members...), `"signature":"`+base64.RawURLEncoding.EncodeToString(signature)+`"`), ",") + "}")
}

func assertSignedWire(t *testing.T, public ed25519.PublicKey, wire []byte) {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(wire, &members); err != nil {
		t.Fatal(err)
	}
	var encoded string
	if err := json.Unmarshal(members["signature"], &encoded); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := stripUnsignedTopLevel(wire)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonical(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, canonical, signature) {
		t.Fatal("test wire has an invalid signature")
	}
}

func withoutMember(members []string, member string) []string {
	result := make([]string, 0, len(members)-1)
	for _, candidate := range members {
		if candidate != member {
			result = append(result, candidate)
		}
	}
	return result
}

func replaceMember(members []string, from, to string) []string {
	result := append([]string{}, members...)
	for index, candidate := range result {
		if candidate == from {
			result[index] = to
			return result
		}
	}
	panic("test member not found")
}
