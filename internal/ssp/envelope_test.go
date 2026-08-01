package ssp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
	"github.com/gowebpki/jcs"
)

var rfc8032VectorSeed = []byte{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
}

const vectorKeyDomain = "snagline-ssp-v1-vector:"

func TestRawGuardRejectsAmbiguousOrInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "duplicate root key", raw: []byte(`{"id":"one","id":"two"}`), want: ErrDuplicateKey},
		{name: "duplicate nested key", raw: []byte(`{"body":{"x":1,"x":2}}`), want: ErrDuplicateKey},
		{name: "trailing value", raw: []byte(`{} {}`)},
		{name: "truncated object", raw: []byte(`{"body":`)},
		{name: "invalid utf8", raw: []byte{'{', 0xff, '}'}},
		{name: "too large", raw: []byte("{" + strings.Repeat("a", MaxEnvelopeBytes) + "}")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := rawGuard(test.raw)
			if err == nil {
				t.Fatal("rawGuard accepted invalid JSON")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("rawGuard error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSignVerifyAndSignedMutation(t *testing.T) {
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
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	envelope := Envelope{
		Schema: "ssp.case.v1", ID: "case-envelope-1", CaseID: "case-1",
		EmittedAt: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T01:00:00Z",
		RoutingEpoch: 1, RegistryRevision: 2, RegistryHash: "sha256:" + strings.Repeat("a", 64),
		AuthorKeyID: "key-1", SignatureAlg: "ed25519",
		Body: json.RawMessage(`{"domain":"runtime","issuer_edge_id":"edge-1","issuer_edge_generation":1,"summary":"confidential help","public_summary":"help","context_manifest":"sha256:` + strings.Repeat("b", 64) + `"}`),
	}
	raw, err := Sign(envelope, signing, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(raw, map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Schema != FamilyCase {
		t.Fatalf("Verify schema = %q, want %q", got.Schema, FamilyCase)
	}
	mutated := strings.Replace(string(raw), `"routing_epoch":1`, `"routing_epoch":2`, 1)
	if _, err := Verify([]byte(mutated), map[string]identity.Ed25519VerifyingKey{"key-1": verifying}, now); err == nil {
		t.Fatal("Verify accepted signed-field mutation")
	}
}

func TestValidateRejectsBodyContractViolations(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	base := Envelope{Schema: "ssp.advice.v1", ID: "a", CaseID: "c", EmittedAt: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T01:00:00Z", RegistryHash: "sha256:" + strings.Repeat("a", 64), AuthorKeyID: "k", SignatureAlg: "ed25519", Body: json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("b", 64) + `","text":"confidential t","public_summary":"t"}`)}
	if err := base.Validate(now); err != nil {
		t.Fatalf("valid advice: %v", err)
	}
	base.Body = json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("b", 64) + `","text":"confidential t","public_summary":"t","unknown":true}`)
	if err := base.Validate(now); err == nil {
		t.Fatal("accepted unknown body field")
	}
	base.Body = json.RawMessage(`{"case_commitment":"sha256:` + strings.Repeat("b", 64) + `","text":1.5,"public_summary":"t"}`)
	if err := base.Validate(now); err == nil {
		t.Fatal("accepted floating point body value")
	}
}

func TestValidateMatchesSchemaBoundaries(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	base := Envelope{
		Schema: "ssp.case.v1", ID: "id", CaseID: "case",
		EmittedAt: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T01:00:00Z",
		RegistryHash: "sha256:" + strings.Repeat("a", 64), AuthorKeyID: "key", SignatureAlg: "ed25519",
		Body: json.RawMessage(`{"domain":"runtime","issuer_edge_id":"edge","issuer_edge_generation":1,"summary":"confidential summary","public_summary":"summary","context_manifest":"sha256:` + strings.Repeat("b", 64) + `"}`),
	}
	if err := base.Validate(now); err != nil {
		t.Fatalf("valid envelope: %v", err)
	}
	for name, mutate := range map[string]func(*Envelope){
		"id":            func(e *Envelope) { e.ID = strings.Repeat("i", 513) },
		"case_id":       func(e *Envelope) { e.CaseID = strings.Repeat("c", 513) },
		"author_key_id": func(e *Envelope) { e.AuthorKeyID = strings.Repeat("k", 513) },
		"issuer_edge_id": func(e *Envelope) {
			e.Body = json.RawMessage(`{"domain":"runtime","issuer_edge_id":"` + strings.Repeat("e", 513) + `","issuer_edge_generation":1,"summary":"confidential summary","public_summary":"summary","context_manifest":"sha256:` + strings.Repeat("b", 64) + `"}`)
		},
		"domain": func(e *Envelope) {
			e.Body = json.RawMessage(`{"domain":"` + strings.Repeat("d", 513) + `","issuer_edge_id":"edge","issuer_edge_generation":1,"summary":"confidential summary","public_summary":"summary","context_manifest":"sha256:` + strings.Repeat("b", 64) + `"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if err := changed.Validate(now); err == nil {
				t.Fatal("accepted schema-boundary violation")
			}
		})
	}
}

func TestValidateEnforcesTrustedEmissionBoundary(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	base := Envelope{
		Schema: "ssp.case.v1", ID: "id", CaseID: "case",
		EmittedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		RegistryHash: "sha256:" + strings.Repeat("a", 64), AuthorKeyID: "key", SignatureAlg: "ed25519",
		Body: json.RawMessage(`{"domain":"runtime","issuer_edge_id":"edge","issuer_edge_generation":1,"summary":"confidential summary","public_summary":"summary","context_manifest":"sha256:` + strings.Repeat("b", 64) + `"}`),
	}
	if err := base.Validate(now); err != nil {
		t.Fatalf("emitted_at boundary: %v", err)
	}
	base.EmittedAt = now.Add(time.Second).Format(time.RFC3339)
	if err := base.Validate(now); err == nil {
		t.Fatal("accepted future emitted_at")
	}
}

func TestValidateRejectsNonSSPUTCTimestamps(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	base := Envelope{
		Schema: "ssp.case.v1", ID: "id", CaseID: "case",
		EmittedAt: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T01:00:00Z",
		RegistryHash: "sha256:" + strings.Repeat("a", 64), AuthorKeyID: "key", SignatureAlg: "ed25519",
		Body: json.RawMessage(`{"domain":"runtime","issuer_edge_id":"edge","issuer_edge_generation":1,"summary":"confidential summary","public_summary":"summary","context_manifest":"sha256:` + strings.Repeat("b", 64) + `"}`),
	}
	for name, timestamp := range map[string]string{
		"offset":       "2030-01-01T00:00:00+00:00",
		"seven digits": "2030-01-01T00:00:00.1234567Z",
		"trailing LF":  "2030-01-01T00:00:00Z\n",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.EmittedAt = timestamp
			if err := candidate.Validate(now); err == nil {
				t.Fatalf("accepted non-SSP timestamp %q", timestamp)
			}
		})
	}
}

func TestDocumentedJCSVectors(t *testing.T) {
	for _, family := range []string{"case-v1", "advice-v1", "registry-v1"} {
		inputPath := filepath.Join("..", "..", "docs", "ssp", "vectors", family+".signing-input.json")
		wantPath := filepath.Join("..", "..", "docs", "ssp", "vectors", family+".signing-input.jcs")
		input, err := os.ReadFile(inputPath)
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(wantPath)
		if err != nil {
			t.Fatal(err)
		}
		got, err := canonical(input)
		if err != nil {
			t.Fatalf("canonical(%s): %v", family, err)
		}
		if string(got) != strings.TrimSpace(string(want)) {
			t.Fatalf("%s JCS mismatch\ngot:  %s\nwant: %s", family, got, want)
		}
	}
}

func TestPublishedRFC8785Corpus(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join("testdata", "rfc8785", "input", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 10 {
		t.Fatalf("RFC 8785 corpus size = %d, want 10", len(inputs))
	}
	for _, inputPath := range inputs {
		name := filepath.Base(inputPath)
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", "rfc8785", "output", name))
			if err != nil {
				t.Fatal(err)
			}
			got, err := jcs.Transform(bytes.TrimSuffix(input, []byte{'\n'}))
			if err != nil {
				t.Fatalf("JCS transform: %v", err)
			}
			if !bytes.Equal(got, bytes.TrimSuffix(want, []byte{'\n'})) {
				t.Fatalf("RFC 8785 mismatch\ngot:  %q\nwant: %q", got, want)
			}
		})
	}
}

func TestIndependentSignedVectors(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for _, fixture := range []struct {
		file    string
		keyFile string
		keyID   string
	}{
		{file: "case-v1.signed.json", keyFile: "edge-public-key.txt", keyID: "edge-key-2026-07"},
		{file: "advice-v1.signed.json", keyFile: "dispatcher-public-key.txt", keyID: "dispatcher-key-2026-07"},
		{file: "registry-v1.signed.json", keyFile: "registry-pinned-public-key.txt", keyID: "registry-pinned-key-2026-07"},
	} {
		raw := readVector(t, fixture.file)
		key := documentedVectorKey(t, fixture.keyFile)
		if _, err := Verify(raw, map[string]identity.Ed25519VerifyingKey{fixture.keyID: key}, now); err != nil {
			t.Fatalf("%s: %v", fixture.file, err)
		}
	}
	key := documentedVectorKey(t, "edge-public-key.txt")
	if _, err := Verify(readVector(t, "case-v1-tampered-routing-epoch.json"), map[string]identity.Ed25519VerifyingKey{"edge-key-2026-07": key}, now); err == nil {
		t.Fatal("tampered signed vector verified")
	}
	registryKey := documentedVectorKey(t, "registry-pinned-public-key.txt")
	if _, err := Verify(
		readVector(t, "registry-v1-header-body-revision-mismatch.signed.json"),
		map[string]identity.Ed25519VerifyingKey{"registry-pinned-key-2026-07": registryKey},
		now,
	); err == nil {
		t.Fatal("registry header/body mismatch vector verified")
	}
	if err := rawGuard(readVector(t, "case-v1-duplicate-key.json")); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate vector error = %v, want ErrDuplicateKey", err)
	}
}

func TestVerifySentinelsAndSignedFieldMutations(t *testing.T) {
	key := documentedVectorKey(t, "edge-public-key.txt")
	keys := map[string]identity.Ed25519VerifyingKey{"edge-key-2026-07": key}
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	valid := readVector(t, "case-v1.signed.json")

	var object map[string]any
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	if _, err := Verify(unknown, keys, now); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("unknown field error = %v, want ErrUnknownField", err)
	}

	mutations := map[string]func(map[string]any){
		"schema":            func(v map[string]any) { v["schema"] = "ssp.proposal.v1" },
		"id":                func(v map[string]any) { v["id"] = "changed" },
		"case_id":           func(v map[string]any) { v["case_id"] = "changed" },
		"emitted_at":        func(v map[string]any) { v["emitted_at"] = "2026-07-28T00:00:01Z" },
		"expires_at":        func(v map[string]any) { v["expires_at"] = "2026-07-28T23:59:59Z" },
		"routing_epoch":     func(v map[string]any) { v["routing_epoch"] = float64(8) },
		"registry_revision": func(v map[string]any) { v["registry_revision"] = float64(13) },
		"registry_hash":     func(v map[string]any) { v["registry_hash"] = "sha256:" + strings.Repeat("d", 64) },
		"author_key_id":     func(v map[string]any) { v["author_key_id"] = "changed" },
		"signature_alg":     func(v map[string]any) { v["signature_alg"] = "changed" },
		"body": func(v map[string]any) {
			v["body"].(map[string]any)["summary"] = "changed"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var changed map[string]any
			if err := json.Unmarshal(valid, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(changed)
			raw, _ := json.Marshal(changed)
			_, err := Verify(raw, keys, now)
			if err == nil {
				t.Fatal("accepted signed-field mutation")
			}
			if name == "schema" && !errors.Is(err, ErrUnknownFamily) {
				t.Fatalf("schema mutation error = %v, want ErrUnknownFamily", err)
			}
		})
	}

	var badSignature map[string]any
	_ = json.Unmarshal(valid, &badSignature)
	badSignature["signature"] = "not-base64!"
	raw, _ := json.Marshal(badSignature)
	if _, err := Verify(raw, keys, now); err == nil || !strings.Contains(err.Error(), "invalid signature") || errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("bad signature error = %v", err)
	}
	invalidUTF8 := append([]byte(nil), valid...)
	invalidUTF8[10] = 0xff
	if _, err := Verify(invalidUTF8, keys, now); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") || !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "ssp", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(raw)
}

func documentedVectorKey(t *testing.T, filename string) identity.Ed25519VerifyingKey {
	t.Helper()
	encoded := string(readVector(t, filename))
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewEd25519VerifyingKey(ed25519.PublicKey(raw))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func documentedVectorPrivateKey(label string) ed25519.PrivateKey {
	material := make([]byte, 0, len(rfc8032VectorSeed)+len(vectorKeyDomain)+len(label))
	material = append(material, rfc8032VectorSeed...)
	material = append(material, vectorKeyDomain...)
	material = append(material, label...)
	seed := sha256.Sum256(material)
	return ed25519.NewKeyFromSeed(seed[:])
}

func documentedVectorKeyForLabel(t *testing.T, label string) identity.Ed25519VerifyingKey {
	t.Helper()
	public := documentedVectorPrivateKey(label).Public().(ed25519.PublicKey)
	key, err := identity.NewEd25519VerifyingKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDerivedRegistryKeysMatchPublishedSplit(t *testing.T) {
	published := map[string]string{
		"registry-pinned-key-2026-07": "registry-pinned-public-key.txt",
		"registry-key-2026-07":        "registry-public-key.txt",
	}
	derived := make(map[string]ed25519.PublicKey, len(published))
	for label, file := range published {
		encoded := string(readVector(t, file))
		want, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("%s: decode public key: %v", file, err)
		}
		got := documentedVectorPrivateKey(label).Public().(ed25519.PublicKey)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s does not match the key derived for %q", file, label)
		}
		derived[label] = got
	}
	if bytes.Equal(derived["registry-pinned-key-2026-07"], derived["registry-key-2026-07"]) {
		t.Fatal("registry trust anchor and in-body registry-usage key are identical")
	}
}

func TestRawGuardEnforcesNestingLimit(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		valid bool
	}{
		{
			name:  "scalar at limit",
			raw:   `{"a":` + strings.Repeat("[", MaxDepth-1) + "null" + strings.Repeat("]", MaxDepth-1) + `}`,
			valid: true,
		},
		{
			name:  "empty array at limit",
			raw:   `{"a":` + strings.Repeat("[", MaxDepth-1) + strings.Repeat("]", MaxDepth-1) + `}`,
			valid: true,
		},
		{
			name:  "empty object at limit",
			raw:   `{"a":` + strings.Repeat("[", MaxDepth-2) + "{}" + strings.Repeat("]", MaxDepth-2) + `}`,
			valid: true,
		},
		{
			name: "scalar beyond limit",
			raw:  `{"a":` + strings.Repeat("[", MaxDepth) + "null" + strings.Repeat("]", MaxDepth) + `}`,
		},
		{
			name: "empty array beyond limit",
			raw:  `{"a":` + strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth) + `}`,
		},
		{
			name: "empty object beyond limit",
			raw:  `{"a":` + strings.Repeat("[", MaxDepth-1) + "{}" + strings.Repeat("]", MaxDepth-1) + `}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := rawGuard([]byte(test.raw))
			if test.valid {
				if err != nil {
					t.Fatalf("rawGuard rejected valid %d-container boundary: %v", MaxDepth, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "nesting depth exceeded") {
				t.Fatalf("rawGuard depth error = %v, want nesting depth rejection", err)
			}
		})
	}
}
