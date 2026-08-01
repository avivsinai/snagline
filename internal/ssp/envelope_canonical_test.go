package ssp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
)

var canonicalNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

// alternateTailEncoding returns a different base64url text that decodes to the
// same bytes, by varying the unused low bits of the final character. It returns
// "" when no such text exists for this input.
func alternateTailEncoding(t *testing.T, encoded string) string {
	t.Helper()
	want, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < len(alphabet); i++ {
		candidate := encoded[:len(encoded)-1] + string(alphabet[i])
		if candidate == encoded {
			continue
		}
		got, err := base64.RawURLEncoding.DecodeString(candidate)
		if err == nil && string(got) == string(want) {
			return candidate
		}
	}
	return ""
}

// TestDecodeCanonicalBase64 pins the property that a byte string has exactly one
// accepted textual form.
func TestDecodeCanonicalBase64(t *testing.T) {
	raw := readVector(t, "case-v1.signed.json")
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	signature, ok := object["signature"].(string)
	if !ok {
		t.Fatal("vector has no signature")
	}

	// Canonical control: the vector's own signature must still decode.
	decoded, err := DecodeCanonicalBase64(signature, ed25519.SignatureSize)
	if err != nil {
		t.Fatalf("canonical signature rejected: %v", err)
	}
	if len(decoded) != ed25519.SignatureSize {
		t.Fatalf("decoded %d bytes", len(decoded))
	}

	// The non-canonical sibling that plain RawURLEncoding accepts must not.
	alternate := alternateTailEncoding(t, signature)
	if alternate == "" {
		t.Fatal("no alternate tail encoding exists; this test would prove nothing")
	}
	if plain, err := base64.RawURLEncoding.DecodeString(alternate); err != nil || string(plain) != string(decoded) {
		t.Fatalf("alternate does not decode to identical bytes under plain decoding: %v", err)
	}
	if _, err := DecodeCanonicalBase64(alternate, ed25519.SignatureSize); err == nil {
		t.Fatal("accepted a non-canonical alternate encoding of the same bytes")
	}

	// Wrong decoded length is refused even when the text is canonical.
	short := base64.RawURLEncoding.EncodeToString(decoded[:32])
	if _, err := DecodeCanonicalBase64(short, ed25519.SignatureSize); err == nil {
		t.Fatal("accepted a canonically encoded value of the wrong length")
	}

	// Padding and non-alphabet input are refused.
	for name, bad := range map[string]string{
		"standard padding": base64.URLEncoding.EncodeToString(decoded),
		"non alphabet":     strings.Repeat("*", len(signature)),
		"empty":            "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCanonicalBase64(bad, ed25519.SignatureSize); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

// TestVerifyRejectsNonCanonicalSignature is the end-to-end consequence: one
// signed statement must have exactly one verifiable wire form. Otherwise a
// replay defence keyed on payload identity can be bypassed by re-encoding the
// signature, because the commitment strips the signature and does not change.
func TestVerifyRejectsNonCanonicalSignature(t *testing.T) {
	raw := readVector(t, "case-v1.signed.json")
	keys := map[string]identity.Ed25519VerifyingKey{
		"edge-key-2026-07": documentedVectorKey(t, "edge-public-key.txt"),
	}

	// Canonical control verifies.
	if _, err := Verify(raw, keys, canonicalNow); err != nil {
		t.Fatalf("canonical vector rejected: %v", err)
	}

	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	signature, _ := object["signature"].(string)
	alternate := alternateTailEncoding(t, signature)
	if alternate == "" {
		t.Fatal("no alternate tail encoding exists; this test would prove nothing")
	}
	object["signature"] = alternate
	reencoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(reencoded, keys, canonicalNow); err == nil {
		t.Fatal("Verify accepted a non-canonical encoding of a valid signature")
	}
}
