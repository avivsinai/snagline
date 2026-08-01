package ssp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
)

var vectorNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

const registryProofKeyID = "registry-pinned-key-2026-07"

func registrySigningKey(t *testing.T, label string) identity.Ed25519SigningKey {
	t.Helper()
	key, err := identity.NewEd25519SigningKey(documentedVectorPrivateKey(label))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func zeroRegistryWithNegativeZeroHeaders(t *testing.T) (canonicalZero, negativeZero []byte) {
	t.Helper()
	var envelope Envelope
	if err := json.Unmarshal(readVector(t, "registry-v1.signed.json"), &envelope); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		t.Fatal(err)
	}
	body["revision"] = float64(0)
	body["routing_epoch"] = float64(0)
	domains, ok := body["domains"].([]any)
	if !ok || len(domains) == 0 {
		t.Fatal("registry vector has no domains")
	}
	for i, entry := range domains {
		domain, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("registry domain %d is not an object", i)
		}
		domain["routing_epoch"] = float64(0)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Body = encoded
	envelope.ID = "registry-envelope-negative-zero"
	envelope.RegistryRevision = 0
	envelope.RoutingEpoch = 0
	envelope.Signature = ""

	canonicalZero, err = Sign(envelope, registrySigningKey(t, registryProofKeyID), vectorNow)
	if err != nil {
		t.Fatal(err)
	}
	negativeZero = append([]byte(nil), canonicalZero...)
	for _, field := range []string{"routing_epoch", "registry_revision"} {
		zero := []byte(`"` + field + `":0`)
		index := bytes.Index(negativeZero, zero)
		bodyIndex := bytes.Index(negativeZero, []byte(`"body":`))
		if index < 0 || bodyIndex < 0 || index > bodyIndex {
			t.Fatalf("signed registry has no top-level %s zero", field)
		}
		negativeZero = bytes.Replace(negativeZero, zero, []byte(`"`+field+`":-0`), 1)
	}
	return canonicalZero, negativeZero
}

func TestVerifyRegistryAcceptsNegativeZeroAndCommitsCanonicalZero(t *testing.T) {
	canonicalZero, negativeZero := zeroRegistryWithNegativeZeroHeaders(t)

	proof, err := VerifyRegistry(
		negativeZero,
		registryProofKeyID,
		documentedVectorKeyForLabel(t, registryProofKeyID),
		vectorNow,
	)
	if err != nil {
		t.Fatalf("verify negative-zero registry: %v", err)
	}
	revision, err := proof.Revision()
	if err != nil || revision != 0 {
		t.Fatalf("revision = %d, err = %v", revision, err)
	}
	epoch, err := proof.RoutingEpoch()
	if err != nil || epoch != 0 {
		t.Fatalf("routing epoch = %d, err = %v", epoch, err)
	}
	raw, err := proof.Raw()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, negativeZero) {
		t.Fatal("proof did not preserve the verified negative-zero wire")
	}
	for _, field := range []string{"routing_epoch", "registry_revision"} {
		if !bytes.Contains(raw, []byte(`"`+field+`":-0`)) {
			t.Fatalf("proof raw bytes lost %s negative-zero alias", field)
		}
	}

	gotCommitment, err := proof.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	wantCommitment, err := EnvelopeCommitment(canonicalZero, vectorNow)
	if err != nil {
		t.Fatal(err)
	}
	if gotCommitment != wantCommitment {
		t.Fatalf("negative-zero commitment = %q, canonical-zero commitment = %q", gotCommitment, wantCommitment)
	}
}

func TestVerifyRegistryMintsProofForPinnedVector(t *testing.T) {
	raw := readVector(t, "registry-v1.signed.json")
	proof, err := VerifyRegistry(raw, registryProofKeyID, documentedVectorKeyForLabel(t, registryProofKeyID), vectorNow)
	if err != nil {
		t.Fatalf("verify registry: %v", err)
	}
	if proof.IsZero() {
		t.Fatal("proof reports itself as zero")
	}

	revision, err := proof.Revision()
	if err != nil || revision != 12 {
		t.Fatalf("revision = %d, err = %v", revision, err)
	}
	epoch, err := proof.RoutingEpoch()
	if err != nil || epoch != 7 {
		t.Fatalf("routing epoch = %d, err = %v", epoch, err)
	}
	author, err := proof.AuthorKeyID()
	if err != nil || author != registryProofKeyID {
		t.Fatalf("author = %q, err = %v", author, err)
	}

	// The commitment must be the same value the standalone helper produces, so
	// the proof does not introduce a second definition of registry_hash.
	want, err := EnvelopeCommitment(raw, vectorNow)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := proof.Commitment()
	if err != nil || commitment != want {
		t.Fatalf("commitment = %q, want %q, err = %v", commitment, want, err)
	}
}

// TestVerifyRegistryRejectsUnauthenticEnvelopes is the reason this type exists:
// structural validity is not authenticity, and each of these is structurally
// fine.
func TestVerifyRegistryRejectsUnauthenticEnvelopes(t *testing.T) {
	pinned := documentedVectorKeyForLabel(t, registryProofKeyID)
	raw := readVector(t, "registry-v1.signed.json")

	decode := func() map[string]any {
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		return object
	}
	encode := func(object map[string]any) []byte {
		encoded, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	t.Run("signature removed", func(t *testing.T) {
		object := decode()
		delete(object, "signature")
		if _, err := VerifyRegistry(encode(object), registryProofKeyID, pinned, vectorNow); err == nil {
			t.Fatal("minted proof for an unsigned envelope")
		}
	})

	t.Run("signature emptied", func(t *testing.T) {
		object := decode()
		object["signature"] = ""
		if _, err := VerifyRegistry(encode(object), registryProofKeyID, pinned, vectorNow); err == nil {
			t.Fatal("minted proof for an empty signature")
		}
	})

	t.Run("signed field mutated", func(t *testing.T) {
		object := decode()
		object["id"] = "registry-envelope-9999"
		if _, err := VerifyRegistry(encode(object), registryProofKeyID, pinned, vectorNow); err == nil {
			t.Fatal("minted proof for a mutated signed field")
		}
	})

	t.Run("body mutated", func(t *testing.T) {
		object := decode()
		body, ok := object["body"].(map[string]any)
		if !ok {
			t.Fatal("body is not an object")
		}
		body["revision"] = float64(13)
		object["registry_revision"] = float64(13)
		if _, err := VerifyRegistry(encode(object), registryProofKeyID, pinned, vectorNow); err == nil {
			t.Fatal("minted proof for a mutated body")
		}
	})

	t.Run("unrelated pinned key", func(t *testing.T) {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		other, err := identity.NewEd25519VerifyingKey(public)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRegistry(raw, registryProofKeyID, other, vectorNow); err == nil {
			t.Fatal("minted proof under an unrelated pinned key")
		}
	})

	t.Run("author relabelled while validly signed", func(t *testing.T) {
		// Signed correctly by the vector key, but claiming a different author id.
		// The pinned key must be unreachable under any id but the pinned one.
		var envelope Envelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.AuthorKeyID = "dispatcher-key-2026-07"
		envelope.Signature = ""
		relabelled, err := Sign(envelope, registrySigningKey(t, registryProofKeyID), vectorNow)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRegistry(relabelled, registryProofKeyID, pinned, vectorNow); err == nil {
			t.Fatal("minted proof for an envelope authored under a non-pinned id")
		}
	})

	t.Run("in-body registry key cannot impersonate trust anchor", func(t *testing.T) {
		var envelope Envelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.Signature = ""
		forged, err := Sign(envelope, registrySigningKey(t, "registry-key-2026-07"), vectorNow)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRegistry(forged, registryProofKeyID, pinned, vectorNow); err == nil {
			t.Fatal("minted proof for trust-anchor label signed by the in-body registry key")
		}
	})

	t.Run("in-body registry author is not the configured trust anchor", func(t *testing.T) {
		var envelope Envelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.AuthorKeyID = "registry-key-2026-07"
		envelope.Signature = ""
		signed, err := Sign(envelope, registrySigningKey(t, "registry-key-2026-07"), vectorNow)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRegistry(signed, registryProofKeyID, pinned, vectorNow); err == nil {
			t.Fatal("minted proof for an in-body registry author under the configured trust anchor")
		}
	})

	t.Run("wrong family", func(t *testing.T) {
		// A validly signed case envelope must not be laundered into registry
		// authority.
		edgeKey := documentedVectorKey(t, "edge-public-key.txt")
		if _, err := VerifyRegistry(readVector(t, "case-v1.signed.json"), "edge-key-2026-07", edgeKey, vectorNow); !errors.Is(err, ErrUnknownFamily) {
			t.Fatalf("error = %v, want ErrUnknownFamily", err)
		}
	})

	t.Run("expired at evaluation time", func(t *testing.T) {
		if _, err := VerifyRegistry(raw, registryProofKeyID, pinned, vectorNow.AddDate(1, 0, 0)); err == nil {
			t.Fatal("minted proof for an expired envelope")
		}
	})

	t.Run("missing pinned arguments", func(t *testing.T) {
		if _, err := VerifyRegistry(raw, "", pinned, vectorNow); err == nil {
			t.Fatal("accepted an empty expected author key id")
		}
		if _, err := VerifyRegistry(raw, registryProofKeyID, identity.Ed25519VerifyingKey{}, vectorNow); err == nil {
			t.Fatal("accepted a zero verifying key")
		}
	})
}

// TestZeroProofProvesNothing pins the property that makes the type useful to a
// downstream package: a value nobody minted must be unusable in every direction.
func TestZeroProofProvesNothing(t *testing.T) {
	var zero VerifiedRegistryEnvelope
	if !zero.IsZero() {
		t.Fatal("zero value does not report itself as zero")
	}
	if _, err := zero.Raw(); !errors.Is(err, ErrUnverifiedProof) {
		t.Fatalf("Raw error = %v", err)
	}
	if _, err := zero.Envelope(); !errors.Is(err, ErrUnverifiedProof) {
		t.Fatalf("Envelope error = %v", err)
	}
	if _, err := zero.Commitment(); !errors.Is(err, ErrUnverifiedProof) {
		t.Fatalf("Commitment error = %v", err)
	}
	if _, err := zero.AuthorKeyID(); !errors.Is(err, ErrUnverifiedProof) {
		t.Fatalf("AuthorKeyID error = %v", err)
	}
	if _, err := zero.Revision(); !errors.Is(err, ErrUnverifiedProof) {
		t.Fatalf("Revision error = %v", err)
	}
	if _, err := zero.RoutingEpoch(); !errors.Is(err, ErrUnverifiedProof) {
		t.Fatalf("RoutingEpoch error = %v", err)
	}
	if _, err := zero.VerifiedAt(); !errors.Is(err, ErrUnverifiedProof) {
		t.Fatalf("VerifiedAt error = %v", err)
	}
	if _, err := zero.ReverifyAt(vectorNow); !errors.Is(err, ErrUnverifiedProof) {
		t.Fatalf("ReverifyAt error = %v", err)
	}
}

// TestReverifyAtRebindsTheInstant covers the divergence a durable-write boundary
// has to close: proof minted while live must not stay usable once the envelope
// has expired.
func TestReverifyAtRebindsTheInstant(t *testing.T) {
	raw := readVector(t, "registry-v1.signed.json")
	proof, err := VerifyRegistry(raw, registryProofKeyID, documentedVectorKeyForLabel(t, registryProofKeyID), vectorNow)
	if err != nil {
		t.Fatal(err)
	}

	// Still inside the validity window: re-verification succeeds and reports the
	// new instant.
	later := vectorNow.Add(24 * time.Hour)
	fresh, err := proof.ReverifyAt(later)
	if err != nil {
		t.Fatalf("reverify inside the window: %v", err)
	}
	at, err := fresh.VerifiedAt()
	if err != nil || !at.Equal(later) {
		t.Fatalf("VerifiedAt = %s, want %s, err = %v", at, later, err)
	}
	firstAt, err := proof.VerifiedAt()
	if err != nil || !firstAt.Equal(vectorNow) {
		t.Fatalf("original proof instant moved: %s", firstAt)
	}

	// Past expiry: re-verification fails, so a stale proof cannot authorize a
	// later durable action.
	if _, err := proof.ReverifyAt(vectorNow.AddDate(1, 0, 0)); err == nil {
		t.Fatal("re-verified an expired envelope")
	}
}

// TestProofAccessorsReturnCopies proves a holder cannot edit what was verified.
func TestProofAccessorsReturnCopies(t *testing.T) {
	raw := append([]byte(nil), readVector(t, "registry-v1.signed.json")...)
	original := append([]byte(nil), raw...)

	proof, err := VerifyRegistry(raw, registryProofKeyID, documentedVectorKeyForLabel(t, registryProofKeyID), vectorNow)
	if err != nil {
		t.Fatal(err)
	}

	// Mutating the caller's buffer must not change the proof.
	raw[0] ^= 0xff
	sealed, err := proof.Raw()
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) != string(original) {
		t.Fatal("mutating the caller's buffer changed the proof")
	}

	// Mutating a returned copy must not change the proof either.
	sealed[0] ^= 0xff
	again, err := proof.Raw()
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(original) {
		t.Fatal("mutating a returned copy changed the proof")
	}

	envelope, err := proof.Envelope()
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.Body) == 0 {
		t.Fatal("projected envelope has no body")
	}
	envelope.Body[0] = ' '
	fresh, err := proof.Envelope()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Body[0] == ' ' {
		t.Fatal("mutating a projected body changed the proof")
	}
	if !strings.HasPrefix(string(fresh.Body), "{") {
		t.Fatalf("projected body is not an object: %q", fresh.Body[:1])
	}
}
