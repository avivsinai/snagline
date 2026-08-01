package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/ssp"
)

var vectorNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

const (
	pinnedKeyID     = "registry-pinned-key-2026-07"
	vectorKeyDomain = "snagline-ssp-v1-vector:"
)

var rfc8032Seed1 = []byte{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
}

func TestDecodeRegistryBuildsProviderNeutralAuthority(t *testing.T) {
	snapshot := verifyRegistryForTest(t, readVector(t, "registry-v1.signed.json"))

	if snapshot.Revision() != 12 || snapshot.RoutingEpoch() != 7 {
		t.Fatalf("coordinates = (%d,%d)", snapshot.Revision(), snapshot.RoutingEpoch())
	}
	route, ok := snapshot.Domain("runtime")
	if !ok || route.DispatcherPrincipalID != "dispatcher-0001" ||
		!slices.Equal(route.IssuerEdgeIDs, []string{"edge-local-0001"}) ||
		!slices.Equal(route.Families, []string{ssp.FamilyCase, ssp.FamilyAdvice}) {
		t.Fatalf("route = %#v, found=%t", route, ok)
	}
	if !snapshot.AuthorizesCaseIssuer("runtime", "edge-local-0001") ||
		snapshot.AuthorizesCaseIssuer("runtime", "missing") {
		t.Fatal("case issuer authorization is not exact")
	}
	edge, ok := snapshot.Edge("edge-local-0001")
	if !ok || edge.Generation != 1 ||
		!snapshot.AuthorizesCaseIssuerGeneration("runtime", "edge-local-0001", 1) ||
		snapshot.AuthorizesCaseIssuerGeneration("runtime", "edge-local-0001", 2) {
		t.Fatalf("edge generation authorization = %#v, found=%t", edge, ok)
	}
	if _, ok := snapshot.SigningKeyFor("dispatcher-0001", UsageAdvice, vectorNow); !ok {
		t.Fatal("dispatcher advice key not resolved")
	}
	if _, ok := snapshot.SigningKeyFor("dispatcher-0001", UsageEdge, vectorNow); ok {
		t.Fatal("dispatcher gained edge-key authority")
	}
}

func TestRegistryAccessorsDoNotAliasAuthority(t *testing.T) {
	snapshot := verifyRegistryForTest(t, readVector(t, "registry-v1.signed.json"))
	domains := snapshot.Domains()
	principals := snapshot.Principals()
	keys := snapshot.Keys()
	domains[0].IssuerEdgeIDs[0] = "mutated"
	principals[0].SSPKeyIDs[0] = "mutated"
	keys[0].PublicKey[0] ^= 0xff

	route, _ := snapshot.Domain("runtime")
	principal, _ := snapshot.Principal("dispatcher-0001")
	key, _ := snapshot.Key("dispatcher-key-2026-07")
	if route.IssuerEdgeIDs[0] != "edge-local-0001" ||
		principal.SSPKeyIDs[0] != "dispatcher-key-2026-07" ||
		bytes.Equal(key.PublicKey, keys[0].PublicKey) {
		t.Fatal("caller mutation reached registry authority")
	}
}

func TestRegistryEpochAndExactBinding(t *testing.T) {
	snapshot := verifyRegistryForTest(t, readVector(t, "registry-v1.signed.json"))
	if err := snapshot.CheckBinding(snapshot.Revision(), snapshot.Commitment()); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.CheckBinding(snapshot.Revision(), "sha256:"+string(make([]byte, 64))); err == nil {
		t.Fatal("accepted mismatched registry commitment")
	}
	if !snapshot.MachineAcceptableEpoch("runtime", 7) ||
		snapshot.MachineAcceptableEpoch("runtime", 6) ||
		snapshot.MachineAcceptableEpoch("missing", 7) {
		t.Fatal("routing epoch fence failed")
	}
}

func verifyRegistryForTest(t *testing.T, raw []byte) Registry {
	t.Helper()
	verifying, err := identity.NewEd25519VerifyingKey(pinnedKey(t))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ssp.VerifyRegistry(raw, pinnedKeyID, verifying, vectorNow)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := proof.Envelope()
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := proof.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := decodeRegistry(envelope, commitment)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func vectorPath(name string) string {
	return filepath.Join("..", "..", "docs", "ssp", "vectors", name)
}

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(vectorPath(name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(raw)
}

func vectorPrivateKey(label string) ed25519.PrivateKey {
	material := append([]byte(nil), rfc8032Seed1...)
	material = append(material, vectorKeyDomain...)
	material = append(material, label...)
	seed := sha256.Sum256(material)
	return ed25519.NewKeyFromSeed(seed[:])
}

func pinnedKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	return vectorPrivateKey(pinnedKeyID).Public().(ed25519.PublicKey)
}

func signingKey(t *testing.T, label string) identity.Ed25519SigningKey {
	t.Helper()
	key, err := identity.NewEd25519SigningKey(vectorPrivateKey(label))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signedRegistryRevision(t *testing.T, revision int64, id string) []byte {
	t.Helper()
	var envelope ssp.Envelope
	if err := json.Unmarshal(readVector(t, "registry-v1.signed.json"), &envelope); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		t.Fatal(err)
	}
	body["revision"] = float64(revision)
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Body = encoded
	envelope.ID = id
	envelope.RegistryRevision = revision
	envelope.Signature = ""
	raw, err := ssp.Sign(envelope, signingKey(t, pinnedKeyID), vectorNow)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newVerifier(t *testing.T) *Verifier {
	t.Helper()
	trust, err := NewTrust(pinnedKeyID, pinnedKey(t))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(trust, func() time.Time { return vectorNow })
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}
