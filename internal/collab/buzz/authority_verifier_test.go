package buzz

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/registry"
	"github.com/avivsinai/snagline/internal/ssp"
)

func TestAuthorityVerifierAuthenticatesHistoricalCommittedVectorsFromPinnedRegistry(t *testing.T) {
	registryRaw := readBuzzVector(t, "registry-v1.signed.json")
	caseRaw := readBuzzVector(t, "case-v1.signed.json")
	adviceRaw := readBuzzVector(t, "advice-v1.signed.json")
	registryCommitment := strings.TrimSpace(string(readBuzzVector(t, "registry-v1.commitment.txt")))
	caseEmission, err := signedEmissionTime(caseRaw)
	if err != nil {
		t.Fatal(err)
	}
	caseCommitment, err := ssp.EnvelopeCommitment(caseRaw, caseEmission)
	if err != nil {
		t.Fatal(err)
	}

	rootText := strings.TrimSpace(string(readBuzzVector(t, "registry-pinned-public-key.txt")))
	root, err := base64.RawURLEncoding.DecodeString(rootText)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := registry.NewTrust("registry-pinned-key-2026-07", ed25519.PublicKey(root))
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeCommittedAuthority{
		registry: authority.RegistryRecord{
			TenantID: "tenant-a", Revision: 12, Commitment: registryCommitment,
			Raw: registryRaw, RoutingEpoch: 7,
		},
		caseRecord: authority.CaseRecord{
			TenantID: "tenant-a", CaseID: "case-0001",
			EnvelopeID: "case-envelope-0001",
			Commitment: caseCommitment,
			Raw:        caseRaw, Domain: "runtime", IssuerEdgeID: "edge-local-0001",
			IssuerEdgeGeneration: 1, RoutingEpoch: 7, RegistryRevision: 12,
			RegistryHash: registryCommitment,
		},
	}
	verifier, err := NewAuthorityVerifier(AuthorityVerifierConfig{
		TenantID: "tenant-a", Authority: store, RegistryTrust: trust,
	})
	if err != nil {
		t.Fatal(err)
	}
	if envelope, err := verifier.VerifyCommitted(context.Background(), caseRaw); err != nil || envelope.CaseID != "case-0001" {
		t.Fatalf("case verification = %#v, %v", envelope, err)
	}
	if envelope, err := verifier.VerifyCommitted(context.Background(), adviceRaw); err != nil || envelope.CaseID != "case-0001" {
		t.Fatalf("advice verification = %#v, %v", envelope, err)
	}

	tampered := append([]byte(nil), caseRaw...)
	tampered[len(tampered)-2] ^= 1
	if _, err := verifier.VerifyCommitted(context.Background(), tampered); err == nil {
		t.Fatal("accepted tampered committed bytes")
	}
}

func readBuzzVector(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "ssp", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.TrimSpace(string(raw)))
}

type fakeCommittedAuthority struct {
	registry   authority.RegistryRecord
	caseRecord authority.CaseRecord
}

func (f *fakeCommittedAuthority) ResolveRegistry(_ context.Context, tenant string, revision int64, commitment string) (authority.RegistryRecord, error) {
	if tenant != f.registry.TenantID || revision != f.registry.Revision || commitment != f.registry.Commitment {
		return authority.RegistryRecord{}, authority.ErrRegistryNotFound
	}
	return f.registry, nil
}

func (f *fakeCommittedAuthority) ResolveCase(_ context.Context, tenant, caseID, commitment string) (authority.CaseRecord, error) {
	if tenant != f.caseRecord.TenantID || caseID != f.caseRecord.CaseID || commitment != f.caseRecord.Commitment {
		return authority.CaseRecord{}, authority.ErrCaseNotFound
	}
	return f.caseRecord, nil
}
