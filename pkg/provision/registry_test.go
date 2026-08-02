package provision

import (
	"crypto/ed25519"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/ssp"
)

const testRootKeyID = "test-registry-root-2026"

var testNow = time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

// oneEdgeOneDispatcherDraft is the smallest registry a deployment can route
// with: one domain, one issuing edge, one dispatcher, one specialist, keyed
// by three freshly generated signing keys.
func oneEdgeOneDispatcherDraft(t *testing.T, root, edge, dispatcher SigningKey) RegistryDraft {
	t.Helper()
	rootPublic, err := root.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	edgePublic, err := edge.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	dispatcherPublic, err := dispatcher.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	notBefore := testNow.Add(-5 * time.Minute)
	expiresAt := testNow.Add(30 * 24 * time.Hour)
	return RegistryDraft{
		ID:           "registry-envelope-0001",
		EmittedAt:    testNow,
		ExpiresAt:    testNow.Add(29 * 24 * time.Hour),
		Revision:     1,
		RoutingEpoch: 1,
		Domains: []Domain{{
			Name:                   "support",
			DispatcherPrincipalID:  "dispatcher-0001",
			IssuerEdgeIDs:          []string{"edge-local-0001"},
			SpecialistPrincipalIDs: []string{"specialist-0001"},
			RoutingEpoch:           1,
		}},
		Principals: []Principal{
			{ID: "registry-authority-0001", Roles: []string{"registry-authority"}, SSPKeyIDs: []string{testRootKeyID}},
			{ID: "edge-principal-0001", Roles: []string{"edge"}, SSPKeyIDs: []string{"edge-key-2026"}, EdgeIDs: []string{"edge-local-0001"}},
			{ID: "dispatcher-0001", Roles: []string{"dispatcher"}, SSPKeyIDs: []string{"dispatcher-key-2026"}},
			{ID: "specialist-0001", Roles: []string{"specialist"}},
		},
		Edges: []Edge{{ID: "edge-local-0001", Generation: 1, PrincipalID: "edge-principal-0001"}},
		Keys: []Key{
			{ID: testRootKeyID, PublicKey: rootPublic, PrincipalID: "registry-authority-0001", Usage: KeyUsageRegistry, NotBefore: notBefore, ExpiresAt: expiresAt},
			{ID: "edge-key-2026", PublicKey: edgePublic, PrincipalID: "edge-principal-0001", Usage: KeyUsageEdge, NotBefore: notBefore, ExpiresAt: expiresAt},
			{ID: "dispatcher-key-2026", PublicKey: dispatcherPublic, PrincipalID: "dispatcher-0001", Usage: KeyUsageAdvice, NotBefore: notBefore, ExpiresAt: expiresAt},
		},
	}
}

func generateThreeKeys(t *testing.T) (root, edge, dispatcher SigningKey) {
	t.Helper()
	var err error
	root, err = GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	edge, err = GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err = GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return root, edge, dispatcher
}

var commitmentPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func TestSignRegistryProducesAnEnvelopeInternalSSPVerifiesStrictly(t *testing.T) {
	root, edge, dispatcher := generateThreeKeys(t)
	draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)

	raw, err := SignRegistry(root, testRootKeyID, draft)
	if err != nil {
		t.Fatal(err)
	}

	rootPublic, err := root.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	verifyingKey, err := identity.NewEd25519VerifyingKey(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := ssp.Verify(raw, map[string]identity.Ed25519VerifyingKey{testRootKeyID: verifyingKey}, testNow)
	if err != nil {
		t.Fatalf("internal/ssp refused to verify the envelope pkg/provision produced: %v", err)
	}
	if envelope.Schema != ssp.FamilyRegistry {
		t.Fatalf("schema = %q, want %q", envelope.Schema, ssp.FamilyRegistry)
	}
}

func TestSignRegistryThenVerifyRegistryEnvelopeReproducesProvisioningFlow(t *testing.T) {
	root, edge, dispatcher := generateThreeKeys(t)
	draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)

	raw, err := SignRegistry(root, testRootKeyID, draft)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, err := root.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewRegistryTrust(testRootKeyID, rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := VerifyRegistryEnvelope(trust, raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !commitmentPattern.MatchString(commitment) {
		t.Fatalf("commitment = %q, want a canonical sha256 commitment", commitment)
	}
}

func TestSignRegistryAcceptsNilOptionalStringSlices(t *testing.T) {
	root, edge, dispatcher := generateThreeKeys(t)
	draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)
	draft.Domains[0].SpecialistPrincipalIDs = nil
	draft.Principals[3].Roles = nil
	draft.Principals[3].SSPKeyIDs = nil
	draft.Principals[3].EdgeIDs = nil

	if _, err := SignRegistry(root, testRootKeyID, draft); err != nil {
		t.Fatalf("nil optional slices should normalize to empty JSON arrays, got: %v", err)
	}
}

func TestSignRegistryRejectsAnEmptyIssuerEdgeIDsList(t *testing.T) {
	root, edge, dispatcher := generateThreeKeys(t)
	draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)
	draft.Domains[0].IssuerEdgeIDs = nil

	if _, err := SignRegistry(root, testRootKeyID, draft); err == nil {
		t.Fatal("SignRegistry accepted a domain with no issuer edges")
	}
}

func TestSignRegistryRejectsAMalformedPublicKeyLength(t *testing.T) {
	root, edge, dispatcher := generateThreeKeys(t)
	draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)
	draft.Keys[0].PublicKey = make(ed25519.PublicKey, 16)

	if _, err := SignRegistry(root, testRootKeyID, draft); err == nil {
		t.Fatal("SignRegistry accepted a public key of the wrong length")
	}
}

func TestSignRegistryRejectsAZeroValueRootSigningKey(t *testing.T) {
	realRoot, edge, dispatcher := generateThreeKeys(t)
	// The draft's key material (including the root's own public key entry)
	// comes from a real key; only the *signer* passed to SignRegistry is the
	// zero value under test.
	draft := oneEdgeOneDispatcherDraft(t, realRoot, edge, dispatcher)

	if _, err := SignRegistry(SigningKey{}, testRootKeyID, draft); err == nil {
		t.Fatal("SignRegistry accepted an unconfigured (zero) root signing key")
	}
}

func TestSignRegistryRejectsAnEmptyRootKeyID(t *testing.T) {
	root, edge, dispatcher := generateThreeKeys(t)
	draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)

	if _, err := SignRegistry(root, "", draft); err == nil {
		t.Fatal("SignRegistry accepted an empty root key id")
	}
}

func TestVerifyRegistryEnvelopeFailsClosedOnAWrongTrustKey(t *testing.T) {
	root, edge, dispatcher := generateThreeKeys(t)
	draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)
	raw, err := SignRegistry(root, testRootKeyID, draft)
	if err != nil {
		t.Fatal(err)
	}

	impostor, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	impostorPublic, err := impostor.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewRegistryTrust(testRootKeyID, impostorPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRegistryEnvelope(trust, raw, testNow); err == nil {
		t.Fatal("VerifyRegistryEnvelope accepted a signature under a different root key")
	}
}

func TestVerifyRegistryEnvelopeFailsClosedOnTamperedBytes(t *testing.T) {
	root, edge, dispatcher := generateThreeKeys(t)
	draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)
	raw, err := SignRegistry(root, testRootKeyID, draft)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), raw...)
	for i, b := range tampered {
		if b == '1' {
			tampered[i] = '2'
			break
		}
	}
	rootPublic, err := root.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewRegistryTrust(testRootKeyID, rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRegistryEnvelope(trust, tampered, testNow); err == nil {
		t.Fatal("VerifyRegistryEnvelope accepted tampered envelope bytes")
	}
}

// TestSignRegistryRejectsSemanticallyInvalidDraftsBeforeSigning covers the
// gap between structural and semantic validity. Each draft below is a
// well-formed ssp.registry.v1 envelope — correct field shapes, ids, and
// timestamps — that describes a registry graph the verifier will refuse. A
// provisioning API that signed these would hand the operator an artifact
// that is authentic and unusable, so the defect must surface at sign time,
// naming what is wrong.
func TestSignRegistryRejectsSemanticallyInvalidDraftsBeforeSigning(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		corrupt func(*RegistryDraft)
		wantErr string
	}{
		{
			name: "duplicate principal id",
			corrupt: func(draft *RegistryDraft) {
				draft.Principals = append(draft.Principals, Principal{
					ID: "dispatcher-0001", Roles: []string{"dispatcher"},
					SSPKeyIDs: []string{"dispatcher-key-2026"},
				})
			},
			wantErr: `duplicate principal "dispatcher-0001"`,
		},
		{
			name: "duplicate edge id",
			corrupt: func(draft *RegistryDraft) {
				draft.Edges = append(draft.Edges, Edge{
					ID: "edge-local-0001", Generation: 2, PrincipalID: "edge-principal-0001",
				})
			},
			wantErr: `duplicate edge "edge-local-0001"`,
		},
		{
			name: "duplicate key id",
			corrupt: func(draft *RegistryDraft) {
				draft.Keys = append(draft.Keys, draft.Keys[1])
			},
			wantErr: `duplicate key "edge-key-2026"`,
		},
		{
			name: "domain names a dispatcher principal that does not exist",
			corrupt: func(draft *RegistryDraft) {
				draft.Domains[0].DispatcherPrincipalID = "dispatcher-9999"
			},
			wantErr: `dispatcher "dispatcher-9999" does not resolve`,
		},
		{
			name: "domain names an issuer edge that does not exist",
			corrupt: func(draft *RegistryDraft) {
				draft.Domains[0].IssuerEdgeIDs = []string{"edge-local-9999"}
			},
			wantErr: `issuer edge "edge-local-9999" does not resolve`,
		},
		{
			// Rebinding the root key, rather than the edge or dispatcher key,
			// isolates the two-way ownership rule: the domain checks that run
			// first still pass, so the error that surfaces is the misbinding
			// itself and not a downstream symptom of it.
			name: "key is bound to a principal that does not claim it",
			corrupt: func(draft *RegistryDraft) {
				draft.Keys[0].PrincipalID = "specialist-0001"
			},
			wantErr: `claims key "` + testRootKeyID + `" owned by "specialist-0001"`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root, edge, dispatcher := generateThreeKeys(t)
			draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)
			testCase.corrupt(&draft)

			raw, err := SignRegistry(root, testRootKeyID, draft)
			if err == nil {
				// Show the actual footgun rather than only reporting a
				// missing error: these bytes are signed by the real root key
				// and the verifier this same package ships rejects them.
				rootPublic, keyErr := root.PublicKey()
				if keyErr != nil {
					t.Fatal(keyErr)
				}
				trust, trustErr := NewRegistryTrust(testRootKeyID, rootPublic)
				if trustErr != nil {
					t.Fatal(trustErr)
				}
				_, verifyErr := VerifyRegistryEnvelope(trust, raw, testNow)
				t.Fatalf("SignRegistry signed a semantically invalid registry; "+
					"VerifyRegistryEnvelope then rejected those %d signed bytes with: %v",
					len(raw), verifyErr)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error = %v, want it to name the defect %q", err, testCase.wantErr)
			}
			if raw != nil {
				t.Fatalf("SignRegistry returned %d bytes alongside its error", len(raw))
			}
		})
	}
}

// TestSignRegistryStillSignsAValidDraft is the positive control for the
// semantic validation above: the same builder, uncorrupted, must still round
// trip through the verifier.
func TestSignRegistryStillSignsAValidDraft(t *testing.T) {
	root, edge, dispatcher := generateThreeKeys(t)
	draft := oneEdgeOneDispatcherDraft(t, root, edge, dispatcher)

	raw, err := SignRegistry(root, testRootKeyID, draft)
	if err != nil {
		t.Fatalf("semantic validation rejected a valid draft: %v", err)
	}
	rootPublic, err := root.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewRegistryTrust(testRootKeyID, rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRegistryEnvelope(trust, raw, testNow); err != nil {
		t.Fatalf("a draft SignRegistry accepted did not verify: %v", err)
	}
}

func TestNewRegistryTrustRejectsAMalformedPublicKey(t *testing.T) {
	if _, err := NewRegistryTrust(testRootKeyID, make(ed25519.PublicKey, 4)); err == nil {
		t.Fatal("NewRegistryTrust accepted a malformed root public key")
	}
}

func TestNewRegistryTrustRejectsAnEmptyKeyID(t *testing.T) {
	root, _, _ := generateThreeKeys(t)
	rootPublic, err := root.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRegistryTrust("", rootPublic); err == nil {
		t.Fatal("NewRegistryTrust accepted an empty author key id")
	}
}
