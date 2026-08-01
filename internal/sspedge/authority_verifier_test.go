package sspedge

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/registry"
	"github.com/avivsinai/snagline/internal/ssp"
)

func TestAuthorityVerifierAcceptsHistoricalCommittedCaseAtSignedEmissionTime(t *testing.T) {
	fixture := newAuthorityVerifierFixture(t)
	verifier := fixture.verifier(t)
	delivery := JournalDelivery{
		DeliverySeq:    1,
		TenantID:       fixture.tenant,
		EdgeID:         fixture.edgeID,
		EdgeGeneration: fixture.generation,
		Raw:            fixture.caseRecord.Raw,
	}

	projection, err := verifier.Verify(context.Background(), delivery)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Family != FamilyCase || projection.EnvelopeID != fixture.caseRecord.EnvelopeID ||
		projection.Commitment != fixture.caseRecord.Commitment || projection.Case == nil {
		t.Fatalf("projection = %+v", projection)
	}
	got := projection.Case
	if got.CaseID != fixture.caseRecord.CaseID || got.Domain != fixture.domain ||
		got.IssuerEdgeID != fixture.edgeID || got.IssuerEdgeGeneration != fixture.generation ||
		got.RouteKind != "domain" || got.RouteToken != RoutingToken(fixture.domain) ||
		got.SourceToken != EdgeRoutingToken(fixture.edgeID, fixture.generation) ||
		got.RoutingEpoch != fixture.routingEpoch ||
		got.RegistryRevision != fixture.registryRevision ||
		got.RegistryHash != fixture.registryRecord.Commitment ||
		got.Summary != "historical private case" || got.ContextManifest != verifierDigest("manifest") {
		t.Fatalf("case route projection = %+v", got)
	}
	if fixture.authority.deliveryCalls != 1 || fixture.authority.registryCalls != 1 || fixture.authority.caseCalls != 1 {
		t.Fatalf("authority calls delivery=%d registry=%d case=%d", fixture.authority.deliveryCalls, fixture.authority.registryCalls, fixture.authority.caseCalls)
	}
}

func TestAuthorityVerifierAuthorizesAdviceDispatcherAndExactCommittedCase(t *testing.T) {
	fixture := newAuthorityVerifierFixture(t)
	adviceRaw := fixture.signAdvice(t, fixture.caseRecord.Commitment, fixture.adviceSigning)
	fixture.setAuthorityAdvice(t, adviceRaw)
	projection, err := fixture.verifier(t).Verify(context.Background(), JournalDelivery{
		DeliverySeq:    2,
		TenantID:       fixture.tenant,
		EdgeID:         fixture.edgeID,
		EdgeGeneration: fixture.generation,
		Raw:            adviceRaw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if projection.Family != FamilyAdvice || projection.Advice == nil {
		t.Fatalf("projection = %+v", projection)
	}
	got := projection.Advice
	if got.CaseID != fixture.caseRecord.CaseID || got.CaseCommitment != fixture.caseRecord.Commitment ||
		got.IssuerEdgeID != fixture.edgeID || got.IssuerEdgeGeneration != fixture.generation ||
		got.RouteKind != "edge" || got.RouteToken != EdgeRoutingToken(fixture.edgeID, fixture.generation) ||
		got.RoutingEpoch != fixture.routingEpoch || got.RegistryRevision != fixture.registryRevision ||
		got.RegistryHash != fixture.registryRecord.Commitment || got.Text != "historical display advice" {
		t.Fatalf("advice route projection = %+v", got)
	}

	wrongSigner := fixture.signAdvice(t, fixture.caseRecord.Commitment, fixture.edgeSigning)
	fixture.setAuthorityAdvice(t, wrongSigner)
	_, err = fixture.verifier(t).Verify(context.Background(), JournalDelivery{
		DeliverySeq:    2,
		TenantID:       fixture.tenant,
		EdgeID:         fixture.edgeID,
		EdgeGeneration: fixture.generation,
		Raw:            wrongSigner,
	})
	assertPermanentVerificationError(t, err)
}

func TestAuthorityVerifierClassifiesAuthorityReadsAsTransient(t *testing.T) {
	fixture := newAuthorityVerifierFixture(t)
	fixture.authority.registryErr = errors.New("registry replica unavailable")
	_, err := fixture.verifier(t).Verify(context.Background(), JournalDelivery{
		DeliverySeq: 1, TenantID: fixture.tenant, EdgeID: fixture.edgeID,
		EdgeGeneration: fixture.generation, Raw: fixture.caseRecord.Raw,
	})
	assertTransientVerificationError(t, err)

	fixture.authority.registryErr = nil
	fixture.authority.caseErr = errors.New("case replica unavailable")
	_, err = fixture.verifier(t).Verify(context.Background(), JournalDelivery{
		DeliverySeq: 1, TenantID: fixture.tenant, EdgeID: fixture.edgeID,
		EdgeGeneration: fixture.generation, Raw: fixture.caseRecord.Raw,
	})
	assertTransientVerificationError(t, err)
}

func TestAuthorityVerifierClassifiesMalformedOrUnboundBytesAsPermanent(t *testing.T) {
	fixture := newAuthorityVerifierFixture(t)
	verifier := fixture.verifier(t)
	fixture.authority.delivery.Raw = []byte(`{}`)
	_, err := verifier.Verify(context.Background(), JournalDelivery{
		DeliverySeq: 1, TenantID: fixture.tenant, EdgeID: fixture.edgeID,
		EdgeGeneration: fixture.generation, Raw: []byte(`{}`),
	})
	assertPermanentVerificationError(t, err)

	record := fixture.caseRecord
	record.Raw = append([]byte(nil), record.Raw...)
	record.Raw[len(record.Raw)-2] ^= 1
	fixture.authority.caseRecord = record
	fixture.authority.delivery.Raw = fixture.caseRecord.Raw
	_, err = verifier.Verify(context.Background(), JournalDelivery{
		DeliverySeq: 1, TenantID: fixture.tenant, EdgeID: fixture.edgeID,
		EdgeGeneration: fixture.generation, Raw: fixture.caseRecord.Raw,
	})
	assertPermanentVerificationError(t, err)
}

func TestAuthorityVerifierRejectsDurableMissingEvidenceAndRetriesUnboundCarrier(t *testing.T) {
	fixture := newAuthorityVerifierFixture(t)
	delivery := JournalDelivery{
		DeliverySeq: 1, TenantID: fixture.tenant, EdgeID: fixture.edgeID,
		EdgeGeneration: fixture.generation, Raw: fixture.caseRecord.Raw,
	}

	fixture.authority.registryErr = authority.ErrRegistryNotFound
	_, err := fixture.verifier(t).Verify(context.Background(), delivery)
	assertPermanentVerificationError(t, err)

	fixture.authority.registryErr = nil
	fixture.authority.caseErr = authority.ErrCaseNotFound
	_, err = fixture.verifier(t).Verify(context.Background(), delivery)
	assertPermanentVerificationError(t, err)

	fixture.authority.caseErr = nil
	fixture.authority.delivery.Raw = []byte("different PostgreSQL bytes")
	_, err = fixture.verifier(t).Verify(context.Background(), delivery)
	assertTransientVerificationError(t, err)

	committedAdvice := fixture.signAdvice(t, fixture.caseRecord.Commitment, fixture.adviceSigning)
	fixture.setAuthorityAdvice(t, committedAdvice)
	uncommittedAdvice := fixture.signAdviceVariant(
		t, "uncommitted-advice", "second valid dispatcher advice",
		fixture.caseRecord.Commitment, fixture.adviceSigning,
	)
	_, err = fixture.verifier(t).Verify(context.Background(), JournalDelivery{
		DeliverySeq: 2, TenantID: fixture.tenant, EdgeID: fixture.edgeID,
		EdgeGeneration: fixture.generation, Raw: uncommittedAdvice,
	})
	assertTransientVerificationError(t, err)
}

type verifierAuthority struct {
	registryRecord authority.RegistryRecord
	caseRecord     authority.CaseRecord
	delivery       authority.EdgeDelivery
	registryErr    error
	caseErr        error
	registryCalls  int
	caseCalls      int
	deliveryCalls  int
}

func (a *verifierAuthority) ListEdgeDeliveries(_ context.Context, query authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error) {
	a.deliveryCalls++
	if query.AfterSequence+1 != a.delivery.Sequence {
		return authority.EdgeDeliveryPage{
			HighWatermark: a.delivery.Sequence, CompleteThrough: query.AfterSequence,
		}, nil
	}
	return authority.EdgeDeliveryPage{
		Deliveries:      []authority.EdgeDelivery{a.delivery},
		HighWatermark:   a.delivery.Sequence,
		CompleteThrough: a.delivery.Sequence,
	}, nil
}

func (a *verifierAuthority) ResolveRegistry(_ context.Context, tenant string, revision int64, commitment string) (authority.RegistryRecord, error) {
	a.registryCalls++
	if a.registryErr != nil {
		return authority.RegistryRecord{}, a.registryErr
	}
	if tenant != a.registryRecord.TenantID || revision != a.registryRecord.Revision || commitment != a.registryRecord.Commitment {
		return authority.RegistryRecord{}, authority.ErrRegistryNotFound
	}
	return a.registryRecord, nil
}

func (a *verifierAuthority) ResolveCase(_ context.Context, caseID, commitment string) (authority.CaseRecord, error) {
	a.caseCalls++
	if a.caseErr != nil {
		return authority.CaseRecord{}, a.caseErr
	}
	if caseID != a.caseRecord.CaseID || commitment != a.caseRecord.Commitment {
		return authority.CaseRecord{}, authority.ErrCaseNotFound
	}
	return a.caseRecord, nil
}

type authorityVerifierFixture struct {
	tenant, edgeID, domain         string
	generation                     int64
	routingEpoch, registryRevision int64
	emittedAt                      time.Time
	trust                          registry.Trust
	authority                      *verifierAuthority
	registryRecord                 authority.RegistryRecord
	caseRecord                     authority.CaseRecord
	edgeSigning, adviceSigning     identity.Ed25519SigningKey
}

func newAuthorityVerifierFixture(t *testing.T) authorityVerifierFixture {
	t.Helper()
	emittedAt := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	edgePublic, edgePrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	advicePublic, advicePrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rootSigning, _ := identity.NewEd25519SigningKey(rootPrivate)
	edgeSigning, _ := identity.NewEd25519SigningKey(edgePrivate)
	adviceSigning, _ := identity.NewEd25519SigningKey(advicePrivate)
	trust, err := registry.NewTrust("registry-root", rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	key := func(id string, public ed25519.PublicKey, principal, usage string) map[string]any {
		return map[string]any{
			"key_id": id, "public_key": base64.RawURLEncoding.EncodeToString(public),
			"principal_id": principal, "usage": usage,
			"not_before": emittedAt.Add(-time.Hour).Format(time.RFC3339),
			"expires_at": emittedAt.Add(20 * time.Minute).Format(time.RFC3339),
		}
	}
	body, err := json.Marshal(map[string]any{
		"revision": 12, "routing_epoch": 7, "previous_commitment": nil,
		"domains": []any{map[string]any{
			"domain": "support", "dispatcher_principal_id": "dispatcher-principal",
			"issuer_edge_ids": []string{"edge-1"}, "specialist_principal_ids": []string{},
			"families": []string{ssp.FamilyCase, ssp.FamilyAdvice}, "routing_epoch": 7,
		}},
		"principals": []any{
			map[string]any{"principal_id": "registry-principal", "roles": []string{"registry-authority"}, "ssp_key_ids": []string{"registry-root"}, "edge_ids": []string{}},
			map[string]any{"principal_id": "edge-principal", "roles": []string{"edge"}, "ssp_key_ids": []string{"edge-key"}, "edge_ids": []string{"edge-1"}},
			map[string]any{"principal_id": "dispatcher-principal", "roles": []string{"dispatcher"}, "ssp_key_ids": []string{"advice-key"}, "edge_ids": []string{}},
		},
		"edges": []any{map[string]any{"edge_id": "edge-1", "generation": 3, "principal_id": "edge-principal"}},
		"keys": []any{
			key("registry-root", rootPublic, "registry-principal", "registry"),
			key("edge-key", edgePublic, "edge-principal", "edge"),
			key("advice-key", advicePublic, "dispatcher-principal", "advice"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	registryEmittedAt := emittedAt.Add(-time.Minute)
	registryRaw := signVerifierEnvelope(t, ssp.Envelope{
		Schema: ssp.FamilyRegistry, ID: "registry-envelope",
		EmittedAt:    registryEmittedAt.Format(time.RFC3339),
		ExpiresAt:    emittedAt.Add(20 * time.Minute).Format(time.RFC3339),
		RoutingEpoch: 7, RegistryRevision: 12,
		AuthorKeyID: "registry-root", SignatureAlg: "ed25519", Body: body,
	}, rootSigning, registryEmittedAt)
	registryCommitment, err := ssp.EnvelopeCommitment(registryRaw, emittedAt)
	if err != nil {
		t.Fatal(err)
	}
	caseBody := json.RawMessage(`{"domain":"support","issuer_edge_id":"edge-1","issuer_edge_generation":3,"summary":"historical private case","public_summary":"bounded public case","context_manifest":"` + verifierDigest("manifest") + `"}`)
	caseRaw := signVerifierEnvelope(t, ssp.Envelope{
		Schema: ssp.FamilyCase, ID: "case-envelope", CaseID: "case-1",
		EmittedAt:    emittedAt.Format(time.RFC3339),
		ExpiresAt:    emittedAt.Add(10 * time.Minute).Format(time.RFC3339),
		RoutingEpoch: 7, RegistryRevision: 12, RegistryHash: registryCommitment,
		AuthorKeyID: "edge-key", SignatureAlg: "ed25519", Body: caseBody,
	}, edgeSigning, emittedAt)
	caseCommitment, err := ssp.EnvelopeCommitment(caseRaw, emittedAt)
	if err != nil {
		t.Fatal(err)
	}
	registryRecord := authority.RegistryRecord{
		TenantID: "tenant-a", Revision: 12, EnvelopeID: "registry-envelope",
		Commitment: registryCommitment, Raw: registryRaw, RoutingEpoch: 7,
		AuthorityRevision: 1,
	}
	caseRecord := authority.CaseRecord{
		TenantID: "tenant-a", CaseID: "case-1", EnvelopeID: "case-envelope",
		Commitment: caseCommitment, Raw: caseRaw, Domain: "support",
		IssuerEdgeID: "edge-1", IssuerEdgeGeneration: 3,
		RoutingEpoch: 7, RegistryRevision: 12, RegistryHash: registryCommitment,
		ExpiresAt: emittedAt.Add(10 * time.Minute), AuthorityRevision: 2,
	}
	resolver := &verifierAuthority{
		registryRecord: registryRecord,
		caseRecord:     caseRecord,
		delivery: authority.EdgeDelivery{
			Sequence: 1, Kind: "case", CaseID: caseRecord.CaseID,
			EnvelopeID: caseRecord.EnvelopeID, Commitment: caseRecord.Commitment,
			Raw: caseRecord.Raw, AuthorityRevision: caseRecord.AuthorityRevision,
		},
	}
	return authorityVerifierFixture{
		tenant: "tenant-a", edgeID: "edge-1", domain: "support", generation: 3,
		routingEpoch: 7, registryRevision: 12, emittedAt: emittedAt, trust: trust,
		authority: resolver, registryRecord: registryRecord, caseRecord: caseRecord,
		edgeSigning: edgeSigning, adviceSigning: adviceSigning,
	}
}

func (f authorityVerifierFixture) setAuthorityAdvice(t *testing.T, raw []byte) {
	t.Helper()
	at := f.emittedAt.Add(time.Minute)
	commitment, err := ssp.EnvelopeCommitment(raw, at)
	if err != nil {
		t.Fatal(err)
	}
	f.authority.delivery = authority.EdgeDelivery{
		Sequence: 2, Kind: "advice", CaseID: f.caseRecord.CaseID,
		EnvelopeID: "advice-envelope", Commitment: commitment,
		Raw: raw, AuthorityRevision: 3,
	}
}

func (f authorityVerifierFixture) verifier(t *testing.T) *AuthorityVerifier {
	t.Helper()
	verifier, err := NewAuthorityVerifier(AuthorityVerifierConfig{
		Tenant: f.tenant, Authority: f.authority, RegistryTrust: f.trust,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func (f authorityVerifierFixture) signAdvice(t *testing.T, caseCommitment string, signing identity.Ed25519SigningKey) []byte {
	t.Helper()
	return f.signAdviceVariant(t, "advice-envelope", "historical display advice", caseCommitment, signing)
}

func (f authorityVerifierFixture) signAdviceVariant(
	t *testing.T,
	adviceID string,
	text string,
	caseCommitment string,
	signing identity.Ed25519SigningKey,
) []byte {
	t.Helper()
	keyID := "advice-key"
	if signingKeyPublicEqual(signing, f.edgeSigning) {
		keyID = "edge-key"
	}
	at := f.emittedAt.Add(time.Minute)
	body, err := json.Marshal(map[string]string{"case_commitment": caseCommitment, "text": text, "public_summary": "bounded public advice"})
	if err != nil {
		t.Fatal(err)
	}
	return signVerifierEnvelope(t, ssp.Envelope{
		Schema: ssp.FamilyAdvice, ID: adviceID, CaseID: f.caseRecord.CaseID,
		EmittedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(5 * time.Minute).Format(time.RFC3339),
		RoutingEpoch: f.routingEpoch, RegistryRevision: f.registryRevision,
		RegistryHash: f.registryRecord.Commitment, AuthorKeyID: keyID,
		SignatureAlg: "ed25519", Body: body,
	}, signing, at)
}

func signingKeyPublicEqual(left, right identity.Ed25519SigningKey) bool {
	leftPublic, leftErr := left.PublicKey()
	rightPublic, rightErr := right.PublicKey()
	return leftErr == nil && rightErr == nil && leftPublic.Equal(rightPublic)
}

func signVerifierEnvelope(t *testing.T, envelope ssp.Envelope, key identity.Ed25519SigningKey, now time.Time) []byte {
	t.Helper()
	raw, err := ssp.Sign(envelope, key, now)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func verifierDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func assertPermanentVerificationError(t *testing.T, err error) {
	t.Helper()
	var verification *VerificationError
	if !errors.As(err, &verification) || !verification.Permanent || verification.Reason == "" {
		t.Fatalf("error = %#v, want permanent verification error", err)
	}
}

func assertTransientVerificationError(t *testing.T, err error) {
	t.Helper()
	var verification *VerificationError
	if !errors.As(err, &verification) || verification.Permanent {
		t.Fatalf("error = %#v, want transient verification error", err)
	}
}
