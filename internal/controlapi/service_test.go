package controlapi

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

var controlNow = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func TestSubmitCaseRequiresExactPositiveRegisteredGenerationBeforeAuthority(t *testing.T) {
	fixture := newControlFixture(t)
	raw := fixture.caseRaw(t, "case-1", "case-envelope-1")
	for _, workload := range []WorkloadIdentity{
		{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 0},
		{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 2},
	} {
		if _, err := fixture.service.Submit(context.Background(), workload, raw); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("Submit generation %d error = %v, want ErrUnauthorized", workload.EdgeGeneration, err)
		}
	}
	if fixture.authority.caseCalls != 0 {
		t.Fatalf("CommitCase calls = %d, want 0", fixture.authority.caseCalls)
	}

	fixture.authority.caseErr = errors.New("authority unavailable")
	_, err := fixture.service.Submit(context.Background(), WorkloadIdentity{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 1}, raw)
	if !errors.Is(err, fixture.authority.caseErr) {
		t.Fatalf("Submit authority error = %v, want preserved authority error", err)
	}
	if got := fixture.authority.caseRequest.Raw; string(got) != string(raw) {
		t.Fatal("control API changed exact signed case bytes before authority")
	}
}

func TestSubmitRejectsMismatchedOrStaleAuthorityRegistryBeforeAuthority(t *testing.T) {
	fixture := newControlFixture(t)
	raw := fixture.caseRaw(t, "case-1", "case-envelope-1")
	fixture.authority.registry.Commitment = digest("wrong-registry")
	if _, err := fixture.service.Submit(context.Background(), WorkloadIdentity{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 1}, raw); err == nil {
		t.Fatal("Submit accepted a header that did not match the authority registry artifact")
	}
	if fixture.authority.caseCalls != 0 {
		t.Fatal("mismatched registry reached CommitCase")
	}

	fixture = newControlFixture(t)
	fixture.authority.resolveErr = authority.ErrRegistryNotFound
	if _, err := fixture.service.Submit(context.Background(), WorkloadIdentity{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 1}, raw); !errors.Is(err, authority.ErrRegistryNotFound) {
		t.Fatalf("stale/missing authority registry error = %v", err)
	}
}

func TestSubmitAdviceUsesCommittedCaseFactAndPassesExactBinding(t *testing.T) {
	fixture := newControlFixture(t)
	caseRaw := fixture.caseRaw(t, "case-1", "case-envelope-1")
	caseCommitment, err := ssp.EnvelopeCommitment(caseRaw, controlNow)
	if err != nil {
		t.Fatal(err)
	}
	fixture.authority.facts = []authority.ProjectionFact{{AuthorityRevision: 1, Kind: "case", CaseID: "case-1", EnvelopeID: "case-envelope-1", Commitment: caseCommitment, Raw: caseRaw}}
	adviceRaw := fixture.adviceRaw(t, "case-1", "advice-envelope-1", caseCommitment)

	if _, err := fixture.service.Submit(context.Background(), WorkloadIdentity{PrincipalID: "dispatcher-principal"}, adviceRaw); err != nil {
		t.Fatalf("Submit advice: %v", err)
	}
	if fixture.authority.adviceCalls != 1 || fixture.authority.advice.CaseCommitment != caseCommitment || string(fixture.authority.advice.Raw) != string(adviceRaw) {
		t.Fatalf("advice authority request = %#v", fixture.authority.advice)
	}
}

func TestSubmitRegistryRequiresPublisherAndPreservesExactRaw(t *testing.T) {
	fixture := newControlFixture(t)
	if _, err := fixture.service.SubmitRegistry(context.Background(), WorkloadIdentity{PrincipalID: "registry-publisher", EdgeID: "edge-1", EdgeGeneration: 1}, fixture.authority.registry.Raw); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-publisher-shape error = %v, want ErrUnauthorized", err)
	}
	if _, err := fixture.service.SubmitRegistry(context.Background(), WorkloadIdentity{PrincipalID: "registry-publisher"}, fixture.authority.registry.Raw); err != nil {
		t.Fatalf("SubmitRegistry: %v", err)
	}
	if fixture.authority.registryCalls != 1 || string(fixture.authority.registryRequest.Raw) != string(fixture.authority.registry.Raw) || fixture.authority.registryRequest.Revision != 12 {
		t.Fatalf("registry authority request = %#v", fixture.authority.registryRequest)
	}
}

func TestSubmitRegistryUsesSignedPredecessorWithoutReadingAuthorityHead(t *testing.T) {
	fixture := newControlFixture(t)
	signedPrevious := digest("signed-registry-predecessor")
	raw := fixture.registryRaw(t, 13, "registry-envelope-successor", signedPrevious)
	fixture.authority.headErr = errors.New("CurrentRegistryHead must not be called during admission")

	if _, err := fixture.service.SubmitRegistry(context.Background(), WorkloadIdentity{PrincipalID: "registry-publisher"}, raw); err != nil {
		t.Fatalf("SubmitRegistry: %v", err)
	}
	if fixture.authority.headCalls != 0 {
		t.Fatalf("CurrentRegistryHead calls = %d, want 0", fixture.authority.headCalls)
	}
	request := fixture.authority.registryRequest
	if request.PreviousCommitment != signedPrevious {
		t.Fatalf("authority predecessor = %q, want signed %q", request.PreviousCommitment, signedPrevious)
	}
	if len(request.Edges) != 1 || request.Edges["edge-1"] != (authority.RegistryEdge{PrincipalID: "edge-principal", Generation: 1}) {
		t.Fatalf("authority edges = %#v, want signed edge-1 identity", request.Edges)
	}
}

func TestSubmitClassifiesMalformedInputWithoutMaskingAuthorityFailure(t *testing.T) {
	fixture := newControlFixture(t)
	if _, err := fixture.service.Submit(context.Background(), WorkloadIdentity{}, []byte(`{`)); !errors.Is(err, ErrRejected) {
		t.Fatalf("malformed Submit error = %v, want ErrRejected", err)
	}

	malformedBody := withoutBodyMember(t, fixture.caseRaw(t, "case-malformed", "case-envelope-malformed"), "summary")
	if _, err := fixture.service.Submit(context.Background(), WorkloadIdentity{
		PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 1,
	}, malformedBody); !errors.Is(err, ErrRejected) || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("structurally invalid case error = %v, want only ErrRejected", err)
	}

	tamperedSignature := withBodyMember(t, fixture.caseRaw(t, "case-tampered", "case-envelope-tampered"), "summary", json.RawMessage(`"different but structurally valid"`))
	if _, err := fixture.service.Submit(context.Background(), WorkloadIdentity{
		PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 1,
	}, tamperedSignature); !errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrRejected) {
		t.Fatalf("invalid case signature error = %v, want only ErrUnauthorized", err)
	}

	committedCaseRaw := fixture.caseRaw(t, "case-for-malformed-advice", "case-envelope-for-malformed-advice")
	committedCaseCommitment, err := ssp.EnvelopeCommitment(committedCaseRaw, controlNow)
	if err != nil {
		t.Fatal(err)
	}
	fixture.authority.facts = []authority.ProjectionFact{{
		AuthorityRevision: 1, Kind: "case", CaseID: "case-for-malformed-advice",
		EnvelopeID: "case-envelope-for-malformed-advice", Commitment: committedCaseCommitment, Raw: committedCaseRaw,
	}}
	malformedAdvice := withoutBodyMember(t, fixture.adviceRaw(t, "case-for-malformed-advice", "advice-envelope-malformed", committedCaseCommitment), "text")
	if _, err := fixture.service.Submit(context.Background(), WorkloadIdentity{PrincipalID: "dispatcher-principal"}, malformedAdvice); !errors.Is(err, ErrRejected) || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("structurally invalid advice error = %v, want only ErrRejected", err)
	}

	authorityFailure := errors.New("postgres unavailable")
	fixture.authority.caseErr = authorityFailure
	raw := fixture.caseRaw(t, "case-authority-failure", "case-envelope-authority-failure")
	_, err = fixture.service.Submit(context.Background(), WorkloadIdentity{
		PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 1,
	}, raw)
	if !errors.Is(err, authorityFailure) || errors.Is(err, ErrRejected) {
		t.Fatalf("authority failure = %v, want preserved non-rejection failure", err)
	}
}

func withoutBodyMember(t *testing.T, raw []byte, member string) []byte {
	t.Helper()
	return mutateBodyMember(t, raw, member, nil)
}

func withBodyMember(t *testing.T, raw []byte, member string, value json.RawMessage) []byte {
	t.Helper()
	return mutateBodyMember(t, raw, member, value)
}

func mutateBodyMember(t *testing.T, raw []byte, member string, value json.RawMessage) []byte {
	t.Helper()
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(envelope["body"], &body); err != nil {
		t.Fatal(err)
	}
	if value == nil {
		delete(body, member)
	} else {
		body[member] = append(json.RawMessage(nil), value...)
	}
	envelope["body"], _ = json.Marshal(body)
	mutated, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}

func TestResolveCaseAuthorizesItsRegisteredDispatcherAndTargetEdge(t *testing.T) {
	fixture := newControlFixture(t)
	raw := fixture.caseRaw(t, "case-1", "case-envelope-1")
	commitment, err := ssp.EnvelopeCommitment(raw, controlNow)
	if err != nil {
		t.Fatal(err)
	}
	fixture.authority.facts = []authority.ProjectionFact{{
		AuthorityRevision: 1, Kind: "case", CaseID: "case-1",
		EnvelopeID: "case-envelope-1", Commitment: commitment, Raw: raw,
	}}
	for _, workload := range []WorkloadIdentity{
		{PrincipalID: "dispatcher-principal"},
		{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 1},
	} {
		record, err := fixture.service.ResolveCase(context.Background(), workload, "case-1", commitment)
		if err != nil || record.CaseID != "case-1" || string(record.Raw) != string(raw) {
			t.Fatalf("ResolveCase workload %#v = %#v, %v", workload, record, err)
		}
	}
	for _, workload := range []WorkloadIdentity{
		{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 2},
		{PrincipalID: "other-edge", EdgeID: "edge-1", EdgeGeneration: 1},
		{PrincipalID: "other-dispatcher"},
	} {
		if _, err := fixture.service.ResolveCase(context.Background(), workload, "case-1", commitment); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("ResolveCase workload %#v error = %v, want ErrUnauthorized", workload, err)
		}
	}
}

func TestResolveRegistryReturnsRootVerifiedHistoricalBytesOnlyToAnEdge(t *testing.T) {
	fixture := newControlFixture(t)
	want := append([]byte(nil), fixture.authority.registry.Raw...)
	got, err := fixture.service.ResolveRegistry(context.Background(), WorkloadIdentity{
		PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 1,
	}, fixture.authority.registry.Revision, fixture.authority.registry.Commitment)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Raw) != string(want) || got.Commitment != fixture.authority.registry.Commitment {
		t.Fatalf("registry = %#v", got)
	}
	got.Raw[0] ^= 1
	if string(fixture.authority.registry.Raw) != string(want) {
		t.Fatal("ResolveRegistry aliased authority bytes")
	}
	for _, workload := range []WorkloadIdentity{
		{PrincipalID: "dispatcher-principal"},
		{PrincipalID: "edge-principal", EdgeID: "edge-1", EdgeGeneration: 2},
	} {
		if _, err := fixture.service.ResolveRegistry(context.Background(), workload, fixture.authority.registry.Revision, fixture.authority.registry.Commitment); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("workload %#v error = %v, want unauthorized", workload, err)
		}
	}
}

type controlFixture struct {
	service   *Service
	authority *fakeAuthority
	rootKey   identity.Ed25519SigningKey
	edgeKey   identity.Ed25519SigningKey
	adviceKey identity.Ed25519SigningKey
}

func newControlFixture(t *testing.T) controlFixture {
	t.Helper()
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
	root, _ := identity.NewEd25519SigningKey(rootPrivate)
	edge, _ := identity.NewEd25519SigningKey(edgePrivate)
	advice, _ := identity.NewEd25519SigningKey(advicePrivate)
	trust, err := registry.NewTrust("registry-root", rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"revision": float64(12), "routing_epoch": float64(7), "previous_commitment": nil,
		"domains": []any{map[string]any{"domain": "support", "dispatcher_principal_id": "dispatcher-principal", "issuer_edge_ids": []string{"edge-1"}, "specialist_principal_ids": []string{}, "families": []string{ssp.FamilyCase, ssp.FamilyAdvice}, "routing_epoch": float64(7)}},
		"principals": []any{
			map[string]any{"principal_id": "registry-principal", "roles": []string{"registry-authority"}, "ssp_key_ids": []string{"registry-root"}, "edge_ids": []string{}},
			map[string]any{"principal_id": "edge-principal", "roles": []string{"edge"}, "ssp_key_ids": []string{"edge-key"}, "edge_ids": []string{"edge-1"}},
			map[string]any{"principal_id": "dispatcher-principal", "roles": []string{"dispatcher"}, "ssp_key_ids": []string{"advice-key"}, "edge_ids": []string{}},
		},
		"edges": []any{map[string]any{"edge_id": "edge-1", "generation": float64(1), "principal_id": "edge-principal"}},
		"keys":  []any{testKey("registry-root", rootPublic, "registry-principal", "registry"), testKey("edge-key", edgePublic, "edge-principal", "edge"), testKey("advice-key", advicePublic, "dispatcher-principal", "advice")},
	})
	if err != nil {
		t.Fatal(err)
	}
	registryRaw := sign(t, ssp.Envelope{Schema: ssp.FamilyRegistry, ID: "registry-envelope", EmittedAt: controlNow.Format(time.RFC3339), ExpiresAt: controlNow.Add(time.Hour).Format(time.RFC3339), RoutingEpoch: 7, RegistryRevision: 12, AuthorKeyID: "registry-root", SignatureAlg: "ed25519", Body: body}, root)
	commitment, err := ssp.EnvelopeCommitment(registryRaw, controlNow)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeAuthority{registry: authority.RegistryRecord{TenantID: "tenant-a", Revision: 12, Commitment: commitment, Raw: registryRaw, RoutingEpoch: 7}}
	service, err := New(Config{Tenant: "tenant-a", Clock: func() time.Time { return controlNow }, Authority: fake, RegistryTrust: trust, RegistryPublisherPrincipalID: "registry-publisher"})
	if err != nil {
		t.Fatal(err)
	}
	return controlFixture{service: service, authority: fake, rootKey: root, edgeKey: edge, adviceKey: advice}
}

func (f controlFixture) registryRaw(t *testing.T, revision int64, envelopeID, previous string) []byte {
	t.Helper()
	var envelope ssp.Envelope
	if err := json.Unmarshal(f.authority.registry.Raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		t.Fatal(err)
	}
	body["revision"] = revision
	body["previous_commitment"] = previous
	envelope.ID = envelopeID
	envelope.RegistryRevision = revision
	envelope.Signature = ""
	envelope.Body, _ = json.Marshal(body)
	return sign(t, envelope, f.rootKey)
}

func (f controlFixture) caseRaw(t *testing.T, caseID, envelopeID string) []byte {
	t.Helper()
	body := json.RawMessage(`{"domain":"support","issuer_edge_id":"edge-1","issuer_edge_generation":1,"summary":"help","context_manifest":"` + digest("manifest") + `"}`)
	return sign(t, ssp.Envelope{Schema: ssp.FamilyCase, ID: envelopeID, CaseID: caseID, EmittedAt: controlNow.Format(time.RFC3339), ExpiresAt: controlNow.Add(time.Hour).Format(time.RFC3339), RoutingEpoch: 7, RegistryRevision: 12, RegistryHash: f.authority.registry.Commitment, AuthorKeyID: "edge-key", SignatureAlg: "ed25519", Body: body}, f.edgeKey)
}

func (f controlFixture) adviceRaw(t *testing.T, caseID, envelopeID, caseCommitment string) []byte {
	t.Helper()
	body := json.RawMessage(`{"case_commitment":"` + caseCommitment + `","text":"bounded advice"}`)
	return sign(t, ssp.Envelope{Schema: ssp.FamilyAdvice, ID: envelopeID, CaseID: caseID, EmittedAt: controlNow.Format(time.RFC3339), ExpiresAt: controlNow.Add(time.Hour).Format(time.RFC3339), RoutingEpoch: 7, RegistryRevision: 12, RegistryHash: f.authority.registry.Commitment, AuthorKeyID: "advice-key", SignatureAlg: "ed25519", Body: body}, f.adviceKey)
}

func sign(t *testing.T, envelope ssp.Envelope, key identity.Ed25519SigningKey) []byte {
	t.Helper()
	raw, err := ssp.Sign(envelope, key, controlNow)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func digest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func testKey(id string, public ed25519.PublicKey, principal, usage string) map[string]any {
	return map[string]any{"key_id": id, "public_key": base64.RawURLEncoding.EncodeToString(public), "principal_id": principal, "usage": usage, "not_before": controlNow.Add(-time.Hour).Format(time.RFC3339), "expires_at": controlNow.Add(time.Hour).Format(time.RFC3339)}
}

type fakeAuthority struct {
	registry                              authority.RegistryRecord
	resolveErr                            error
	caseRequest                           authority.CommitCaseRequest
	advice                                authority.CommitAdviceRequest
	caseErr                               error
	registryRequest                       authority.CommitRegistryRequest
	caseCalls, adviceCalls, registryCalls int
	headCalls                             int
	headErr                               error
	facts                                 []authority.ProjectionFact
}

func (f *fakeAuthority) CommitCase(_ context.Context, r authority.CommitCaseRequest) (authority.CommitReceipt, error) {
	f.caseCalls++
	f.caseRequest = r
	return authority.CommitReceipt{AuthorityID: "fake", Revision: 1, EnvelopeID: r.EnvelopeID, Commitment: r.Commitment}, f.caseErr
}
func (f *fakeAuthority) CommitAdvice(_ context.Context, r authority.CommitAdviceRequest) (authority.CommitReceipt, error) {
	f.adviceCalls++
	f.advice = r
	return authority.CommitReceipt{AuthorityID: "fake", Revision: 2, EnvelopeID: r.EnvelopeID, Commitment: r.Commitment}, nil
}
func (f *fakeAuthority) CommitRegistry(_ context.Context, r authority.CommitRegistryRequest) (authority.CommitReceipt, error) {
	f.registryCalls++
	f.registryRequest = r
	return authority.CommitReceipt{AuthorityID: "fake", Revision: 3, EnvelopeID: r.EnvelopeID, Commitment: r.Commitment}, nil
}
func (f *fakeAuthority) ListEdgeDeliveries(context.Context, authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error) {
	return authority.EdgeDeliveryPage{}, nil
}
func (f *fakeAuthority) ListProjectionFacts(_ context.Context, q authority.ProjectionFactQuery) (authority.ProjectionFactPage, error) {
	var out []authority.ProjectionFact
	for _, fact := range f.facts {
		if fact.AuthorityRevision > q.AfterAuthoritySequence {
			out = append(out, fact)
		}
	}
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	var high int64
	for _, fact := range f.facts {
		if fact.AuthorityRevision > high {
			high = fact.AuthorityRevision
		}
	}
	return authority.ProjectionFactPage{Facts: out, HighWatermark: high}, nil
}
func (f *fakeAuthority) ResolveCase(_ context.Context, tenantID, caseID, commitment string) (authority.CaseRecord, error) {
	for _, fact := range f.facts {
		if fact.Kind == "case" && fact.CaseID == caseID && fact.Commitment == commitment {
			var envelope ssp.Envelope
			if err := json.Unmarshal(fact.Raw, &envelope); err != nil {
				return authority.CaseRecord{}, err
			}
			var body caseBody
			if err := json.Unmarshal(envelope.Body, &body); err != nil {
				return authority.CaseRecord{}, err
			}
			return authority.CaseRecord{
				TenantID: tenantID, CaseID: caseID, EnvelopeID: fact.EnvelopeID,
				Commitment: commitment, Raw: append([]byte(nil), fact.Raw...),
				Domain: body.Domain, IssuerEdgeID: body.IssuerEdgeID,
				IssuerEdgeGeneration: body.IssuerEdgeGeneration,
				RoutingEpoch:         envelope.RoutingEpoch, RegistryRevision: envelope.RegistryRevision,
				RegistryHash: envelope.RegistryHash, AuthorityRevision: fact.AuthorityRevision,
			}, nil
		}
	}
	return authority.CaseRecord{}, authority.ErrCaseNotFound
}
func (f *fakeAuthority) ResolveRegistry(context.Context, string, int64, string) (authority.RegistryRecord, error) {
	if f.resolveErr != nil {
		return authority.RegistryRecord{}, f.resolveErr
	}
	return f.registry, nil
}
func (f *fakeAuthority) CurrentRegistryHead(context.Context, string) (authority.RegistryHead, error) {
	f.headCalls++
	if f.headErr != nil {
		return authority.RegistryHead{}, f.headErr
	}
	return authority.RegistryHead{}, authority.ErrRegistryHeadNotFound
}
