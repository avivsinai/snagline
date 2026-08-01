package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/ssp"
)

var edgeNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

func TestOpenCasePersistsExactSignedBytesBeforeGatewaySubmit(t *testing.T) {
	store := &fakeStore{}
	gateway := &fakeGateway{store: store}
	svc := newEdgeService(t, store, gateway)

	result, err := svc.OpenCase(context.Background(), OpenCaseRequest{
		CaseID: "case-1", Domain: "support", Summary: "Need bounded help", ContextManifest: digest("a"),
		Registry: RegistryCoordinates{RoutingEpoch: 7, Revision: 12, Hash: digest("b")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.AcceptedRemote || result.Receipt.Revision != 41 {
		t.Fatalf("result = %#v, want accepted_remote database receipt", result)
	}
	if !gateway.sawPendingBeforeSubmit {
		t.Fatal("gateway submit happened before the exact signed case was persisted")
	}
	if len(store.pending) != 1 || len(store.pending[0].Raw) == 0 {
		t.Fatalf("pending = %#v, want one stored signed envelope", store.pending)
	}
	if got := gateway.submitted[0]; string(got) != string(store.pending[0].Raw) {
		t.Fatal("gateway did not receive the exact stored bytes")
	}
	var signed ssp.Envelope
	if err := json.Unmarshal(store.pending[0].Raw, &signed); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(signed.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body["issuer_edge_generation"] != float64(3) {
		t.Fatalf("case body = %#v, want signed issuer edge generation", body)
	}
}

func TestNewServiceRejectsNonPositiveEdgeGeneration(t *testing.T) {
	signer, err := NewCaseSigner(testSigningKey(t, "edge-generation"))
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{}
	_, err = NewService(ServiceConfig{
		EdgeID: "edge-a", EdgeGeneration: 0, PrincipalID: "principal-edge",
		AuthorKeyID: "edge-key", Signer: signer, Store: store,
		Gateway: &fakeGateway{store: store}, EnvelopeTTL: time.Hour,
		NewID: sequenceID("case-envelope-1"),
	})
	if err == nil {
		t.Fatal("NewService accepted generation zero")
	}
}

func TestOpenCaseLostResponseRetriesExactBytesAndDoesNotClaimCommitted(t *testing.T) {
	store := &fakeStore{}
	gateway := &fakeGateway{store: store, err: errors.New("lost response")}
	svc := newEdgeService(t, store, gateway)
	request := OpenCaseRequest{CaseID: "case-1", Domain: "support", Summary: "Need bounded help", ContextManifest: digest("a"), Registry: RegistryCoordinates{RoutingEpoch: 7, Revision: 12, Hash: digest("b")}}

	first, err := svc.OpenCase(context.Background(), request)
	if err == nil {
		t.Fatal("OpenCase unexpectedly succeeded")
	}
	if first.AcceptedRemote || len(store.acceptedCases) != 0 {
		t.Fatalf("lost response result = %#v; no accepted_remote claim is allowed", first)
	}
	firstRaw := append([]byte(nil), store.pending[0].Raw...)
	gateway.err = nil
	retried, err := svc.RetryCase(context.Background(), "case-1")
	if err != nil {
		t.Fatal(err)
	}
	if !retried.AcceptedRemote || string(gateway.submitted[1]) != string(firstRaw) {
		t.Fatalf("retry=%#v submitted=%q want exact original bytes", retried, gateway.submitted[1])
	}
	if len(store.acceptedCases) != 1 || store.acceptedCases[0].Receipt.Revision != 41 {
		t.Fatalf("accepted cases = %#v", store.acceptedCases)
	}
}

func TestOpenCaseRejectsUnboundedInputBeforeSpoolingOrSubmitting(t *testing.T) {
	store := &fakeStore{}
	gateway := &fakeGateway{store: store}
	svc := newEdgeService(t, store, gateway)

	_, err := svc.OpenCase(context.Background(), OpenCaseRequest{
		CaseID: "case-1", Domain: "support", Summary: strings.Repeat("x", 4097), ContextManifest: digest("a"),
		Registry: RegistryCoordinates{RoutingEpoch: 7, Revision: 12, Hash: digest("b")},
	})
	if err == nil {
		t.Fatal("OpenCase accepted an unbounded summary")
	}
	if len(store.pending) != 0 || len(gateway.submitted) != 0 {
		t.Fatalf("invalid input reached persistence or gateway: pending=%d submitted=%d", len(store.pending), len(gateway.submitted))
	}
}

func TestFinalizeAdviceSignsOnlyExactCaseBindingAndNoRouteFields(t *testing.T) {
	store := &fakeStore{cases: map[string]CaseRecord{
		"case-1": {CaseID: "case-1", Commitment: digest("c"), Registry: RegistryCoordinates{RoutingEpoch: 7, Revision: 12, Hash: digest("b")}, ExpiresAt: edgeNow.Add(time.Hour), Committed: true},
	}}
	gateway := &fakeGateway{store: store}
	finalizer := newFinalizer(t, store, gateway)

	result, err := finalizer.FinalizeAdvice(context.Background(), FinalizeAdviceRequest{CaseID: "case-1", CaseCommitment: digest("c"), Text: "Use the bounded next step."})
	if err != nil {
		t.Fatal(err)
	}
	if !result.AcceptedRemote {
		t.Fatalf("result = %#v", result)
	}
	var envelope ssp.Envelope
	if err := json.Unmarshal(gateway.submitted[0], &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != ssp.FamilyAdvice || envelope.CaseID != "case-1" {
		t.Fatalf("advice envelope = %#v", envelope)
	}
	var body map[string]any
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 2 || body["case_commitment"] != digest("c") || body["text"] != "Use the bounded next step." {
		t.Fatalf("advice body = %#v, want exact case_commitment + text", body)
	}
	for _, forbidden := range []string{"domain", "target_edge_id", "issuer_edge_id", "buzz"} {
		if _, ok := body[forbidden]; ok {
			t.Fatalf("advice body exposes route field %q: %#v", forbidden, body)
		}
	}
}

func TestFinalizeAdviceLostResponseRetriesExactBytesAndNeverCreatesSecondAdvice(t *testing.T) {
	store := &fakeStore{cases: map[string]CaseRecord{"case-1": {CaseID: "case-1", Commitment: digest("c"), Registry: RegistryCoordinates{RoutingEpoch: 7, Revision: 12, Hash: digest("b")}, ExpiresAt: edgeNow.Add(time.Hour), Committed: true}}}
	gateway := &fakeGateway{store: store, err: errors.New("lost response")}
	finalizer := newFinalizer(t, store, gateway)
	request := FinalizeAdviceRequest{CaseID: "case-1", CaseCommitment: digest("c"), Text: "Use the bounded next step."}

	first, err := finalizer.FinalizeAdvice(context.Background(), request)
	if err == nil || first.AcceptedRemote || len(store.acceptedAdvice) != 0 {
		t.Fatalf("lost response must remain pending: result=%#v err=%v", first, err)
	}
	if len(store.pendingAdvice) != 1 {
		t.Fatalf("pending advice = %#v", store.pendingAdvice)
	}
	raw := append([]byte(nil), store.pendingAdvice[0].Raw...)
	if _, err := finalizer.FinalizeAdvice(context.Background(), request); !errors.Is(err, ErrAlreadyPending) {
		t.Fatalf("second finalization error = %v, want ErrAlreadyPending", err)
	}
	gateway.err = nil
	retried, err := finalizer.RetryAdvice(context.Background(), "case-1")
	if err != nil || !retried.AcceptedRemote || string(gateway.submitted[1]) != string(raw) {
		t.Fatalf("retry=%#v err=%v submitted=%q", retried, err, gateway.submitted[1])
	}
	if len(store.acceptedAdvice) != 1 {
		t.Fatalf("accepted advice = %#v", store.acceptedAdvice)
	}
}

func TestReadSurfacesNeverSubmitOrSign(t *testing.T) {
	store := &fakeStore{cases: map[string]CaseRecord{"case-1": {CaseID: "case-1", Summary: "Need help", Committed: true}}, advice: map[string][]AdviceView{"case-1": {{AdviceID: "advice-1", CaseID: "case-1", Text: "Read this", ReceivedAt: edgeNow}}}}
	gateway := &fakeGateway{store: store}
	svc := newEdgeService(t, store, gateway)

	if _, err := svc.GetCase(context.Background(), "case-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ListAdvice(context.Background(), "case-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PresentAdvice(context.Background(), "advice-1"); err != nil {
		t.Fatal(err)
	}
	if len(gateway.submitted) != 0 {
		t.Fatalf("read surface submitted %d envelopes", len(gateway.submitted))
	}
}

func TestServiceNeverExposesSigningKey(t *testing.T) {
	store := &fakeStore{}
	svc := newEdgeService(t, store, &fakeGateway{store: store})
	if _, exposed := any(svc).(interface {
		SigningKey() identity.Ed25519SigningKey
	}); exposed {
		t.Fatal("service exposes a signing key")
	}
}

func newEdgeService(t *testing.T, store *fakeStore, gateway *fakeGateway) *Service {
	t.Helper()
	key := testSigningKey(t, "edge")
	signer, err := NewCaseSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(ServiceConfig{EdgeID: "edge-a", EdgeGeneration: 3, PrincipalID: "principal-edge", AuthorKeyID: "edge-key", Signer: signer, Store: store, Gateway: gateway, Clock: func() time.Time { return edgeNow }, EnvelopeTTL: time.Hour, NewID: sequenceID("case-envelope-1")})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func newFinalizer(t *testing.T, store *fakeStore, gateway *fakeGateway) *Finalizer {
	t.Helper()
	signer, err := NewAdviceSigner(testSigningKey(t, "dispatcher"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewFinalizer(FinalizerConfig{PrincipalID: "principal-dispatcher", AuthorKeyID: "dispatcher-key", Signer: signer, Cases: store, Spool: store, Gateway: gateway, Clock: func() time.Time { return edgeNow }, EnvelopeTTL: time.Hour, NewID: sequenceID("advice-envelope-1")})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type fakeStore struct {
	pending        []PendingCase
	acceptedCases  []AcceptedRemoteCase
	pendingAdvice  []PendingAdvice
	acceptedAdvice []AcceptedRemoteAdvice
	cases          map[string]CaseRecord
	advice         map[string][]AdviceView
}

func (f *fakeStore) SavePendingCase(_ context.Context, p PendingCase) error {
	f.pending = append(f.pending, clonePending(p))
	return nil
}
func (f *fakeStore) LoadPendingCase(_ context.Context, id string) (PendingCase, bool, error) {
	for _, p := range f.pending {
		if p.CaseID == id {
			return clonePending(p), true, nil
		}
	}
	return PendingCase{}, false, nil
}
func (f *fakeStore) MarkCaseAcceptedRemote(_ context.Context, c AcceptedRemoteCase) error {
	f.acceptedCases = append(f.acceptedCases, c)
	return nil
}
func (f *fakeStore) SavePendingAdvice(_ context.Context, p PendingAdvice) error {
	f.pendingAdvice = append(f.pendingAdvice, cloneAdvice(p))
	return nil
}
func (f *fakeStore) LoadPendingAdvice(_ context.Context, id string) (PendingAdvice, bool, error) {
	for _, p := range f.pendingAdvice {
		if p.CaseID == id {
			return cloneAdvice(p), true, nil
		}
	}
	return PendingAdvice{}, false, nil
}
func (f *fakeStore) MarkAdviceAcceptedRemote(_ context.Context, a AcceptedRemoteAdvice) error {
	f.acceptedAdvice = append(f.acceptedAdvice, a)
	return nil
}
func (f *fakeStore) GetCase(_ context.Context, id string) (CaseRecord, bool, error) {
	c, ok := f.cases[id]
	return c, ok, nil
}
func (f *fakeStore) ListAdvice(_ context.Context, id string) ([]AdviceView, error) {
	return append([]AdviceView(nil), f.advice[id]...), nil
}
func (f *fakeStore) PresentAdvice(_ context.Context, id string) (AdviceView, bool, error) {
	for _, items := range f.advice {
		for _, item := range items {
			if item.AdviceID == id {
				return item, true, nil
			}
		}
	}
	return AdviceView{}, false, nil
}

type fakeGateway struct {
	store                  *fakeStore
	err                    error
	submitted              [][]byte
	sawPendingBeforeSubmit bool
}

func (f *fakeGateway) Submit(_ context.Context, _ WorkloadIdentity, raw []byte) (CommitReceipt, error) {
	f.sawPendingBeforeSubmit = len(f.store.pending) > 0
	f.submitted = append(f.submitted, append([]byte(nil), raw...))
	if f.err != nil {
		return CommitReceipt{}, f.err
	}
	return CommitReceipt{AuthorityID: "postgres-primary", Revision: 41, EnvelopeID: envelopeID(raw), Commitment: mustCommitment(raw)}, nil
}

func testSigningKey(t *testing.T, label string) identity.Ed25519SigningKey {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	key, err := identity.NewEd25519SigningKey(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func digest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
func sequenceID(value string) func() (string, error) {
	return func() (string, error) { return value, nil }
}
func clonePending(p PendingCase) PendingCase    { p.Raw = append([]byte(nil), p.Raw...); return p }
func cloneAdvice(p PendingAdvice) PendingAdvice { p.Raw = append([]byte(nil), p.Raw...); return p }
func envelopeID(raw []byte) string              { var e ssp.Envelope; _ = json.Unmarshal(raw, &e); return e.ID }
func mustCommitment(raw []byte) string {
	commitment, err := ssp.EnvelopeCommitment(raw, edgeNow)
	if err != nil {
		panic(err)
	}
	return commitment
}
