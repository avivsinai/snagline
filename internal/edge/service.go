// Package edge owns the local, provider-neutral SSP edge boundary.
//
// It can create a signed support case and display accepted advice. It cannot
// execute advice, choose an advice route, or expose the private signing key.
package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/ssp"
)

var (
	ErrNotFound              = errors.New("edge: not found")
	ErrNotCommitted          = errors.New("edge: case is not committed")
	ErrAlreadyPending        = errors.New("edge: case already has a pending submission")
	ErrPendingAdviceConflict = errors.New("edge: pending advice conflicts with finalization request")
)

var sha256Commitment = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// RegistryCoordinates are copied into a case envelope and, for advice, are
// derived exclusively from the exact committed case.
type RegistryCoordinates struct {
	RoutingEpoch int64
	Revision     int64
	Hash         string
}

// OpenCaseRequest is the bounded local input for a new support case.
// Environment/tenant/region are deployment scope and deliberately are not
// request fields. The signed case body owns domain and issuer_edge_id.
type OpenCaseRequest struct {
	CaseID          string
	Domain          string
	Summary         string
	PublicSummary   string
	ContextManifest string
	Registry        RegistryCoordinates
}

// PendingCase is the encrypted-spool record. Implementations must encrypt Raw
// at rest and preserve it byte-for-byte until the global authority accepts it.
type PendingCase struct {
	EnvelopeID string
	CaseID     string
	Commitment string
	Raw        []byte
	CreatedAt  time.Time
}

// CommitReceipt is issued by PostgreSQL, the global transactional authority.
// JetStream delivery is deliberately absent: it can replay the committed fact,
// but it cannot prove admission.
type CommitReceipt struct {
	AuthorityID string
	Revision    int64
	EnvelopeID  string
	Commitment  string
}

// AcceptedRemoteCase records the sole evidence that an edge may call a
// submission accepted_remote: a stable receipt from the global authority.
type AcceptedRemoteCase struct {
	EnvelopeID string
	CaseID     string
	Commitment string
	Receipt    CommitReceipt
	AcceptedAt time.Time
}

// CaseRecord and AdviceView are display/read-model values. Neither carries a
// private key, a raw signing payload, a provider route, or an effect command.
type CaseRecord struct {
	EnvelopeID string
	CaseID     string
	Commitment string
	Summary    string
	Registry   RegistryCoordinates
	ExpiresAt  time.Time
	Committed  bool
}

type AdviceView struct {
	AdviceID   string
	CaseID     string
	Text       string
	ReceivedAt time.Time
}

// EncryptedPendingSpool is the local durability boundary. SavePendingCase must
// durably encrypt Raw before returning nil. MarkCaseCommitted must be driven
// only by an actual CommitReceipt; it is never called on a transport attempt.
type EncryptedPendingSpool interface {
	SavePendingCase(context.Context, PendingCase) error
	LoadPendingCase(context.Context, string) (PendingCase, bool, error)
	MarkCaseAcceptedRemote(context.Context, AcceptedRemoteCase) error
}

// ReadModel is read/display-only. It intentionally has no mutation or provider
// adapter methods.
type ReadModel interface {
	GetCase(context.Context, string) (CaseRecord, bool, error)
	ListAdvice(context.Context, string) ([]AdviceView, error)
	PresentAdvice(context.Context, string) (AdviceView, bool, error)
}

type CaseStore interface {
	EncryptedPendingSpool
	ReadModel
}

type WorkloadIdentity struct {
	PrincipalID    string
	EdgeID         string
	EdgeGeneration int64
}

// GatewayClient authenticates the local workload and accepts exact SSP bytes.
// There is deliberately no route parameter: the gateway derives it after
// verification from the signed case or exact committed-case binding.
type GatewayClient interface {
	Submit(context.Context, WorkloadIdentity, []byte) (CommitReceipt, error)
}

// CaseSigner can create only a case envelope. It is not a generic signing
// primitive and has no method for returning private key material.
type CaseSigner interface {
	SignCase(ssp.Envelope, time.Time) ([]byte, error)
}

type localCaseSigner struct{ key identity.Ed25519SigningKey }

func NewCaseSigner(key identity.Ed25519SigningKey) (CaseSigner, error) {
	if key.IsZero() {
		return nil, errors.New("edge: case signing key is required")
	}
	return localCaseSigner{key: key}, nil
}

func (s localCaseSigner) SignCase(envelope ssp.Envelope, now time.Time) ([]byte, error) {
	if envelope.Schema != ssp.FamilyCase {
		return nil, errors.New("edge: case signer only signs ssp.case.v1")
	}
	return ssp.Sign(envelope, s.key, now)
}

type ServiceConfig struct {
	EdgeID         string
	EdgeGeneration int64
	PrincipalID    string
	AuthorKeyID    string
	Signer         CaseSigner
	Store          CaseStore
	Gateway        GatewayClient
	Clock          func() time.Time
	EnvelopeTTL    time.Duration
	NewID          func() (string, error)
}

type Service struct {
	edgeID         string
	edgeGeneration int64
	principalID    string
	authorKeyID    string
	signer         CaseSigner
	store          CaseStore
	gateway        GatewayClient
	clock          func() time.Time
	ttl            time.Duration
	newID          func() (string, error)
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.EdgeID == "" || config.EdgeGeneration <= 0 || config.PrincipalID == "" || config.AuthorKeyID == "" || config.Signer == nil || config.Store == nil || config.Gateway == nil || config.NewID == nil {
		return nil, errors.New("edge: edge identity, signer, store, gateway, and ID generator are required")
	}
	if config.EnvelopeTTL <= 0 {
		return nil, errors.New("edge: envelope TTL must be positive")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{edgeID: config.EdgeID, edgeGeneration: config.EdgeGeneration, principalID: config.PrincipalID, authorKeyID: config.AuthorKeyID, signer: config.Signer, store: config.Store, gateway: config.Gateway, clock: clock, ttl: config.EnvelopeTTL, newID: config.NewID}, nil
}

type CaseSubmission struct {
	EnvelopeID     string
	CaseID         string
	Commitment     string
	AcceptedRemote bool
	Receipt        CommitReceipt
}

// OpenCase signs one exact SSP case, durably spools its bytes, then submits
// those same bytes. A failed/lost submission remains pending and never causes a
// committed claim. RetryCase always resubmits the stored bytes without signing.
func (s *Service) OpenCase(ctx context.Context, request OpenCaseRequest) (CaseSubmission, error) {
	if s == nil {
		return CaseSubmission{}, errors.New("edge: nil service")
	}
	if err := validateOpenCaseRequest(request); err != nil {
		return CaseSubmission{}, err
	}
	if _, exists, err := s.store.LoadPendingCase(ctx, request.CaseID); err != nil {
		return CaseSubmission{}, fmt.Errorf("edge: load pending case: %w", err)
	} else if exists {
		return CaseSubmission{}, ErrAlreadyPending
	}
	now := s.clock().UTC()
	envelopeID, err := s.newID()
	if err != nil {
		return CaseSubmission{}, fmt.Errorf("edge: create envelope ID: %w", err)
	}
	body, err := json.Marshal(struct {
		Domain               string `json:"domain"`
		IssuerEdgeID         string `json:"issuer_edge_id"`
		IssuerEdgeGeneration int64  `json:"issuer_edge_generation"`
		Summary              string `json:"summary"`
		PublicSummary        string `json:"public_summary"`
		ContextManifest      string `json:"context_manifest"`
	}{Domain: request.Domain, IssuerEdgeID: s.edgeID, IssuerEdgeGeneration: s.edgeGeneration, Summary: request.Summary, PublicSummary: request.PublicSummary, ContextManifest: request.ContextManifest})
	if err != nil {
		return CaseSubmission{}, fmt.Errorf("edge: encode case body: %w", err)
	}
	raw, err := s.signer.SignCase(ssp.Envelope{
		Schema: ssp.FamilyCase, ID: envelopeID, CaseID: request.CaseID,
		EmittedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(s.ttl).Format(time.RFC3339),
		RoutingEpoch: request.Registry.RoutingEpoch, RegistryRevision: request.Registry.Revision, RegistryHash: request.Registry.Hash,
		AuthorKeyID: s.authorKeyID, SignatureAlg: "ed25519", Body: body,
	}, now)
	if err != nil {
		return CaseSubmission{}, fmt.Errorf("edge: sign case: %w", err)
	}
	commitment, err := ssp.EnvelopeCommitment(raw, now)
	if err != nil {
		return CaseSubmission{}, fmt.Errorf("edge: commit signed case: %w", err)
	}
	pending := PendingCase{EnvelopeID: envelopeID, CaseID: request.CaseID, Commitment: commitment, Raw: append([]byte(nil), raw...), CreatedAt: now}
	if err := s.store.SavePendingCase(ctx, pending); err != nil {
		return CaseSubmission{}, fmt.Errorf("edge: save pending case: %w", err)
	}
	return s.submitPending(ctx, pending)
}

func (s *Service) RetryCase(ctx context.Context, caseID string) (CaseSubmission, error) {
	if s == nil {
		return CaseSubmission{}, errors.New("edge: nil service")
	}
	pending, ok, err := s.store.LoadPendingCase(ctx, caseID)
	if err != nil {
		return CaseSubmission{}, fmt.Errorf("edge: load pending case: %w", err)
	}
	if !ok {
		return CaseSubmission{}, ErrNotFound
	}
	return s.submitPending(ctx, pending)
}

func (s *Service) submitPending(ctx context.Context, pending PendingCase) (CaseSubmission, error) {
	result := CaseSubmission{EnvelopeID: pending.EnvelopeID, CaseID: pending.CaseID, Commitment: pending.Commitment}
	receipt, err := s.gateway.Submit(ctx, WorkloadIdentity{
		PrincipalID: s.principalID, EdgeID: s.edgeID, EdgeGeneration: s.edgeGeneration,
	}, append([]byte(nil), pending.Raw...))
	if err != nil {
		return result, fmt.Errorf("edge: submit pending case: %w", err)
	}
	if receipt.EnvelopeID != pending.EnvelopeID {
		return result, errors.New("edge: authority accepted different envelope")
	}
	if receipt.Commitment != pending.Commitment {
		return result, errors.New("edge: authority accepted different commitment")
	}
	if receipt.AuthorityID == "" || receipt.Revision <= 0 {
		return result, errors.New("edge: gateway returned incomplete commit receipt")
	}
	if err := s.store.MarkCaseAcceptedRemote(ctx, AcceptedRemoteCase{EnvelopeID: pending.EnvelopeID, CaseID: pending.CaseID, Commitment: pending.Commitment, Receipt: receipt, AcceptedAt: s.clock().UTC()}); err != nil {
		return result, fmt.Errorf("edge: mark accepted remote case: %w", err)
	}
	result.AcceptedRemote, result.Receipt = true, receipt
	return result, nil
}

func (s *Service) GetCase(ctx context.Context, caseID string) (CaseRecord, error) {
	c, ok, err := s.store.GetCase(ctx, caseID)
	if err != nil {
		return CaseRecord{}, err
	}
	if !ok {
		return CaseRecord{}, ErrNotFound
	}
	return c, nil
}
func (s *Service) ListAdvice(ctx context.Context, caseID string) ([]AdviceView, error) {
	return s.store.ListAdvice(ctx, caseID)
}
func (s *Service) PresentAdvice(ctx context.Context, adviceID string) (AdviceView, error) {
	a, ok, err := s.store.PresentAdvice(ctx, adviceID)
	if err != nil {
		return AdviceView{}, err
	}
	if !ok {
		return AdviceView{}, ErrNotFound
	}
	return a, nil
}

// AdviceSigner is intentionally family-specific. It cannot sign an arbitrary
// payload, and no API returns its underlying private key.
type AdviceSigner interface {
	SignAdvice(ssp.Envelope, time.Time) ([]byte, error)
}
type localAdviceSigner struct{ key identity.Ed25519SigningKey }

func NewAdviceSigner(key identity.Ed25519SigningKey) (AdviceSigner, error) {
	if key.IsZero() {
		return nil, errors.New("edge: advice signing key is required")
	}
	return localAdviceSigner{key: key}, nil
}
func (s localAdviceSigner) SignAdvice(envelope ssp.Envelope, now time.Time) ([]byte, error) {
	if envelope.Schema != ssp.FamilyAdvice {
		return nil, errors.New("edge: advice signer only signs ssp.advice.v1")
	}
	return ssp.Sign(envelope, s.key, now)
}

type FinalizeAdviceRequest struct {
	CaseID         string
	CaseCommitment string
	Text           string
	PublicSummary  string
}

// PendingAdvice is durable encrypted local state for the one final advice
// semantic key: CaseID. A retry reuses Raw, AdviceID, and Commitment exactly.
type PendingAdvice struct {
	AdviceID       string
	CaseID         string
	CaseCommitment string
	Commitment     string
	Raw            []byte
	CreatedAt      time.Time
}

type AcceptedRemoteAdvice struct {
	AdviceID   string
	CaseID     string
	Commitment string
	Receipt    CommitReceipt
	AcceptedAt time.Time
}

// AdviceSpool must encrypt Raw at rest. Its semantic lookup key is CaseID, so
// a lost response cannot cause a second advice finalization for one case.
type AdviceSpool interface {
	SavePendingAdvice(context.Context, PendingAdvice) error
	LoadPendingAdvice(context.Context, string) (PendingAdvice, bool, error)
	MarkAdviceAcceptedRemote(context.Context, AcceptedRemoteAdvice) error
}

type FinalizerConfig struct {
	PrincipalID string
	AuthorKeyID string
	Signer      AdviceSigner
	Cases       interface {
		GetCase(context.Context, string) (CaseRecord, bool, error)
	}
	Spool       AdviceSpool
	Gateway     GatewayClient
	Clock       func() time.Time
	EnvelopeTTL time.Duration
	NewID       func() (string, error)
}
type Finalizer struct {
	principalID string
	authorKeyID string
	signer      AdviceSigner
	cases       interface {
		GetCase(context.Context, string) (CaseRecord, bool, error)
	}
	spool   AdviceSpool
	gateway GatewayClient
	clock   func() time.Time
	ttl     time.Duration
	newID   func() (string, error)
}

func NewFinalizer(config FinalizerConfig) (*Finalizer, error) {
	if config.PrincipalID == "" || config.AuthorKeyID == "" || config.Signer == nil || config.Cases == nil || config.Spool == nil || config.Gateway == nil || config.NewID == nil || config.EnvelopeTTL <= 0 {
		return nil, errors.New("edge: dispatcher identity, signer, cases, advice spool, gateway, positive TTL, and ID generator are required")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Finalizer{principalID: config.PrincipalID, authorKeyID: config.AuthorKeyID, signer: config.Signer, cases: config.Cases, spool: config.Spool, gateway: config.Gateway, clock: clock, ttl: config.EnvelopeTTL, newID: config.NewID}, nil
}

type AdviceSubmission struct {
	EnvelopeID     string
	CaseID         string
	Commitment     string
	AcceptedRemote bool
	Receipt        CommitReceipt
}

// FinalizeAdvice is a one-shot dispatcher action. It derives all header
// coordinates from the committed case and signs a body containing exactly the
// case commitment, confidential inert text, and explicit public summary. It
// spools before submission and cannot mint
// a second finalization for a case after a lost response.
func (s *Finalizer) FinalizeAdvice(ctx context.Context, request FinalizeAdviceRequest) (AdviceSubmission, error) {
	if s == nil {
		return AdviceSubmission{}, errors.New("edge: nil finalizer")
	}
	if err := validateFinalizeAdviceRequest(request); err != nil {
		return AdviceSubmission{}, err
	}
	if pending, exists, err := s.spool.LoadPendingAdvice(ctx, request.CaseID); err != nil {
		return AdviceSubmission{}, fmt.Errorf("edge: load pending advice: %w", err)
	} else if exists {
		matches, err := pendingAdviceMatchesRequest(pending.Raw, request, s.clock().UTC())
		if err != nil {
			return AdviceSubmission{}, fmt.Errorf("edge: decode pending advice: %w", err)
		}
		if !matches {
			return AdviceSubmission{}, ErrPendingAdviceConflict
		}
		return AdviceSubmission{}, ErrAlreadyPending
	}
	caseRecord, ok, err := s.cases.GetCase(ctx, request.CaseID)
	if err != nil {
		return AdviceSubmission{}, fmt.Errorf("edge: read committed case: %w", err)
	}
	if !ok {
		return AdviceSubmission{}, ErrNotFound
	}
	if !caseRecord.Committed || caseRecord.Commitment != request.CaseCommitment {
		return AdviceSubmission{}, ErrNotCommitted
	}
	now := s.clock().UTC()
	expires := now.Add(s.ttl)
	if caseRecord.ExpiresAt.Before(expires) {
		expires = caseRecord.ExpiresAt
	}
	if !expires.After(now) {
		return AdviceSubmission{}, ErrNotCommitted
	}
	id, err := s.newID()
	if err != nil {
		return AdviceSubmission{}, fmt.Errorf("edge: create advice ID: %w", err)
	}
	body, err := json.Marshal(struct {
		CaseCommitment string `json:"case_commitment"`
		Text           string `json:"text"`
		PublicSummary  string `json:"public_summary"`
	}{CaseCommitment: request.CaseCommitment, Text: request.Text, PublicSummary: request.PublicSummary})
	if err != nil {
		return AdviceSubmission{}, fmt.Errorf("edge: encode advice body: %w", err)
	}
	raw, err := s.signer.SignAdvice(ssp.Envelope{Schema: ssp.FamilyAdvice, ID: id, CaseID: caseRecord.CaseID, EmittedAt: now.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339), RoutingEpoch: caseRecord.Registry.RoutingEpoch, RegistryRevision: caseRecord.Registry.Revision, RegistryHash: caseRecord.Registry.Hash, AuthorKeyID: s.authorKeyID, SignatureAlg: "ed25519", Body: body}, now)
	if err != nil {
		return AdviceSubmission{}, fmt.Errorf("edge: sign advice: %w", err)
	}
	commitment, err := ssp.EnvelopeCommitment(raw, now)
	if err != nil {
		return AdviceSubmission{}, fmt.Errorf("edge: commit signed advice: %w", err)
	}
	pending := PendingAdvice{AdviceID: id, CaseID: caseRecord.CaseID, CaseCommitment: request.CaseCommitment, Commitment: commitment, Raw: append([]byte(nil), raw...), CreatedAt: now}
	if err := s.spool.SavePendingAdvice(ctx, pending); err != nil {
		return AdviceSubmission{}, fmt.Errorf("edge: save pending advice: %w", err)
	}
	return s.submitPendingAdvice(ctx, pending)
}

func (s *Finalizer) RetryAdvice(ctx context.Context, caseID string) (AdviceSubmission, error) {
	if s == nil {
		return AdviceSubmission{}, errors.New("edge: nil finalizer")
	}
	pending, ok, err := s.spool.LoadPendingAdvice(ctx, caseID)
	if err != nil {
		return AdviceSubmission{}, fmt.Errorf("edge: load pending advice: %w", err)
	}
	if !ok {
		return AdviceSubmission{}, ErrNotFound
	}
	return s.submitPendingAdvice(ctx, pending)
}

func (s *Finalizer) submitPendingAdvice(ctx context.Context, pending PendingAdvice) (AdviceSubmission, error) {
	result := AdviceSubmission{EnvelopeID: pending.AdviceID, CaseID: pending.CaseID, Commitment: pending.Commitment}
	receipt, err := s.gateway.Submit(ctx, WorkloadIdentity{PrincipalID: s.principalID}, append([]byte(nil), pending.Raw...))
	if err != nil {
		return result, fmt.Errorf("edge: submit pending advice: %w", err)
	}
	if receipt.EnvelopeID != pending.AdviceID || receipt.Commitment != pending.Commitment || receipt.AuthorityID == "" || receipt.Revision <= 0 {
		return result, errors.New("edge: gateway returned mismatched or incomplete commit receipt")
	}
	if err := s.spool.MarkAdviceAcceptedRemote(ctx, AcceptedRemoteAdvice{AdviceID: pending.AdviceID, CaseID: pending.CaseID, Commitment: pending.Commitment, Receipt: receipt, AcceptedAt: s.clock().UTC()}); err != nil {
		return result, fmt.Errorf("edge: mark accepted remote advice: %w", err)
	}
	result.AcceptedRemote, result.Receipt = true, receipt
	return result, nil
}

func validateOpenCaseRequest(request OpenCaseRequest) error {
	if !validOpaque(request.CaseID) || !validOpaque(request.Domain) {
		return errors.New("edge: case ID and domain must be bounded opaque identifiers")
	}
	if !validText(request.Summary, 4096) {
		return errors.New("edge: case summary must contain 1..4096 UTF-8 code points")
	}
	if !validText(request.PublicSummary, 1024) {
		return errors.New("edge: public case summary must contain 1..1024 UTF-8 code points")
	}
	if !sha256Commitment.MatchString(request.ContextManifest) || !sha256Commitment.MatchString(request.Registry.Hash) || request.Registry.RoutingEpoch < 0 || request.Registry.Revision < 0 {
		return errors.New("edge: case registry coordinates or context manifest are invalid")
	}
	return nil
}

func validateFinalizeAdviceRequest(request FinalizeAdviceRequest) error {
	if !validOpaque(request.CaseID) || !sha256Commitment.MatchString(request.CaseCommitment) || !validText(request.Text, 8192) || !validText(request.PublicSummary, 1024) {
		return errors.New("edge: advice request is invalid")
	}
	return nil
}

// pendingAdviceMatchesRequest decodes the exact internally signed wire rather
// than trusting duplicate spool metadata. EnvelopeCommitment supplies the same
// strict structural and family validation used by SSP verification; the
// encrypted spool owns the internally produced signature bytes.
func pendingAdviceMatchesRequest(raw []byte, request FinalizeAdviceRequest, now time.Time) (bool, error) {
	if _, err := ssp.EnvelopeCommitment(raw, now); err != nil {
		return false, err
	}
	var envelope ssp.Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return false, err
	}
	if envelope.Schema != ssp.FamilyAdvice {
		return false, errors.New("stored envelope is not advice")
	}
	var body struct {
		CaseCommitment string `json:"case_commitment"`
		Text           string `json:"text"`
		PublicSummary  string `json:"public_summary"`
	}
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		return false, err
	}
	return envelope.CaseID == request.CaseID &&
		body.CaseCommitment == request.CaseCommitment &&
		body.Text == request.Text &&
		body.PublicSummary == request.PublicSummary, nil
}

func validOpaque(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= 1 && utf8.RuneCountInString(value) <= 512
}

func validText(value string, maximum int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= 1 && utf8.RuneCountInString(value) <= maximum
}
