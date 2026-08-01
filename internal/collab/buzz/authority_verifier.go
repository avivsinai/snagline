package buzz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/identity"
	"github.com/avivsinai/snagline/internal/registry"
	"github.com/avivsinai/snagline/internal/ssp"
)

// CommittedAuthority is the read-only evidence required to independently
// authenticate a committed case or advice projection.
type CommittedAuthority interface {
	ResolveRegistry(context.Context, string, int64, string) (authority.RegistryRecord, error)
	ResolveCase(context.Context, string, string, string) (authority.CaseRecord, error)
}

type AuthorityVerifierConfig struct {
	TenantID      string
	Authority     CommittedAuthority
	RegistryTrust registry.Trust
}

// AuthorityVerifier re-verifies exact committed bytes against the exact
// root-signed registry snapshot bound into them. It uses signed emission times
// for historical cryptographic verification, so a disposable Buzz projection
// remains rebuildable after live admission windows expire.
type AuthorityVerifier struct {
	tenantID  string
	authority CommittedAuthority
	trust     registry.Trust
}

var _ CommittedVerifier = (*AuthorityVerifier)(nil)

func NewAuthorityVerifier(config AuthorityVerifierConfig) (*AuthorityVerifier, error) {
	if strings.TrimSpace(config.TenantID) == "" || config.Authority == nil {
		return nil, errors.New("collab buzz: tenant and committed authority are required")
	}
	// NewVerifier is also the validation boundary for the opaque Trust value.
	if _, err := registry.NewVerifier(config.RegistryTrust, time.Now); err != nil {
		return nil, fmt.Errorf("collab buzz: registry trust: %w", err)
	}
	return &AuthorityVerifier{tenantID: config.TenantID, authority: config.Authority, trust: config.RegistryTrust}, nil
}

func (v *AuthorityVerifier) VerifyCommitted(ctx context.Context, raw []byte) (ssp.Envelope, error) {
	if v == nil {
		return ssp.Envelope{}, errors.New("collab buzz: nil authority verifier")
	}
	header, err := ssp.ReadHeader(raw)
	if err != nil {
		return ssp.Envelope{}, fmt.Errorf("collab buzz: committed header: %w", err)
	}
	if header.Schema != ssp.FamilyCase && header.Schema != ssp.FamilyAdvice {
		return ssp.Envelope{}, fmt.Errorf("collab buzz: unsupported committed family %q", header.Schema)
	}
	snapshot, err := v.resolveRegistry(ctx, header)
	if err != nil {
		return ssp.Envelope{}, err
	}
	emittedAt, err := signedEmissionTime(raw)
	if err != nil {
		return ssp.Envelope{}, err
	}
	key, ok := snapshot.Key(header.AuthorKeyID)
	expectedUsage := registry.UsageEdge
	if header.Schema == ssp.FamilyAdvice {
		expectedUsage = registry.UsageAdvice
	}
	if !ok || key.Usage != expectedUsage || !key.Usable(emittedAt) {
		return ssp.Envelope{}, errors.New("collab buzz: committed signer is not authorized")
	}
	verifyingKey, err := identity.NewEd25519VerifyingKey(key.PublicKey)
	if err != nil {
		return ssp.Envelope{}, errors.New("collab buzz: committed signer is invalid")
	}
	envelope, err := ssp.Verify(raw, map[string]identity.Ed25519VerifyingKey{header.AuthorKeyID: verifyingKey}, emittedAt)
	if err != nil {
		return ssp.Envelope{}, fmt.Errorf("collab buzz: verify committed bytes: %w", err)
	}
	switch envelope.Schema {
	case ssp.FamilyCase:
		if err := authorizeProjectedCase(snapshot, key, envelope); err != nil {
			return ssp.Envelope{}, err
		}
	case ssp.FamilyAdvice:
		if err := v.authorizeProjectedAdvice(ctx, snapshot, key, envelope); err != nil {
			return ssp.Envelope{}, err
		}
	}
	return envelope, nil
}

func (v *AuthorityVerifier) resolveRegistry(ctx context.Context, header ssp.EnvelopeHeader) (registry.Registry, error) {
	record, err := v.authority.ResolveRegistry(ctx, v.tenantID, header.RegistryRevision, header.RegistryHash)
	if err != nil {
		return registry.Registry{}, fmt.Errorf("collab buzz: resolve committed registry: %w", err)
	}
	emittedAt, err := signedEmissionTime(record.Raw)
	if err != nil {
		return registry.Registry{}, errors.New("collab buzz: committed registry time is invalid")
	}
	verifier, err := registry.NewVerifier(v.trust, func() time.Time { return emittedAt })
	if err != nil {
		return registry.Registry{}, fmt.Errorf("collab buzz: registry verifier: %w", err)
	}
	verified, err := verifier.Verify(record.Raw)
	if err != nil {
		return registry.Registry{}, fmt.Errorf("collab buzz: root verify committed registry: %w", err)
	}
	snapshot, err := verified.Snapshot()
	if err != nil {
		return registry.Registry{}, err
	}
	commitment, err := verified.Commitment()
	if err != nil {
		return registry.Registry{}, err
	}
	if record.TenantID != v.tenantID ||
		record.Revision != header.RegistryRevision ||
		record.Commitment != header.RegistryHash ||
		record.Commitment != commitment ||
		record.RoutingEpoch != snapshot.RoutingEpoch() ||
		snapshot.Revision() != record.Revision ||
		snapshot.CheckBinding(header.RegistryRevision, header.RegistryHash) != nil {
		return registry.Registry{}, errors.New("collab buzz: committed registry evidence conflicts")
	}
	return snapshot, nil
}

type projectedCaseBody struct {
	Domain               string `json:"domain"`
	IssuerEdgeID         string `json:"issuer_edge_id"`
	IssuerEdgeGeneration int64  `json:"issuer_edge_generation"`
}

func authorizeProjectedCase(snapshot registry.Registry, key registry.KeyRecord, envelope ssp.Envelope) error {
	var body projectedCaseBody
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		return errors.New("collab buzz: committed case body is invalid")
	}
	edge, edgeOK := snapshot.Edge(body.IssuerEdgeID)
	principal, principalOK := snapshot.Principal(edge.PrincipalID)
	route, routeOK := snapshot.Domain(body.Domain)
	if !edgeOK || !principalOK || !routeOK ||
		body.IssuerEdgeGeneration <= 0 ||
		edge.Generation != body.IssuerEdgeGeneration ||
		key.PrincipalID != edge.PrincipalID ||
		!slices.Contains(principal.SSPKeyIDs, envelope.AuthorKeyID) ||
		!snapshot.AuthorizesCaseIssuerGeneration(body.Domain, body.IssuerEdgeID, body.IssuerEdgeGeneration) ||
		!slices.Contains(route.Families, ssp.FamilyCase) ||
		!snapshot.MachineAcceptableEpoch(body.Domain, envelope.RoutingEpoch) {
		return errors.New("collab buzz: committed case authorization conflicts")
	}
	return nil
}

type projectedAdviceBody struct {
	CaseCommitment string `json:"case_commitment"`
}

func (v *AuthorityVerifier) authorizeProjectedAdvice(ctx context.Context, snapshot registry.Registry, key registry.KeyRecord, envelope ssp.Envelope) error {
	var body projectedAdviceBody
	if err := json.Unmarshal(envelope.Body, &body); err != nil || body.CaseCommitment == "" {
		return errors.New("collab buzz: committed advice body is invalid")
	}
	record, err := v.authority.ResolveCase(ctx, v.tenantID, envelope.CaseID, body.CaseCommitment)
	if err != nil {
		return fmt.Errorf("collab buzz: resolve advice case: %w", err)
	}
	caseEmission, err := signedEmissionTime(record.Raw)
	if err != nil {
		return errors.New("collab buzz: committed advice case time is invalid")
	}
	caseCommitment, err := ssp.EnvelopeCommitment(record.Raw, caseEmission)
	if err != nil || caseCommitment != record.Commitment {
		return errors.New("collab buzz: committed advice case evidence conflicts")
	}
	caseHeader, err := ssp.ReadHeader(record.Raw)
	if err != nil ||
		record.TenantID != v.tenantID ||
		record.CaseID != envelope.CaseID ||
		record.RegistryRevision != envelope.RegistryRevision ||
		record.RegistryHash != envelope.RegistryHash ||
		record.RoutingEpoch != envelope.RoutingEpoch ||
		caseHeader.RegistryRevision != envelope.RegistryRevision ||
		caseHeader.RegistryHash != envelope.RegistryHash ||
		caseHeader.RoutingEpoch != envelope.RoutingEpoch {
		return errors.New("collab buzz: committed advice case binding conflicts")
	}
	caseKey, ok := snapshot.Key(caseHeader.AuthorKeyID)
	if !ok || caseKey.Usage != registry.UsageEdge || !caseKey.Usable(caseEmission) {
		return errors.New("collab buzz: committed advice case signer is not authorized")
	}
	caseVerifyingKey, err := identity.NewEd25519VerifyingKey(caseKey.PublicKey)
	if err != nil {
		return errors.New("collab buzz: committed advice case signer is invalid")
	}
	caseEnvelope, err := ssp.Verify(record.Raw, map[string]identity.Ed25519VerifyingKey{caseHeader.AuthorKeyID: caseVerifyingKey}, caseEmission)
	if err != nil || authorizeProjectedCase(snapshot, caseKey, caseEnvelope) != nil {
		return errors.New("collab buzz: committed advice case is invalid")
	}
	var caseBody projectedCaseBody
	if err := json.Unmarshal(caseEnvelope.Body, &caseBody); err != nil || caseBody.Domain != record.Domain {
		return errors.New("collab buzz: committed advice case domain conflicts")
	}
	route, routeOK := snapshot.Domain(caseBody.Domain)
	principal, principalOK := snapshot.Principal(route.DispatcherPrincipalID)
	if !routeOK || !principalOK ||
		key.PrincipalID != route.DispatcherPrincipalID ||
		!slices.Contains(principal.SSPKeyIDs, envelope.AuthorKeyID) ||
		!slices.Contains(route.Families, ssp.FamilyAdvice) ||
		!snapshot.MachineAcceptableEpoch(caseBody.Domain, envelope.RoutingEpoch) {
		return errors.New("collab buzz: committed advice authorization conflicts")
	}
	return nil
}

func signedEmissionTime(raw []byte) (time.Time, error) {
	var hint struct {
		EmittedAt string `json:"emitted_at"`
	}
	if err := json.Unmarshal(raw, &hint); err != nil {
		return time.Time{}, errors.New("collab buzz: committed emission time is invalid")
	}
	emittedAt, err := ssp.ParseTimestamp(hint.EmittedAt)
	if err != nil {
		return time.Time{}, errors.New("collab buzz: committed emission time is invalid")
	}
	return emittedAt, nil
}
