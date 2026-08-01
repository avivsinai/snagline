package sspedge

import (
	"bytes"
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

// ProjectionAuthority is the narrow, read-only PostgreSQL evidence boundary
// needed to independently verify an edge delivery.
type ProjectionAuthority interface {
	ListEdgeDeliveries(context.Context, authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error)
	ResolveCase(context.Context, string, string) (authority.CaseRecord, error)
	ResolveRegistry(context.Context, string, int64, string) (authority.RegistryRecord, error)
}

type AuthorityVerifierConfig struct {
	Tenant        string
	Authority     ProjectionAuthority
	RegistryTrust registry.Trust
}

// AuthorityVerifier reconstructs display-only projections from exact
// PostgreSQL facts and a deployment-pinned registry root. It has no mutation,
// provider, broker cursor, or effect authority.
type AuthorityVerifier struct {
	tenant    string
	authority ProjectionAuthority
	trust     registry.Trust
}

var _ Verifier = (*AuthorityVerifier)(nil)

func NewAuthorityVerifier(config AuthorityVerifierConfig) (*AuthorityVerifier, error) {
	if strings.TrimSpace(config.Tenant) == "" || config.Authority == nil {
		return nil, errors.New("sspedge: tenant and projection authority are required")
	}
	if _, err := registry.NewVerifier(config.RegistryTrust, time.Now); err != nil {
		return nil, fmt.Errorf("sspedge: registry trust: %w", err)
	}
	return &AuthorityVerifier{
		tenant: config.Tenant, authority: config.Authority, trust: config.RegistryTrust,
	}, nil
}

type verifiedCaseBody struct {
	Domain               string `json:"domain"`
	IssuerEdgeID         string `json:"issuer_edge_id"`
	IssuerEdgeGeneration int64  `json:"issuer_edge_generation"`
	Summary              string `json:"summary"`
	PublicSummary        string `json:"public_summary"`
	ContextManifest      string `json:"context_manifest"`
}

type verifiedAdviceBody struct {
	CaseCommitment string `json:"case_commitment"`
	Text           string `json:"text"`
	PublicSummary  string `json:"public_summary"`
}

func (v *AuthorityVerifier) Verify(ctx context.Context, delivery JournalDelivery) (*VerifiedProjection, error) {
	if v == nil || v.authority == nil {
		return nil, Transient(errors.New("sspedge: nil authority verifier"))
	}
	if delivery.TenantID != v.tenant || delivery.EdgeID == "" || delivery.EdgeGeneration <= 0 ||
		delivery.DeliverySeq <= 0 || len(delivery.Raw) == 0 {
		return nil, Permanent("delivery_identity_mismatch", errors.New("sspedge: invalid delivery identity"))
	}
	authorityDelivery, err := v.resolveExactDelivery(ctx, delivery)
	if err != nil {
		return nil, err
	}
	header, err := ssp.ReadHeader(delivery.Raw)
	if err != nil {
		return nil, Permanent("malformed_envelope", fmt.Errorf("sspedge: read delivery header: %w", err))
	}
	if header.Schema != ssp.FamilyCase && header.Schema != ssp.FamilyAdvice {
		return nil, Permanent("unsupported_family", fmt.Errorf("sspedge: unsupported family %q", header.Schema))
	}
	emittedAt, err := ssp.ParseTimestamp(header.EmittedAt)
	if err != nil {
		return nil, Permanent("invalid_emission_time", err)
	}
	commitment, err := ssp.EnvelopeCommitment(delivery.Raw, emittedAt)
	if err != nil {
		return nil, Permanent("invalid_envelope", fmt.Errorf("sspedge: delivery commitment: %w", err))
	}
	kind := "case"
	if header.Schema == ssp.FamilyAdvice {
		kind = "advice"
	}
	if authorityDelivery.Kind != kind ||
		authorityDelivery.CaseID != header.CaseID ||
		authorityDelivery.EnvelopeID != header.ID ||
		authorityDelivery.Commitment != commitment ||
		authorityDelivery.AuthorityRevision <= 0 {
		return nil, Permanent("authority_delivery_mismatch", errors.New("sspedge: exact authority delivery metadata does not match SSP bytes"))
	}
	registryRecord, snapshot, err := v.resolveRegistry(ctx, header, emittedAt)
	if err != nil {
		return nil, err
	}

	switch header.Schema {
	case ssp.FamilyCase:
		return v.verifyCaseDelivery(ctx, delivery, header, commitment, registryRecord, snapshot, emittedAt)
	case ssp.FamilyAdvice:
		return v.verifyAdviceDelivery(ctx, delivery, header, commitment, registryRecord, snapshot, emittedAt)
	default:
		panic("unreachable")
	}
}

func (v *AuthorityVerifier) resolveExactDelivery(
	ctx context.Context,
	delivery JournalDelivery,
) (authority.EdgeDelivery, error) {
	page, err := v.authority.ListEdgeDeliveries(ctx, authority.EdgeDeliveryQuery{
		TenantID: v.tenant, EdgeID: delivery.EdgeID, EdgeGeneration: delivery.EdgeGeneration,
		AfterSequence: delivery.DeliverySeq - 1, Limit: 1,
	})
	if err != nil {
		return authority.EdgeDelivery{}, Transient(fmt.Errorf("sspedge: resolve exact authority delivery: %w", err))
	}
	if len(page.Deliveries) != 1 ||
		page.Deliveries[0].Sequence != delivery.DeliverySeq ||
		!bytes.Equal(page.Deliveries[0].Raw, delivery.Raw) {
		// A carrier coordinate is not authority. Missing or different bytes may
		// be replica lag or a forged broker message, and must never durably
		// consume the claimed PostgreSQL delivery sequence.
		return authority.EdgeDelivery{}, Transient(errors.New("sspedge: carrier delivery is not the exact PostgreSQL delivery"))
	}
	return page.Deliveries[0], nil
}

func (v *AuthorityVerifier) resolveRegistry(
	ctx context.Context,
	header ssp.EnvelopeHeader,
	at time.Time,
) (authority.RegistryRecord, registry.Registry, error) {
	record, err := v.authority.ResolveRegistry(ctx, v.tenant, header.RegistryRevision, header.RegistryHash)
	if err != nil {
		if errors.Is(err, authority.ErrRegistryNotFound) {
			return authority.RegistryRecord{}, registry.Registry{}, Permanent("registry_not_found", err)
		}
		return authority.RegistryRecord{}, registry.Registry{}, Transient(fmt.Errorf("sspedge: resolve authority registry: %w", err))
	}
	snapshot, err := v.verifyRegistryRecord(record, header.RegistryRevision, header.RegistryHash, header.RoutingEpoch, at)
	if err != nil {
		return authority.RegistryRecord{}, registry.Registry{}, err
	}
	return record, snapshot, nil
}

func (v *AuthorityVerifier) verifyRegistryRecord(
	record authority.RegistryRecord,
	revision int64,
	commitment string,
	routingEpoch int64,
	at time.Time,
) (registry.Registry, error) {
	if record.TenantID != v.tenant || record.Revision != revision ||
		record.Commitment != commitment || record.RoutingEpoch != routingEpoch ||
		record.EnvelopeID == "" || len(record.Raw) == 0 || record.AuthorityRevision <= 0 {
		return registry.Registry{}, Permanent("registry_authority_mismatch", errors.New("sspedge: authority registry metadata mismatch"))
	}
	rootVerifier, err := registry.NewVerifier(v.trust, func() time.Time { return at })
	if err != nil {
		return registry.Registry{}, Transient(fmt.Errorf("sspedge: construct registry verifier: %w", err))
	}
	verified, err := rootVerifier.Verify(record.Raw)
	if err != nil {
		return registry.Registry{}, Permanent("invalid_registry_proof", fmt.Errorf("sspedge: verify authority registry: %w", err))
	}
	snapshot, err := verified.Snapshot()
	if err != nil {
		return registry.Registry{}, Permanent("invalid_registry_proof", err)
	}
	actualCommitment, err := verified.Commitment()
	if err != nil {
		return registry.Registry{}, Permanent("invalid_registry_proof", err)
	}
	registryHeader, err := ssp.ReadHeader(record.Raw)
	if err != nil ||
		registryHeader.Schema != ssp.FamilyRegistry ||
		registryHeader.ID != record.EnvelopeID ||
		registryHeader.RegistryRevision != record.Revision ||
		registryHeader.RoutingEpoch != record.RoutingEpoch ||
		actualCommitment != record.Commitment ||
		snapshot.Revision() != record.Revision ||
		snapshot.RoutingEpoch() != record.RoutingEpoch ||
		snapshot.Expired(at) ||
		snapshot.CheckBinding(revision, commitment) != nil {
		if err == nil {
			err = errors.New("sspedge: root-verified registry does not match authority record")
		}
		return registry.Registry{}, Permanent("registry_authority_mismatch", err)
	}
	return snapshot, nil
}

func verifyRegisteredEnvelope(
	raw []byte,
	header ssp.EnvelopeHeader,
	snapshot registry.Registry,
	usage registry.KeyUsage,
	emittedAt time.Time,
) (registry.KeyRecord, ssp.Envelope, error) {
	key, ok := snapshot.Key(header.AuthorKeyID)
	if !ok || key.Usage != usage || !key.Usable(emittedAt) {
		return registry.KeyRecord{}, ssp.Envelope{}, Permanent("unauthorized_signing_key", errors.New("sspedge: signing key is not authorized at emission"))
	}
	verifyingKey, err := identity.NewEd25519VerifyingKey(key.PublicKey)
	if err != nil {
		return registry.KeyRecord{}, ssp.Envelope{}, Permanent("invalid_signing_key", err)
	}
	envelope, err := ssp.Verify(raw, map[string]identity.Ed25519VerifyingKey{
		header.AuthorKeyID: verifyingKey,
	}, emittedAt)
	if err != nil {
		return registry.KeyRecord{}, ssp.Envelope{}, Permanent("invalid_signature", fmt.Errorf("sspedge: verify delivery envelope: %w", err))
	}
	actualEmission, err := ssp.ParseTimestamp(envelope.EmittedAt)
	if err != nil || !actualEmission.Equal(emittedAt) || !key.Usable(actualEmission) {
		return registry.KeyRecord{}, ssp.Envelope{}, Permanent("unauthorized_signing_key", errors.New("sspedge: signing key is not authorized at signed emission"))
	}
	return key, envelope, nil
}

func authorizeCase(
	snapshot registry.Registry,
	header ssp.EnvelopeHeader,
	key registry.KeyRecord,
	envelope ssp.Envelope,
) (verifiedCaseBody, error) {
	var body verifiedCaseBody
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		return verifiedCaseBody{}, Permanent("invalid_case_body", err)
	}
	registeredEdge, edgeOK := snapshot.Edge(body.IssuerEdgeID)
	principal, principalOK := snapshot.Principal(registeredEdge.PrincipalID)
	route, routeOK := snapshot.Domain(body.Domain)
	if !edgeOK || !principalOK || !routeOK ||
		registeredEdge.Generation != body.IssuerEdgeGeneration ||
		key.PrincipalID != registeredEdge.PrincipalID ||
		!slices.Contains(principal.SSPKeyIDs, header.AuthorKeyID) ||
		!slices.Contains(principal.EdgeIDs, body.IssuerEdgeID) ||
		!snapshot.AuthorizesCaseIssuerGeneration(body.Domain, body.IssuerEdgeID, body.IssuerEdgeGeneration) ||
		!slices.Contains(route.Families, ssp.FamilyCase) ||
		!snapshot.MachineAcceptableEpoch(body.Domain, envelope.RoutingEpoch) {
		return verifiedCaseBody{}, Permanent("unauthorized_case", errors.New("sspedge: registry does not authorize case issuer and route"))
	}
	return body, nil
}

func (v *AuthorityVerifier) verifyCaseDelivery(
	ctx context.Context,
	delivery JournalDelivery,
	header ssp.EnvelopeHeader,
	commitment string,
	_ authority.RegistryRecord,
	snapshot registry.Registry,
	emittedAt time.Time,
) (*VerifiedProjection, error) {
	key, envelope, err := verifyRegisteredEnvelope(delivery.Raw, header, snapshot, registry.UsageEdge, emittedAt)
	if err != nil {
		return nil, err
	}
	body, err := authorizeCase(snapshot, header, key, envelope)
	if err != nil {
		return nil, err
	}
	if envelope.Schema != ssp.FamilyCase ||
		body.IssuerEdgeID != delivery.EdgeID ||
		body.IssuerEdgeGeneration != delivery.EdgeGeneration {
		return nil, Permanent("delivery_identity_mismatch", errors.New("sspedge: case does not belong to delivery edge generation"))
	}
	record, err := v.authority.ResolveCase(ctx, envelope.CaseID, commitment)
	if err != nil {
		if errors.Is(err, authority.ErrCaseNotFound) {
			return nil, Permanent("case_not_found", err)
		}
		return nil, Transient(fmt.Errorf("sspedge: resolve authority case: %w", err))
	}
	expiresAt, err := ssp.ParseTimestamp(envelope.ExpiresAt)
	if err != nil {
		return nil, Permanent("invalid_case_expiry", err)
	}
	if err := validateAuthorityCaseRecord(record, v.tenant, envelope, body, commitment, delivery.Raw, expiresAt); err != nil {
		return nil, err
	}
	return &VerifiedProjection{
		EnvelopeID: envelope.ID,
		Commitment: commitment,
		Family:     FamilyCase,
		Case: &Case{
			CaseID: envelope.CaseID, IssuerEdgeID: body.IssuerEdgeID,
			IssuerEdgeGeneration: body.IssuerEdgeGeneration,
			Domain:               body.Domain, Summary: body.Summary,
			ContextManifest: body.ContextManifest,
			RouteKind:       "domain", RouteToken: RoutingToken(body.Domain),
			SourceToken:  EdgeRoutingToken(body.IssuerEdgeID, body.IssuerEdgeGeneration),
			RoutingEpoch: envelope.RoutingEpoch, RegistryRevision: envelope.RegistryRevision,
			RegistryHash: envelope.RegistryHash, ExpiresAt: expiresAt,
		},
	}, nil
}

func validateAuthorityCaseRecord(
	record authority.CaseRecord,
	tenant string,
	envelope ssp.Envelope,
	body verifiedCaseBody,
	commitment string,
	raw []byte,
	expiresAt time.Time,
) error {
	if record.TenantID != tenant || record.CaseID != envelope.CaseID ||
		record.EnvelopeID != envelope.ID || record.Commitment != commitment ||
		!bytes.Equal(record.Raw, raw) || record.Domain != body.Domain ||
		record.IssuerEdgeID != body.IssuerEdgeID ||
		record.IssuerEdgeGeneration != body.IssuerEdgeGeneration ||
		record.RoutingEpoch != envelope.RoutingEpoch ||
		record.RegistryRevision != envelope.RegistryRevision ||
		record.RegistryHash != envelope.RegistryHash ||
		!record.ExpiresAt.Equal(expiresAt) || record.AuthorityRevision <= 0 {
		return Permanent("case_authority_mismatch", errors.New("sspedge: verified case does not match committed authority record"))
	}
	return nil
}

func (v *AuthorityVerifier) verifyAdviceDelivery(
	ctx context.Context,
	delivery JournalDelivery,
	header ssp.EnvelopeHeader,
	commitment string,
	registryRecord authority.RegistryRecord,
	snapshot registry.Registry,
	emittedAt time.Time,
) (*VerifiedProjection, error) {
	key, envelope, err := verifyRegisteredEnvelope(delivery.Raw, header, snapshot, registry.UsageAdvice, emittedAt)
	if err != nil {
		return nil, err
	}
	if envelope.Schema != ssp.FamilyAdvice {
		return nil, Permanent("unsupported_family", errors.New("sspedge: verified advice family mismatch"))
	}
	var body verifiedAdviceBody
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		return nil, Permanent("invalid_advice_body", err)
	}
	record, err := v.authority.ResolveCase(ctx, envelope.CaseID, body.CaseCommitment)
	if err != nil {
		if errors.Is(err, authority.ErrCaseNotFound) {
			return nil, Permanent("case_not_found", err)
		}
		return nil, Transient(fmt.Errorf("sspedge: resolve advice case: %w", err))
	}
	caseEnvelope, caseBody, err := v.verifyCommittedCase(record, registryRecord)
	if err != nil {
		return nil, err
	}
	route, routeOK := snapshot.Domain(caseBody.Domain)
	principal, principalOK := snapshot.Principal(route.DispatcherPrincipalID)
	if !routeOK || !principalOK ||
		key.PrincipalID != route.DispatcherPrincipalID ||
		!slices.Contains(principal.SSPKeyIDs, header.AuthorKeyID) ||
		!slices.Contains(route.Families, ssp.FamilyAdvice) ||
		!snapshot.MachineAcceptableEpoch(caseBody.Domain, envelope.RoutingEpoch) {
		return nil, Permanent("unauthorized_advice", errors.New("sspedge: registry does not authorize advice dispatcher"))
	}
	if body.CaseCommitment != record.Commitment ||
		envelope.CaseID != record.CaseID ||
		envelope.RoutingEpoch != record.RoutingEpoch ||
		envelope.RegistryRevision != record.RegistryRevision ||
		envelope.RegistryHash != record.RegistryHash ||
		caseEnvelope.CaseID != envelope.CaseID ||
		record.IssuerEdgeID != delivery.EdgeID ||
		record.IssuerEdgeGeneration != delivery.EdgeGeneration {
		return nil, Permanent("advice_case_binding_mismatch", errors.New("sspedge: advice does not bind exact committed case and target generation"))
	}
	expiresAt, err := ssp.ParseTimestamp(envelope.ExpiresAt)
	if err != nil {
		return nil, Permanent("invalid_advice_expiry", err)
	}
	return &VerifiedProjection{
		EnvelopeID: envelope.ID,
		Commitment: commitment,
		Family:     FamilyAdvice,
		Advice: &Advice{
			AdviceID: envelope.ID, CaseID: envelope.CaseID,
			CaseCommitment: record.Commitment, Text: body.Text,
			IssuerEdgeID: record.IssuerEdgeID, IssuerEdgeGeneration: record.IssuerEdgeGeneration,
			RouteKind: "edge", RouteToken: EdgeRoutingToken(record.IssuerEdgeID, record.IssuerEdgeGeneration),
			RoutingEpoch: record.RoutingEpoch, RegistryRevision: record.RegistryRevision,
			RegistryHash: record.RegistryHash, ExpiresAt: expiresAt,
		},
	}, nil
}

func (v *AuthorityVerifier) verifyCommittedCase(
	record authority.CaseRecord,
	registryRecord authority.RegistryRecord,
) (ssp.Envelope, verifiedCaseBody, error) {
	header, err := ssp.ReadHeader(record.Raw)
	if err != nil || header.Schema != ssp.FamilyCase {
		if err == nil {
			err = errors.New("sspedge: committed case family mismatch")
		}
		return ssp.Envelope{}, verifiedCaseBody{}, Permanent("invalid_committed_case", err)
	}
	emittedAt, err := ssp.ParseTimestamp(header.EmittedAt)
	if err != nil {
		return ssp.Envelope{}, verifiedCaseBody{}, Permanent("invalid_committed_case", err)
	}
	snapshot, err := v.verifyRegistryRecord(
		registryRecord, header.RegistryRevision, header.RegistryHash, header.RoutingEpoch, emittedAt,
	)
	if err != nil {
		return ssp.Envelope{}, verifiedCaseBody{}, err
	}
	key, envelope, err := verifyRegisteredEnvelope(record.Raw, header, snapshot, registry.UsageEdge, emittedAt)
	if err != nil {
		return ssp.Envelope{}, verifiedCaseBody{}, err
	}
	body, err := authorizeCase(snapshot, header, key, envelope)
	if err != nil {
		return ssp.Envelope{}, verifiedCaseBody{}, err
	}
	actualCommitment, err := ssp.EnvelopeCommitment(record.Raw, emittedAt)
	if err != nil {
		return ssp.Envelope{}, verifiedCaseBody{}, Permanent("invalid_committed_case", err)
	}
	expiresAt, err := ssp.ParseTimestamp(envelope.ExpiresAt)
	if err != nil {
		return ssp.Envelope{}, verifiedCaseBody{}, Permanent("invalid_committed_case", err)
	}
	if err := validateAuthorityCaseRecord(record, v.tenant, envelope, body, actualCommitment, record.Raw, expiresAt); err != nil {
		return ssp.Envelope{}, verifiedCaseBody{}, err
	}
	return envelope, body, nil
}
