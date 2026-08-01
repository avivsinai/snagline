// Package controlapi admits verified SSP envelopes into the PostgreSQL
// authority. It has no delivery, provider, Buzz, or JetStream dependency.
package controlapi

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

var (
	ErrUnauthorized       = errors.New("controlapi: workload is not authorized")
	ErrRejected           = errors.New("controlapi: malformed or structurally invalid SSP input")
	ErrUnsupportedFamily  = errors.New("controlapi: unsupported SSP family")
	ErrExpiredInput       = errors.New("controlapi: semantic input is expired")
	ErrInvalidCaseBinding = errors.New("controlapi: advice does not bind the committed case")
)

// WorkloadIdentity comes from the authenticated ingress, never the envelope.
// EdgeGeneration is mandatory for edge senders and forbidden for dispatchers.
type WorkloadIdentity struct {
	PrincipalID    string
	EdgeID         string
	EdgeGeneration int64
}

type Config struct {
	Tenant                       string
	Clock                        func() time.Time
	Authority                    authority.Store
	RegistryTrust                registry.Trust
	RegistryPublisherPrincipalID string
}

type Service struct {
	tenant                       string
	clock                        func() time.Time
	authority                    authority.Store
	registryTrust                registry.Trust
	registryVerifier             *registry.Verifier
	registryPublisherPrincipalID string
}

func New(config Config) (*Service, error) {
	if strings.TrimSpace(config.Tenant) == "" || config.Authority == nil || strings.TrimSpace(config.RegistryPublisherPrincipalID) == "" {
		return nil, errors.New("controlapi: tenant, authority, and registry publisher principal are required")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	verifier, err := registry.NewVerifier(config.RegistryTrust, clock)
	if err != nil {
		return nil, fmt.Errorf("controlapi: registry verifier: %w", err)
	}
	return &Service{tenant: config.Tenant, clock: clock, authority: config.Authority, registryTrust: config.RegistryTrust, registryVerifier: verifier, registryPublisherPrincipalID: config.RegistryPublisherPrincipalID}, nil
}

// SubmitRegistry accepts a root-signed registry only from the configured
// publisher and gives its exact bytes to the global authority.
func (s *Service) SubmitRegistry(ctx context.Context, workload WorkloadIdentity, raw []byte) (authority.CommitReceipt, error) {
	if s == nil {
		return authority.CommitReceipt{}, errors.New("controlapi: nil service")
	}
	if workload.PrincipalID != s.registryPublisherPrincipalID || workload.EdgeID != "" || workload.EdgeGeneration != 0 {
		return authority.CommitReceipt{}, ErrUnauthorized
	}
	header, err := ssp.ReadHeader(raw)
	if err != nil {
		return authority.CommitReceipt{}, rejected("read registry header", err)
	}
	if header.Schema != ssp.FamilyRegistry {
		return authority.CommitReceipt{}, rejected("registry family", fmt.Errorf("%w: %q", ErrUnsupportedFamily, header.Schema))
	}
	verified, err := s.registryVerifier.Verify(raw)
	if err != nil {
		return authority.CommitReceipt{}, classifySSPError("verify registry", err)
	}
	snapshot, err := verified.Snapshot()
	if err != nil {
		return authority.CommitReceipt{}, rejected("decode verified registry snapshot", err)
	}
	commitment, err := verified.Commitment()
	if err != nil {
		return authority.CommitReceipt{}, rejected("calculate registry commitment", err)
	}
	if snapshot.Revision() != header.RegistryRevision || snapshot.RoutingEpoch() != header.RoutingEpoch || snapshot.Expired(s.now()) {
		return authority.CommitReceipt{}, ErrExpiredInput
	}
	edges := make(map[string]authority.RegistryEdge, len(snapshot.Edges()))
	for _, edge := range snapshot.Edges() {
		edges[edge.EdgeID] = authority.RegistryEdge{
			PrincipalID: edge.PrincipalID,
			Generation:  edge.Generation,
		}
	}
	return s.authority.CommitRegistry(ctx, authority.CommitRegistryRequest{
		TenantID: s.tenant, Revision: snapshot.Revision(), EnvelopeID: header.ID,
		Commitment: commitment, Raw: append([]byte(nil), raw...), RoutingEpoch: snapshot.RoutingEpoch(),
		PreviousCommitment: snapshot.PreviousCommitment(), Edges: edges,
		AuthenticatedPrincipalID: workload.PrincipalID, Decision: "verified_registry_admission",
	})
}

// Submit verifies a case or advice against the exact root-verified registry
// artifact resolved from PostgreSQL, then hands the exact signed bytes to the
// transactional authority.
func (s *Service) Submit(ctx context.Context, workload WorkloadIdentity, raw []byte) (authority.CommitReceipt, error) {
	if s == nil {
		return authority.CommitReceipt{}, errors.New("controlapi: nil service")
	}
	header, err := ssp.ReadHeader(raw)
	if err != nil {
		return authority.CommitReceipt{}, rejected("read envelope header", err)
	}
	if header.Schema != ssp.FamilyCase && header.Schema != ssp.FamilyAdvice {
		return authority.CommitReceipt{}, rejected("envelope family", fmt.Errorf("%w: %q", ErrUnsupportedFamily, header.Schema))
	}
	snapshot, err := s.resolveRegistry(ctx, header)
	if err != nil {
		return authority.CommitReceipt{}, err
	}
	switch header.Schema {
	case ssp.FamilyCase:
		return s.submitCase(ctx, workload, raw, header, snapshot)
	case ssp.FamilyAdvice:
		return s.submitAdvice(ctx, workload, raw, header, snapshot)
	default:
		panic("unreachable")
	}
}

type caseBody struct {
	Domain               string `json:"domain"`
	IssuerEdgeID         string `json:"issuer_edge_id"`
	IssuerEdgeGeneration int64  `json:"issuer_edge_generation"`
}

type adviceBody struct {
	CaseCommitment string `json:"case_commitment"`
}

func (s *Service) submitCase(ctx context.Context, workload WorkloadIdentity, raw []byte, header ssp.EnvelopeHeader, snapshot registry.Registry) (authority.CommitReceipt, error) {
	key, verified, err := verifyRegisteredEnvelope(raw, header, snapshot, registry.UsageEdge, s.now())
	if err != nil {
		return authority.CommitReceipt{}, classifySSPError("verify case", err)
	}
	if verified.Schema != ssp.FamilyCase {
		return authority.CommitReceipt{}, rejected("verify case family", ssp.ErrUnknownFamily)
	}
	if key.PrincipalID == "" {
		return authority.CommitReceipt{}, fmt.Errorf("%w: invalid case signature", ErrUnauthorized)
	}
	var body caseBody
	if err := json.Unmarshal(verified.Body, &body); err != nil {
		return authority.CommitReceipt{}, rejected("decode verified case", err)
	}
	edge, edgeOK := snapshot.Edge(body.IssuerEdgeID)
	principal, principalOK := snapshot.Principal(edge.PrincipalID)
	route, routeOK := snapshot.Domain(body.Domain)
	if workload.PrincipalID == "" || workload.EdgeID == "" || workload.EdgeGeneration <= 0 ||
		!edgeOK || !principalOK || !routeOK || workload.EdgeID != body.IssuerEdgeID ||
		workload.EdgeGeneration != body.IssuerEdgeGeneration || edge.Generation != body.IssuerEdgeGeneration ||
		workload.PrincipalID != edge.PrincipalID || key.PrincipalID != edge.PrincipalID ||
		!slices.Contains(principal.SSPKeyIDs, header.AuthorKeyID) ||
		!snapshot.AuthorizesCaseIssuerGeneration(body.Domain, body.IssuerEdgeID, body.IssuerEdgeGeneration) ||
		!slices.Contains(route.Families, ssp.FamilyCase) || !snapshot.MachineAcceptableEpoch(body.Domain, verified.RoutingEpoch) {
		return authority.CommitReceipt{}, ErrUnauthorized
	}
	commitment, err := ssp.EnvelopeCommitment(raw, s.now())
	if err != nil {
		return authority.CommitReceipt{}, rejected("calculate case commitment", err)
	}
	expiresAt, err := ssp.ParseTimestamp(verified.ExpiresAt)
	if err != nil {
		return authority.CommitReceipt{}, rejected("parse case expiry", err)
	}
	return s.authority.CommitCase(ctx, authority.CommitCaseRequest{
		TenantID: s.tenant, CaseID: verified.CaseID, EnvelopeID: verified.ID, Commitment: commitment,
		Raw: append([]byte(nil), raw...), Domain: body.Domain, IssuerEdgeID: body.IssuerEdgeID,
		IssuerEdgeGeneration: body.IssuerEdgeGeneration, RoutingEpoch: verified.RoutingEpoch,
		RegistryRevision: verified.RegistryRevision, RegistryHash: verified.RegistryHash, ExpiresAt: expiresAt,
		AuthenticatedPrincipalID: workload.PrincipalID, AuthenticatedEdgeID: workload.EdgeID, Decision: "verified_case_admission",
	})
}

func (s *Service) submitAdvice(ctx context.Context, workload WorkloadIdentity, raw []byte, header ssp.EnvelopeHeader, snapshot registry.Registry) (authority.CommitReceipt, error) {
	var untrusted ssp.Envelope
	if err := json.Unmarshal(raw, &untrusted); err != nil {
		return authority.CommitReceipt{}, rejected("decode advice binding hint", err)
	}
	var hint adviceBody
	if err := json.Unmarshal(untrusted.Body, &hint); err != nil {
		return authority.CommitReceipt{}, rejected("decode advice binding hint body", err)
	}
	committed, err := s.findCommittedCase(ctx, header.CaseID, hint.CaseCommitment, header, snapshot)
	if err != nil {
		return authority.CommitReceipt{}, err
	}
	route, routeOK := snapshot.Domain(committed.domain)
	key, verified, verifyErr := verifyRegisteredEnvelope(raw, header, snapshot, registry.UsageAdvice, s.now())
	if verifyErr != nil {
		return authority.CommitReceipt{}, classifySSPError("verify advice", verifyErr)
	}
	if verified.Schema != ssp.FamilyAdvice {
		return authority.CommitReceipt{}, rejected("verify advice family", ssp.ErrUnknownFamily)
	}
	if key.PrincipalID == "" {
		return authority.CommitReceipt{}, fmt.Errorf("%w: invalid advice signature", ErrUnauthorized)
	}
	principal, principalOK := snapshot.Principal(route.DispatcherPrincipalID)
	if workload.PrincipalID == "" || workload.PrincipalID != route.DispatcherPrincipalID || workload.EdgeID != "" || workload.EdgeGeneration != 0 ||
		!routeOK || route.DispatcherPrincipalID == "" || key.PrincipalID != route.DispatcherPrincipalID ||
		!principalOK || !slices.Contains(principal.SSPKeyIDs, header.AuthorKeyID) ||
		!slices.Contains(route.Families, ssp.FamilyAdvice) || !snapshot.MachineAcceptableEpoch(committed.domain, header.RoutingEpoch) {
		return authority.CommitReceipt{}, ErrUnauthorized
	}
	var body adviceBody
	if err := json.Unmarshal(verified.Body, &body); err != nil {
		return authority.CommitReceipt{}, rejected("decode verified advice", err)
	}
	if body.CaseCommitment != committed.commitment {
		return authority.CommitReceipt{}, ErrInvalidCaseBinding
	}
	commitment, err := ssp.EnvelopeCommitment(raw, s.now())
	if err != nil {
		return authority.CommitReceipt{}, rejected("calculate advice commitment", err)
	}
	return s.authority.CommitAdvice(ctx, authority.CommitAdviceRequest{
		TenantID: s.tenant, CaseID: verified.CaseID, EnvelopeID: verified.ID, CaseCommitment: committed.commitment,
		Commitment: commitment, Raw: append([]byte(nil), raw...), RoutingEpoch: verified.RoutingEpoch,
		RegistryRevision: verified.RegistryRevision, RegistryHash: verified.RegistryHash,
		AuthenticatedPrincipalID: workload.PrincipalID, Decision: "verified_advice_admission",
	})
}

func (s *Service) resolveRegistry(ctx context.Context, header ssp.EnvelopeHeader) (registry.Registry, error) {
	record, err := s.authority.ResolveRegistry(ctx, s.tenant, header.RegistryRevision, header.RegistryHash)
	if err != nil {
		return registry.Registry{}, fmt.Errorf("controlapi: resolve authority registry: %w", err)
	}
	verified, err := s.registryVerifier.Verify(record.Raw)
	if err != nil {
		if errors.Is(err, ssp.ErrExpiredEnvelope) {
			return registry.Registry{}, ErrExpiredInput
		}
		return registry.Registry{}, fmt.Errorf("controlapi: root verify authority registry: %w", err)
	}
	snapshot, err := verified.Snapshot()
	if err != nil {
		return registry.Registry{}, err
	}
	commitment, err := verified.Commitment()
	if err != nil {
		return registry.Registry{}, err
	}
	if record.Revision != header.RegistryRevision || record.Commitment != header.RegistryHash || commitment != record.Commitment ||
		snapshot.Revision() != record.Revision || snapshot.RoutingEpoch() != record.RoutingEpoch ||
		snapshot.Expired(s.now()) || snapshot.CheckBinding(header.RegistryRevision, header.RegistryHash) != nil {
		return registry.Registry{}, ErrExpiredInput
	}
	return snapshot, nil
}

type committedCase struct {
	commitment string
	domain     string
	record     authority.CaseRecord
}

func (s *Service) findCommittedCase(ctx context.Context, caseID, commitment string, header ssp.EnvelopeHeader, snapshot registry.Registry) (committedCase, error) {
	fact, err := s.authority.ResolveCase(ctx, s.tenant, caseID, commitment)
	if err != nil {
		return committedCase{}, fmt.Errorf("controlapi: resolve committed case: %w", err)
	}
	caseHeader, err := ssp.ReadHeader(fact.Raw)
	if err != nil || caseHeader.RegistryRevision != header.RegistryRevision ||
		caseHeader.RegistryHash != header.RegistryHash ||
		caseHeader.RoutingEpoch != header.RoutingEpoch {
		return committedCase{}, ErrInvalidCaseBinding
	}
	key, verified, err := verifyRegisteredEnvelope(fact.Raw, caseHeader, snapshot, registry.UsageEdge, s.now())
	if errors.Is(err, ssp.ErrExpiredEnvelope) {
		return committedCase{}, ErrExpiredInput
	}
	if err != nil || verified.Schema != ssp.FamilyCase || key.PrincipalID == "" {
		return committedCase{}, ErrInvalidCaseBinding
	}
	actual, err := ssp.EnvelopeCommitment(fact.Raw, s.now())
	if err != nil || actual != fact.Commitment {
		return committedCase{}, ErrInvalidCaseBinding
	}
	var body caseBody
	if err := json.Unmarshal(verified.Body, &body); err != nil {
		return committedCase{}, ErrInvalidCaseBinding
	}
	if verified.CaseID != caseID || body.Domain == "" || body.Domain != fact.Domain {
		return committedCase{}, ErrInvalidCaseBinding
	}
	return committedCase{commitment: fact.Commitment, domain: body.Domain, record: fact}, nil
}

// ResolveCase returns exact committed case evidence only to the dispatcher
// authorized by the registry snapshot bound into that case. An authenticated
// edge or unrelated dispatcher cannot use the read endpoint as a case oracle.
func (s *Service) ResolveCase(ctx context.Context, workload WorkloadIdentity, caseID, commitment string) (authority.CaseRecord, error) {
	if s == nil {
		return authority.CaseRecord{}, errors.New("controlapi: nil service")
	}
	record, err := s.authority.ResolveCase(ctx, s.tenant, caseID, commitment)
	if err != nil {
		return authority.CaseRecord{}, fmt.Errorf("controlapi: resolve committed case: %w", err)
	}
	header, err := ssp.ReadHeader(record.Raw)
	if err != nil || header.Schema != ssp.FamilyCase {
		return authority.CaseRecord{}, ErrInvalidCaseBinding
	}
	snapshot, err := s.resolveRegistry(ctx, header)
	if err != nil {
		return authority.CaseRecord{}, err
	}
	committed, err := s.findCommittedCase(ctx, caseID, commitment, header, snapshot)
	if err != nil {
		return authority.CaseRecord{}, err
	}
	route, routeOK := snapshot.Domain(committed.domain)
	targetEdge, edgeOK := snapshot.Edge(committed.record.IssuerEdgeID)
	dispatcherAuthorized := routeOK && workload.PrincipalID != "" &&
		workload.PrincipalID == route.DispatcherPrincipalID &&
		workload.EdgeID == "" && workload.EdgeGeneration == 0
	edgeAuthorized := edgeOK && workload.PrincipalID != "" &&
		workload.PrincipalID == targetEdge.PrincipalID &&
		workload.EdgeID == committed.record.IssuerEdgeID &&
		workload.EdgeGeneration == committed.record.IssuerEdgeGeneration &&
		targetEdge.Generation == committed.record.IssuerEdgeGeneration
	if !dispatcherAuthorized && !edgeAuthorized {
		return authority.CaseRecord{}, ErrUnauthorized
	}
	committed.record.Raw = append([]byte(nil), committed.record.Raw...)
	return committed.record, nil
}

// ResolveRegistry returns an exact root-verified historical registry artifact
// only to an edge identity contained in that artifact. The caller re-verifies
// the same bytes locally; this endpoint is retrieval, not delegated trust.
func (s *Service) ResolveRegistry(ctx context.Context, workload WorkloadIdentity, revision int64, commitment string) (authority.RegistryRecord, error) {
	if s == nil {
		return authority.RegistryRecord{}, errors.New("controlapi: nil service")
	}
	if workload.PrincipalID == "" || workload.EdgeID == "" || workload.EdgeGeneration <= 0 {
		return authority.RegistryRecord{}, ErrUnauthorized
	}
	record, err := s.authority.ResolveRegistry(ctx, s.tenant, revision, commitment)
	if err != nil {
		return authority.RegistryRecord{}, fmt.Errorf("controlapi: resolve registry evidence: %w", err)
	}
	header, err := ssp.ReadHeader(record.Raw)
	if err != nil || header.Schema != ssp.FamilyRegistry {
		return authority.RegistryRecord{}, ErrInvalidCaseBinding
	}
	emittedAt, err := ssp.ParseTimestamp(header.EmittedAt)
	if err != nil {
		return authority.RegistryRecord{}, ErrInvalidCaseBinding
	}
	verifier, err := registry.NewVerifier(s.registryTrust, func() time.Time { return emittedAt })
	if err != nil {
		return authority.RegistryRecord{}, err
	}
	verified, err := verifier.Verify(record.Raw)
	if err != nil {
		return authority.RegistryRecord{}, fmt.Errorf("controlapi: root verify registry evidence: %w", err)
	}
	snapshot, err := verified.Snapshot()
	if err != nil {
		return authority.RegistryRecord{}, err
	}
	actual, err := verified.Commitment()
	if err != nil {
		return authority.RegistryRecord{}, err
	}
	edge, ok := snapshot.Edge(workload.EdgeID)
	if !ok || edge.PrincipalID != workload.PrincipalID || edge.Generation != workload.EdgeGeneration ||
		record.TenantID != s.tenant || record.Revision != revision || record.Revision != snapshot.Revision() ||
		record.RoutingEpoch != snapshot.RoutingEpoch() || record.Commitment != commitment || actual != commitment {
		return authority.RegistryRecord{}, ErrUnauthorized
	}
	record.Raw = append([]byte(nil), record.Raw...)
	return record, nil
}

func verifyRegisteredEnvelope(raw []byte, header ssp.EnvelopeHeader, snapshot registry.Registry, usage registry.KeyUsage, now time.Time) (registry.KeyRecord, ssp.Envelope, error) {
	key, ok := snapshot.Key(header.AuthorKeyID)
	if !ok || key.Usage != usage || !key.Usable(now) {
		return registry.KeyRecord{}, ssp.Envelope{}, ErrUnauthorized
	}
	verifying, err := identity.NewEd25519VerifyingKey(key.PublicKey)
	if err != nil {
		return registry.KeyRecord{}, ssp.Envelope{}, err
	}
	verified, err := ssp.Verify(raw, map[string]identity.Ed25519VerifyingKey{header.AuthorKeyID: verifying}, now)
	if err != nil {
		return registry.KeyRecord{}, ssp.Envelope{}, err
	}
	emittedAt, err := ssp.ParseTimestamp(verified.EmittedAt)
	if err != nil || !key.Usable(emittedAt) {
		return registry.KeyRecord{}, ssp.Envelope{}, ErrUnauthorized
	}
	return key, verified, nil
}

func (s *Service) now() time.Time { return s.clock().UTC() }

func rejected(operation string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrRejected, operation, err)
}

func classifySSPError(operation string, err error) error {
	switch {
	case errors.Is(err, ssp.ErrExpiredEnvelope):
		return fmt.Errorf("%w: %s", ErrExpiredInput, operation)
	case errors.Is(err, ssp.ErrInvalidEnvelope):
		return rejected(operation, err)
	default:
		return fmt.Errorf("%w: %s", ErrUnauthorized, operation)
	}
}
