package provision

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/avivsinai/snagline/internal/registry"
	"github.com/avivsinai/snagline/internal/registrygraph"
	"github.com/avivsinai/snagline/internal/ssp"
)

// KeyUsage names what a registry key is trusted to do. It mirrors the
// closed vocabulary internal/ssp enforces on ssp.registry.v1 key records.
type KeyUsage string

const (
	// KeyUsageRegistry marks the root key that authors registry envelopes.
	KeyUsageRegistry KeyUsage = "registry"
	// KeyUsageEdge marks a key an edge uses to author ssp.case.v1 envelopes.
	KeyUsageEdge KeyUsage = "edge"
	// KeyUsageAdvice marks a key a dispatcher uses to author ssp.advice.v1
	// envelopes.
	KeyUsageAdvice KeyUsage = "advice"
)

// Domain describes one routed support domain within a registry. Every
// domain implicitly authorizes exactly the ssp.case.v1 and ssp.advice.v1
// families — the only two families a registry may route — so Domain carries
// no family field of its own.
type Domain struct {
	// Name is the domain's opaque identifier.
	Name string
	// DispatcherPrincipalID is the principal authorized to submit final
	// advice for this domain.
	DispatcherPrincipalID string
	// IssuerEdgeIDs lists the edges authorized to issue cases into this
	// domain. It must be non-empty.
	IssuerEdgeIDs []string
	// SpecialistPrincipalIDs lists the principals authorized to act as
	// specialists for this domain. It may be empty.
	SpecialistPrincipalIDs []string
	// RoutingEpoch is this domain's current routing epoch, independent of
	// the registry's own top-level routing epoch.
	RoutingEpoch int64
}

// Principal describes one registry principal: the roles it holds, the SSP
// keys it may sign with, and the edges it operates.
type Principal struct {
	ID        string
	Roles     []string
	SSPKeyIDs []string
	EdgeIDs   []string
}

// Edge describes one enrolled edge installation and its current generation.
// A stale edge installation is fenced by generation, not by ID alone.
type Edge struct {
	ID          string
	Generation  int64
	PrincipalID string
}

// Key describes one registry key record: an Ed25519 public key, the
// principal it belongs to, what it is trusted to do, and its validity
// window.
type Key struct {
	ID          string
	PublicKey   ed25519.PublicKey
	PrincipalID string
	Usage       KeyUsage
	NotBefore   time.Time
	ExpiresAt   time.Time
}

// RegistryDraft is the unsigned content of one ssp.registry.v1 envelope. It
// carries no authority itself; SignRegistry is what turns it into a
// root-authorized artifact.
type RegistryDraft struct {
	// ID is the envelope's opaque identifier.
	ID string
	// EmittedAt is both the envelope's emitted_at and the instant SignRegistry
	// validates the draft as of.
	EmittedAt time.Time
	// ExpiresAt is the envelope's validity deadline.
	ExpiresAt time.Time
	// Revision is the registry revision this envelope declares.
	Revision int64
	// RoutingEpoch is the registry's top-level routing epoch.
	RoutingEpoch int64
	// PreviousCommitment is the prior revision's commitment, or empty for a
	// genesis registry with no predecessor.
	PreviousCommitment string
	Domains            []Domain
	Principals         []Principal
	Edges              []Edge
	Keys               []Key
}

// RegistryTrust is a deployment-pinned root used only to authenticate
// registry artifacts, mirroring internal/registry.Trust.
type RegistryTrust struct {
	inner registry.Trust
}

// NewRegistryTrust pins a root key id and its Ed25519 public key as the
// trust root future registry envelopes are verified against.
func NewRegistryTrust(rootKeyID string, rootPublicKey ed25519.PublicKey) (RegistryTrust, error) {
	inner, err := registry.NewTrust(rootKeyID, rootPublicKey)
	if err != nil {
		return RegistryTrust{}, err
	}
	return RegistryTrust{inner: inner}, nil
}

// SignRegistry builds and signs one ssp.registry.v1 envelope from draft,
// authored under rootKeyID by root. It fails closed: the frozen
// ssp.registry.v1 structural validation (opaque id shapes, the fixed
// case/advice family pair, non-empty issuer edges, bounded integers, and
// so on) runs before any bytes are produced, exactly as internal/ssp would
// re-run it on the way back in.
func SignRegistry(root SigningKey, rootKeyID string, draft RegistryDraft) ([]byte, error) {
	if root.signing.IsZero() {
		return nil, errors.New("provision: root signing key is not configured")
	}
	if rootKeyID == "" {
		return nil, errors.New("provision: root key id is required")
	}

	domains := make([]registryDomainWire, len(draft.Domains))
	for i, d := range draft.Domains {
		domains[i] = registryDomainWire{
			Domain:                 d.Name,
			DispatcherPrincipalID:  d.DispatcherPrincipalID,
			IssuerEdgeIDs:          nonNilStrings(d.IssuerEdgeIDs),
			SpecialistPrincipalIDs: nonNilStrings(d.SpecialistPrincipalIDs),
			Families:               []string{ssp.FamilyCase, ssp.FamilyAdvice},
			RoutingEpoch:           d.RoutingEpoch,
		}
	}
	principals := make([]registryPrincipalWire, len(draft.Principals))
	for i, p := range draft.Principals {
		principals[i] = registryPrincipalWire{
			PrincipalID: p.ID,
			Roles:       nonNilStrings(p.Roles),
			SSPKeyIDs:   nonNilStrings(p.SSPKeyIDs),
			EdgeIDs:     nonNilStrings(p.EdgeIDs),
		}
	}
	edges := make([]registryEdgeWire, len(draft.Edges))
	for i, e := range draft.Edges {
		edges[i] = registryEdgeWire{EdgeID: e.ID, Generation: e.Generation, PrincipalID: e.PrincipalID}
	}
	keys := make([]registryKeyWire, len(draft.Keys))
	for i, k := range draft.Keys {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("provision: key %q public key must be %d bytes", k.ID, ed25519.PublicKeySize)
		}
		keys[i] = registryKeyWire{
			KeyID:       k.ID,
			PublicKey:   base64.RawURLEncoding.EncodeToString(k.PublicKey),
			PrincipalID: k.PrincipalID,
			Usage:       string(k.Usage),
			NotBefore:   k.NotBefore.UTC().Format(time.RFC3339),
			ExpiresAt:   k.ExpiresAt.UTC().Format(time.RFC3339),
		}
	}

	body := registryBodyWire{
		Revision:     draft.Revision,
		RoutingEpoch: draft.RoutingEpoch,
		Domains:      domains,
		Principals:   principals,
		Edges:        edges,
		Keys:         keys,
	}
	if draft.PreviousCommitment != "" {
		body.PreviousCommitment = &draft.PreviousCommitment
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("provision: marshal registry body: %w", err)
	}

	now := draft.EmittedAt.UTC()
	envelope := ssp.Envelope{
		Schema:           ssp.FamilyRegistry,
		ID:               draft.ID,
		EmittedAt:        now.Format(time.RFC3339),
		ExpiresAt:        draft.ExpiresAt.UTC().Format(time.RFC3339),
		RoutingEpoch:     draft.RoutingEpoch,
		RegistryRevision: draft.Revision,
		AuthorKeyID:      rootKeyID,
		SignatureAlg:     "ed25519",
		Body:             rawBody,
	}
	// Structural validity is not enough. ssp.Sign checks field shapes; it
	// cannot tell that a domain routes to a dispatcher nobody declared, or
	// that two principals share an id. registrygraph.Validate is the same
	// semantic pass internal/registry runs on the way back in, so running it
	// here is what makes SignRegistry either return a registry that will
	// verify or an error naming the defect — never signed, authentic bytes
	// the verifier will reject.
	if err := registrygraph.Validate(envelope); err != nil {
		return nil, fmt.Errorf("provision: draft would not verify: %w", err)
	}
	return ssp.Sign(envelope, root.signing, now)
}

// VerifyRegistryEnvelope re-verifies signed registry bytes against trust as
// of now and returns the canonical commitment string — the value every
// ssp.case.v1 and ssp.advice.v1 envelope binds to as registry_hash. It fails
// closed: any verification error is returned and no commitment is produced.
func VerifyRegistryEnvelope(trust RegistryTrust, raw []byte, now time.Time) (string, error) {
	verifier, err := registry.NewVerifier(trust.inner, func() time.Time { return now })
	if err != nil {
		return "", err
	}
	verified, err := verifier.Verify(raw)
	if err != nil {
		return "", err
	}
	return verified.Commitment()
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// registryDomainWire, registryPrincipalWire, registryEdgeWire,
// registryKeyWire, and registryBodyWire mirror the ssp.registry.v1 body
// exactly as internal/registry decodes it. They exist only to serialize a
// RegistryDraft to the frozen wire shape; internal/ssp is the sole owner of
// what that shape means and validates it independently on every verify.
type registryDomainWire struct {
	Domain                 string   `json:"domain"`
	DispatcherPrincipalID  string   `json:"dispatcher_principal_id"`
	IssuerEdgeIDs          []string `json:"issuer_edge_ids"`
	SpecialistPrincipalIDs []string `json:"specialist_principal_ids"`
	Families               []string `json:"families"`
	RoutingEpoch           int64    `json:"routing_epoch"`
}

type registryPrincipalWire struct {
	PrincipalID string   `json:"principal_id"`
	Roles       []string `json:"roles"`
	SSPKeyIDs   []string `json:"ssp_key_ids"`
	EdgeIDs     []string `json:"edge_ids"`
}

type registryEdgeWire struct {
	EdgeID      string `json:"edge_id"`
	Generation  int64  `json:"generation"`
	PrincipalID string `json:"principal_id"`
}

type registryKeyWire struct {
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"`
	PrincipalID string `json:"principal_id"`
	Usage       string `json:"usage"`
	NotBefore   string `json:"not_before"`
	ExpiresAt   string `json:"expires_at"`
}

type registryBodyWire struct {
	Revision           int64                   `json:"revision"`
	RoutingEpoch       int64                   `json:"routing_epoch"`
	PreviousCommitment *string                 `json:"previous_commitment"`
	Domains            []registryDomainWire    `json:"domains"`
	Principals         []registryPrincipalWire `json:"principals"`
	Edges              []registryEdgeWire      `json:"edges"`
	Keys               []registryKeyWire       `json:"keys"`
}
