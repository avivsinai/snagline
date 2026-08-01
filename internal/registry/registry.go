// Package registry turns a root-verified ssp.registry.v1 envelope into the
// provider-neutral authorization model used by admission and projections.
package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"
)

type KeyUsage string

const (
	UsageAdvice   KeyUsage = "advice"
	UsageEdge     KeyUsage = "edge"
	UsageRegistry KeyUsage = "registry"
)

type KeyRecord struct {
	KeyID       string
	PublicKey   ed25519.PublicKey
	PrincipalID string
	Usage       KeyUsage
	NotBefore   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

func (k KeyRecord) Usable(at time.Time) bool {
	if k.RevokedAt != nil && !at.Before(*k.RevokedAt) {
		return false
	}
	return !at.Before(k.NotBefore) && at.Before(k.ExpiresAt)
}

type PrincipalRecord struct {
	PrincipalID string
	Roles       []string
	SSPKeyIDs   []string
	EdgeIDs     []string
}

type EdgeRecord struct {
	EdgeID      string
	Generation  int64
	PrincipalID string
}

type DomainRoute struct {
	Domain                 string
	DispatcherPrincipalID  string
	IssuerEdgeIDs          []string
	SpecialistPrincipalIDs []string
	Families               []string
	RoutingEpoch           int64
}

type Registry struct {
	revision           int64
	routingEpoch       int64
	previousCommitment string
	commitment         string
	authorKeyID        string
	expiresAt          time.Time

	domainsList    []DomainRoute
	principalsList []PrincipalRecord
	edgesList      []EdgeRecord
	keysList       []KeyRecord

	domains    map[string]DomainRoute
	principals map[string]PrincipalRecord
	edges      map[string]EdgeRecord
	keys       map[string]KeyRecord
}

func (r Registry) Revision() int64               { return r.revision }
func (r Registry) RoutingEpoch() int64           { return r.routingEpoch }
func (r Registry) PreviousCommitment() string    { return r.previousCommitment }
func (r Registry) Commitment() string            { return r.commitment }
func (r Registry) AuthorKeyID() string           { return r.authorKeyID }
func (r Registry) ExpiresAt() time.Time          { return r.expiresAt }
func (r Registry) Domains() []DomainRoute        { return cloneDomainRoutes(r.domainsList) }
func (r Registry) Principals() []PrincipalRecord { return clonePrincipalRecords(r.principalsList) }
func (r Registry) Edges() []EdgeRecord           { return append([]EdgeRecord(nil), r.edgesList...) }
func (r Registry) Keys() []KeyRecord             { return cloneKeyRecords(r.keysList) }

func (r Registry) Domain(domain string) (DomainRoute, bool) {
	value, ok := r.domains[domain]
	if !ok {
		return DomainRoute{}, false
	}
	return cloneDomainRoute(value), true
}

func (r Registry) AuthorizesCaseIssuer(domain, edgeID string) bool {
	route, ok := r.domains[domain]
	if !ok || edgeID == "" {
		return false
	}
	for _, candidate := range route.IssuerEdgeIDs {
		if candidate == edgeID {
			return true
		}
	}
	return false
}

// AuthorizesCaseIssuerGeneration requires both route membership and the
// currently registered enrollment generation. An edge ID alone cannot fence a
// stale installation.
func (r Registry) AuthorizesCaseIssuerGeneration(domain, edgeID string, generation int64) bool {
	if generation <= 0 || !r.AuthorizesCaseIssuer(domain, edgeID) {
		return false
	}
	edge, ok := r.edges[edgeID]
	return ok && edge.Generation == generation
}

func (r Registry) Principal(id string) (PrincipalRecord, bool) {
	value, ok := r.principals[id]
	if !ok {
		return PrincipalRecord{}, false
	}
	return clonePrincipalRecord(value), true
}

func (r Registry) Edge(id string) (EdgeRecord, bool) {
	value, ok := r.edges[id]
	return value, ok
}

func (r Registry) Key(id string) (KeyRecord, bool) {
	value, ok := r.keys[id]
	if !ok {
		return KeyRecord{}, false
	}
	return cloneKeyRecord(value), true
}

func (r Registry) SigningKeyFor(principalID string, usage KeyUsage, at time.Time) (KeyRecord, bool) {
	principal, ok := r.principals[principalID]
	if !ok {
		return KeyRecord{}, false
	}
	for _, keyID := range principal.SSPKeyIDs {
		key, ok := r.keys[keyID]
		if ok && key.PrincipalID == principalID && key.Usage == usage && key.Usable(at) {
			return cloneKeyRecord(key), true
		}
	}
	return KeyRecord{}, false
}

func (r *Registry) index() {
	r.domains = make(map[string]DomainRoute, len(r.domainsList))
	for _, value := range r.domainsList {
		r.domains[value.Domain] = cloneDomainRoute(value)
	}
	r.principals = make(map[string]PrincipalRecord, len(r.principalsList))
	for _, value := range r.principalsList {
		r.principals[value.PrincipalID] = clonePrincipalRecord(value)
	}
	r.edges = make(map[string]EdgeRecord, len(r.edgesList))
	for _, value := range r.edgesList {
		r.edges[value.EdgeID] = value
	}
	r.keys = make(map[string]KeyRecord, len(r.keysList))
	for _, value := range r.keysList {
		r.keys[value.KeyID] = cloneKeyRecord(value)
	}
}

func cloneStrings(in []string) []string {
	return append([]string(nil), in...)
}

func cloneDomainRoute(in DomainRoute) DomainRoute {
	in.IssuerEdgeIDs = cloneStrings(in.IssuerEdgeIDs)
	in.SpecialistPrincipalIDs = cloneStrings(in.SpecialistPrincipalIDs)
	in.Families = cloneStrings(in.Families)
	return in
}

func cloneDomainRoutes(in []DomainRoute) []DomainRoute {
	out := make([]DomainRoute, len(in))
	for i := range in {
		out[i] = cloneDomainRoute(in[i])
	}
	return out
}

func clonePrincipalRecord(in PrincipalRecord) PrincipalRecord {
	in.Roles = cloneStrings(in.Roles)
	in.SSPKeyIDs = cloneStrings(in.SSPKeyIDs)
	in.EdgeIDs = cloneStrings(in.EdgeIDs)
	return in
}

func clonePrincipalRecords(in []PrincipalRecord) []PrincipalRecord {
	out := make([]PrincipalRecord, len(in))
	for i := range in {
		out[i] = clonePrincipalRecord(in[i])
	}
	return out
}

func cloneKeyRecord(in KeyRecord) KeyRecord {
	in.PublicKey = append(ed25519.PublicKey(nil), in.PublicKey...)
	if in.RevokedAt != nil {
		copyValue := *in.RevokedAt
		in.RevokedAt = &copyValue
	}
	return in
}

func cloneKeyRecords(in []KeyRecord) []KeyRecord {
	out := make([]KeyRecord, len(in))
	for i := range in {
		out[i] = cloneKeyRecord(in[i])
	}
	return out
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, fmt.Errorf("registry: public key must be canonical %d-byte base64url", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
