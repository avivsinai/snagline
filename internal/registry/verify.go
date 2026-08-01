package registry

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/avivsinai/snagline/internal/registrygraph"
	"github.com/avivsinai/snagline/internal/ssp"
)

type registryBody struct {
	Revision           int64   `json:"revision"`
	RoutingEpoch       int64   `json:"routing_epoch"`
	PreviousCommitment *string `json:"previous_commitment"`
	Domains            []struct {
		Domain                 string   `json:"domain"`
		DispatcherPrincipalID  string   `json:"dispatcher_principal_id"`
		IssuerEdgeIDs          []string `json:"issuer_edge_ids"`
		SpecialistPrincipalIDs []string `json:"specialist_principal_ids"`
		Families               []string `json:"families"`
		RoutingEpoch           int64    `json:"routing_epoch"`
	} `json:"domains"`
	Principals []struct {
		PrincipalID string   `json:"principal_id"`
		Roles       []string `json:"roles"`
		SSPKeyIDs   []string `json:"ssp_key_ids"`
		EdgeIDs     []string `json:"edge_ids"`
	} `json:"principals"`
	Edges []struct {
		EdgeID      string `json:"edge_id"`
		Generation  int64  `json:"generation"`
		PrincipalID string `json:"principal_id"`
	} `json:"edges"`
	Keys []struct {
		KeyID       string  `json:"key_id"`
		PublicKey   string  `json:"public_key"`
		PrincipalID string  `json:"principal_id"`
		Usage       string  `json:"usage"`
		NotBefore   string  `json:"not_before"`
		ExpiresAt   string  `json:"expires_at"`
		RevokedAt   *string `json:"revoked_at"`
	} `json:"keys"`
}

func decodeRegistry(envelope ssp.Envelope, commitment string) (Registry, error) {
	if err := registrygraph.Validate(envelope); err != nil {
		return Registry{}, err
	}
	var body registryBody
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		return Registry{}, fmt.Errorf("registry: decode body: %w", err)
	}
	expiresAt, err := ssp.ParseTimestamp(envelope.ExpiresAt)
	if err != nil {
		return Registry{}, fmt.Errorf("registry: envelope expires_at: %w", err)
	}
	result := Registry{
		revision: body.Revision, routingEpoch: body.RoutingEpoch,
		commitment: commitment, authorKeyID: envelope.AuthorKeyID,
		expiresAt: expiresAt,
	}
	if body.PreviousCommitment != nil {
		result.previousCommitment = *body.PreviousCommitment
	}
	for _, route := range body.Domains {
		result.domainsList = append(result.domainsList, cloneDomainRoute(DomainRoute{
			Domain: route.Domain, DispatcherPrincipalID: route.DispatcherPrincipalID,
			IssuerEdgeIDs: route.IssuerEdgeIDs, SpecialistPrincipalIDs: route.SpecialistPrincipalIDs,
			Families: route.Families, RoutingEpoch: route.RoutingEpoch,
		}))
	}
	for _, principal := range body.Principals {
		result.principalsList = append(result.principalsList, clonePrincipalRecord(PrincipalRecord{
			PrincipalID: principal.PrincipalID, Roles: principal.Roles,
			SSPKeyIDs: principal.SSPKeyIDs, EdgeIDs: principal.EdgeIDs,
		}))
	}
	for _, edge := range body.Edges {
		result.edgesList = append(result.edgesList, EdgeRecord{
			EdgeID: edge.EdgeID, Generation: edge.Generation, PrincipalID: edge.PrincipalID,
		})
	}
	for _, key := range body.Keys {
		publicKey, err := decodePublicKey(key.PublicKey)
		if err != nil {
			return Registry{}, fmt.Errorf("registry: key %q: %w", key.KeyID, err)
		}
		notBefore, err := ssp.ParseTimestamp(key.NotBefore)
		if err != nil {
			return Registry{}, fmt.Errorf("registry: key %q not_before: %w", key.KeyID, err)
		}
		keyExpiresAt, err := ssp.ParseTimestamp(key.ExpiresAt)
		if err != nil {
			return Registry{}, fmt.Errorf("registry: key %q expires_at: %w", key.KeyID, err)
		}
		var revokedAt *time.Time
		if key.RevokedAt != nil {
			parsed, err := ssp.ParseTimestamp(*key.RevokedAt)
			if err != nil {
				return Registry{}, fmt.Errorf("registry: key %q revoked_at: %w", key.KeyID, err)
			}
			revokedAt = &parsed
		}
		result.keysList = append(result.keysList, cloneKeyRecord(KeyRecord{
			KeyID: key.KeyID, PublicKey: publicKey, PrincipalID: key.PrincipalID,
			Usage: KeyUsage(key.Usage), NotBefore: notBefore,
			ExpiresAt: keyExpiresAt, RevokedAt: revokedAt,
		}))
	}
	result.index()
	return result, nil
}
