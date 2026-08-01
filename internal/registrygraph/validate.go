// Package registrygraph validates the semantic graph inside the pristine
// advice-only SSP registry.
package registrygraph

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/avivsinai/snagline/internal/ssp"
)

// Validate checks duplicate identifiers, reference resolution, two-way
// ownership, and the role/key bindings required by case and advice admission.
// Buzz identities and effect authorizations are deliberately absent.
func Validate(envelope ssp.Envelope) error {
	var body registryBody
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		return fmt.Errorf("registry: decode body: %w", err)
	}

	domains := make(map[string]domain, len(body.Domains))
	for _, entry := range body.Domains {
		if _, exists := domains[entry.Domain]; exists {
			return fmt.Errorf("registry: duplicate domain %q", entry.Domain)
		}
		domains[entry.Domain] = entry
	}
	principals := make(map[string]principal, len(body.Principals))
	for _, entry := range body.Principals {
		if _, exists := principals[entry.PrincipalID]; exists {
			return fmt.Errorf("registry: duplicate principal %q", entry.PrincipalID)
		}
		principals[entry.PrincipalID] = entry
	}
	edges := make(map[string]edge, len(body.Edges))
	for _, entry := range body.Edges {
		if _, exists := edges[entry.EdgeID]; exists {
			return fmt.Errorf("registry: duplicate edge %q", entry.EdgeID)
		}
		edges[entry.EdgeID] = entry
	}
	keys := make(map[string]key, len(body.Keys))
	for _, entry := range body.Keys {
		if _, exists := keys[entry.KeyID]; exists {
			return fmt.Errorf("registry: duplicate key %q", entry.KeyID)
		}
		keys[entry.KeyID] = entry
	}

	for _, route := range body.Domains {
		where := fmt.Sprintf("domain %q", route.Domain)
		dispatcher, ok := principals[route.DispatcherPrincipalID]
		if !ok {
			return fmt.Errorf("registry: %s dispatcher %q does not resolve", where, route.DispatcherPrincipalID)
		}
		if !slices.Contains(dispatcher.Roles, "dispatcher") {
			return fmt.Errorf("registry: %s dispatcher %q lacks dispatcher role", where, route.DispatcherPrincipalID)
		}
		if !principalHasUsage(dispatcher, keys, "advice") {
			return fmt.Errorf("registry: %s dispatcher %q has no advice key", where, route.DispatcherPrincipalID)
		}
		for _, id := range route.SpecialistPrincipalIDs {
			specialist, ok := principals[id]
			if !ok {
				return fmt.Errorf("registry: %s specialist %q does not resolve", where, id)
			}
			if !slices.Contains(specialist.Roles, "specialist") {
				return fmt.Errorf("registry: %s specialist %q lacks specialist role", where, id)
			}
		}
		for _, id := range route.IssuerEdgeIDs {
			registered, ok := edges[id]
			if !ok {
				return fmt.Errorf("registry: %s issuer edge %q does not resolve", where, id)
			}
			owner := principals[registered.PrincipalID]
			if !principalHasUsage(owner, keys, "edge") {
				return fmt.Errorf("registry: %s issuer edge %q owner has no edge key", where, id)
			}
		}
	}

	for _, entry := range body.Principals {
		where := fmt.Sprintf("principal %q", entry.PrincipalID)
		for _, id := range entry.SSPKeyIDs {
			registered, ok := keys[id]
			if !ok {
				return fmt.Errorf("registry: %s key %q does not resolve", where, id)
			}
			if registered.PrincipalID != entry.PrincipalID {
				return fmt.Errorf("registry: %s claims key %q owned by %q", where, id, registered.PrincipalID)
			}
		}
		for _, id := range entry.EdgeIDs {
			registered, ok := edges[id]
			if !ok {
				return fmt.Errorf("registry: %s edge %q does not resolve", where, id)
			}
			if registered.PrincipalID != entry.PrincipalID {
				return fmt.Errorf("registry: %s claims edge %q owned by %q", where, id, registered.PrincipalID)
			}
		}
	}

	for _, entry := range body.Edges {
		where := fmt.Sprintf("edge %q", entry.EdgeID)
		owner, ok := principals[entry.PrincipalID]
		if !ok {
			return fmt.Errorf("registry: %s principal %q does not resolve", where, entry.PrincipalID)
		}
		if !slices.Contains(owner.Roles, "edge") {
			return fmt.Errorf("registry: %s principal %q lacks edge role", where, entry.PrincipalID)
		}
		if !slices.Contains(owner.EdgeIDs, entry.EdgeID) {
			return fmt.Errorf("registry: %s is not claimed by principal %q", where, entry.PrincipalID)
		}
	}

	for _, entry := range body.Keys {
		owner, ok := principals[entry.PrincipalID]
		if !ok {
			return fmt.Errorf("registry: key %q principal %q does not resolve", entry.KeyID, entry.PrincipalID)
		}
		if !slices.Contains(owner.SSPKeyIDs, entry.KeyID) {
			return fmt.Errorf("registry: key %q is not claimed by principal %q", entry.KeyID, entry.PrincipalID)
		}
		if entry.Usage == "registry" && !slices.Contains(owner.Roles, "registry-authority") {
			return fmt.Errorf("registry: registry key %q owner %q lacks registry-authority role", entry.KeyID, entry.PrincipalID)
		}
	}
	return nil
}

func principalHasUsage(owner principal, keys map[string]key, usage string) bool {
	for _, id := range owner.SSPKeyIDs {
		if registered, ok := keys[id]; ok && registered.PrincipalID == owner.PrincipalID && registered.Usage == usage {
			return true
		}
	}
	return false
}

type registryBody struct {
	Domains    []domain    `json:"domains"`
	Principals []principal `json:"principals"`
	Edges      []edge      `json:"edges"`
	Keys       []key       `json:"keys"`
}

type domain struct {
	Domain                 string   `json:"domain"`
	DispatcherPrincipalID  string   `json:"dispatcher_principal_id"`
	IssuerEdgeIDs          []string `json:"issuer_edge_ids"`
	SpecialistPrincipalIDs []string `json:"specialist_principal_ids"`
}

type principal struct {
	PrincipalID string   `json:"principal_id"`
	Roles       []string `json:"roles"`
	SSPKeyIDs   []string `json:"ssp_key_ids"`
	EdgeIDs     []string `json:"edge_ids"`
}

type edge struct {
	EdgeID      string `json:"edge_id"`
	Generation  int64  `json:"generation"`
	PrincipalID string `json:"principal_id"`
}

type key struct {
	KeyID       string `json:"key_id"`
	PrincipalID string `json:"principal_id"`
	Usage       string `json:"usage"`
}
