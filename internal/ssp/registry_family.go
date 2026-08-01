package ssp

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Structural limits from docs/ssp/registry-v1.schema.json.  These are part of
// the frozen contract: an oversized snapshot is rejected, never truncated.
const (
	maxRegistryDomains    = 4096
	maxRegistryPrincipals = 16384
	maxRegistryEdges      = 16384
	maxRegistryKeys       = 32768

	maxOpaqueIDArrayItems = 16384

	// maxSafeInteger is the frozen schema's integer ceiling, the largest
	// value that survives a round trip through a JSON implementation using
	// IEEE-754 doubles.  The envelope-wide number guard already enforces it
	// across the whole body; the per-field checks below restate it so a future
	// refactor cannot quietly drop the bound for one field.
	maxSafeInteger = 1<<53 - 1
)

// Closed vocabularies. A value outside these sets is rejected rather than
// carried through as an uninterpreted string.
var (
	registryKeyUsages = map[string]struct{}{
		"advice": {}, "edge": {}, "registry": {},
	}
)

// validateRegistryBody enforces the structural half of ssp.registry.v1:
// the frozen member sets and their JSON types, closed vocabularies, bounded
// integers and array sizes, and the header/body revision and routing-epoch
// mirrors.  Authorization, key binding, anti-rollback, and equivocation
// semantics are deliberately not here; internal/registry owns those.
func validateRegistryBody(e Envelope) error {
	const what = "ssp.registry.v1 body"
	if _, err := requireTypedMembers(e.Body, what, []memberRule{
		{name: "revision", kind: jsonNumber},
		{name: "routing_epoch", kind: jsonNumber},
		{name: "previous_commitment", kind: jsonString, nullable: true},
		{name: "domains", kind: jsonArray},
		{name: "principals", kind: jsonArray},
		{name: "edges", kind: jsonArray},
		{name: "keys", kind: jsonArray},
	}); err != nil {
		return err
	}

	var body struct {
		Revision           int64             `json:"revision"`
		RoutingEpoch       int64             `json:"routing_epoch"`
		PreviousCommitment *string           `json:"previous_commitment"`
		Domains            []json.RawMessage `json:"domains"`
		Principals         []json.RawMessage `json:"principals"`
		Edges              []json.RawMessage `json:"edges"`
		Keys               []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(e.Body, &body); err != nil {
		return fmt.Errorf("ssp: invalid %s: %w", what, err)
	}

	if err := checkIntegerRange(what, "revision", body.Revision, 0); err != nil {
		return err
	}
	if err := checkIntegerRange(what, "routing_epoch", body.RoutingEpoch, 0); err != nil {
		return err
	}
	if body.PreviousCommitment != nil && !sha256HexPattern.MatchString(*body.PreviousCommitment) {
		return errors.New("ssp: registry body previous_commitment must be null or a canonical sha256 commitment")
	}

	// A verifier that trusted only the signed header could otherwise accept a
	// snapshot whose contents describe a different revision or epoch than the
	// one every other family commits to.
	if body.Revision != e.RegistryRevision {
		return errors.New("ssp: registry body revision does not match header registry_revision")
	}
	if body.RoutingEpoch != e.RoutingEpoch {
		return errors.New("ssp: registry body routing_epoch does not match header routing_epoch")
	}

	for _, group := range []struct {
		field    string
		entries  []json.RawMessage
		max      int
		validate func(int, json.RawMessage) error
	}{
		{"domains", body.Domains, maxRegistryDomains, validateDomainRoute},
		{"principals", body.Principals, maxRegistryPrincipals, validatePrincipalRecord},
		{"edges", body.Edges, maxRegistryEdges, validateEdgeRecord},
		{"keys", body.Keys, maxRegistryKeys, validateKeyRecord},
	} {
		if len(group.entries) > group.max {
			return fmt.Errorf("ssp: registry %s exceeds %d entries", group.field, group.max)
		}
		for i, raw := range group.entries {
			if err := group.validate(i, raw); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateDomainRoute(index int, raw json.RawMessage) error {
	what := fmt.Sprintf("domains[%d]", index)
	if _, err := requireTypedMembers(raw, what, []memberRule{
		{name: "domain", kind: jsonString},
		{name: "dispatcher_principal_id", kind: jsonString},
		{name: "issuer_edge_ids", kind: jsonArray},
		{name: "specialist_principal_ids", kind: jsonArray},
		{name: "families", kind: jsonArray},
		{name: "routing_epoch", kind: jsonNumber},
	}); err != nil {
		return err
	}
	var route struct {
		Domain                 string   `json:"domain"`
		DispatcherPrincipalID  string   `json:"dispatcher_principal_id"`
		IssuerEdgeIDs          []string `json:"issuer_edge_ids"`
		SpecialistPrincipalIDs []string `json:"specialist_principal_ids"`
		Families               []string `json:"families"`
		RoutingEpoch           int64    `json:"routing_epoch"`
	}
	if err := json.Unmarshal(raw, &route); err != nil {
		return fmt.Errorf("ssp: invalid %s: %w", what, err)
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"domain", route.Domain},
		{"dispatcher_principal_id", route.DispatcherPrincipalID},
	} {
		if !validOpaqueID(field.value) {
			return fmt.Errorf("ssp: %s has invalid %s", what, field.name)
		}
	}
	if len(route.IssuerEdgeIDs) == 0 {
		return fmt.Errorf("ssp: %s issuer_edge_ids must not be empty", what)
	}
	if err := validateOpaqueIDArray(what, "issuer_edge_ids", route.IssuerEdgeIDs); err != nil {
		return err
	}
	if err := validateOpaqueIDArray(what, "specialist_principal_ids", route.SpecialistPrincipalIDs); err != nil {
		return err
	}
	if err := validateRouteFamilies(what, route.Families); err != nil {
		return err
	}
	return checkIntegerRange(what, "routing_epoch", route.RoutingEpoch, 0)
}

// validateRouteFamilies freezes a route to the two advice-only SSP families.
// A registry is policy material, so an unknown or legacy family must never be
// carried as a harmless-looking opaque string for a later layer to interpret.
func validateRouteFamilies(what string, families []string) error {
	if len(families) != 2 {
		return fmt.Errorf("ssp: %s families must contain exactly case and advice", what)
	}
	seen := make(map[string]struct{}, 2)
	for _, family := range families {
		if family != FamilyCase && family != FamilyAdvice {
			return fmt.Errorf("ssp: %s has unsupported family %q", what, family)
		}
		if _, exists := seen[family]; exists {
			return fmt.Errorf("ssp: %s has duplicate family %q", what, family)
		}
		seen[family] = struct{}{}
	}
	if _, ok := seen[FamilyCase]; !ok {
		return fmt.Errorf("ssp: %s is missing %s", what, FamilyCase)
	}
	if _, ok := seen[FamilyAdvice]; !ok {
		return fmt.Errorf("ssp: %s is missing %s", what, FamilyAdvice)
	}
	return nil
}

func validatePrincipalRecord(index int, raw json.RawMessage) error {
	what := fmt.Sprintf("principals[%d]", index)
	if _, err := requireTypedMembers(raw, what, []memberRule{
		{name: "principal_id", kind: jsonString},
		{name: "roles", kind: jsonArray},
		{name: "ssp_key_ids", kind: jsonArray},
		{name: "edge_ids", kind: jsonArray},
	}); err != nil {
		return err
	}
	var record struct {
		PrincipalID string   `json:"principal_id"`
		Roles       []string `json:"roles"`
		SSPKeyIDs   []string `json:"ssp_key_ids"`
		EdgeIDs     []string `json:"edge_ids"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("ssp: invalid %s: %w", what, err)
	}
	if !validOpaqueID(record.PrincipalID) {
		return fmt.Errorf("ssp: %s has invalid principal_id", what)
	}
	for _, field := range []struct {
		name   string
		values []string
	}{
		{"roles", record.Roles},
		{"ssp_key_ids", record.SSPKeyIDs},
		{"edge_ids", record.EdgeIDs},
	} {
		if err := validateOpaqueIDArray(what, field.name, field.values); err != nil {
			return err
		}
	}
	return nil
}

func validateEdgeRecord(index int, raw json.RawMessage) error {
	what := fmt.Sprintf("edges[%d]", index)
	if _, err := requireTypedMembers(raw, what, []memberRule{
		{name: "edge_id", kind: jsonString},
		{name: "principal_id", kind: jsonString},
		{name: "generation", kind: jsonNumber},
	}); err != nil {
		return err
	}
	var record struct {
		EdgeID      string `json:"edge_id"`
		PrincipalID string `json:"principal_id"`
		Generation  int64  `json:"generation"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("ssp: invalid %s: %w", what, err)
	}
	if !validOpaqueID(record.EdgeID) {
		return fmt.Errorf("ssp: %s has invalid edge_id", what)
	}
	if !validOpaqueID(record.PrincipalID) {
		return fmt.Errorf("ssp: %s has invalid principal_id", what)
	}
	if err := checkIntegerRange(what, "generation", record.Generation, 1); err != nil {
		return err
	}
	return nil
}

func validateKeyRecord(index int, raw json.RawMessage) error {
	what := fmt.Sprintf("keys[%d]", index)
	if _, err := requireTypedMembers(raw, what, []memberRule{
		{name: "key_id", kind: jsonString},
		{name: "public_key", kind: jsonString},
		{name: "principal_id", kind: jsonString},
		{name: "usage", kind: jsonString},
		{name: "not_before", kind: jsonString},
		{name: "expires_at", kind: jsonString},
		// The frozen schema declares revoked_at as ["string","null"], so an
		// explicit null is a legitimate "not revoked" marker here.
		{name: "revoked_at", kind: jsonString, optional: true, nullable: true},
	}); err != nil {
		return err
	}
	var record struct {
		KeyID       string  `json:"key_id"`
		PublicKey   string  `json:"public_key"`
		PrincipalID string  `json:"principal_id"`
		Usage       string  `json:"usage"`
		NotBefore   string  `json:"not_before"`
		ExpiresAt   string  `json:"expires_at"`
		RevokedAt   *string `json:"revoked_at"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("ssp: invalid %s: %w", what, err)
	}
	if !validOpaqueID(record.KeyID) {
		return fmt.Errorf("ssp: %s has invalid key_id", what)
	}
	if !validOpaqueID(record.PrincipalID) {
		return fmt.Errorf("ssp: %s has invalid principal_id", what)
	}
	// A raw Ed25519 public key, base64url without padding.  Rejecting the
	// shape here keeps a malformed key from reaching key selection.
	if _, err := DecodeCanonicalBase64(record.PublicKey, ed25519.PublicKeySize); err != nil {
		return fmt.Errorf("ssp: %s has invalid public_key", what)
	}
	if _, ok := registryKeyUsages[record.Usage]; !ok {
		return fmt.Errorf("ssp: %s has invalid usage", what)
	}
	notBefore, err := parseRegistryTimestamp(what, "not_before", record.NotBefore)
	if err != nil {
		return err
	}
	expiresAt, err := parseRegistryTimestamp(what, "expires_at", record.ExpiresAt)
	if err != nil {
		return err
	}
	if !expiresAt.After(notBefore) {
		return fmt.Errorf("ssp: %s has invalid validity window", what)
	}
	if record.RevokedAt != nil {
		if _, err := parseRegistryTimestamp(what, "revoked_at", *record.RevokedAt); err != nil {
			return err
		}
	}
	return nil
}

func parseRegistryTimestamp(what, field, value string) (time.Time, error) {
	parsed, err := ParseTimestamp(value)
	if err != nil {
		return time.Time{}, fmt.Errorf("ssp: %s has invalid %s", what, field)
	}
	return parsed, nil
}

// checkIntegerRange enforces a frozen schema minimum together with the shared
// JS-safe integer ceiling.
func checkIntegerRange(what, field string, value, min int64) error {
	if value < min || value > maxSafeInteger {
		return fmt.Errorf("ssp: %s has invalid %s", what, field)
	}
	return nil
}

// validateOpaqueIDArray enforces the opaqueIDArray definition: bounded length,
// 1..512-rune members, and uniqueItems.  Duplicates are rejected because a
// repeated identifier makes "resolves exactly once" unprovable.
func validateOpaqueIDArray(what, field string, values []string) error {
	if len(values) > maxOpaqueIDArrayItems {
		return fmt.Errorf("ssp: %s %s exceeds %d entries", what, field, maxOpaqueIDArrayItems)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validOpaqueID(value) {
			return fmt.Errorf("ssp: %s %s has an invalid entry", what, field)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("ssp: %s %s has a duplicate entry", what, field)
		}
		seen[value] = struct{}{}
	}
	return nil
}

// jsonType is the JSON type of a raw member value, determined from the wire
// rather than from what it happens to unmarshal into.  Go decoding maps a JSON
// null onto a nil slice or an empty string, which would silently satisfy a
// "required array" or "required string" rule; comparing wire types instead
// keeps null distinguishable.
type jsonType int

const (
	jsonInvalid jsonType = iota
	jsonNull
	jsonBool
	jsonNumber
	jsonString
	jsonArray
	jsonObject
)

func (t jsonType) String() string {
	switch t {
	case jsonNull:
		return "null"
	case jsonBool:
		return "boolean"
	case jsonNumber:
		return "number"
	case jsonString:
		return "string"
	case jsonArray:
		return "array"
	case jsonObject:
		return "object"
	default:
		return "invalid"
	}
}

// memberRule describes one member of a frozen schema object.
type memberRule struct {
	name     string
	kind     jsonType
	optional bool
	// nullable marks a member the frozen schema declares as ["<kind>","null"].
	nullable bool
}

// requireMembers enforces a frozen schema's required list, its declared member
// types, and its additionalProperties:false constraint, returning the raw
// member set for any caller that needs to inspect presence itself.
//
// Type checking happens against the raw JSON because struct decoding cannot
// distinguish an absent member, an explicit null, and a zero value.  Duplicate
// keys are already rejected by rawGuard before any envelope reaches here.
func requireTypedMembers(raw []byte, what string, rules []memberRule) (map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("ssp: invalid %s: %w", what, err)
	}
	allowed := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		allowed[rule.name] = struct{}{}
		value, present := members[rule.name]
		if !present {
			if rule.optional {
				continue
			}
			return nil, fmt.Errorf("ssp: %s is missing %q", what, rule.name)
		}
		actual := classifyJSON(value)
		if actual == rule.kind || (rule.nullable && actual == jsonNull) {
			continue
		}
		return nil, fmt.Errorf("ssp: %s member %q is %s, want %s", what, rule.name, actual, rule.kind)
	}
	for key := range members {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("ssp: %s has unknown member %q", what, key)
		}
	}
	return members, nil
}

func classifyJSON(raw []byte) jsonType {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case 'n':
			return jsonNull
		case 't', 'f':
			return jsonBool
		case '"':
			return jsonString
		case '[':
			return jsonArray
		case '{':
			return jsonObject
		default:
			if b == '-' || (b >= '0' && b <= '9') {
				return jsonNumber
			}
			return jsonInvalid
		}
	}
	return jsonInvalid
}
