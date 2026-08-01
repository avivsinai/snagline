package ssp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRegistryRejectsBuzzAndEffectEraFields(t *testing.T) {
	registry := readVector(t, "registry-v1.signed.json")
	var envelope Envelope
	if err := json.Unmarshal(registry, &envelope); err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"operations", "proposal_authorizations", "revocation_policies"} {
		candidate := envelope
		mutated := make(map[string]json.RawMessage, len(body)+1)
		for key, value := range body {
			mutated[key] = value
		}
		mutated[field] = json.RawMessage(`[]`)
		candidate.Body, _ = json.Marshal(mutated)
		if err := candidate.Validate(time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)); err == nil {
			t.Fatalf("accepted %s", field)
		}
	}
	if strings.Contains(string(envelope.Body), "community_id") || strings.Contains(string(envelope.Body), "buzz_pub_keys") {
		t.Fatal("registry vector retains Buzz mapping")
	}
}

func TestRegistryRequiresPositiveEdgeGeneration(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"edge_id":"edge-1","principal_id":"principal-1"}`),
		json.RawMessage(`{"edge_id":"edge-1","principal_id":"principal-1","generation":0}`),
	} {
		if err := validateEdgeRecord(0, raw); err == nil {
			t.Fatalf("accepted edge record %s", raw)
		}
	}
}

func TestRegistryDomainFamiliesAreExactlyCaseAndAdvice(t *testing.T) {
	registry := readVector(t, "registry-v1.signed.json")
	var envelope Envelope
	if err := json.Unmarshal(registry, &envelope); err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		t.Fatal(err)
	}
	var domains []map[string]json.RawMessage
	if err := json.Unmarshal(body["domains"], &domains); err != nil || len(domains) == 0 {
		t.Fatalf("decode domains: %v", err)
	}
	for name, families := range map[string]string{
		"legacy proposal":   `["ssp.case.v1","ssp.proposal.v1"]`,
		"legacy operation":  `["ssp.case.v1","ssp.operation.v1"]`,
		"legacy receipt":    `["ssp.case.v1","ssp.receipt.v1"]`,
		"legacy revocation": `["ssp.case.v1","ssp.revocation.v1"]`,
		"missing advice":    `["ssp.case.v1"]`,
	} {
		t.Run(name, func(t *testing.T) {
			candidate := envelope
			candidateDomains := append([]map[string]json.RawMessage(nil), domains...)
			candidateDomains[0] = mapsClone(candidateDomains[0])
			candidateDomains[0]["families"] = json.RawMessage(families)
			mutated := mapsClone(body)
			mutated["domains"], _ = json.Marshal(candidateDomains)
			candidate.Body, _ = json.Marshal(mutated)
			if err := candidate.Validate(time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)); err == nil {
				t.Fatalf("accepted families %s", families)
			}
		})
	}
}

func TestRegistryRequiresCanonicalPreviousCommitment(t *testing.T) {
	registry := readVector(t, "registry-v1.signed.json")
	var envelope Envelope
	if err := json.Unmarshal(registry, &envelope); err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Body, &body); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for name, previous := range map[string]json.RawMessage{
		"initial registry":   json.RawMessage(`null`),
		"successor registry": json.RawMessage(`"sha256:` + strings.Repeat("a", 64) + `"`),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := envelope
			candidateBody := mapsClone(body)
			candidateBody["previous_commitment"] = previous
			candidate.Body, _ = json.Marshal(candidateBody)
			if err := candidate.Validate(now); err != nil {
				t.Fatalf("rejected valid predecessor form: %v", err)
			}
		})
	}
	for name, previous := range map[string]json.RawMessage{
		"missing":         nil,
		"uppercase hash":  json.RawMessage(`"sha256:` + strings.Repeat("A", 64) + `"`),
		"wrong algorithm": json.RawMessage(`"sha512:` + strings.Repeat("a", 64) + `"`),
		"wrong JSON type": json.RawMessage(`7`),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := envelope
			candidateBody := mapsClone(body)
			if previous == nil {
				delete(candidateBody, "previous_commitment")
			} else {
				candidateBody["previous_commitment"] = previous
			}
			candidate.Body, _ = json.Marshal(candidateBody)
			if err := candidate.Validate(now); err == nil {
				t.Fatal("accepted invalid predecessor form")
			}
		})
	}
}

func mapsClone(input map[string]json.RawMessage) map[string]json.RawMessage {
	output := make(map[string]json.RawMessage, len(input))
	for key, value := range input {
		output[key] = append(json.RawMessage(nil), value...)
	}
	return output
}
