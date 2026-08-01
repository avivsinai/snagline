package ssp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type timestampCorpus struct {
	Cases []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"cases"`
	BoundaryCases []struct {
		Name     string `json:"name"`
		Role     string `json:"role"`
		Value    string `json:"value"`
		Accepted bool   `json:"accepted"`
	} `json:"boundary_cases"`
}

func loadTimestampCorpus(t *testing.T) timestampCorpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "ssp", "vectors", "timestamp-v1-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus timestampCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	return corpus
}

func TestTimestampV1Corpus(t *testing.T) {
	corpus := loadTimestampCorpus(t)
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := ParseTimestamp(tc.Value)
			if got := err == nil; got != tc.Valid {
				t.Fatalf("ParseTimestamp(%q) err=%v valid=%t", tc.Value, err, tc.Valid)
			}
		})
	}
}

func TestEnvelopeTimestampBoundariesFromCorpus(t *testing.T) {
	corpus := loadTimestampCorpus(t)
	now := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	covered := map[string]bool{}

	for _, tc := range corpus.BoundaryCases {
		if tc.Role != "envelope.emitted_at" && tc.Role != "envelope.expires_at" {
			continue
		}
		covered[tc.Role] = true
		envelope := Envelope{
			Schema:           "ssp.case.v1",
			ID:               "timestamp-boundary-envelope",
			CaseID:           "timestamp-boundary-case",
			EmittedAt:        "2026-07-28T11:45:00Z",
			ExpiresAt:        "2026-07-28T13:00:00Z",
			RoutingEpoch:     1,
			RegistryRevision: 1,
			RegistryHash:     "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			AuthorKeyID:      "timestamp-boundary-key",
			SignatureAlg:     "ed25519",
			Body:             []byte(`{"domain":"support","issuer_edge_id":"edge-1","issuer_edge_generation":1,"summary":"confidential timestamp detail","public_summary":"timestamp boundary","context_manifest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`),
		}
		switch tc.Role {
		case "envelope.emitted_at":
			envelope.EmittedAt = tc.Value
		case "envelope.expires_at":
			envelope.ExpiresAt = tc.Value
		}

		t.Run(tc.Name, func(t *testing.T) {
			err := envelope.Validate(now)
			if got := err == nil; got != tc.Accepted {
				t.Fatalf("Envelope.Validate() err=%v accepted=%t", err, tc.Accepted)
			}
		})
	}

	for _, role := range []string{"envelope.emitted_at", "envelope.expires_at"} {
		if !covered[role] {
			t.Fatalf("timestamp corpus does not cover %s boundary semantics", role)
		}
	}
}
