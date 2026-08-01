package registrygraph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/avivsinai/snagline/internal/ssp"
)

func TestValidateAcceptsMinimalAdviceRegistryGraph(t *testing.T) {
	if err := Validate(graphEnvelope(validGraphBody())); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejectsBrokenAuthorityBindings(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"missing dispatcher": func(body map[string]any) {
			first(body, "domains")["dispatcher_principal_id"] = "missing"
		},
		"dispatcher role": func(body map[string]any) {
			first(body, "principals")["roles"] = []any{"specialist"}
		},
		"issuer edge": func(body map[string]any) {
			first(body, "domains")["issuer_edge_ids"] = []any{"missing"}
		},
		"edge two way ownership": func(body map[string]any) {
			principals := body["principals"].([]any)
			principals[1].(map[string]any)["edge_ids"] = []any{}
		},
		"key two way ownership": func(body map[string]any) {
			keys := body["keys"].([]any)
			keys[0].(map[string]any)["principal_id"] = "edge-principal"
		},
		"dispatcher advice key": func(body map[string]any) {
			keys := body["keys"].([]any)
			keys[0].(map[string]any)["usage"] = "edge"
		},
	} {
		t.Run(name, func(t *testing.T) {
			body := validGraphBody()
			mutate(body)
			if err := Validate(graphEnvelope(body)); err == nil {
				t.Fatal("Validate accepted broken graph")
			}
		})
	}
}

func validGraphBody() map[string]any {
	return map[string]any{
		"domains": []any{map[string]any{
			"domain": "runtime", "dispatcher_principal_id": "dispatcher",
			"issuer_edge_ids": []any{"edge-1"}, "specialist_principal_ids": []any{"specialist"},
			"families": []any{"ssp.case.v1", "ssp.advice.v1"}, "routing_epoch": float64(7),
		}},
		"principals": []any{
			map[string]any{"principal_id": "dispatcher", "roles": []any{"dispatcher"}, "ssp_key_ids": []any{"advice-key"}, "edge_ids": []any{}},
			map[string]any{"principal_id": "edge-principal", "roles": []any{"edge"}, "ssp_key_ids": []any{"edge-key"}, "edge_ids": []any{"edge-1"}},
			map[string]any{"principal_id": "specialist", "roles": []any{"specialist"}, "ssp_key_ids": []any{}, "edge_ids": []any{}},
			map[string]any{"principal_id": "registry-authority", "roles": []any{"registry-authority"}, "ssp_key_ids": []any{"registry-key"}, "edge_ids": []any{}},
		},
		"edges": []any{map[string]any{"edge_id": "edge-1", "principal_id": "edge-principal"}},
		"keys": []any{
			map[string]any{"key_id": "advice-key", "principal_id": "dispatcher", "usage": "advice"},
			map[string]any{"key_id": "edge-key", "principal_id": "edge-principal", "usage": "edge"},
			map[string]any{"key_id": "registry-key", "principal_id": "registry-authority", "usage": "registry"},
		},
	}
}

func graphEnvelope(body map[string]any) ssp.Envelope {
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return ssp.Envelope{Body: raw}
}

func first(body map[string]any, field string) map[string]any {
	values := body[field].([]any)
	if len(values) == 0 {
		panic("empty " + field)
	}
	return values[0].(map[string]any)
}

func TestValidationErrorsRemainRedactedFromKeyMaterial(t *testing.T) {
	body := validGraphBody()
	keys := body["keys"].([]any)
	keys[0].(map[string]any)["principal_id"] = "missing-secret-like-value"
	err := Validate(graphEnvelope(body))
	if err == nil {
		t.Fatal("Validate accepted missing principal")
	}
	if strings.Contains(err.Error(), "public_key") {
		t.Fatalf("error leaked key material field: %v", err)
	}
}
