package authority

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestValidateCaseRejectsNonPositiveIssuerGeneration(t *testing.T) {
	request := validCaseRequest()
	request.IssuerEdgeGeneration = 0

	err := request.Validate()
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Validate() error = %v, want ErrInvalidRequest", err)
	}
}

func TestValidateAdviceDoesNotAcceptAnAuthorityTarget(t *testing.T) {
	request := validAdviceRequest()
	if err := request.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	if _, found := reflect.TypeOf(CommitAdviceRequest{}).FieldByName("TargetEdgeID"); found {
		t.Fatal("CommitAdviceRequest must not allow callers to choose an advice target")
	}
	if _, found := reflect.TypeOf(CommitAdviceRequest{}).FieldByName("TargetEdgeGeneration"); found {
		t.Fatal("CommitAdviceRequest must not allow callers to choose an advice generation")
	}
}

func TestValidateRegistryRequiresNonNegativeRevision(t *testing.T) {
	request := validRegistryRequest()
	request.Revision = -1

	err := request.Validate()
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Validate() error = %v, want ErrInvalidRequest", err)
	}
}

func TestRequestsCloneRawBytes(t *testing.T) {
	caseRequest := validCaseRequest()
	committedCase := caseRequest.clone()
	caseRequest.Raw[0] = 'X'
	if string(committedCase.Raw) != `{"signed":"case"}` {
		t.Fatalf("case raw = %q, want preserved copy", committedCase.Raw)
	}

	adviceRequest := validAdviceRequest()
	advice := adviceRequest.clone()
	adviceRequest.Raw[0] = 'X'
	if string(advice.Raw) != `{"signed":"advice"}` {
		t.Fatalf("advice raw = %q, want preserved copy", advice.Raw)
	}
}

func TestEdgeDeliveryQueryRequiresPositiveGenerationAndBoundedLimit(t *testing.T) {
	query := EdgeDeliveryQuery{TenantID: "tenant-a", EdgeID: "edge-a", PrincipalID: "principal-a", EdgeGeneration: 0, Limit: 1}
	if err := query.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero generation error = %v, want ErrInvalidRequest", err)
	}
	query.EdgeGeneration = 1
	query.Limit = 0
	if err := query.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero limit error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegistryRequiresPositiveInitialSignedRevision(t *testing.T) {
	request := validRegistryRequest()
	request.Revision = 0
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero revision error = %v, want ErrInvalidRequest", err)
	}
}

func TestValidateRegistryRequiresCanonicalPredecessorAndEdges(t *testing.T) {
	request := validRegistryRequest()
	request.PreviousCommitment = "SHA256:not-canonical"
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("malformed predecessor error = %v, want ErrInvalidRequest", err)
	}

	request = validRegistryRequest()
	request.Edges["edge-a"] = RegistryEdge{PrincipalID: "principal-a", Generation: 0}
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero edge generation error = %v, want ErrInvalidRequest", err)
	}

	request = validRegistryRequest()
	request.Edges[""] = RegistryEdge{PrincipalID: "principal-a", Generation: 1}
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("blank edge ID error = %v, want ErrInvalidRequest", err)
	}

	request = validRegistryRequest()
	request.Edges["edge-a"] = RegistryEdge{Generation: 1}
	if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("blank edge principal error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegistryCloneOwnsEdges(t *testing.T) {
	request := validRegistryRequest()
	clone := request.clone()
	request.Edges["edge-a"] = RegistryEdge{PrincipalID: "changed", Generation: 99}
	if clone.Edges["edge-a"] != (RegistryEdge{PrincipalID: "principal-a", Generation: 1}) {
		t.Fatalf("cloned edge = %#v, want original", clone.Edges["edge-a"])
	}
}

func validCaseRequest() CommitCaseRequest {
	return CommitCaseRequest{
		TenantID: "tenant-a", CaseID: "case-a", EnvelopeID: "case-envelope-a",
		Commitment: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Raw:        []byte(`{"signed":"case"}`), Domain: "support", IssuerEdgeID: "edge-a", IssuerEdgeGeneration: 1,
		RoutingEpoch: 7, RegistryRevision: 12, RegistryHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", ExpiresAt: time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC),
	}
}

func validAdviceRequest() CommitAdviceRequest {
	return CommitAdviceRequest{
		TenantID: "tenant-a", CaseID: "case-a", EnvelopeID: "advice-envelope-a",
		CaseCommitment: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Commitment:     "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Raw:            []byte(`{"signed":"advice"}`), RoutingEpoch: 7, RegistryRevision: 12,
		RegistryHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
}

func validRegistryRequest() CommitRegistryRequest {
	return CommitRegistryRequest{
		TenantID: "tenant-a", Revision: 12, EnvelopeID: "registry-envelope-a",
		Commitment: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Raw:        []byte(`{"signed":"registry"}`), RoutingEpoch: 7,
		Edges: map[string]RegistryEdge{"edge-a": {PrincipalID: "principal-a", Generation: 1}},
	}
}
