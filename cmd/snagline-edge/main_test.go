package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/edgeclient"
	"github.com/avivsinai/snagline/internal/sspedge"
)

func TestEdgeHandlerAndClientShareExactCaseWireContract(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sledgewire-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "edge.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	svc := &fakeEdgeService{advice: []edge.AdviceView{{AdviceID: "advice-1", CaseID: "case-1", Text: "confidential", ReceivedAt: time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)}}}
	server := httptest.NewUnstartedServer(newHandler(svc))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	client, err := edgeclient.New(edgeclient.Config{Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	request := edgeclient.OpenCaseRequest{CaseID: "case-1", Domain: "runtime", Summary: "secret", PublicSummary: "public", ContextManifest: testCommitment("a"), Registry: edgeclient.RegistryCoordinates{RoutingEpoch: 1, Revision: 2, Hash: testCommitment("b")}}
	opened, err := client.OpenCase(context.Background(), request)
	if err != nil || !opened.AcceptedRemote || svc.request.CaseID != "case-1" {
		t.Fatalf("opened=%#v request=%#v err=%v", opened, svc.request, err)
	}
	record, err := client.GetCase(context.Background(), "case-1")
	if err != nil || record.Summary != "secret" || record.Registry.Revision != 2 {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	advice, err := client.ListAdvice(context.Background(), "case-1")
	if err != nil || len(advice) != 1 || advice[0].Text != "confidential" {
		t.Fatalf("advice=%#v err=%v", advice, err)
	}
}

func TestEdgeHandlerRejectsUnknownOpenCaseFields(t *testing.T) {
	h := newHandler(&fakeEdgeService{})
	r := httptest.NewRequest(http.MethodPost, "/v1/cases", strings.NewReader(`{"case_id":"case-1","unexpected":true}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", w.Code)
	}
	var response apiError
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Code != "invalid_request" {
		t.Fatalf("response=%#v", response)
	}
}

func TestEdgeHandlerCallsOnlyRequestedReadSurface(t *testing.T) {
	svc := &fakeEdgeService{}
	h := newHandler(svc)
	r := httptest.NewRequest(http.MethodGet, "/v1/cases/case-1/advice", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || svc.listed != "case-1" || svc.opened != 0 {
		t.Fatalf("status=%d service=%#v", w.Code, svc)
	}
}

func TestEdgeHandlerRetriesPersistedCaseWithoutNewCaseInput(t *testing.T) {
	svc := &fakeEdgeService{}
	h := newHandler(svc)
	r := httptest.NewRequest(http.MethodPost, "/v1/cases/case-1/retry", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted || svc.retried != "case-1" || svc.opened != 0 {
		t.Fatalf("status=%d service=%#v", w.Code, svc)
	}

	withBody := httptest.NewRequest(http.MethodPost, "/v1/cases/case-1/retry", strings.NewReader(`{}`))
	withBodyRecorder := httptest.NewRecorder()
	h.ServeHTTP(withBodyRecorder, withBody)
	if withBodyRecorder.Code != http.StatusBadRequest {
		t.Fatalf("retry with body status=%d", withBodyRecorder.Code)
	}
}

func TestEdgeHandlerClaimsAndAcknowledgesOnlyFixedFronts(t *testing.T) {
	svc := &fakeEdgeService{deliveries: []sspedge.FrontDelivery{{CaseID: "case-1", AdviceID: "advice-1", MessageID: "snagline.cli.advice.v1/advice-1", Text: "inert", ClaimToken: "claim"}}}
	h := newHandler(svc)
	claim := httptest.NewRequest(http.MethodPost, "/v1/fronts/cli/claims", strings.NewReader(`{"owner":"front","lease_seconds":60,"limit":1}`))
	claim.Header.Set("Content-Type", "application/json")
	claimResponse := httptest.NewRecorder()
	h.ServeHTTP(claimResponse, claim)
	if claimResponse.Code != http.StatusOK || svc.claimedFront != sspedge.FrontCLI || svc.claimedOwner != "front" || svc.claimedTTL != time.Minute || svc.claimedLimit != 1 {
		t.Fatalf("claim status=%d service=%+v", claimResponse.Code, svc)
	}
	ack := httptest.NewRequest(http.MethodPost, "/v1/fronts/cli/acks", strings.NewReader(`{"message_id":"snagline.cli.advice.v1/advice-1","claim_token":"claim","receipt_id":"cli-render/v1/snagline.cli.advice.v1/advice-1"}`))
	ackResponse := httptest.NewRecorder()
	h.ServeHTTP(ackResponse, ack)
	if ackResponse.Code != http.StatusOK || svc.ack.Front != sspedge.FrontCLI || svc.ack.ClaimToken != "claim" {
		t.Fatalf("ack status=%d receipt=%+v", ackResponse.Code, svc.ack)
	}
	bad := httptest.NewRequest(http.MethodPost, "/v1/fronts/buzz/claims", strings.NewReader(`{"owner":"front","lease_seconds":60,"limit":1}`))
	badResponse := httptest.NewRecorder()
	h.ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusNotFound {
		t.Fatalf("unknown front status=%d", badResponse.Code)
	}
}

type fakeEdgeService struct {
	opened       int
	listed       string
	retried      string
	deliveries   []sspedge.FrontDelivery
	claimedFront sspedge.Front
	claimedOwner string
	claimedTTL   time.Duration
	claimedLimit int
	ack          sspedge.FrontReceipt
	request      edge.OpenCaseRequest
	advice       []edge.AdviceView
}

func (f *fakeEdgeService) OpenCase(_ context.Context, request edge.OpenCaseRequest) (edge.CaseSubmission, error) {
	f.opened++
	f.request = request
	return validCaseSubmission(request.CaseID), nil
}
func (f *fakeEdgeService) RetryCase(_ context.Context, id string) (edge.CaseSubmission, error) {
	f.retried = id
	return validCaseSubmission(id), nil
}
func (f *fakeEdgeService) GetCase(_ context.Context, id string) (edge.CaseRecord, error) {
	return edge.CaseRecord{EnvelopeID: "env-1", CaseID: id, Commitment: testCommitment("c"), Summary: "secret", Registry: edge.RegistryCoordinates{RoutingEpoch: 1, Revision: 2, Hash: testCommitment("b")}, ExpiresAt: time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC), Committed: true}, nil
}
func (f *fakeEdgeService) ListAdvice(_ context.Context, id string) ([]edge.AdviceView, error) {
	f.listed = id
	return f.advice, nil
}

func validCaseSubmission(caseID string) edge.CaseSubmission {
	commitment := testCommitment("c")
	return edge.CaseSubmission{EnvelopeID: "env-1", CaseID: caseID, Commitment: commitment, AcceptedRemote: true, Receipt: edge.CommitReceipt{AuthorityID: "authority", Revision: 3, EnvelopeID: "env-1", Commitment: commitment}}
}

func testCommitment(character string) string { return "sha256:" + strings.Repeat(character, 64) }
func (f *fakeEdgeService) PresentAdvice(context.Context, string) (edge.AdviceView, error) {
	return edge.AdviceView{}, nil
}
func (f *fakeEdgeService) ClaimFrontDeliveries(_ context.Context, front sspedge.Front, owner string, ttl time.Duration, limit int, _ time.Time) ([]sspedge.FrontDelivery, error) {
	f.claimedFront, f.claimedOwner, f.claimedTTL, f.claimedLimit = front, owner, ttl, limit
	return f.deliveries, nil
}
func (f *fakeEdgeService) MarkFrontDelivered(_ context.Context, receipt sspedge.FrontReceipt, _ time.Time) (sspedge.DeliveryOutcome, error) {
	f.ack = receipt
	return sspedge.DeliveryRecorded, nil
}
