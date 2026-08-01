package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/sspedge"
)

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
}

func (f *fakeEdgeService) OpenCase(context.Context, edge.OpenCaseRequest) (edge.CaseSubmission, error) {
	f.opened++
	return edge.CaseSubmission{AcceptedRemote: true}, nil
}
func (f *fakeEdgeService) RetryCase(_ context.Context, id string) (edge.CaseSubmission, error) {
	f.retried = id
	return edge.CaseSubmission{CaseID: id, AcceptedRemote: true}, nil
}
func (f *fakeEdgeService) GetCase(context.Context, string) (edge.CaseRecord, error) {
	return edge.CaseRecord{CaseID: "case-1"}, nil
}
func (f *fakeEdgeService) ListAdvice(_ context.Context, id string) ([]edge.AdviceView, error) {
	f.listed = id
	return []edge.AdviceView{}, nil
}
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
