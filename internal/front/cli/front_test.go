package cli

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/edgeclient"
)

func TestRenderOnceRendersInertCaseAdviceAndAcknowledges(t *testing.T) {
	store := &fakeStore{deliveries: []edgeclient.Delivery{{CaseID: "case-1", AdviceID: "advice-1", MessageID: "snagline.cli.advice.v1/advice-1", Text: "do not execute this", ClaimToken: "claim"}}}
	var out bytes.Buffer
	got, err := RenderOnce(context.Background(), Config{Client: store, Owner: "cli", LeaseTTL: time.Minute, Limit: 1}, &out, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got.Rendered != 1 || got.Acknowledged != 1 {
		t.Fatalf("result=%+v", got)
	}
	if want := "case: case-1\nadvice: advice-1\ndo not execute this\n"; out.String() != want {
		t.Fatalf("output=%q", out.String())
	}
	if store.receipt.Front != edgeclient.FrontCLI {
		t.Fatalf("receipt=%+v", store.receipt)
	}
}
func TestRenderOnceRejectsMalformedConfig(t *testing.T) {
	if _, err := RenderOnce(context.Background(), Config{}, &bytes.Buffer{}, time.Now().UTC()); err == nil {
		t.Fatal("invalid config accepted")
	}
}

type fakeStore struct {
	deliveries []edgeclient.Delivery
	receipt    edgeclient.AckRequest
}

func (s *fakeStore) Claim(_ context.Context, _ edgeclient.ClaimRequest) ([]edgeclient.Delivery, error) {
	return s.deliveries, nil
}
func (s *fakeStore) Ack(_ context.Context, r edgeclient.AckRequest) (edgeclient.DeliveryOutcome, error) {
	s.receipt = r
	return edgeclient.DeliveryRecorded, nil
}
