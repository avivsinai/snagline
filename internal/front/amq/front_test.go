package amq

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/edgeclient"
)

func TestDeliverOnceUsesConfiguredLaneAndStablePassiveID(t *testing.T) {
	store := &fakeStore{deliveries: []edgeclient.Delivery{{CaseID: "case-1", AdviceID: "advice-1", MessageID: "snagline.amq.advice.v1/advice-1", Text: "inert text", ClaimToken: "claim"}}}
	sender := &fakeSender{}
	lane := Lane{Root: "/private/amq", Session: "support", From: "edge", To: "agent", Binary: "/usr/local/bin/amq"}
	got, err := DeliverOnce(context.Background(), Config{Client: store, Sender: sender, Owner: "amq", LeaseTTL: time.Minute, Limit: 1, Lane: lane}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got.Sent != 1 || got.Acknowledged != 1 {
		t.Fatalf("result=%+v", got)
	}
	if sender.lane != lane {
		t.Fatalf("lane=%+v", sender.lane)
	}
	if sender.message.MessageID != "snagline.amq.advice.v1/advice-1" || sender.message.CaseID != "case-1" {
		t.Fatalf("message=%+v", sender.message)
	}
	if store.receipt.ReceiptID != "amq-passive/v1/support/agent/snagline.amq.advice.v1/advice-1" {
		t.Fatalf("receipt=%+v", store.receipt)
	}
}
func TestDeliverOnceDoesNotAcceptCallerSelectedLaneOrMalformedConfig(t *testing.T) {
	store := &fakeStore{}
	sender := &fakeSender{}
	if _, err := DeliverOnce(context.Background(), Config{Client: store, Sender: sender, Owner: "amq", LeaseTTL: time.Minute, Limit: 1, Lane: Lane{Session: "anything"}}, time.Now().UTC()); err == nil {
		t.Fatal("unscoped lane accepted")
	}
	if sender.calls != 0 {
		t.Fatal("sender called for invalid config")
	}
}

func TestDeliverRetryKeepsPassiveMessageID(t *testing.T) {
	store := &fakeStore{deliveries: []edgeclient.Delivery{{CaseID: "case-1", AdviceID: "advice-1", MessageID: "snagline.amq.advice.v1/advice-1", Text: "inert", ClaimToken: "claim"}}, markErr: errors.New("receipt interrupted")}
	sender := &fakeSender{}
	cfg := Config{Client: store, Sender: sender, Owner: "amq", LeaseTTL: time.Minute, Limit: 1, Lane: Lane{Root: "/private/amq", Session: "support", From: "edge", To: "agent", Binary: "/usr/local/bin/amq"}}
	if _, err := DeliverOnce(context.Background(), cfg, time.Now().UTC()); err == nil {
		t.Fatal("interrupted receipt succeeded")
	}
	store.markErr = nil
	if _, err := DeliverOnce(context.Background(), cfg, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if sender.calls != 2 || sender.message.MessageID != "snagline.amq.advice.v1/advice-1" {
		t.Fatalf("retry changed passive identity: %+v calls=%d", sender.message, sender.calls)
	}
}

type fakeStore struct {
	deliveries []edgeclient.Delivery
	receipt    edgeclient.AckRequest
	markErr    error
}

func (s *fakeStore) Claim(_ context.Context, _ edgeclient.ClaimRequest) ([]edgeclient.Delivery, error) {
	return s.deliveries, nil
}
func (s *fakeStore) Ack(_ context.Context, r edgeclient.AckRequest) (edgeclient.DeliveryOutcome, error) {
	s.receipt = r
	return edgeclient.DeliveryRecorded, s.markErr
}

type fakeSender struct {
	lane    Lane
	message PassiveMessage
	calls   int
}

func (s *fakeSender) SendPassive(_ context.Context, l Lane, m PassiveMessage) error {
	s.calls++
	s.lane = l
	s.message = m
	return nil
}
