// Package amq delivers inert advice displays over a preconfigured local lane.
// It is not an AMQ instruction or SSP-verification surface.
package amq

import (
	"context"
	"errors"
	"time"

	"github.com/avivsinai/snagline/internal/edgeclient"
)

type Client interface {
	Claim(context.Context, edgeclient.ClaimRequest) ([]edgeclient.Delivery, error)
	Ack(context.Context, edgeclient.AckRequest) (edgeclient.DeliveryOutcome, error)
}

// Lane is selected from protected local configuration. It is never derived
// from advice, SSP fields, or a received AMQ message.
type Lane struct{ Root, Session, From, To, Binary string }
type PassiveMessage struct{ MessageID, CaseID, AdviceID, Text string }
type Sender interface {
	SendPassive(context.Context, Lane, PassiveMessage) error
}
type Config struct {
	Client   Client
	Sender   Sender
	Owner    string
	LeaseTTL time.Duration
	Limit    int
	Lane     Lane
}
type Result struct{ Sent, Acknowledged int }

func DeliverOnce(ctx context.Context, cfg Config, now time.Time) (Result, error) {
	if cfg.Client == nil || cfg.Sender == nil || cfg.Owner == "" || cfg.LeaseTTL <= 0 || cfg.Limit <= 0 || cfg.Lane.Root == "" || cfg.Lane.Session == "" || cfg.Lane.From == "" || cfg.Lane.To == "" || cfg.Lane.Binary == "" || now.IsZero() {
		return Result{}, errors.New("amq front: invalid configuration")
	}
	deliveries, err := cfg.Client.Claim(ctx, edgeclient.ClaimRequest{Front: edgeclient.FrontAMQ, Owner: cfg.Owner, LeaseTTL: cfg.LeaseTTL, Limit: cfg.Limit})
	if err != nil {
		return Result{}, err
	}
	var result Result
	for _, d := range deliveries {
		if d.CaseID == "" || d.AdviceID == "" || d.MessageID == "" || d.Text == "" || len(d.Text) > 8192 {
			return result, errors.New("amq front: invalid delivery")
		}
		message := PassiveMessage{MessageID: d.MessageID, CaseID: d.CaseID, AdviceID: d.AdviceID, Text: d.Text}
		if err := cfg.Sender.SendPassive(ctx, cfg.Lane, message); err != nil {
			return result, err
		}
		result.Sent++
		if _, err := cfg.Client.Ack(ctx, edgeclient.AckRequest{Front: edgeclient.FrontAMQ, MessageID: d.MessageID, ClaimToken: d.ClaimToken, ReceiptID: "amq-passive/v1/" + cfg.Lane.Session + "/" + cfg.Lane.To + "/" + d.MessageID}); err != nil {
			return result, err
		}
		result.Acknowledged++
	}
	return result, nil
}
