// Package cli renders inert accepted advice from the edge outbox. It never
// parses advice as an instruction or performs a provider action.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/avivsinai/snagline/internal/edgeclient"
)

type Client interface {
	Claim(context.Context, edgeclient.ClaimRequest) ([]edgeclient.Delivery, error)
	Ack(context.Context, edgeclient.AckRequest) (edgeclient.DeliveryOutcome, error)
}
type Config struct {
	Client   Client
	Owner    string
	LeaseTTL time.Duration
	Limit    int
}
type Result struct{ Rendered, Acknowledged int }

func RenderOnce(ctx context.Context, cfg Config, out io.Writer, now time.Time) (Result, error) {
	if cfg.Client == nil || cfg.Owner == "" || cfg.LeaseTTL <= 0 || cfg.Limit <= 0 || out == nil || now.IsZero() {
		return Result{}, errors.New("cli front: invalid configuration")
	}
	deliveries, err := cfg.Client.Claim(ctx, edgeclient.ClaimRequest{Front: edgeclient.FrontCLI, Owner: cfg.Owner, LeaseTTL: cfg.LeaseTTL, Limit: cfg.Limit})
	if err != nil {
		return Result{}, err
	}
	var result Result
	for _, d := range deliveries {
		if d.CaseID == "" || d.AdviceID == "" || d.MessageID == "" || d.Text == "" || len(d.Text) > 8192 {
			return result, errors.New("cli front: invalid delivery")
		}
		if _, err := fmt.Fprintf(out, "case: %s\nadvice: %s\n%s\n", d.CaseID, d.AdviceID, d.Text); err != nil {
			return result, err
		}
		result.Rendered++
		if _, err := cfg.Client.Ack(ctx, edgeclient.AckRequest{Front: edgeclient.FrontCLI, MessageID: d.MessageID, ClaimToken: d.ClaimToken, ReceiptID: "cli-render/v1/" + d.MessageID}); err != nil {
			return result, err
		}
		result.Acknowledged++
	}
	return result, nil
}
