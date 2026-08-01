package outbox

import (
	"context"
	"errors"

	"github.com/avivsinai/snagline/internal/deliverystream"
	"github.com/nats-io/nats.go/jetstream"
)

// JetStreamPublisher adapts the bounded delivery stream to Worker. A nil error
// means JetStream returned a publish acknowledgement, never semantic commit.
type JetStreamPublisher struct {
	JetStream jetstream.JetStream
}

var _ Publisher = JetStreamPublisher{}

func (p JetStreamPublisher) Publish(ctx context.Context, request PublishRequest) error {
	if p.JetStream == nil {
		return errors.New("outbox: JetStream publisher is required")
	}
	_, err := deliverystream.Publish(ctx, p.JetStream, request)
	return err
}
