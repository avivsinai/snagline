package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	deliveryoutbox "github.com/avivsinai/snagline/internal/delivery/outbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maxOutboxAttempts = 20

var ErrStaleOutboxLease = errors.New("authority/postgres: stale outbox lease")

var _ deliveryoutbox.Source = (*Store)(nil)

// Claim leases a bounded set of committed outbox rows. SKIP LOCKED lets
// multiple workers make progress without ever granting the same live lease.
func (s *Store) Claim(ctx context.Context, workerID string, limit int, lease time.Duration) ([]deliveryoutbox.Item, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("authority/postgres: nil store")
	}
	if strings.TrimSpace(workerID) == "" || limit <= 0 || limit > deliveryoutbox.MaxBatchSize ||
		lease <= 0 || lease > deliveryoutbox.MaxLease {
		return nil, errors.New("authority/postgres: invalid outbox claim")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("authority/postgres: begin outbox claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
SELECT outbox_id
FROM authority_outbox
WHERE published_at IS NULL
  AND poisoned_at IS NULL
  AND next_attempt_at <= clock_timestamp()
  AND (lease_until IS NULL OR lease_until <= clock_timestamp())
ORDER BY next_attempt_at, created_at, outbox_id
FOR UPDATE SKIP LOCKED
LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("authority/postgres: select outbox claims: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("authority/postgres: scan outbox claim: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("authority/postgres: iterate outbox claims: %w", err)
	}
	rows.Close()

	items := make([]deliveryoutbox.Item, 0, len(ids))
	for _, id := range ids {
		token := uuid.NewString()
		command, err := tx.Exec(ctx, `
UPDATE authority_outbox
SET lease_owner = $2,
    lease_token = $3,
    lease_until = clock_timestamp() + ($4 * interval '1 microsecond')
WHERE outbox_id = $1
  AND published_at IS NULL
  AND poisoned_at IS NULL`, id, workerID, token, lease.Microseconds())
		if err != nil {
			return nil, fmt.Errorf("authority/postgres: lease outbox item: %w", err)
		}
		if command.RowsAffected() != 1 {
			return nil, ErrStaleOutboxLease
		}
		item, err := readClaimedOutboxItem(ctx, tx, id, token)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("authority/postgres: commit outbox claim: %w", err)
	}
	return items, nil
}

func readClaimedOutboxItem(ctx context.Context, tx pgx.Tx, id, token string) (deliveryoutbox.Item, error) {
	var item deliveryoutbox.Item
	err := tx.QueryRow(ctx, `
SELECT o.outbox_id, o.lease_token, o.tenant_id, o.event_kind, o.entity_id,
       o.destination_kind, o.destination_key, o.raw, o.authority_revision,
       COALESCE(c.domain, ''),
       COALESCE(d.edge_id, ''),
       COALESCE(d.edge_generation, 0),
       COALESCE(d.delivery_sequence, 0)
FROM authority_outbox o
LEFT JOIN authority_cases c
  ON o.destination_kind = 'domain_dispatch'
 AND c.tenant_id = o.tenant_id
 AND c.commit_revision = o.authority_revision
LEFT JOIN authority_edge_deliveries d
  ON o.destination_kind = 'edge_delivery'
 AND d.tenant_id = o.tenant_id
 AND d.authority_revision = o.authority_revision
WHERE o.outbox_id = $1 AND o.lease_token = $2`, id, token).Scan(
		&item.ID, &item.LeaseToken, &item.TenantID, &item.EventKind, &item.EntityID,
		&item.DestinationKind, &item.DestinationKey, &item.Raw, &item.AuthorityRevision,
		&item.DomainID, &item.EdgeID, &item.EdgeGeneration, &item.DeliverySequence,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return deliveryoutbox.Item{}, ErrStaleOutboxLease
	}
	if err != nil {
		return deliveryoutbox.Item{}, fmt.Errorf("authority/postgres: read claimed outbox item: %w", err)
	}
	item.Raw = append([]byte(nil), item.Raw...)
	return item, nil
}

func (s *Store) MarkPublished(ctx context.Context, itemID, leaseToken string) error {
	if s == nil || s.pool == nil || strings.TrimSpace(itemID) == "" || strings.TrimSpace(leaseToken) == "" {
		return errors.New("authority/postgres: invalid outbox publish closure")
	}
	command, err := s.pool.Exec(ctx, `
UPDATE authority_outbox
SET published_at = clock_timestamp(),
    lease_owner = NULL,
    lease_token = NULL,
    lease_until = NULL,
    last_error = ''
WHERE outbox_id = $1
  AND lease_token = $2
  AND lease_until > clock_timestamp()
  AND published_at IS NULL
  AND poisoned_at IS NULL`, itemID, leaseToken)
	if err != nil {
		return fmt.Errorf("authority/postgres: mark outbox published: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrStaleOutboxLease
	}
	return nil
}

func (s *Store) Release(ctx context.Context, itemID, leaseToken string, retryAt time.Time, redactedReason string) error {
	if s == nil || s.pool == nil || strings.TrimSpace(itemID) == "" ||
		strings.TrimSpace(leaseToken) == "" || retryAt.IsZero() ||
		(redactedReason != deliveryoutbox.ReasonPublishFailed && redactedReason != deliveryoutbox.ReasonMalformedItem) {
		return errors.New("authority/postgres: invalid outbox release")
	}
	command, err := s.pool.Exec(ctx, `
UPDATE authority_outbox
SET attempts = attempts + 1,
    next_attempt_at = $3,
    last_error = $4,
    poisoned_at = CASE WHEN attempts + 1 >= $5 THEN clock_timestamp() ELSE NULL END,
    lease_owner = NULL,
    lease_token = NULL,
    lease_until = NULL
WHERE outbox_id = $1
  AND lease_token = $2
  AND lease_until > clock_timestamp()
  AND published_at IS NULL
  AND poisoned_at IS NULL`, itemID, leaseToken, retryAt.UTC(), redactedReason, maxOutboxAttempts)
	if err != nil {
		return fmt.Errorf("authority/postgres: release outbox item: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrStaleOutboxLease
	}
	return nil
}
