// Package postgres implements authority.Store on PostgreSQL transactions.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const transactionAttempts = 3

var errRetryTransaction = errors.New("authority/postgres: retry transaction")

const (
	registryHaltPredecessorMismatch  = "predecessor commitment mismatch"
	registryHaltSameRevisionConflict = "same-revision conflicting evidence"
	registryHaltRevisionRollback     = "registry revision rollback"
)

// Store is the global semantic authority. Its pool must point at PostgreSQL;
// JetStream and Buzz clients are intentionally absent from this package.
type Store struct {
	pool        *pgxpool.Pool
	authorityID string
}

func New(pool *pgxpool.Pool, authorityID string) (*Store, error) {
	if pool == nil || strings.TrimSpace(authorityID) == "" {
		return nil, errors.New("authority/postgres: pool and authority ID are required")
	}
	return &Store{pool: pool, authorityID: authorityID}, nil
}

var _ authority.Store = (*Store)(nil)

func (s *Store) CommitCase(ctx context.Context, request authority.CommitCaseRequest) (authority.CommitReceipt, error) {
	if err := request.Validate(); err != nil {
		return authority.CommitReceipt{}, err
	}
	request.Raw = append([]byte(nil), request.Raw...)
	return s.transaction(ctx, "case", func(tx pgx.Tx) (authority.CommitReceipt, bool, error) {
		if receipt, found, err := existingCase(ctx, tx, request); err != nil || found {
			return s.withAuthority(receipt), false, err
		}
		head, found, err := registryHeadForUpdate(ctx, tx, request.TenantID)
		if err != nil {
			return authority.CommitReceipt{}, false, err
		}
		if !found {
			return authority.CommitReceipt{}, false, authority.ErrRegistryNotFound
		}
		if head.Halted {
			return authority.CommitReceipt{}, false, authority.ErrRegistryHalted
		}
		if head.Revision != request.RegistryRevision ||
			head.Commitment != request.RegistryHash ||
			head.RoutingEpoch != request.RoutingEpoch {
			return authority.CommitReceipt{}, false, authority.ErrRegistryBinding
		}
		if collision, err := caseCollision(ctx, tx, request); err != nil {
			return authority.CommitReceipt{}, false, err
		} else if collision {
			return authority.CommitReceipt{}, false, authority.ErrConflictingCase
		}
		revision, err := allocateRevision(ctx, tx)
		if err != nil {
			return authority.CommitReceipt{}, false, err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO authority_cases (
    tenant_id, case_id, envelope_id, commitment, raw, domain, issuer_edge_id,
    issuer_edge_generation, routing_epoch, registry_revision, registry_hash,
    expires_at, commit_revision
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, request.TenantID,
			request.CaseID, request.EnvelopeID, request.Commitment, request.Raw,
			request.Domain, request.IssuerEdgeID, request.IssuerEdgeGeneration,
			request.RoutingEpoch, request.RegistryRevision, request.RegistryHash,
			request.ExpiresAt.UTC(), revision)
		if err != nil {
			if isUniqueViolation(err) {
				return authority.CommitReceipt{}, false, errRetryTransaction
			}
			return authority.CommitReceipt{}, false, fmt.Errorf("authority/postgres: insert case: %w", err)
		}
		sequence, err := allocateDeliverySequence(ctx, tx, request.TenantID, request.IssuerEdgeID, request.IssuerEdgeGeneration)
		if err != nil {
			return authority.CommitReceipt{}, false, err
		}
		if err := insertEdgeDelivery(ctx, tx, request.TenantID, request.IssuerEdgeID, request.IssuerEdgeGeneration, sequence, "case", request.CaseID, request.EnvelopeID, request.Commitment, request.Raw, revision); err != nil {
			return authority.CommitReceipt{}, false, err
		}
		if err := recordAudit(ctx, tx, request.TenantID, "case", request.CaseID, request.Commitment, request.AuthenticatedPrincipalID, request.AuthenticatedEdgeID, request.Decision, revision); err != nil {
			return authority.CommitReceipt{}, false, err
		}
		if err := insertOutbox(ctx, tx, request.TenantID, "case", request.CaseID, request.Raw, revision,
			outboxDestination{"domain_dispatch", request.Domain},
			outboxDestination{"edge_delivery", edgeKey(request.IssuerEdgeID, request.IssuerEdgeGeneration)}); err != nil {
			return authority.CommitReceipt{}, false, err
		}
		return s.receipt(revision, request.EnvelopeID, request.Commitment), true, nil
	})
}

func (s *Store) CommitAdvice(ctx context.Context, request authority.CommitAdviceRequest) (authority.CommitReceipt, error) {
	if err := request.Validate(); err != nil {
		return authority.CommitReceipt{}, err
	}
	request.Raw = append([]byte(nil), request.Raw...)
	return s.transaction(ctx, "advice", func(tx pgx.Tx) (authority.CommitReceipt, bool, error) {
		existingReceipt, existingFound, existingErr := existingAdvice(ctx, tx, request)
		switch {
		case existingErr != nil && !errors.Is(existingErr, authority.ErrFinalAdviceAlreadySet):
			return authority.CommitReceipt{}, false, existingErr
		case existingFound && existingErr == nil:
			return s.withAuthority(existingReceipt), false, nil
		}
		head, headFound, err := registryHeadForUpdate(ctx, tx, request.TenantID)
		if err != nil {
			return authority.CommitReceipt{}, false, err
		}
		if !headFound {
			return authority.CommitReceipt{}, false, authority.ErrRegistryNotFound
		}
		if head.Halted {
			return authority.CommitReceipt{}, false, authority.ErrRegistryHalted
		}
		if errors.Is(existingErr, authority.ErrFinalAdviceAlreadySet) {
			return authority.CommitReceipt{}, false, authority.ErrFinalAdviceAlreadySet
		}
		var caseCommitment, edgeID, registryHash string
		var generation, routingEpoch, registryRevision int64
		err = tx.QueryRow(ctx, `
SELECT commitment, issuer_edge_id, issuer_edge_generation, routing_epoch, registry_revision, registry_hash
FROM authority_cases WHERE tenant_id = $1 AND case_id = $2`, request.TenantID, request.CaseID).
			Scan(&caseCommitment, &edgeID, &generation, &routingEpoch, &registryRevision, &registryHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return authority.CommitReceipt{}, false, authority.ErrCaseNotFound
		}
		if err != nil {
			return authority.CommitReceipt{}, false, fmt.Errorf("authority/postgres: lock committed case: %w", err)
		}
		if request.CaseCommitment != caseCommitment || request.RoutingEpoch != routingEpoch || request.RegistryRevision != registryRevision || request.RegistryHash != registryHash {
			return authority.CommitReceipt{}, false, authority.ErrCaseBinding
		}
		if collision, err := adviceCollision(ctx, tx, request); err != nil {
			return authority.CommitReceipt{}, false, err
		} else if collision {
			return authority.CommitReceipt{}, false, authority.ErrFinalAdviceAlreadySet
		}
		sequence, err := allocateDeliverySequence(ctx, tx, request.TenantID, edgeID, generation)
		if err != nil {
			return authority.CommitReceipt{}, false, err
		}
		revision, err := allocateRevision(ctx, tx)
		if err != nil {
			return authority.CommitReceipt{}, false, err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO authority_advice (
    tenant_id, case_id, envelope_id, case_commitment, commitment, raw,
    routing_epoch, registry_revision, registry_hash, target_edge_id,
    target_edge_generation, delivery_sequence, commit_revision
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, request.TenantID,
			request.CaseID, request.EnvelopeID, request.CaseCommitment, request.Commitment,
			request.Raw, request.RoutingEpoch, request.RegistryRevision, request.RegistryHash,
			edgeID, generation, sequence, revision)
		if err != nil {
			if isUniqueViolation(err) {
				return authority.CommitReceipt{}, false, errRetryTransaction
			}
			return authority.CommitReceipt{}, false, fmt.Errorf("authority/postgres: insert final advice: %w", err)
		}
		if err := insertEdgeDelivery(ctx, tx, request.TenantID, edgeID, generation, sequence, "advice", request.CaseID, request.EnvelopeID, request.Commitment, request.Raw, revision); err != nil {
			return authority.CommitReceipt{}, false, err
		}
		if err := recordAudit(ctx, tx, request.TenantID, "advice", request.CaseID, request.Commitment, request.AuthenticatedPrincipalID, request.AuthenticatedEdgeID, request.Decision, revision); err != nil {
			return authority.CommitReceipt{}, false, err
		}
		if err := insertOutbox(ctx, tx, request.TenantID, "advice", request.CaseID, request.Raw, revision,
			outboxDestination{"edge_delivery", edgeKey(edgeID, generation)}); err != nil {
			return authority.CommitReceipt{}, false, err
		}
		return s.receipt(revision, request.EnvelopeID, request.Commitment), true, nil
	})
}

func (s *Store) CommitRegistry(ctx context.Context, request authority.CommitRegistryRequest) (authority.CommitReceipt, error) {
	if err := request.Validate(); err != nil {
		return authority.CommitReceipt{}, err
	}
	request.Raw = append([]byte(nil), request.Raw...)
	request.Edges = cloneRegistryEdges(request.Edges)
	return s.transaction(ctx, "registry", func(tx pgx.Tx) (authority.CommitReceipt, bool, error) {
		head, headFound, err := registryHeadForUpdate(ctx, tx, request.TenantID)
		if err != nil {
			return authority.CommitReceipt{}, false, err
		}
		if headFound && head.Halted {
			return authority.CommitReceipt{}, false, authority.ErrRegistryHalted
		}
		if headFound && request.Revision < head.Revision {
			if err := haltRegistryHead(ctx, tx, request.TenantID, registryHaltRevisionRollback); err != nil {
				return authority.CommitReceipt{}, false, err
			}
			return authority.CommitReceipt{}, true, authority.ErrRegistryRollback
		}
		if headFound && request.Revision == head.Revision {
			receipt, exact, err := existingRegistry(ctx, tx, request)
			if err != nil {
				return authority.CommitReceipt{}, false, err
			}
			if !exact {
				if err := haltRegistryHead(ctx, tx, request.TenantID, registryHaltSameRevisionConflict); err != nil {
					return authority.CommitReceipt{}, false, err
				}
				return authority.CommitReceipt{}, true, authority.ErrRegistryEquivocation
			}
			return s.withAuthority(receipt), false, nil
		}
		if headFound {
			if request.Revision != head.Revision+1 {
				return authority.CommitReceipt{}, false, authority.ErrRegistryRevisionSequence
			}
			if request.PreviousCommitment != head.Commitment {
				if err := haltRegistryHead(ctx, tx, request.TenantID, registryHaltPredecessorMismatch); err != nil {
					return authority.CommitReceipt{}, false, err
				}
				return authority.CommitReceipt{}, true, authority.ErrRegistryEquivocation
			}
		} else if request.PreviousCommitment != "" {
			return authority.CommitReceipt{}, false, authority.ErrRegistryEquivocation
		}
		if collision, err := registryCollision(ctx, tx, request); err != nil {
			return authority.CommitReceipt{}, false, err
		} else if collision {
			return authority.CommitReceipt{}, false, authority.ErrConflictingRegistry
		}
		if err := enforceEdgeGenerationHighWater(ctx, tx, request, head, headFound); err != nil {
			return authority.CommitReceipt{}, false, err
		}
		revision, err := allocateRevision(ctx, tx)
		if err != nil {
			return authority.CommitReceipt{}, false, err
		}
		_, err = tx.Exec(ctx, `
INSERT INTO authority_registries (
    tenant_id, registry_revision, envelope_id, commitment, raw, routing_epoch,
    previous_commitment, commit_revision
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, request.TenantID, request.Revision,
			request.EnvelopeID, request.Commitment, request.Raw, request.RoutingEpoch,
			nullableText(request.PreviousCommitment), revision)
		if err != nil {
			if isUniqueViolation(err) {
				return authority.CommitReceipt{}, false, errRetryTransaction
			}
			return authority.CommitReceipt{}, false, fmt.Errorf("authority/postgres: insert registry: %w", err)
		}
		if headFound {
			_, err = tx.Exec(ctx, `
UPDATE authority_registry_heads
SET latest_revision = $2, latest_commitment = $3, routing_epoch = $4, updated_at = clock_timestamp()
WHERE tenant_id = $1`, request.TenantID, request.Revision, request.Commitment, request.RoutingEpoch)
		} else {
			_, err = tx.Exec(ctx, `
INSERT INTO authority_registry_heads (tenant_id, latest_revision, latest_commitment, routing_epoch)
VALUES ($1,$2,$3,$4)`, request.TenantID, request.Revision, request.Commitment, request.RoutingEpoch)
		}
		if err != nil {
			if isUniqueViolation(err) {
				return authority.CommitReceipt{}, false, errRetryTransaction
			}
			return authority.CommitReceipt{}, false, fmt.Errorf("authority/postgres: update registry head: %w", err)
		}
		if err := recordAudit(ctx, tx, request.TenantID, "registry", request.EnvelopeID, request.Commitment, request.AuthenticatedPrincipalID, request.AuthenticatedEdgeID, request.Decision, revision); err != nil {
			return authority.CommitReceipt{}, false, err
		}
		return s.receipt(revision, request.EnvelopeID, request.Commitment), true, nil
	})
}

func haltRegistryHead(ctx context.Context, tx pgx.Tx, tenantID, reason string) error {
	tag, err := tx.Exec(ctx, `
UPDATE authority_registry_heads
SET halted = TRUE, halt_reason = $2, updated_at = clock_timestamp()
WHERE tenant_id = $1`, tenantID, reason)
	if err != nil {
		return fmt.Errorf("authority/postgres: halt registry head: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("authority/postgres: registry head disappeared while halting")
	}
	return nil
}

func enforceEdgeGenerationHighWater(
	ctx context.Context,
	tx pgx.Tx,
	request authority.CommitRegistryRequest,
	head authority.RegistryHead,
	headFound bool,
) error {
	edgeIDs := make([]string, 0, len(request.Edges))
	for edgeID := range request.Edges {
		edgeIDs = append(edgeIDs, edgeID)
	}
	sort.Strings(edgeIDs)
	for _, edgeID := range edgeIDs {
		edge := request.Edges[edgeID]
		var highest, lastSeen int64
		var principalID string
		err := tx.QueryRow(ctx, `
SELECT highest_generation, last_seen_registry_revision, principal_id
FROM authority_edge_generation_high_water
WHERE tenant_id = $1 AND edge_id = $2
FOR UPDATE`, request.TenantID, edgeID).Scan(&highest, &lastSeen, &principalID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return fmt.Errorf("authority/postgres: lock edge generation high-water: %w", err)
		case edge.Generation < highest:
			return authority.ErrEdgeGenerationRollback
		case edge.Generation == highest &&
			(!headFound || lastSeen != head.Revision || principalID != edge.PrincipalID):
			return authority.ErrEdgeGenerationRollback
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO authority_edge_generation_high_water (
    tenant_id, edge_id, principal_id, highest_generation, last_seen_registry_revision
) VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (tenant_id, edge_id) DO UPDATE
SET principal_id = EXCLUDED.principal_id,
    highest_generation = EXCLUDED.highest_generation,
    last_seen_registry_revision = EXCLUDED.last_seen_registry_revision`,
			request.TenantID, edgeID, edge.PrincipalID, edge.Generation, request.Revision); err != nil {
			return fmt.Errorf("authority/postgres: advance edge generation high-water: %w", err)
		}
	}
	return nil
}

func cloneRegistryEdges(source map[string]authority.RegistryEdge) map[string]authority.RegistryEdge {
	clone := make(map[string]authority.RegistryEdge, len(source))
	for edgeID, edge := range source {
		clone[edgeID] = edge
	}
	return clone
}

func (s *Store) ListEdgeDeliveries(ctx context.Context, query authority.EdgeDeliveryQuery) (authority.EdgeDeliveryPage, error) {
	if s == nil || s.pool == nil {
		return authority.EdgeDeliveryPage{}, errors.New("authority/postgres: nil store")
	}
	if err := query.Validate(); err != nil {
		return authority.EdgeDeliveryPage{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return authority.EdgeDeliveryPage{}, fmt.Errorf("authority/postgres: begin edge delivery read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var latestRevision, highestGeneration, lastSeenRevision int64
	var principalID string
	var halted bool
	err = tx.QueryRow(ctx, `
SELECT h.latest_revision, h.halted, e.principal_id, e.highest_generation,
       e.last_seen_registry_revision
FROM authority_registry_heads h
JOIN authority_edge_generation_high_water e ON e.tenant_id = h.tenant_id
WHERE h.tenant_id = $1 AND e.edge_id = $2`,
		query.TenantID, query.EdgeID).Scan(
		&latestRevision, &halted, &principalID, &highestGeneration, &lastSeenRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.EdgeDeliveryPage{}, authority.ErrEdgeNotActive
	}
	if err != nil {
		return authority.EdgeDeliveryPage{}, fmt.Errorf("authority/postgres: resolve active edge identity: %w", err)
	}
	if halted {
		return authority.EdgeDeliveryPage{}, authority.ErrRegistryHalted
	}
	if principalID != query.PrincipalID ||
		highestGeneration != query.EdgeGeneration ||
		lastSeenRevision != latestRevision {
		return authority.EdgeDeliveryPage{}, authority.ErrEdgeNotActive
	}
	page := authority.EdgeDeliveryPage{}
	if err := tx.QueryRow(ctx, `
SELECT COALESCE(MAX(delivery_sequence), 0) FROM authority_edge_deliveries
WHERE tenant_id = $1 AND edge_id = $2 AND edge_generation = $3`, query.TenantID, query.EdgeID, query.EdgeGeneration).Scan(&page.HighWatermark); err != nil {
		return authority.EdgeDeliveryPage{}, fmt.Errorf("authority/postgres: edge delivery watermark: %w", err)
	}
	rows, err := tx.Query(ctx, `
SELECT delivery_sequence, delivery_kind, case_id, envelope_id, commitment, raw, authority_revision
FROM authority_edge_deliveries
WHERE tenant_id = $1 AND edge_id = $2 AND edge_generation = $3 AND delivery_sequence > $4
ORDER BY delivery_sequence ASC LIMIT $5`, query.TenantID, query.EdgeID, query.EdgeGeneration, query.AfterSequence, query.Limit)
	if err != nil {
		return authority.EdgeDeliveryPage{}, fmt.Errorf("authority/postgres: list edge deliveries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var delivery authority.EdgeDelivery
		if err := rows.Scan(&delivery.Sequence, &delivery.Kind, &delivery.CaseID, &delivery.EnvelopeID, &delivery.Commitment, &delivery.Raw, &delivery.AuthorityRevision); err != nil {
			return authority.EdgeDeliveryPage{}, fmt.Errorf("authority/postgres: scan edge delivery: %w", err)
		}
		delivery.Raw = append([]byte(nil), delivery.Raw...)
		page.Deliveries = append(page.Deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return authority.EdgeDeliveryPage{}, fmt.Errorf("authority/postgres: iterate edge deliveries: %w", err)
	}
	rows.Close()
	page.CompleteThrough = query.AfterSequence
	if len(page.Deliveries) > 0 {
		page.CompleteThrough = page.Deliveries[len(page.Deliveries)-1].Sequence
	}
	if len(page.Deliveries) < query.Limit && page.HighWatermark > page.CompleteThrough {
		page.CompleteThrough = page.HighWatermark
	}
	if err := tx.Commit(ctx); err != nil {
		return authority.EdgeDeliveryPage{}, fmt.Errorf("authority/postgres: commit edge delivery read: %w", err)
	}
	return page, nil
}

func (s *Store) ListProjectionFacts(ctx context.Context, query authority.ProjectionFactQuery) (authority.ProjectionFactPage, error) {
	if s == nil || s.pool == nil {
		return authority.ProjectionFactPage{}, errors.New("authority/postgres: nil store")
	}
	if err := query.Validate(); err != nil {
		return authority.ProjectionFactPage{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return authority.ProjectionFactPage{}, fmt.Errorf("authority/postgres: begin projection read: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	page := authority.ProjectionFactPage{}
	if err := tx.QueryRow(ctx, `
SELECT COALESCE(MAX(commit_revision), 0) FROM (
    SELECT commit_revision FROM authority_cases WHERE tenant_id = $1
    UNION ALL SELECT commit_revision FROM authority_advice WHERE tenant_id = $1
) facts`, query.TenantID).Scan(&page.HighWatermark); err != nil {
		return authority.ProjectionFactPage{}, fmt.Errorf("authority/postgres: projection watermark: %w", err)
	}
	rows, err := tx.Query(ctx, `
SELECT commit_revision, kind, case_id, envelope_id, commitment, raw FROM (
    SELECT commit_revision, 'case' AS kind, case_id, envelope_id, commitment, raw FROM authority_cases WHERE tenant_id = $1
    UNION ALL
    SELECT commit_revision, 'advice' AS kind, case_id, envelope_id, commitment, raw FROM authority_advice WHERE tenant_id = $1
) facts WHERE commit_revision > $2 ORDER BY commit_revision ASC LIMIT $3`, query.TenantID, query.AfterAuthoritySequence, query.Limit)
	if err != nil {
		return authority.ProjectionFactPage{}, fmt.Errorf("authority/postgres: list projection facts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fact authority.ProjectionFact
		if err := rows.Scan(&fact.AuthorityRevision, &fact.Kind, &fact.CaseID, &fact.EnvelopeID, &fact.Commitment, &fact.Raw); err != nil {
			return authority.ProjectionFactPage{}, fmt.Errorf("authority/postgres: scan projection fact: %w", err)
		}
		fact.Raw = append([]byte(nil), fact.Raw...)
		page.Facts = append(page.Facts, fact)
	}
	if err := rows.Err(); err != nil {
		return authority.ProjectionFactPage{}, fmt.Errorf("authority/postgres: iterate projection facts: %w", err)
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return authority.ProjectionFactPage{}, fmt.Errorf("authority/postgres: commit projection read: %w", err)
	}
	return page, nil
}

func (s *Store) ResolveCase(ctx context.Context, tenantID, caseID, commitment string) (authority.CaseRecord, error) {
	if s == nil || s.pool == nil {
		return authority.CaseRecord{}, errors.New("authority/postgres: nil store")
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(caseID) == "" || !validCommitment(commitment) {
		return authority.CaseRecord{}, authority.ErrInvalidRequest
	}
	var record authority.CaseRecord
	err := s.pool.QueryRow(ctx, `
SELECT tenant_id, case_id, envelope_id, commitment, raw, domain, issuer_edge_id,
       issuer_edge_generation, routing_epoch, registry_revision, registry_hash,
       expires_at, commit_revision
FROM authority_cases
WHERE tenant_id = $1 AND case_id = $2 AND commitment = $3`,
		tenantID, caseID, commitment).Scan(
		&record.TenantID, &record.CaseID, &record.EnvelopeID, &record.Commitment,
		&record.Raw, &record.Domain, &record.IssuerEdgeID, &record.IssuerEdgeGeneration,
		&record.RoutingEpoch, &record.RegistryRevision, &record.RegistryHash,
		&record.ExpiresAt, &record.AuthorityRevision,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.CaseRecord{}, authority.ErrCaseNotFound
	}
	if err != nil {
		return authority.CaseRecord{}, fmt.Errorf("authority/postgres: resolve case: %w", err)
	}
	record.Raw = append([]byte(nil), record.Raw...)
	return record, nil
}

func (s *Store) ResolveRegistry(ctx context.Context, tenantID string, registryRevision int64, commitment string) (authority.RegistryRecord, error) {
	if s == nil || s.pool == nil {
		return authority.RegistryRecord{}, errors.New("authority/postgres: nil store")
	}
	if strings.TrimSpace(tenantID) == "" || registryRevision <= 0 || !validCommitment(commitment) {
		return authority.RegistryRecord{}, authority.ErrInvalidRequest
	}
	var record authority.RegistryRecord
	err := s.pool.QueryRow(ctx, `
SELECT tenant_id, registry_revision, envelope_id, commitment, raw, routing_epoch, COALESCE(previous_commitment, ''), commit_revision
FROM authority_registries
WHERE tenant_id = $1 AND registry_revision = $2 AND commitment = $3`, tenantID, registryRevision, commitment).
		Scan(&record.TenantID, &record.Revision, &record.EnvelopeID, &record.Commitment, &record.Raw, &record.RoutingEpoch, &record.PreviousCommitment, &record.AuthorityRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.RegistryRecord{}, authority.ErrRegistryNotFound
	}
	if err != nil {
		return authority.RegistryRecord{}, fmt.Errorf("authority/postgres: resolve registry: %w", err)
	}
	record.Raw = append([]byte(nil), record.Raw...)
	return record, nil
}

func (s *Store) CurrentRegistryHead(ctx context.Context, tenantID string) (authority.RegistryHead, error) {
	if s == nil || s.pool == nil {
		return authority.RegistryHead{}, errors.New("authority/postgres: nil store")
	}
	if strings.TrimSpace(tenantID) == "" {
		return authority.RegistryHead{}, authority.ErrInvalidRequest
	}
	var head authority.RegistryHead
	err := s.pool.QueryRow(ctx, `
SELECT tenant_id, latest_revision, latest_commitment, routing_epoch, halted, halt_reason
FROM authority_registry_heads WHERE tenant_id = $1`, tenantID).
		Scan(&head.TenantID, &head.Revision, &head.Commitment, &head.RoutingEpoch, &head.Halted, &head.HaltReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.RegistryHead{}, authority.ErrRegistryHeadNotFound
	}
	if err != nil {
		return authority.RegistryHead{}, fmt.Errorf("authority/postgres: current registry head: %w", err)
	}
	return head, nil
}

func (s *Store) transaction(ctx context.Context, label string, work func(pgx.Tx) (authority.CommitReceipt, bool, error)) (authority.CommitReceipt, error) {
	if s == nil || s.pool == nil {
		return authority.CommitReceipt{}, errors.New("authority/postgres: nil store")
	}
	for attempt := 0; attempt < transactionAttempts; attempt++ {
		tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			return authority.CommitReceipt{}, fmt.Errorf("authority/postgres: begin %s transaction: %w", label, err)
		}
		receipt, commit, workErr := work(tx)
		if workErr != nil && !commit {
			rollbackErr := tx.Rollback(ctx)
			if retryable(workErr) || retryable(rollbackErr) {
				continue
			}
			return authority.CommitReceipt{}, workErr
		}
		if err := tx.Commit(ctx); err != nil {
			if retryable(err) {
				continue
			}
			return authority.CommitReceipt{}, fmt.Errorf("authority/postgres: commit %s transaction: %w", label, err)
		}
		return receipt, workErr
	}
	return authority.CommitReceipt{}, fmt.Errorf("authority/postgres: %s transaction exhausted serializable retries", label)
}

func (s *Store) receipt(revision int64, envelopeID, commitment string) authority.CommitReceipt {
	return authority.CommitReceipt{AuthorityID: s.authorityID, Revision: revision, EnvelopeID: envelopeID, Commitment: commitment}
}

func (s *Store) withAuthority(receipt authority.CommitReceipt) authority.CommitReceipt {
	if receipt.Revision > 0 {
		receipt.AuthorityID = s.authorityID
	}
	return receipt
}

func allocateRevision(ctx context.Context, tx pgx.Tx) (int64, error) {
	var revision int64
	if err := tx.QueryRow(ctx, `INSERT INTO authority_revisions DEFAULT VALUES RETURNING revision`).Scan(&revision); err != nil {
		return 0, fmt.Errorf("authority/postgres: allocate authority revision: %w", err)
	}
	return revision, nil
}

func allocateDeliverySequence(ctx context.Context, tx pgx.Tx, tenantID, edgeID string, generation int64) (int64, error) {
	var sequence int64
	err := tx.QueryRow(ctx, `
INSERT INTO authority_edge_delivery_sequences (tenant_id, edge_id, edge_generation, next_sequence)
VALUES ($1,$2,$3,2)
ON CONFLICT (tenant_id, edge_id, edge_generation)
DO UPDATE SET next_sequence = authority_edge_delivery_sequences.next_sequence + 1
RETURNING next_sequence - 1`, tenantID, edgeID, generation).Scan(&sequence)
	if err != nil {
		return 0, fmt.Errorf("authority/postgres: allocate edge delivery sequence: %w", err)
	}
	return sequence, nil
}

func insertEdgeDelivery(ctx context.Context, tx pgx.Tx, tenantID, edgeID string, generation, sequence int64, kind, caseID, envelopeID, commitment string, raw []byte, revision int64) error {
	_, err := tx.Exec(ctx, `
INSERT INTO authority_edge_deliveries (
    tenant_id, edge_id, edge_generation, delivery_sequence, delivery_kind,
    case_id, envelope_id, commitment, raw, authority_revision
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, tenantID, edgeID, generation,
		sequence, kind, caseID, envelopeID, commitment, raw, revision)
	if err != nil {
		return fmt.Errorf("authority/postgres: write immutable edge delivery: %w", err)
	}
	return nil
}

func recordAudit(ctx context.Context, tx pgx.Tx, tenantID, kind, entityID, commitment, principalID, edgeID, decision string, revision int64) error {
	_, err := tx.Exec(ctx, `
INSERT INTO authority_audit (
    tenant_id, entity_kind, entity_id, commitment, authenticated_principal_id,
    authenticated_edge_id, decision, authority_revision
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, tenantID, kind, entityID, commitment,
		nullableText(principalID), nullableText(edgeID), nullableText(decision), revision)
	if err != nil {
		return fmt.Errorf("authority/postgres: write audit: %w", err)
	}
	return nil
}

type outboxDestination struct{ kind, key string }

func insertOutbox(ctx context.Context, tx pgx.Tx, tenantID, eventKind, entityID string, raw []byte, revision int64, destinations ...outboxDestination) error {
	for _, destination := range destinations {
		id := deterministicOutboxID(tenantID, eventKind, entityID, revision, destination.kind, destination.key)
		_, err := tx.Exec(ctx, `
INSERT INTO authority_outbox (
    outbox_id, tenant_id, event_kind, entity_id, destination_kind, destination_key,
    raw, authority_revision
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, tenantID, eventKind, entityID,
			destination.kind, destination.key, raw, revision)
		if err != nil {
			return fmt.Errorf("authority/postgres: write %s outbox: %w", destination.kind, err)
		}
	}
	return nil
}

func deterministicOutboxID(parts ...any) string {
	h := sha256.New()
	for _, part := range parts {
		value := fmt.Sprint(part)
		_, _ = h.Write([]byte(fmt.Sprintf("%d:", len(value))))
		_, _ = h.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func edgeKey(edgeID string, generation int64) string { return fmt.Sprintf("%s@%d", edgeID, generation) }

func existingCase(ctx context.Context, tx pgx.Tx, request authority.CommitCaseRequest) (authority.CommitReceipt, bool, error) {
	var existing authority.CommitCaseRequest
	var revision int64
	err := tx.QueryRow(ctx, `
SELECT envelope_id, commitment, raw, domain, issuer_edge_id, issuer_edge_generation,
       routing_epoch, registry_revision, registry_hash, expires_at, commit_revision
FROM authority_cases WHERE tenant_id = $1 AND case_id = $2`, request.TenantID, request.CaseID).
		Scan(&existing.EnvelopeID, &existing.Commitment, &existing.Raw, &existing.Domain,
			&existing.IssuerEdgeID, &existing.IssuerEdgeGeneration, &existing.RoutingEpoch,
			&existing.RegistryRevision, &existing.RegistryHash, &existing.ExpiresAt, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.CommitReceipt{}, false, nil
	}
	if err != nil {
		return authority.CommitReceipt{}, false, fmt.Errorf("authority/postgres: resolve case: %w", err)
	}
	exact := existing.EnvelopeID == request.EnvelopeID && existing.Commitment == request.Commitment && bytes.Equal(existing.Raw, request.Raw) && existing.Domain == request.Domain && existing.IssuerEdgeID == request.IssuerEdgeID && existing.IssuerEdgeGeneration == request.IssuerEdgeGeneration && existing.RoutingEpoch == request.RoutingEpoch && existing.RegistryRevision == request.RegistryRevision && existing.RegistryHash == request.RegistryHash && existing.ExpiresAt.Equal(request.ExpiresAt)
	if !exact {
		return authority.CommitReceipt{}, true, authority.ErrConflictingCase
	}
	return authority.CommitReceipt{Revision: revision, EnvelopeID: existing.EnvelopeID, Commitment: existing.Commitment}, true, nil
}

func existingAdvice(ctx context.Context, tx pgx.Tx, request authority.CommitAdviceRequest) (authority.CommitReceipt, bool, error) {
	var envelopeID, caseCommitment, commitment, registryHash string
	var raw []byte
	var routingEpoch, registryRevision, revision int64
	err := tx.QueryRow(ctx, `
SELECT envelope_id, case_commitment, commitment, raw, routing_epoch, registry_revision, registry_hash, commit_revision
FROM authority_advice WHERE tenant_id = $1 AND case_id = $2`, request.TenantID, request.CaseID).
		Scan(&envelopeID, &caseCommitment, &commitment, &raw, &routingEpoch, &registryRevision, &registryHash, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.CommitReceipt{}, false, nil
	}
	if err != nil {
		return authority.CommitReceipt{}, false, fmt.Errorf("authority/postgres: resolve final advice: %w", err)
	}
	exact := envelopeID == request.EnvelopeID && caseCommitment == request.CaseCommitment && commitment == request.Commitment && bytes.Equal(raw, request.Raw) && routingEpoch == request.RoutingEpoch && registryRevision == request.RegistryRevision && registryHash == request.RegistryHash
	if !exact {
		return authority.CommitReceipt{}, true, authority.ErrFinalAdviceAlreadySet
	}
	return authority.CommitReceipt{Revision: revision, EnvelopeID: envelopeID, Commitment: commitment}, true, nil
}

func existingRegistry(ctx context.Context, tx pgx.Tx, request authority.CommitRegistryRequest) (authority.CommitReceipt, bool, error) {
	var envelopeID, commitment, previous string
	var raw []byte
	var routingEpoch, revision int64
	err := tx.QueryRow(ctx, `
SELECT envelope_id, commitment, raw, routing_epoch, COALESCE(previous_commitment, ''), commit_revision
FROM authority_registries WHERE tenant_id = $1 AND registry_revision = $2`, request.TenantID, request.Revision).
		Scan(&envelopeID, &commitment, &raw, &routingEpoch, &previous, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.CommitReceipt{}, false, errors.New("authority/postgres: current registry head has no immutable registry row")
	}
	if err != nil {
		return authority.CommitReceipt{}, false, fmt.Errorf("authority/postgres: resolve registry: %w", err)
	}
	exact := envelopeID == request.EnvelopeID && commitment == request.Commitment && bytes.Equal(raw, request.Raw) && routingEpoch == request.RoutingEpoch && previous == request.PreviousCommitment
	if !exact {
		return authority.CommitReceipt{}, false, nil
	}
	return authority.CommitReceipt{Revision: revision, EnvelopeID: envelopeID, Commitment: commitment}, true, nil
}

func caseCollision(ctx context.Context, tx pgx.Tx, request authority.CommitCaseRequest) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM authority_cases WHERE tenant_id = $1 AND (envelope_id = $2 OR commitment = $3))`, request.TenantID, request.EnvelopeID, request.Commitment).Scan(&exists)
	return exists, err
}

func adviceCollision(ctx context.Context, tx pgx.Tx, request authority.CommitAdviceRequest) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM authority_advice WHERE tenant_id = $1 AND (envelope_id = $2 OR commitment = $3))`, request.TenantID, request.EnvelopeID, request.Commitment).Scan(&exists)
	return exists, err
}

func registryCollision(ctx context.Context, tx pgx.Tx, request authority.CommitRegistryRequest) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM authority_registries WHERE tenant_id = $1 AND (envelope_id = $2 OR commitment = $3))`, request.TenantID, request.EnvelopeID, request.Commitment).Scan(&exists)
	return exists, err
}

func registryHeadForUpdate(ctx context.Context, tx pgx.Tx, tenantID string) (authority.RegistryHead, bool, error) {
	var head authority.RegistryHead
	err := tx.QueryRow(ctx, `
SELECT tenant_id, latest_revision, latest_commitment, routing_epoch, halted, halt_reason
FROM authority_registry_heads WHERE tenant_id = $1 FOR UPDATE`, tenantID).
		Scan(&head.TenantID, &head.Revision, &head.Commitment, &head.RoutingEpoch, &head.Halted, &head.HaltReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.RegistryHead{}, false, nil
	}
	if err != nil {
		return authority.RegistryHead{}, false, fmt.Errorf("authority/postgres: lock registry head: %w", err)
	}
	return head, true, nil
}

func validCommitment(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func retryable(err error) bool {
	if errors.Is(err, errRetryTransaction) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}
