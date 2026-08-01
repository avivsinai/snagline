package sspedge

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/ssp"
)

var _ edge.AdviceSpool = (*DB)(nil)

func validatePendingAdvice(pending edge.PendingAdvice) error {
	if strings.TrimSpace(pending.AdviceID) == "" ||
		strings.TrimSpace(pending.CaseID) == "" ||
		!sha256RE.MatchString(pending.CaseCommitment) ||
		!sha256RE.MatchString(pending.Commitment) ||
		len(pending.Raw) == 0 || len(pending.Raw) > ssp.MaxEnvelopeBytes ||
		pending.CreatedAt.IsZero() {
		return errors.New("sspedge: invalid pending advice")
	}
	return nil
}

// SavePendingAdvice persists one exact final advice wire under the semantic
// key CaseID. Replaying every field is idempotent; any difference conflicts.
func (d *DB) SavePendingAdvice(ctx context.Context, pending edge.PendingAdvice) error {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return errors.New("sspedge: nil store")
	}
	if err := validatePendingAdvice(pending); err != nil {
		return err
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existing, exists, err := d.loadPendingAdviceTx(ctx, tx, pending.CaseID)
	if err != nil {
		return err
	}
	if exists {
		if existing.AdviceID == pending.AdviceID &&
			existing.CaseCommitment == pending.CaseCommitment &&
			existing.Commitment == pending.Commitment &&
			existing.CreatedAt.Equal(pending.CreatedAt) &&
			bytes.Equal(existing.Raw, pending.Raw) {
			return tx.Commit()
		}
		return errors.New("sspedge: pending advice conflicts with stored exact wire")
	}

	ciphertext, err := d.seal("ssp_edge_pending_advice", pending.CaseID, pending.Raw)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO ssp_edge_pending_advice
			(case_id,advice_id,case_commitment,commitment,raw_ciphertext,key_version,created_at,state)
		VALUES (?,?,?,?,?,1,?,'pending')`,
		pending.CaseID, pending.AdviceID, pending.CaseCommitment, pending.Commitment,
		ciphertext, sqlTime(pending.CreatedAt))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) LoadPendingAdvice(ctx context.Context, caseID string) (edge.PendingAdvice, bool, error) {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return edge.PendingAdvice{}, false, errors.New("sspedge: nil store")
	}
	if strings.TrimSpace(caseID) == "" {
		return edge.PendingAdvice{}, false, errors.New("sspedge: case ID is required")
	}
	pending, exists, err := d.scanPendingAdvice(d.sqlDB.QueryRowContext(ctx, `
		SELECT advice_id,case_commitment,commitment,raw_ciphertext,created_at
		FROM ssp_edge_pending_advice
		WHERE case_id=?`, caseID), caseID)
	if err != nil {
		return edge.PendingAdvice{}, false, err
	}
	return pending, exists, nil
}

func (d *DB) scanPendingAdvice(row rowScanner, caseID string) (edge.PendingAdvice, bool, error) {
	var adviceID, caseCommitment, commitment, createdAtRaw string
	var ciphertext []byte
	err := row.Scan(&adviceID, &caseCommitment, &commitment, &ciphertext, &createdAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return edge.PendingAdvice{}, false, nil
	}
	if err != nil {
		return edge.PendingAdvice{}, false, err
	}
	createdAt, err := parseSQLTime(createdAtRaw)
	if err != nil {
		return edge.PendingAdvice{}, false, err
	}
	raw, err := d.open("ssp_edge_pending_advice", caseID, ciphertext)
	if err != nil {
		return edge.PendingAdvice{}, false, err
	}
	return edge.PendingAdvice{
		AdviceID:       adviceID,
		CaseID:         caseID,
		CaseCommitment: caseCommitment,
		Commitment:     commitment,
		Raw:            append([]byte(nil), raw...),
		CreatedAt:      createdAt,
	}, true, nil
}

func (d *DB) loadPendingAdviceTx(ctx context.Context, tx *sql.Tx, caseID string) (edge.PendingAdvice, bool, error) {
	return d.scanPendingAdvice(tx.QueryRowContext(ctx, `
		SELECT advice_id,case_commitment,commitment,raw_ciphertext,created_at
		FROM ssp_edge_pending_advice
		WHERE case_id=?`, caseID), caseID)
}

func validateAcceptedRemoteAdvice(accepted edge.AcceptedRemoteAdvice) error {
	if strings.TrimSpace(accepted.AdviceID) == "" ||
		strings.TrimSpace(accepted.CaseID) == "" ||
		!sha256RE.MatchString(accepted.Commitment) ||
		strings.TrimSpace(accepted.Receipt.AuthorityID) == "" ||
		accepted.Receipt.Revision <= 0 ||
		accepted.Receipt.EnvelopeID != accepted.AdviceID ||
		accepted.Receipt.Commitment != accepted.Commitment ||
		accepted.AcceptedAt.IsZero() {
		return errors.New("sspedge: invalid accepted_remote advice receipt")
	}
	return nil
}

// MarkAdviceAcceptedRemote is the only advice transition driven by a durable
// PostgreSQL receipt. Provider publication and broker delivery cannot call it.
func (d *DB) MarkAdviceAcceptedRemote(ctx context.Context, accepted edge.AcceptedRemoteAdvice) error {
	if d == nil || d.sqlDB == nil {
		return errors.New("sspedge: nil store")
	}
	if err := validateAcceptedRemoteAdvice(accepted); err != nil {
		return err
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var adviceID, commitment, state, authorityID, acceptedAtRaw string
	var authorityRevision int64
	err = tx.QueryRowContext(ctx, `
		SELECT advice_id,commitment,state,COALESCE(authority_id,''),
		       COALESCE(authority_revision,0),COALESCE(accepted_at,'')
		FROM ssp_edge_pending_advice
		WHERE case_id=?`, accepted.CaseID).
		Scan(&adviceID, &commitment, &state, &authorityID, &authorityRevision, &acceptedAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("sspedge: pending advice not found")
	}
	if err != nil {
		return err
	}
	if adviceID != accepted.AdviceID || commitment != accepted.Commitment {
		return errors.New("sspedge: authority receipt does not bind stored pending advice")
	}
	if state == "accepted_remote" {
		if authorityID == accepted.Receipt.AuthorityID &&
			authorityRevision == accepted.Receipt.Revision &&
			acceptedAtRaw == sqlTime(accepted.AcceptedAt) {
			return tx.Commit()
		}
		return errors.New("sspedge: accepted_remote advice receipt conflicts with stored evidence")
	}
	if state != "pending" {
		return errors.New("sspedge: pending advice has invalid state")
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE ssp_edge_pending_advice
		SET state='accepted_remote',authority_id=?,authority_revision=?,accepted_at=?
		WHERE case_id=? AND state='pending'`,
		accepted.Receipt.AuthorityID, accepted.Receipt.Revision, sqlTime(accepted.AcceptedAt), accepted.CaseID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
