package sspedge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/avivsinai/snagline/internal/edge"
	"github.com/avivsinai/snagline/internal/ssp"
)

var _ edge.CaseStore = (*DB)(nil)

type encryptedCasePayload struct {
	Summary         string `json:"summary"`
	ContextManifest string `json:"context_manifest"`
}

func encodeCasePayload(summary, contextManifest string) ([]byte, error) {
	return json.Marshal(encryptedCasePayload{Summary: summary, ContextManifest: contextManifest})
}

func decodeCasePayload(raw []byte) (encryptedCasePayload, error) {
	var payload encryptedCasePayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return encryptedCasePayload{}, fmt.Errorf("sspedge: decode case payload: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return encryptedCasePayload{}, errors.New("sspedge: case payload must contain exactly one value")
	}
	return payload, nil
}

func validatePendingCase(pending edge.PendingCase) error {
	if strings.TrimSpace(pending.EnvelopeID) == "" ||
		strings.TrimSpace(pending.CaseID) == "" ||
		!sha256RE.MatchString(pending.Commitment) ||
		len(pending.Raw) == 0 || len(pending.Raw) > ssp.MaxEnvelopeBytes ||
		pending.CreatedAt.IsZero() {
		return errors.New("sspedge: invalid pending case")
	}
	return nil
}

// SavePendingCase durably stores the exact signed SSP wire under authenticated
// encryption. An exact replay is idempotent; a reused case ID with any
// different identity, timestamp, or bytes is a conflict.
func (d *DB) SavePendingCase(ctx context.Context, pending edge.PendingCase) error {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return errors.New("sspedge: nil store")
	}
	if err := validatePendingCase(pending); err != nil {
		return err
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existing, exists, err := d.loadPendingCaseTx(ctx, tx, pending.CaseID)
	if err != nil {
		return err
	}
	if exists {
		if existing.EnvelopeID == pending.EnvelopeID &&
			existing.Commitment == pending.Commitment &&
			existing.CreatedAt.Equal(pending.CreatedAt) &&
			bytes.Equal(existing.Raw, pending.Raw) {
			return tx.Commit()
		}
		return errors.New("sspedge: pending case conflicts with stored exact wire")
	}

	ciphertext, err := d.seal("ssp_edge_pending_cases", pending.CaseID, pending.Raw)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO ssp_edge_pending_cases
			(case_id,envelope_id,commitment,raw_ciphertext,key_version,created_at,state)
		VALUES (?,?,?,?,1,?,'pending')`,
		pending.CaseID, pending.EnvelopeID, pending.Commitment, ciphertext, sqlTime(pending.CreatedAt))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// LoadPendingCase returns the immutable submission bytes even after a receipt
// has been recorded. Keeping the accepted row prevents reopening a semantic
// case ID and lets a retry resubmit the same bytes idempotently.
func (d *DB) LoadPendingCase(ctx context.Context, caseID string) (edge.PendingCase, bool, error) {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return edge.PendingCase{}, false, errors.New("sspedge: nil store")
	}
	if strings.TrimSpace(caseID) == "" {
		return edge.PendingCase{}, false, errors.New("sspedge: case ID is required")
	}
	row := d.sqlDB.QueryRowContext(ctx, `
		SELECT envelope_id,commitment,raw_ciphertext,created_at
		FROM ssp_edge_pending_cases
		WHERE case_id=?`, caseID)
	pending, exists, err := d.scanPendingCase(row, caseID)
	if err != nil {
		return edge.PendingCase{}, false, err
	}
	return pending, exists, nil
}

type rowScanner interface {
	Scan(...any) error
}

func (d *DB) scanPendingCase(row rowScanner, caseID string) (edge.PendingCase, bool, error) {
	var envelopeID, commitment, createdAtRaw string
	var ciphertext []byte
	err := row.Scan(&envelopeID, &commitment, &ciphertext, &createdAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return edge.PendingCase{}, false, nil
	}
	if err != nil {
		return edge.PendingCase{}, false, err
	}
	createdAt, err := parseSQLTime(createdAtRaw)
	if err != nil {
		return edge.PendingCase{}, false, err
	}
	raw, err := d.open("ssp_edge_pending_cases", caseID, ciphertext)
	if err != nil {
		return edge.PendingCase{}, false, err
	}
	return edge.PendingCase{
		EnvelopeID: envelopeID,
		CaseID:     caseID,
		Commitment: commitment,
		Raw:        append([]byte(nil), raw...),
		CreatedAt:  createdAt,
	}, true, nil
}

func (d *DB) loadPendingCaseTx(ctx context.Context, tx *sql.Tx, caseID string) (edge.PendingCase, bool, error) {
	return d.scanPendingCase(tx.QueryRowContext(ctx, `
		SELECT envelope_id,commitment,raw_ciphertext,created_at
		FROM ssp_edge_pending_cases
		WHERE case_id=?`, caseID), caseID)
}

func validateAcceptedRemote(accepted edge.AcceptedRemoteCase) error {
	if strings.TrimSpace(accepted.EnvelopeID) == "" ||
		strings.TrimSpace(accepted.CaseID) == "" ||
		!sha256RE.MatchString(accepted.Commitment) ||
		strings.TrimSpace(accepted.Receipt.AuthorityID) == "" ||
		accepted.Receipt.Revision <= 0 ||
		accepted.Receipt.EnvelopeID != accepted.EnvelopeID ||
		accepted.Receipt.Commitment != accepted.Commitment ||
		accepted.AcceptedAt.IsZero() {
		return errors.New("sspedge: invalid accepted_remote receipt")
	}
	return nil
}

// MarkCaseAcceptedRemote is the only transition to accepted_remote. A broker
// delivery or local projection cannot populate the PostgreSQL receipt fields.
func (d *DB) MarkCaseAcceptedRemote(ctx context.Context, accepted edge.AcceptedRemoteCase) error {
	if d == nil || d.sqlDB == nil {
		return errors.New("sspedge: nil store")
	}
	if err := validateAcceptedRemote(accepted); err != nil {
		return err
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var envelopeID, commitment, state, authorityID, acceptedAtRaw string
	var authorityRevision int64
	err = tx.QueryRowContext(ctx, `
		SELECT envelope_id,commitment,state,COALESCE(authority_id,''),
		       COALESCE(authority_revision,0),COALESCE(accepted_at,'')
		FROM ssp_edge_pending_cases
		WHERE case_id=?`, accepted.CaseID).
		Scan(&envelopeID, &commitment, &state, &authorityID, &authorityRevision, &acceptedAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("sspedge: pending case not found")
	}
	if err != nil {
		return err
	}
	if envelopeID != accepted.EnvelopeID || commitment != accepted.Commitment {
		return errors.New("sspedge: authority receipt does not bind stored pending case")
	}
	if state == "accepted_remote" {
		if authorityID == accepted.Receipt.AuthorityID &&
			authorityRevision == accepted.Receipt.Revision &&
			acceptedAtRaw == sqlTime(accepted.AcceptedAt) {
			return tx.Commit()
		}
		return errors.New("sspedge: accepted_remote receipt conflicts with stored evidence")
	}
	if state != "pending" {
		return errors.New("sspedge: pending case has invalid state")
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE ssp_edge_pending_cases
		SET state='accepted_remote',authority_id=?,authority_revision=?,accepted_at=?
		WHERE case_id=? AND state='pending'`,
		accepted.Receipt.AuthorityID, accepted.Receipt.Revision, sqlTime(accepted.AcceptedAt), accepted.CaseID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) GetCase(ctx context.Context, caseID string) (edge.CaseRecord, bool, error) {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return edge.CaseRecord{}, false, errors.New("sspedge: nil store")
	}
	if strings.TrimSpace(caseID) == "" {
		return edge.CaseRecord{}, false, errors.New("sspedge: case ID is required")
	}
	var envelopeID, commitment, registryHash, expiresAtRaw string
	var routingEpoch, registryRevision int64
	var ciphertext []byte
	err := d.sqlDB.QueryRowContext(ctx, `
		SELECT envelope_id,commitment,routing_epoch,registry_revision,registry_hash,
		       payload_ciphertext,expires_at
		FROM ssp_edge_cases
		WHERE case_id=? AND state='accepted'`, caseID).
		Scan(&envelopeID, &commitment, &routingEpoch, &registryRevision, &registryHash, &ciphertext, &expiresAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return edge.CaseRecord{}, false, nil
	}
	if err != nil {
		return edge.CaseRecord{}, false, err
	}
	plain, err := d.open("ssp_edge_cases", caseID, ciphertext)
	if err != nil {
		return edge.CaseRecord{}, false, err
	}
	payload, err := decodeCasePayload(plain)
	if err != nil {
		return edge.CaseRecord{}, false, err
	}
	expiresAt, err := parseSQLTime(expiresAtRaw)
	if err != nil {
		return edge.CaseRecord{}, false, err
	}
	return edge.CaseRecord{
		EnvelopeID: envelopeID,
		CaseID:     caseID,
		Commitment: commitment,
		Summary:    payload.Summary,
		Registry: edge.RegistryCoordinates{
			RoutingEpoch: routingEpoch,
			Revision:     registryRevision,
			Hash:         registryHash,
		},
		ExpiresAt: expiresAt,
		Committed: true,
	}, true, nil
}

func (d *DB) ListAdvice(ctx context.Context, caseID string) ([]edge.AdviceView, error) {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return nil, errors.New("sspedge: nil store")
	}
	if strings.TrimSpace(caseID) == "" {
		return nil, errors.New("sspedge: case ID is required")
	}
	rows, err := d.sqlDB.QueryContext(ctx, `
		SELECT advice_id,text_ciphertext,received_at
		FROM ssp_edge_advice
		WHERE case_id=? AND state='accepted'
		ORDER BY received_at,advice_id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]edge.AdviceView, 0)
	for rows.Next() {
		var adviceID, receivedAtRaw string
		var ciphertext []byte
		if err := rows.Scan(&adviceID, &ciphertext, &receivedAtRaw); err != nil {
			return nil, err
		}
		text, err := d.open("ssp_edge_advice", adviceID, ciphertext)
		if err != nil {
			return nil, err
		}
		receivedAt, err := parseSQLTime(receivedAtRaw)
		if err != nil {
			return nil, err
		}
		out = append(out, edge.AdviceView{
			AdviceID:   adviceID,
			CaseID:     caseID,
			Text:       string(text),
			ReceivedAt: receivedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *DB) PresentAdvice(ctx context.Context, adviceID string) (edge.AdviceView, bool, error) {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return edge.AdviceView{}, false, errors.New("sspedge: nil store")
	}
	if strings.TrimSpace(adviceID) == "" {
		return edge.AdviceView{}, false, errors.New("sspedge: advice ID is required")
	}
	var caseID, receivedAtRaw string
	var ciphertext []byte
	err := d.sqlDB.QueryRowContext(ctx, `
		SELECT case_id,text_ciphertext,received_at
		FROM ssp_edge_advice
		WHERE advice_id=? AND state='accepted'`, adviceID).
		Scan(&caseID, &ciphertext, &receivedAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return edge.AdviceView{}, false, nil
	}
	if err != nil {
		return edge.AdviceView{}, false, err
	}
	text, err := d.open("ssp_edge_advice", adviceID, ciphertext)
	if err != nil {
		return edge.AdviceView{}, false, err
	}
	receivedAt, err := parseSQLTime(receivedAtRaw)
	if err != nil {
		return edge.AdviceView{}, false, err
	}
	return edge.AdviceView{
		AdviceID:   adviceID,
		CaseID:     caseID,
		Text:       string(text),
		ReceivedAt: receivedAt,
	}, true, nil
}

func parseSQLTime(raw string) (time.Time, error) {
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("sspedge: invalid stored timestamp: %w", err)
	}
	return value, nil
}
