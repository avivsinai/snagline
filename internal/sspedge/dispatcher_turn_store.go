package sspedge

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"
)

const (
	maxDispatcherTurnRequestBytes = 64 << 10
	maxDispatcherTurnResultBytes  = 16 << 10
	maxDispatcherTurnRetention    = 30 * 24 * time.Hour
	maxDispatcherTurnCapacity     = 1 << 20
	maxDispatcherTurnClaimTTL     = 10 * time.Minute
	dispatcherTurnRequestAAD      = "ssp_edge_dispatcher_turn_request"
	dispatcherTurnResultAAD       = "ssp_edge_dispatcher_turn_result"
)

var (
	dispatcherTurnIDPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ErrDispatcherTurnMismatch = errors.New("sspedge: dispatcher turn request conflicts with stored binding")
	ErrDispatcherTurnCapacity = errors.New("sspedge: dispatcher turn replay guard is full")
)

// DispatcherTurnBinding is the durable outcome for one Buzz event. A pending
// exact binding may be retried; a completed binding returns its canonical
// result without invoking the authority again.
type DispatcherTurnBinding struct {
	Completed  bool
	InFlight   bool
	ClaimToken string
	Result     []byte
}

// BindDispatcherTurn atomically prunes expired bindings, checks the complete
// canonical request for an existing event, and reserves capacity plus one
// bounded execution claim for a new one. Request bytes are encrypted with the
// same field key as the dispatcher advice spool; this table is not a second
// state authority.
func (d *DB) BindDispatcherTurn(ctx context.Context, eventID string, request []byte, now time.Time, retention, claimTTL time.Duration, capacity int) (DispatcherTurnBinding, error) {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return DispatcherTurnBinding{}, errors.New("sspedge: nil store")
	}
	if !dispatcherTurnIDPattern.MatchString(eventID) || len(request) == 0 || len(request) > maxDispatcherTurnRequestBytes || now.IsZero() || retention <= 0 || retention > maxDispatcherTurnRetention || claimTTL <= 0 || claimTTL > maxDispatcherTurnClaimTTL || capacity <= 0 || capacity > maxDispatcherTurnCapacity {
		return DispatcherTurnBinding{}, errors.New("sspedge: invalid dispatcher turn binding")
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return DispatcherTurnBinding{}, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM ssp_edge_dispatcher_turns WHERE expires_unix_nano<=?`, now.UnixNano()); err != nil {
		return DispatcherTurnBinding{}, err
	}
	var requestCiphertext, resultCiphertext []byte
	var state, storedClaim string
	var claimExpires int64
	err = tx.QueryRowContext(ctx, `
		SELECT request_ciphertext,result_ciphertext,state,COALESCE(claim_token,''),COALESCE(claim_expires_unix_nano,0)
		FROM ssp_edge_dispatcher_turns
		WHERE event_id=?`, eventID).Scan(&requestCiphertext, &resultCiphertext, &state, &storedClaim, &claimExpires)
	if err == nil {
		storedRequest, err := d.open(dispatcherTurnRequestAAD, eventID, requestCiphertext)
		if err != nil {
			return DispatcherTurnBinding{}, err
		}
		if !bytes.Equal(storedRequest, request) {
			return DispatcherTurnBinding{}, ErrDispatcherTurnMismatch
		}
		binding := DispatcherTurnBinding{}
		switch state {
		case "pending":
			if len(resultCiphertext) != 0 {
				return DispatcherTurnBinding{}, errors.New("sspedge: pending dispatcher turn has a result")
			}
			if (storedClaim == "") != (claimExpires == 0) {
				return DispatcherTurnBinding{}, errors.New("sspedge: pending dispatcher turn has an invalid claim")
			}
			if storedClaim != "" && claimExpires > now.UnixNano() {
				binding.InFlight = true
				if err := tx.Commit(); err != nil {
					return DispatcherTurnBinding{}, err
				}
				return binding, nil
			}
			token, err := claimToken()
			if err != nil {
				return DispatcherTurnBinding{}, err
			}
			updated, err := tx.ExecContext(ctx, `
				UPDATE ssp_edge_dispatcher_turns
				SET claim_token=?,claim_expires_unix_nano=?
				WHERE event_id=? AND state='pending'`, token, now.Add(claimTTL).UnixNano(), eventID)
			if err != nil {
				return DispatcherTurnBinding{}, err
			}
			rows, err := updated.RowsAffected()
			if err != nil || rows != 1 {
				if err != nil {
					return DispatcherTurnBinding{}, err
				}
				return DispatcherTurnBinding{}, errors.New("sspedge: dispatcher turn claim lost its binding")
			}
			binding.ClaimToken = token
		case "completed":
			if len(resultCiphertext) == 0 || storedClaim != "" || claimExpires != 0 {
				return DispatcherTurnBinding{}, errors.New("sspedge: completed dispatcher turn state is invalid")
			}
			binding.Result, err = d.open(dispatcherTurnResultAAD, eventID, resultCiphertext)
			if err != nil || len(binding.Result) == 0 || len(binding.Result) > maxDispatcherTurnResultBytes {
				if err != nil {
					return DispatcherTurnBinding{}, err
				}
				return DispatcherTurnBinding{}, errors.New("sspedge: invalid stored dispatcher turn result")
			}
			binding.Completed = true
		default:
			return DispatcherTurnBinding{}, errors.New("sspedge: invalid dispatcher turn state")
		}
		if err := tx.Commit(); err != nil {
			return DispatcherTurnBinding{}, err
		}
		binding.Result = append([]byte(nil), binding.Result...)
		return binding, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DispatcherTurnBinding{}, err
	}
	var used int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ssp_edge_dispatcher_turns`).Scan(&used); err != nil {
		return DispatcherTurnBinding{}, err
	}
	if used >= capacity {
		return DispatcherTurnBinding{}, ErrDispatcherTurnCapacity
	}
	requestCiphertext, err = d.seal(dispatcherTurnRequestAAD, eventID, request)
	if err != nil {
		return DispatcherTurnBinding{}, err
	}
	token, err := claimToken()
	if err != nil {
		return DispatcherTurnBinding{}, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO ssp_edge_dispatcher_turns
			(event_id,request_ciphertext,result_ciphertext,state,created_unix_nano,expires_unix_nano,completed_unix_nano,claim_token,claim_expires_unix_nano)
		VALUES (?,?,NULL,'pending',?,?,NULL,?,?)`,
		eventID, requestCiphertext, now.UnixNano(), now.Add(retention).UnixNano(), token, now.Add(claimTTL).UnixNano())
	if err != nil {
		return DispatcherTurnBinding{}, err
	}
	if err := tx.Commit(); err != nil {
		return DispatcherTurnBinding{}, err
	}
	return DispatcherTurnBinding{ClaimToken: token}, nil
}

// CompleteDispatcherTurn atomically binds the canonical success result to the
// exact request. Repeating the same completion is idempotent; any changed
// request or result fails closed.
func (d *DB) CompleteDispatcherTurn(ctx context.Context, eventID string, request, result []byte, completedAt time.Time, claim string) error {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return errors.New("sspedge: nil store")
	}
	if !dispatcherTurnIDPattern.MatchString(eventID) || !dispatcherTurnIDPattern.MatchString(claim) || len(request) == 0 || len(request) > maxDispatcherTurnRequestBytes || len(result) == 0 || len(result) > maxDispatcherTurnResultBytes || completedAt.IsZero() {
		return errors.New("sspedge: invalid dispatcher turn completion")
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var requestCiphertext, resultCiphertext []byte
	var state, storedClaim string
	err = tx.QueryRowContext(ctx, `
		SELECT request_ciphertext,result_ciphertext,state,COALESCE(claim_token,'')
		FROM ssp_edge_dispatcher_turns
		WHERE event_id=?`, eventID).Scan(&requestCiphertext, &resultCiphertext, &state, &storedClaim)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("sspedge: dispatcher turn binding not found")
	}
	if err != nil {
		return err
	}
	storedRequest, err := d.open(dispatcherTurnRequestAAD, eventID, requestCiphertext)
	if err != nil {
		return err
	}
	if !bytes.Equal(storedRequest, request) {
		return ErrDispatcherTurnMismatch
	}
	if state == "completed" {
		if storedClaim != "" {
			return errors.New("sspedge: completed dispatcher turn retained a claim")
		}
		storedResult, err := d.open(dispatcherTurnResultAAD, eventID, resultCiphertext)
		if err != nil {
			return err
		}
		if !bytes.Equal(storedResult, result) {
			return errors.New("sspedge: dispatcher turn result conflicts with stored binding")
		}
		return tx.Commit()
	}
	if state != "pending" || len(resultCiphertext) != 0 || storedClaim != claim {
		return errors.New("sspedge: invalid dispatcher turn state")
	}
	resultCiphertext, err = d.seal(dispatcherTurnResultAAD, eventID, result)
	if err != nil {
		return err
	}
	update, err := tx.ExecContext(ctx, `
		UPDATE ssp_edge_dispatcher_turns
		SET result_ciphertext=?,state='completed',completed_unix_nano=?,claim_token=NULL,claim_expires_unix_nano=NULL
		WHERE event_id=? AND state='pending' AND claim_token=?`, resultCiphertext, completedAt.UnixNano(), eventID, claim)
	if err != nil {
		return err
	}
	rows, err := update.RowsAffected()
	if err != nil || rows != 1 {
		if err != nil {
			return err
		}
		return errors.New("sspedge: dispatcher turn completion lost its binding")
	}
	return tx.Commit()
}

// ReleaseDispatcherTurnClaim makes an ambiguous pending reservation retryable
// without freeing its capacity or allowing a stale execution to complete it.
func (d *DB) ReleaseDispatcherTurnClaim(ctx context.Context, eventID string, request []byte, claim string) error {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return errors.New("sspedge: nil store")
	}
	if !dispatcherTurnIDPattern.MatchString(eventID) || !dispatcherTurnIDPattern.MatchString(claim) || len(request) == 0 || len(request) > maxDispatcherTurnRequestBytes {
		return errors.New("sspedge: invalid dispatcher turn claim release")
	}
	return d.updatePendingDispatcherTurnClaim(ctx, eventID, request, claim, false)
}

// AbandonDispatcherTurn removes an uncompleted reservation after a
// deterministic pre-spool failure. The caller must present the exact canonical
// request and its claim so a stale execution cannot free a live retry.
func (d *DB) AbandonDispatcherTurn(ctx context.Context, eventID string, request []byte, claim string) error {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return errors.New("sspedge: nil store")
	}
	if !dispatcherTurnIDPattern.MatchString(eventID) || !dispatcherTurnIDPattern.MatchString(claim) || len(request) == 0 || len(request) > maxDispatcherTurnRequestBytes {
		return errors.New("sspedge: invalid dispatcher turn abandonment")
	}
	return d.updatePendingDispatcherTurnClaim(ctx, eventID, request, claim, true)
}

func (d *DB) updatePendingDispatcherTurnClaim(ctx context.Context, eventID string, request []byte, claim string, abandon bool) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var requestCiphertext, resultCiphertext []byte
	var state, storedClaim string
	err = tx.QueryRowContext(ctx, `
		SELECT request_ciphertext,result_ciphertext,state,COALESCE(claim_token,'')
		FROM ssp_edge_dispatcher_turns
		WHERE event_id=?`, eventID).Scan(&requestCiphertext, &resultCiphertext, &state, &storedClaim)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("sspedge: dispatcher turn binding not found")
	}
	if err != nil {
		return err
	}
	storedRequest, err := d.open(dispatcherTurnRequestAAD, eventID, requestCiphertext)
	if err != nil {
		return err
	}
	if !bytes.Equal(storedRequest, request) {
		return ErrDispatcherTurnMismatch
	}
	if state != "pending" || len(resultCiphertext) != 0 || storedClaim != claim {
		return errors.New("sspedge: dispatcher turn claim is not owned by this execution")
	}
	statement := `UPDATE ssp_edge_dispatcher_turns SET claim_token=NULL,claim_expires_unix_nano=NULL WHERE event_id=? AND state='pending' AND claim_token=?`
	if abandon {
		statement = `DELETE FROM ssp_edge_dispatcher_turns WHERE event_id=? AND state='pending' AND claim_token=?`
	}
	updated, err := tx.ExecContext(ctx, statement, eventID, claim)
	if err != nil {
		return err
	}
	rows, err := updated.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New("sspedge: dispatcher turn claim update lost its binding")
	}
	return tx.Commit()
}
