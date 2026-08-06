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
	Completed bool
	Result    []byte
}

// BindDispatcherTurn atomically prunes expired bindings, checks the complete
// canonical request for an existing event, and reserves capacity for a new
// one. Request bytes are encrypted with the same field key as the dispatcher
// advice spool; this table is not a second state authority.
func (d *DB) BindDispatcherTurn(ctx context.Context, eventID string, request []byte, now time.Time, retention time.Duration, capacity int) (DispatcherTurnBinding, error) {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return DispatcherTurnBinding{}, errors.New("sspedge: nil store")
	}
	if !dispatcherTurnIDPattern.MatchString(eventID) || len(request) == 0 || len(request) > maxDispatcherTurnRequestBytes || now.IsZero() || retention <= 0 || retention > maxDispatcherTurnRetention || capacity <= 0 || capacity > maxDispatcherTurnCapacity {
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
	var state string
	err = tx.QueryRowContext(ctx, `
		SELECT request_ciphertext,result_ciphertext,state
		FROM ssp_edge_dispatcher_turns
		WHERE event_id=?`, eventID).Scan(&requestCiphertext, &resultCiphertext, &state)
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
		case "completed":
			if len(resultCiphertext) == 0 {
				return DispatcherTurnBinding{}, errors.New("sspedge: completed dispatcher turn has no result")
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
	_, err = tx.ExecContext(ctx, `
		INSERT INTO ssp_edge_dispatcher_turns
			(event_id,request_ciphertext,result_ciphertext,state,created_unix_nano,expires_unix_nano,completed_unix_nano)
		VALUES (?,?,NULL,'pending',?,?,NULL)`,
		eventID, requestCiphertext, now.UnixNano(), now.Add(retention).UnixNano())
	if err != nil {
		return DispatcherTurnBinding{}, err
	}
	if err := tx.Commit(); err != nil {
		return DispatcherTurnBinding{}, err
	}
	return DispatcherTurnBinding{}, nil
}

// CompleteDispatcherTurn atomically binds the canonical success result to the
// exact request. Repeating the same completion is idempotent; any changed
// request or result fails closed.
func (d *DB) CompleteDispatcherTurn(ctx context.Context, eventID string, request, result []byte, completedAt time.Time) error {
	if d == nil || d.sqlDB == nil || d.key == nil {
		return errors.New("sspedge: nil store")
	}
	if !dispatcherTurnIDPattern.MatchString(eventID) || len(request) == 0 || len(request) > maxDispatcherTurnRequestBytes || len(result) == 0 || len(result) > maxDispatcherTurnResultBytes || completedAt.IsZero() {
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
	var state string
	err = tx.QueryRowContext(ctx, `
		SELECT request_ciphertext,result_ciphertext,state
		FROM ssp_edge_dispatcher_turns
		WHERE event_id=?`, eventID).Scan(&requestCiphertext, &resultCiphertext, &state)
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
		storedResult, err := d.open(dispatcherTurnResultAAD, eventID, resultCiphertext)
		if err != nil {
			return err
		}
		if !bytes.Equal(storedResult, result) {
			return errors.New("sspedge: dispatcher turn result conflicts with stored binding")
		}
		return tx.Commit()
	}
	if state != "pending" || len(resultCiphertext) != 0 {
		return errors.New("sspedge: invalid dispatcher turn state")
	}
	resultCiphertext, err = d.seal(dispatcherTurnResultAAD, eventID, result)
	if err != nil {
		return err
	}
	update, err := tx.ExecContext(ctx, `
		UPDATE ssp_edge_dispatcher_turns
		SET result_ciphertext=?,state='completed',completed_unix_nano=?
		WHERE event_id=? AND state='pending'`, resultCiphertext, completedAt.UnixNano(), eventID)
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
