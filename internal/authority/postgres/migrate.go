package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/avivsinai/snagline/internal/authority/postgres/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const authoritySchemaVersion = 1

// Migrate installs the pristine authority schema under a transaction-scoped
// advisory lock. Repeated startup is idempotent; an unknown newer schema fails
// closed instead of attempting a downgrade.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("authority/postgres: migration pool is required")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("authority/postgres: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('snagline.authority.schema.v1'))`); err != nil {
		return fmt.Errorf("authority/postgres: lock migration: %w", err)
	}
	if _, err := tx.Exec(ctx, `
CREATE TABLE IF NOT EXISTS snagline_schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
)`); err != nil {
		return fmt.Errorf("authority/postgres: create migration ledger: %w", err)
	}
	var newest int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM snagline_schema_migrations`).Scan(&newest); err != nil {
		return fmt.Errorf("authority/postgres: read migration ledger: %w", err)
	}
	if newest > authoritySchemaVersion {
		return fmt.Errorf("authority/postgres: database schema version %d is newer than supported version %d", newest, authoritySchemaVersion)
	}
	if newest < authoritySchemaVersion {
		script, err := migrations.FS.ReadFile("0001_authority.up.sql")
		if err != nil {
			return fmt.Errorf("authority/postgres: read embedded migration: %w", err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return fmt.Errorf("authority/postgres: apply schema version 1: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO snagline_schema_migrations(version) VALUES ($1)`, authoritySchemaVersion); err != nil {
			return fmt.Errorf("authority/postgres: record schema version 1: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("authority/postgres: commit migration: %w", err)
	}
	return nil
}
