//go:build integration

package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigrateCreatesFreshAuthoritySchemaExactlyOnce(t *testing.T) {
	dsn := os.Getenv("SNAGLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SNAGLINE_TEST_POSTGRES_DSN is required")
	}
	admin, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "snagline_migrate_" + strings.ReplaceAll(strings.ToLower(t.Name()), "/", "_")
	if _, err := admin.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(context.Background(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`) })
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path TO `+schema)
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if err := Migrate(context.Background(), pool); err != nil {
			t.Fatalf("Migrate attempt %d: %v", attempt+1, err)
		}
	}
	var versionCount, caseTableCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM snagline_schema_migrations WHERE version = 1`).Scan(&versionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'authority_cases'`, schema).Scan(&caseTableCount); err != nil {
		t.Fatal(err)
	}
	if versionCount != 1 || caseTableCount != 1 {
		t.Fatalf("migration evidence = versions:%d cases:%d", versionCount, caseTableCount)
	}
}
