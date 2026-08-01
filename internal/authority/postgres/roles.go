package postgres

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RoleConfig names the NOLOGIN database roles granted to independently
// credentialed Snagline processes. Login principals are provisioned outside
// Snagline and may be made members of exactly one of these roles.
//
// The migrator is deliberately not represented here: it needs owner-level
// DDL/role-administration privileges and must use a distinct DSN.
type RoleConfig struct {
	ControlRole   string
	DeliveryRole  string
	ProjectorRole string
}

var authorityRoleName = regexp.MustCompile(`\A[a-z][a-z0-9_]{0,62}\z`)

// DefaultRoleConfig returns stable, database-local authority role names.
func DefaultRoleConfig() RoleConfig {
	return RoleConfig{
		ControlRole:   "snagline_authority_control",
		DeliveryRole:  "snagline_authority_delivery",
		ProjectorRole: "snagline_authority_projector",
	}
}

func (config RoleConfig) validate() error {
	names := []string{config.ControlRole, config.DeliveryRole, config.ProjectorRole}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if !authorityRoleName.MatchString(name) {
			return errors.New("authority/postgres: role names must be lowercase PostgreSQL identifiers")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("authority/postgres: authority role names must be distinct")
		}
		seen[name] = struct{}{}
	}
	return nil
}

// ProvisionRoles creates idempotent NOLOGIN roles and grants only the SQL
// operations required by the current authority processes in the pool's
// current schema. It intentionally never creates login credentials or embeds
// passwords. Call it only from an explicit migrator process/DSN after Migrate.
func ProvisionRoles(ctx context.Context, pool *pgxpool.Pool, config RoleConfig) error {
	if pool == nil {
		return errors.New("authority/postgres: role provision pool is required")
	}
	if err := config.validate(); err != nil {
		return err
	}
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil || !authorityRoleName.MatchString(schema) {
		return errors.New("authority/postgres: current schema must be a lowercase PostgreSQL identifier")
	}
	statements := roleProvisionStatements(schema, config)
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("authority/postgres: provision role boundary: %w", err)
		}
	}
	return nil
}

func roleProvisionStatements(schema string, config RoleConfig) []string {
	q := quoteIdentifier
	control, delivery, projector := q(config.ControlRole), q(config.DeliveryRole), q(config.ProjectorRole)
	schemaName := q(schema)
	roles := strings.Join([]string{control, delivery, projector}, ", ")
	return []string{
		createNoLoginRole(config.ControlRole),
		createNoLoginRole(config.DeliveryRole),
		createNoLoginRole(config.ProjectorRole),
		fmt.Sprintf("REVOKE CREATE ON SCHEMA %s FROM PUBLIC", schemaName),
		fmt.Sprintf("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %s FROM PUBLIC", schemaName),
		fmt.Sprintf("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %s FROM PUBLIC", schemaName),
		fmt.Sprintf("REVOKE ALL PRIVILEGES ON SCHEMA %s FROM %s", schemaName, roles),
		fmt.Sprintf("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %s FROM %s", schemaName, roles),
		fmt.Sprintf("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %s FROM %s", schemaName, roles),
		fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", schemaName, roles),
		fmt.Sprintf("GRANT SELECT ON TABLE snagline_schema_migrations, authority_revisions, authority_cases, authority_advice, authority_edge_delivery_sequences, authority_edge_deliveries, authority_registry_heads, authority_edge_generation_high_water, authority_registries TO %s", control),
		fmt.Sprintf("GRANT INSERT ON TABLE authority_revisions, authority_cases, authority_advice, authority_edge_delivery_sequences, authority_edge_deliveries, authority_registry_heads, authority_edge_generation_high_water, authority_registries, authority_audit, authority_outbox TO %s", control),
		fmt.Sprintf("GRANT UPDATE (next_sequence) ON TABLE authority_edge_delivery_sequences TO %s", control),
		fmt.Sprintf("GRANT UPDATE (principal_id, highest_generation, last_seen_registry_revision) ON TABLE authority_edge_generation_high_water TO %s", control),
		fmt.Sprintf("GRANT UPDATE (latest_revision, latest_commitment, routing_epoch, halted, halt_reason, updated_at) ON TABLE authority_registry_heads TO %s", control),
		fmt.Sprintf("GRANT USAGE ON SEQUENCE authority_revisions_revision_seq, authority_audit_audit_id_seq TO %s", control),
		fmt.Sprintf("GRANT SELECT ON TABLE authority_outbox, authority_cases, authority_edge_deliveries TO %s", delivery),
		fmt.Sprintf("GRANT UPDATE (attempts, next_attempt_at, lease_owner, lease_token, lease_until, last_error, poisoned_at, published_at) ON TABLE authority_outbox TO %s", delivery),
		fmt.Sprintf("GRANT SELECT ON TABLE authority_cases, authority_advice, authority_registries TO %s", projector),
	}
}

func createNoLoginRole(name string) string {
	return fmt.Sprintf("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s) THEN CREATE ROLE %s NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; END IF; END $$", quoteLiteral(name), quoteIdentifier(name))
}

func quoteIdentifier(value string) string { return `"` + strings.ReplaceAll(value, `"`, `""`) + `"` }

func quoteLiteral(value string) string { return `'` + strings.ReplaceAll(value, `'`, `''`) + `'` }
