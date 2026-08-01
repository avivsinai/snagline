//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProvisionRolesSeparatesMigratorControlDeliveryAndProjector(t *testing.T) {
	fixture := newRoleFixture(t)

	controlStore, err := New(fixture.control, "role-test")
	if err != nil {
		t.Fatal(err)
	}
	registry := testRegistry(12, "roles", "")
	registry.Edges = map[string]authority.RegistryEdge{
		"edge-roles": {PrincipalID: "edge-principal", Generation: 7},
	}
	if _, err := controlStore.CommitRegistry(context.Background(), registry); err != nil {
		t.Fatalf("control CommitRegistry: %v", err)
	}
	caseRequest := testCase("case-roles", "edge-roles", 7, "roles")
	caseRequest.RegistryHash = registry.Commitment
	if _, err := controlStore.CommitCase(context.Background(), caseRequest); err != nil {
		t.Fatalf("control CommitCase: %v", err)
	}
	page, err := controlStore.ListEdgeDeliveries(context.Background(), authority.EdgeDeliveryQuery{
		TenantID: caseRequest.TenantID, EdgeID: caseRequest.IssuerEdgeID,
		PrincipalID: "edge-principal", EdgeGeneration: caseRequest.IssuerEdgeGeneration, Limit: 10,
	})
	if err != nil || len(page.Deliveries) == 0 {
		t.Fatalf("control ListEdgeDeliveries = %#v, %v; want reconciliation reads", page, err)
	}
	var schemaVersion int
	if err := fixture.control.QueryRow(context.Background(), `SELECT MAX(version) FROM snagline_schema_migrations`).Scan(&schemaVersion); err != nil || schemaVersion != 1 {
		t.Fatalf("control schema version = %d, %v; want readiness access", schemaVersion, err)
	}

	mustPermissionDenied(t, fixture.control, `UPDATE authority_cases SET raw = raw`)
	mustPermissionDenied(t, fixture.control, `UPDATE authority_advice SET raw = raw`)
	mustPermissionDenied(t, fixture.control, `UPDATE authority_registries SET raw = raw`)
	mustPermissionDenied(t, fixture.control, `DELETE FROM authority_cases`)
	mustPermissionDenied(t, fixture.control, `DELETE FROM authority_advice`)
	mustPermissionDenied(t, fixture.control, `DELETE FROM authority_registries`)
	mustPermissionDenied(t, fixture.control, `SELECT raw FROM authority_outbox`)

	items, err := controlStore.Claim(context.Background(), "wrong-role", 1, time.Minute)
	if err == nil || len(items) != 0 {
		t.Fatalf("control outbox lease = %#v, %v; want denied", items, err)
	}

	deliveryStore, err := New(fixture.delivery, "role-test")
	if err != nil {
		t.Fatal(err)
	}
	items, err = deliveryStore.Claim(context.Background(), "delivery-role", 10, time.Minute)
	if err != nil || len(items) == 0 {
		t.Fatalf("delivery Claim = %#v, %v; want leased outbox rows", items, err)
	}
	if err := deliveryStore.MarkPublished(context.Background(), items[0].ID, items[0].LeaseToken); err != nil {
		t.Fatalf("delivery MarkPublished: %v", err)
	}
	mustPermissionDenied(t, fixture.delivery, `INSERT INTO authority_cases (tenant_id) VALUES ('tenant-a')`)
	mustPermissionDenied(t, fixture.delivery, `UPDATE authority_cases SET raw = raw`)
	mustPermissionDenied(t, fixture.delivery, `UPDATE authority_outbox SET raw = raw`)
	mustPermissionDenied(t, fixture.delivery, `DELETE FROM authority_outbox`)

	projectorStore, err := New(fixture.projector, "role-test")
	if err != nil {
		t.Fatal(err)
	}
	facts, err := projectorStore.ListProjectionFacts(context.Background(), authority.ProjectionFactQuery{TenantID: "tenant-a", Limit: 10})
	if err != nil || len(facts.Facts) == 0 {
		t.Fatalf("projector ListProjectionFacts = %#v, %v; want read-only projection facts", facts, err)
	}
	if _, err := projectorStore.ResolveCase(context.Background(), "tenant-a", caseRequest.CaseID, caseRequest.Commitment); err != nil {
		t.Fatalf("projector ResolveCase: %v", err)
	}
	if _, err := projectorStore.ResolveRegistry(context.Background(), "tenant-a", registry.Revision, registry.Commitment); err != nil {
		t.Fatalf("projector ResolveRegistry: %v", err)
	}
	mustPermissionDenied(t, fixture.projector, `INSERT INTO authority_revisions DEFAULT VALUES`)
	mustPermissionDenied(t, fixture.projector, `UPDATE authority_cases SET raw = raw`)
	mustPermissionDenied(t, fixture.projector, `DELETE FROM authority_registries`)
	mustPermissionDenied(t, fixture.projector, `SELECT raw FROM authority_outbox`)

	if err := Migrate(context.Background(), fixture.control); err == nil {
		t.Fatal("ordinary control role unexpectedly ran migrations")
	}
}

func mustPermissionDenied(t *testing.T, conn interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, statement string) {
	t.Helper()
	_, err := conn.Exec(context.Background(), statement)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("%q error = %v; want PostgreSQL insufficient_privilege (42501)", statement, err)
	}
}

type roleFixture struct {
	control, delivery, projector *pgxpool.Pool
}

func newRoleFixture(t *testing.T) roleFixture {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("SNAGLINE_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set SNAGLINE_TEST_POSTGRES_DSN to run PostgreSQL authority integration tests")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !canCreateRoles(ctx, admin) {
		admin.Close()
		t.Skip("SNAGLINE_TEST_POSTGRES_DSN role lacks CREATEROLE required for role-boundary integration")
	}
	unique := fmt.Sprintf("%d", time.Now().UnixNano())
	schema := "authority_roles_" + unique
	roles := RoleConfig{
		ControlRole:   "snagline_ctl_" + unique,
		DeliveryRole:  "snagline_del_" + unique,
		ProjectorRole: "snagline_prj_" + unique,
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoteIdentifier(schema)); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	migrator := newSchemaPool(t, dsn, schema, "")
	if err := Migrate(ctx, migrator); err != nil {
		migrator.Close()
		admin.Close()
		t.Fatal(err)
	}
	if err := ProvisionRoles(ctx, migrator, roles); err != nil {
		migrator.Close()
		admin.Close()
		t.Fatal(err)
	}
	if _, err := migrator.Exec(ctx, "GRANT DELETE ON authority_cases TO "+quoteIdentifier(roles.ProjectorRole)); err != nil {
		migrator.Close()
		admin.Close()
		t.Fatal(err)
	}
	if err := ProvisionRoles(ctx, migrator, roles); err != nil {
		migrator.Close()
		admin.Close()
		t.Fatalf("convergent ProvisionRoles: %v", err)
	}
	for _, role := range []string{roles.ControlRole, roles.DeliveryRole, roles.ProjectorRole} {
		if _, err := admin.Exec(ctx, "GRANT "+quoteIdentifier(role)+" TO CURRENT_USER"); err != nil {
			migrator.Close()
			admin.Close()
			t.Fatal(err)
		}
	}
	fixture := roleFixture{
		control:   newSchemaPool(t, dsn, schema, roles.ControlRole),
		delivery:  newSchemaPool(t, dsn, schema, roles.DeliveryRole),
		projector: newSchemaPool(t, dsn, schema, roles.ProjectorRole),
	}
	t.Cleanup(func() {
		fixture.control.Close()
		fixture.delivery.Close()
		fixture.projector.Close()
		migrator.Close()
		for _, role := range []string{roles.ControlRole, roles.DeliveryRole, roles.ProjectorRole} {
			_, _ = admin.Exec(context.Background(), "REVOKE "+quoteIdentifier(role)+" FROM CURRENT_USER")
			_, _ = admin.Exec(context.Background(), "DROP ROLE "+quoteIdentifier(role))
		}
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quoteIdentifier(schema)+" CASCADE")
		admin.Close()
	})
	return fixture
}

func canCreateRoles(ctx context.Context, pool *pgxpool.Pool) bool {
	var allowed bool
	if err := pool.QueryRow(ctx, `SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user`).Scan(&allowed); err != nil {
		return false
	}
	return allowed
}

func newSchemaPool(t *testing.T, dsn, schema, role string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if _, err := conn.Exec(ctx, "SET search_path TO "+quoteIdentifier(schema)); err != nil {
			return err
		}
		if role != "" {
			_, err := conn.Exec(ctx, "SET ROLE "+quoteIdentifier(role))
			return err
		}
		return nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}
