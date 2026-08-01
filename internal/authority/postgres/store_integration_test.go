//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/authority"
	"github.com/avivsinai/snagline/internal/authority/postgres/migrations"
	deliveryoutbox "github.com/avivsinai/snagline/internal/delivery/outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStoreCaseIdempotencyPreservesRawBytesAndPublishesOnlyAfterCommit(t *testing.T) {
	store, pool := newCaseIntegrationStore(t)
	request := testCase("case-a", "edge-a", 7, "a")

	first, err := store.CommitCase(context.Background(), request)
	if err != nil {
		t.Fatalf("CommitCase: %v", err)
	}
	retry, err := store.CommitCase(context.Background(), request)
	if err != nil {
		t.Fatalf("CommitCase exact retry: %v", err)
	}
	if first != retry || first.AuthorityID != "postgres-test" || first.Revision <= 0 {
		t.Fatalf("receipts = %#v and %#v, want one post-commit authority receipt", first, retry)
	}

	var caseRaw, outboxRaw []byte
	var auditCount, outboxCount int
	if err := pool.QueryRow(context.Background(), `SELECT raw FROM authority_cases WHERE tenant_id = $1 AND case_id = $2`, request.TenantID, request.CaseID).Scan(&caseRaw); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT raw FROM authority_outbox WHERE authority_revision = $1`, first.Revision).Scan(&outboxRaw); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_audit WHERE entity_kind = 'case'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_outbox WHERE event_kind = 'case'`).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if string(caseRaw) != string(request.Raw) || string(outboxRaw) != string(request.Raw) || auditCount != 1 || outboxCount != 2 {
		t.Fatalf("raw/audit/outbox = (%q,%q,%d,%d), want exact raw and two atomic delivery rows", caseRaw, outboxRaw, auditCount, outboxCount)
	}

	conflict := request
	conflict.Commitment = commitment("different")
	if _, err := store.CommitCase(context.Background(), conflict); !errors.Is(err, authority.ErrConflictingCase) {
		t.Fatalf("CommitCase conflicting semantic identity error = %v, want ErrConflictingCase", err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_outbox WHERE event_kind = 'case'`).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 2 {
		t.Fatalf("outbox rows after rejected conflict = %d, want 2", outboxCount)
	}
}

func TestStoreCaseExactReplaySurvivesRegistryAdvancement(t *testing.T) {
	store, _ := newCaseIntegrationStore(t)
	request := testCase("case-retry-after-registry", "edge-a", 7, "retry-after-registry")
	first, err := store.CommitCase(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	successor := testRegistry(13, "retry-after-registry-successor", request.RegistryHash)
	if _, err := store.CommitRegistry(context.Background(), successor); err != nil {
		t.Fatal(err)
	}
	retry, err := store.CommitCase(context.Background(), request)
	if err != nil || retry != first {
		t.Fatalf("exact case retry after registry advancement = %#v, %v; want original %#v", retry, err, first)
	}
}

func TestStoreAdviceDerivesCaseTargetAllocatesSequenceAndIsFinal(t *testing.T) {
	store, pool := newCaseIntegrationStore(t)
	caseA := testCase("case-a", "edge-a", 7, "a")
	caseB := testCase("case-b", "edge-a", 7, "b")
	if _, err := store.CommitCase(context.Background(), caseA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitCase(context.Background(), caseB); err != nil {
		t.Fatal(err)
	}

	adviceA := testAdvice(caseA, "advice-a", "a")
	first, err := store.CommitAdvice(context.Background(), adviceA)
	if err != nil {
		t.Fatalf("CommitAdvice: %v", err)
	}
	retry, err := store.CommitAdvice(context.Background(), adviceA)
	if err != nil || retry != first {
		t.Fatalf("CommitAdvice exact retry = %#v, %v; want %#v", retry, err, first)
	}
	var edgeID string
	var generation, sequence int64
	if err := pool.QueryRow(context.Background(), `
SELECT target_edge_id, target_edge_generation, delivery_sequence
FROM authority_advice WHERE tenant_id = $1 AND case_id = $2`, caseA.TenantID, caseA.CaseID).Scan(&edgeID, &generation, &sequence); err != nil {
		t.Fatal(err)
	}
	if edgeID != caseA.IssuerEdgeID || generation != caseA.IssuerEdgeGeneration || sequence != 3 {
		t.Fatalf("first advice target = (%q,%d,%d), want committed case target (%q,%d,3)", edgeID, generation, sequence, caseA.IssuerEdgeID, caseA.IssuerEdgeGeneration)
	}

	replacement := adviceA
	replacement.Commitment = commitment("replacement")
	if _, err := store.CommitAdvice(context.Background(), replacement); !errors.Is(err, authority.ErrFinalAdviceAlreadySet) {
		t.Fatalf("CommitAdvice replacement error = %v, want ErrFinalAdviceAlreadySet", err)
	}
	badBinding := testAdvice(caseB, "advice-b", "b")
	badBinding.CaseCommitment = caseA.Commitment
	if _, err := store.CommitAdvice(context.Background(), badBinding); !errors.Is(err, authority.ErrCaseBinding) {
		t.Fatalf("CommitAdvice case binding error = %v, want ErrCaseBinding", err)
	}
	adviceB := testAdvice(caseB, "advice-b", "b")
	if _, err := store.CommitAdvice(context.Background(), adviceB); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT delivery_sequence FROM authority_advice WHERE tenant_id = $1 AND case_id = $2`, caseB.TenantID, caseB.CaseID).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	if sequence != 4 {
		t.Fatalf("second advice sequence = %d, want 4", sequence)
	}
	firstPage, err := store.ListEdgeDeliveries(context.Background(), authority.EdgeDeliveryQuery{TenantID: caseA.TenantID, EdgeID: caseA.IssuerEdgeID, PrincipalID: "edge-principal", EdgeGeneration: caseA.IssuerEdgeGeneration, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Deliveries) != 3 || firstPage.HighWatermark != 4 || firstPage.CompleteThrough != 3 || string(firstPage.Deliveries[0].Raw) != string(caseA.Raw) {
		t.Fatalf("first recovery page = %#v, want first three exact immutable deliveries", firstPage)
	}
	secondPage, err := store.ListEdgeDeliveries(context.Background(), authority.EdgeDeliveryQuery{TenantID: caseA.TenantID, EdgeID: caseA.IssuerEdgeID, PrincipalID: "edge-principal", EdgeGeneration: caseA.IssuerEdgeGeneration, AfterSequence: 3, Limit: 3})
	if err != nil || len(secondPage.Deliveries) != 1 || secondPage.CompleteThrough != 4 {
		t.Fatalf("second recovery page = %#v, %v; want final contiguous delivery", secondPage, err)
	}
	projection, err := store.ListProjectionFacts(context.Background(), authority.ProjectionFactQuery{TenantID: caseA.TenantID, Limit: 10})
	if err != nil || len(projection.Facts) != 4 || projection.HighWatermark < projection.Facts[len(projection.Facts)-1].AuthorityRevision {
		t.Fatalf("projection facts = %#v, %v; want database-backed case/advice facts", projection, err)
	}
}

func TestStoreCaseRequiresCurrentRegistryHeadInsideTransaction(t *testing.T) {
	store, pool := newCaseIntegrationStore(t)
	current := testRegistry(13, "b", commitment("registry-a"))
	if _, err := store.CommitRegistry(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	stale := testCase("case-stale-registry", "edge-a", 7, "stale")
	if _, err := store.CommitCase(context.Background(), stale); !errors.Is(err, authority.ErrRegistryBinding) {
		t.Fatalf("stale registry case error = %v, want ErrRegistryBinding", err)
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_cases WHERE case_id = 'case-stale-registry'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stale registry case rows = %d, want 0", count)
	}
}

func TestStoreRegistryRequiresSequentialExactRevisions(t *testing.T) {
	store, pool := newIntegrationStore(t)
	zero := testRegistry(12, "zero", "")
	first, err := store.CommitRegistry(context.Background(), zero)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.CommitRegistry(context.Background(), zero)
	if err != nil || retry != first {
		t.Fatalf("CommitRegistry exact retry = %#v, %v; want %#v", retry, err, first)
	}
	if _, err := store.CommitRegistry(context.Background(), testRegistry(14, "two", zero.Commitment)); !errors.Is(err, authority.ErrRegistryRevisionSequence) {
		t.Fatalf("CommitRegistry skipped revision error = %v, want ErrRegistryRevisionSequence", err)
	}
	one := testRegistry(13, "one", zero.Commitment)
	if _, err := store.CommitRegistry(context.Background(), one); err != nil {
		t.Fatal(err)
	}
	var auditCount, outboxCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_audit WHERE entity_kind = 'registry'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_outbox WHERE event_kind = 'registry'`).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 || outboxCount != 0 {
		t.Fatalf("registry audit/outbox = (%d,%d), want (2,0)", auditCount, outboxCount)
	}
	head, err := store.CurrentRegistryHead(context.Background(), "tenant-a")
	if err != nil || head.Revision != one.Revision || head.Commitment != one.Commitment || head.Halted {
		t.Fatalf("registry head = %#v, %v", head, err)
	}
	resolved, err := store.ResolveRegistry(context.Background(), "tenant-a", zero.Revision, zero.Commitment)
	if err != nil || string(resolved.Raw) != string(zero.Raw) || resolved.RoutingEpoch != zero.RoutingEpoch {
		t.Fatalf("resolved registry = %#v, %v", resolved, err)
	}
	equivocation := testRegistry(14, "equivocation", commitment("wrong"))
	if _, err := store.CommitRegistry(context.Background(), equivocation); !errors.Is(err, authority.ErrRegistryEquivocation) {
		t.Fatalf("equivocation error = %v, want ErrRegistryEquivocation", err)
	}
	head, err = store.CurrentRegistryHead(context.Background(), "tenant-a")
	if err != nil || !head.Halted {
		t.Fatalf("halted registry head = %#v, %v", head, err)
	}
	if _, err := store.CommitRegistry(context.Background(), testRegistry(14, "after-halt", one.Commitment)); !errors.Is(err, authority.ErrRegistryHalted) {
		t.Fatalf("after-halt error = %v, want ErrRegistryHalted", err)
	}
}

func TestStoreCurrentRegistryHeadExactRetryIsIdempotent(t *testing.T) {
	store, pool := newIntegrationStore(t)
	initial := testRegistry(12, "current-retry-initial", "")
	if _, err := store.CommitRegistry(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	current := testRegistry(13, "current-retry-current", initial.Commitment)
	first, err := store.CommitRegistry(context.Background(), current)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.CommitRegistry(context.Background(), current)
	if err != nil || retry != first {
		t.Fatalf("current-head exact retry = %#v, %v; want %#v", retry, err, first)
	}
	var registries, audits, revisions int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_registries`).Scan(&registries); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_audit WHERE entity_kind = 'registry'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_revisions`).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if registries != 2 || audits != 2 || revisions != 2 {
		t.Fatalf("current-head retry persistence = registries:%d audits:%d revisions:%d, want 2/2/2", registries, audits, revisions)
	}
	head, err := store.CurrentRegistryHead(context.Background(), current.TenantID)
	if err != nil || head.Revision != current.Revision || head.Commitment != current.Commitment || head.Halted {
		t.Fatalf("current head after exact retry = %#v, %v", head, err)
	}
}

func TestStoreSameRevisionConflictingRegistryEvidenceHaltsAllAdmissions(t *testing.T) {
	store, pool := newIntegrationStore(t)
	current := testRegistry(12, "same-revision-current", "")
	if _, err := store.CommitRegistry(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	conflict := current
	conflict.Raw = []byte(`{"registry":"same-revision-conflicting-evidence"}`)
	if _, err := store.CommitRegistry(context.Background(), conflict); !errors.Is(err, authority.ErrRegistryEquivocation) {
		t.Fatalf("same-revision conflicting evidence error = %v, want ErrRegistryEquivocation", err)
	}
	head, err := store.CurrentRegistryHead(context.Background(), current.TenantID)
	if err != nil || !head.Halted || head.HaltReason != "same-revision conflicting evidence" || head.Revision != current.Revision || head.Commitment != current.Commitment {
		t.Fatalf("same-revision conflict head = %#v, %v", head, err)
	}
	if _, err := store.CommitRegistry(context.Background(), testRegistry(13, "same-revision-after-halt", current.Commitment)); !errors.Is(err, authority.ErrRegistryHalted) {
		t.Fatalf("registry admission after same-revision halt = %v, want ErrRegistryHalted", err)
	}
	caseRequest := testCase("case-after-same-revision-halt", "edge-a", 7, "after-same-revision-halt")
	caseRequest.RegistryRevision = current.Revision
	caseRequest.RegistryHash = current.Commitment
	if _, err := store.CommitCase(context.Background(), caseRequest); !errors.Is(err, authority.ErrRegistryHalted) {
		t.Fatalf("case admission after same-revision halt = %v, want ErrRegistryHalted", err)
	}
	var registries, audits, revisions, cases, outbox int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_registries`).Scan(&registries); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_audit`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_revisions`).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_cases`).Scan(&cases); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_outbox`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if registries != 1 || audits != 1 || revisions != 1 || cases != 0 || outbox != 0 {
		t.Fatalf("same-revision halt persistence = registries:%d audits:%d revisions:%d cases:%d outbox:%d, want 1/1/1/0/0", registries, audits, revisions, cases, outbox)
	}
}

func TestStoreHistoricalRegistryRollbackHaltsAllAdmissions(t *testing.T) {
	store, pool := newIntegrationStore(t)
	historical := testRegistry(12, "rollback-historical", "")
	if _, err := store.CommitRegistry(context.Background(), historical); err != nil {
		t.Fatal(err)
	}
	current := testRegistry(13, "rollback-current", historical.Commitment)
	if _, err := store.CommitRegistry(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitRegistry(context.Background(), historical); !errors.Is(err, authority.ErrRegistryRollback) {
		t.Fatalf("exact historical rollback error = %v, want ErrRegistryRollback", err)
	}
	head, err := store.CurrentRegistryHead(context.Background(), current.TenantID)
	if err != nil || !head.Halted || head.HaltReason != "registry revision rollback" || head.Revision != current.Revision || head.Commitment != current.Commitment {
		t.Fatalf("rollback head = %#v, %v", head, err)
	}
	if _, err := store.CommitRegistry(context.Background(), testRegistry(14, "rollback-after-halt", current.Commitment)); !errors.Is(err, authority.ErrRegistryHalted) {
		t.Fatalf("registry admission after rollback halt = %v, want ErrRegistryHalted", err)
	}
	caseRequest := testCase("case-after-rollback-halt", "edge-a", 7, "after-rollback-halt")
	caseRequest.RegistryRevision = current.Revision
	caseRequest.RegistryHash = current.Commitment
	if _, err := store.CommitCase(context.Background(), caseRequest); !errors.Is(err, authority.ErrRegistryHalted) {
		t.Fatalf("case admission after rollback halt = %v, want ErrRegistryHalted", err)
	}
	var registries, audits, revisions, cases, outbox int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_registries`).Scan(&registries); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_audit`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_revisions`).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_cases`).Scan(&cases); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_outbox`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if registries != 2 || audits != 2 || revisions != 2 || cases != 0 || outbox != 0 {
		t.Fatalf("rollback halt persistence = registries:%d audits:%d revisions:%d cases:%d outbox:%d, want 2/2/2/0/0", registries, audits, revisions, cases, outbox)
	}
}

func TestStoreRegistryHaltRejectsAdviceAdmission(t *testing.T) {
	store, pool := newCaseIntegrationStore(t)
	caseRequest := testCase("case-before-registry-halt", "edge-a", 7, "before-registry-halt")
	if _, err := store.CommitCase(context.Background(), caseRequest); err != nil {
		t.Fatal(err)
	}
	conflict := testRegistry(12, "a", "")
	conflict.Raw = []byte(`{"registry":"conflicting-evidence"}`)
	if _, err := store.CommitRegistry(context.Background(), conflict); !errors.Is(err, authority.ErrRegistryEquivocation) {
		t.Fatalf("same-revision conflicting evidence error = %v, want ErrRegistryEquivocation", err)
	}
	if _, err := store.CommitAdvice(context.Background(), testAdvice(caseRequest, "advice-after-registry-halt", "after-registry-halt")); !errors.Is(err, authority.ErrRegistryHalted) {
		t.Fatalf("advice admission after registry halt = %v, want ErrRegistryHalted", err)
	}
	var adviceCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_advice`).Scan(&adviceCount); err != nil {
		t.Fatal(err)
	}
	if adviceCount != 0 {
		t.Fatalf("advice rows after registry halt = %d, want 0", adviceCount)
	}
}

func TestStoreRegistryHaltPreservesExactAdviceRetry(t *testing.T) {
	store, pool := newCaseIntegrationStore(t)
	caseRequest := testCase("case-advice-retry-after-registry-halt", "edge-a", 7, "advice-retry-after-registry-halt")
	if _, err := store.CommitCase(context.Background(), caseRequest); err != nil {
		t.Fatal(err)
	}
	committed := testAdvice(caseRequest, "advice-before-registry-halt", "before-registry-halt")
	first, err := store.CommitAdvice(context.Background(), committed)
	if err != nil {
		t.Fatal(err)
	}

	conflict := testRegistry(12, "a", "")
	conflict.Raw = []byte(`{"registry":"conflicting-evidence"}`)
	if _, err := store.CommitRegistry(context.Background(), conflict); !errors.Is(err, authority.ErrRegistryEquivocation) {
		t.Fatalf("same-revision conflicting evidence error = %v, want ErrRegistryEquivocation", err)
	}

	retry, err := store.CommitAdvice(context.Background(), committed)
	if err != nil || retry != first {
		t.Fatalf("exact advice retry after registry halt = %#v, %v; want original %#v", retry, err, first)
	}
	if _, err := store.CommitAdvice(context.Background(), testAdvice(caseRequest, "advice-after-registry-halt", "after-registry-halt")); !errors.Is(err, authority.ErrRegistryHalted) {
		t.Fatalf("new advice after registry halt = %v, want ErrRegistryHalted", err)
	}
	var adviceCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_advice`).Scan(&adviceCount); err != nil {
		t.Fatal(err)
	}
	if adviceCount != 1 {
		t.Fatalf("advice rows after registry halt = %d, want 1", adviceCount)
	}
}

func TestStoreRegistryRejectsEdgeGenerationRollbackAtomically(t *testing.T) {
	store, pool := newIntegrationStore(t)
	initial := testRegistry(12, "generation-initial", "")
	initial.Edges = map[string]authority.RegistryEdge{"edge-a": {PrincipalID: "edge-principal", Generation: 7}}
	if _, err := store.CommitRegistry(context.Background(), initial); err != nil {
		t.Fatal(err)
	}

	rollback := testRegistry(13, "generation-rollback", initial.Commitment)
	rollback.Edges = map[string]authority.RegistryEdge{"edge-a": {PrincipalID: "edge-principal", Generation: 6}}
	if _, err := store.CommitRegistry(context.Background(), rollback); !errors.Is(err, authority.ErrEdgeGenerationRollback) {
		t.Fatalf("generation rollback error = %v, want ErrEdgeGenerationRollback", err)
	}

	head, err := store.CurrentRegistryHead(context.Background(), initial.TenantID)
	if err != nil || head.Revision != initial.Revision || head.Commitment != initial.Commitment || head.Halted {
		t.Fatalf("head after rejected rollback = %#v, %v; want unchanged healthy initial head", head, err)
	}
	for _, query := range []string{
		"SELECT count(*) FROM authority_registries",
		"SELECT count(*) FROM authority_audit WHERE entity_kind = 'registry'",
		"SELECT count(*) FROM authority_revisions",
	} {
		var count int
		if err := pool.QueryRow(context.Background(), query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s after rejected rollback = %d, want 1", query, count)
		}
	}
	var generation, lastSeen int64
	if err := pool.QueryRow(context.Background(), `
SELECT highest_generation, last_seen_registry_revision
FROM authority_edge_generation_high_water
WHERE tenant_id = $1 AND edge_id = 'edge-a'`, initial.TenantID).Scan(&generation, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if generation != 7 || lastSeen != 12 {
		t.Fatalf("edge high-water after rejected rollback = (%d,%d), want (7,12)", generation, lastSeen)
	}
}

func TestStoreRegistryRequiresGenerationAdvanceAfterEdgeRemoval(t *testing.T) {
	store, _ := newIntegrationStore(t)
	initial := testRegistry(12, "tombstone-initial", "")
	initial.Edges = map[string]authority.RegistryEdge{"edge-a": {PrincipalID: "edge-principal", Generation: 7}}
	if _, err := store.CommitRegistry(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	removed := testRegistry(13, "tombstone-removed", initial.Commitment)
	removed.Edges = map[string]authority.RegistryEdge{}
	if _, err := store.CommitRegistry(context.Background(), removed); err != nil {
		t.Fatal(err)
	}
	staleReturn := testRegistry(14, "tombstone-stale-return", removed.Commitment)
	staleReturn.Edges = map[string]authority.RegistryEdge{"edge-a": {PrincipalID: "edge-principal", Generation: 7}}
	if _, err := store.CommitRegistry(context.Background(), staleReturn); !errors.Is(err, authority.ErrEdgeGenerationRollback) {
		t.Fatalf("same-generation return error = %v, want ErrEdgeGenerationRollback", err)
	}
	advancedReturn := testRegistry(14, "tombstone-advanced-return", removed.Commitment)
	advancedReturn.Edges = map[string]authority.RegistryEdge{"edge-a": {PrincipalID: "edge-principal", Generation: 8}}
	if _, err := store.CommitRegistry(context.Background(), advancedReturn); err != nil {
		t.Fatalf("advanced generation return: %v", err)
	}
}

func TestStoreRegistryRequiresGenerationAdvanceForPrincipalReplacement(t *testing.T) {
	store, _ := newIntegrationStore(t)
	initial := testRegistry(12, "principal-initial", "")
	if _, err := store.CommitRegistry(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	replacement := testRegistry(13, "principal-replacement", initial.Commitment)
	replacement.Edges = map[string]authority.RegistryEdge{
		"edge-a": {PrincipalID: "replacement-principal", Generation: 7},
	}
	if _, err := store.CommitRegistry(context.Background(), replacement); !errors.Is(err, authority.ErrEdgeGenerationRollback) {
		t.Fatalf("same-generation principal replacement error = %v, want ErrEdgeGenerationRollback", err)
	}
	replacement.Edges["edge-a"] = authority.RegistryEdge{PrincipalID: "replacement-principal", Generation: 8}
	if _, err := store.CommitRegistry(context.Background(), replacement); err != nil {
		t.Fatalf("advanced principal replacement: %v", err)
	}
}

func TestStoreEdgeDeliveryReadRequiresCurrentRegistryIdentity(t *testing.T) {
	store, _ := newCaseIntegrationStore(t)
	request := testCase("case-stale-reconciliation", "edge-a", 7, "stale-reconciliation")
	if _, err := store.CommitCase(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	query := authority.EdgeDeliveryQuery{
		TenantID: request.TenantID, EdgeID: request.IssuerEdgeID,
		PrincipalID: "edge-principal", EdgeGeneration: request.IssuerEdgeGeneration, Limit: 10,
	}
	if page, err := store.ListEdgeDeliveries(context.Background(), query); err != nil || len(page.Deliveries) == 0 {
		t.Fatalf("active edge read = %#v, %v", page, err)
	}

	removed := testRegistry(13, "stale-reconciliation-removed", request.RegistryHash)
	removed.Edges = map[string]authority.RegistryEdge{}
	if _, err := store.CommitRegistry(context.Background(), removed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListEdgeDeliveries(context.Background(), query); !errors.Is(err, authority.ErrEdgeNotActive) {
		t.Fatalf("removed edge read error = %v, want ErrEdgeNotActive", err)
	}

	replacement := testRegistry(14, "stale-reconciliation-replacement", removed.Commitment)
	replacement.Edges = map[string]authority.RegistryEdge{
		"edge-a": {PrincipalID: "edge-principal", Generation: 8},
	}
	if _, err := store.CommitRegistry(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListEdgeDeliveries(context.Background(), query); !errors.Is(err, authority.ErrEdgeNotActive) {
		t.Fatalf("old generation after reenrollment error = %v, want ErrEdgeNotActive", err)
	}
	query.EdgeGeneration = 8
	if _, err := store.ListEdgeDeliveries(context.Background(), query); err != nil {
		t.Fatalf("current replacement generation read: %v", err)
	}
}

func TestStoreConcurrentSignedRegistryChainNeverFalseHalts(t *testing.T) {
	store, _ := newIntegrationStore(t)
	initial := testRegistry(12, "concurrent-chain-initial", "")
	if _, err := store.CommitRegistry(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	next := testRegistry(13, "concurrent-chain-next", initial.Commitment)
	afterNext := testRegistry(14, "concurrent-chain-after-next", next.Commitment)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, request := range []authority.CommitRegistryRequest{next, afterNext} {
		request := request
		go func() {
			<-start
			_, err := store.CommitRegistry(context.Background(), request)
			results <- err
		}()
	}
	close(start)
	errs := []error{<-results, <-results}
	for _, err := range errs {
		if err != nil && !errors.Is(err, authority.ErrRegistryRevisionSequence) {
			t.Fatalf("concurrent signed-chain error = %v, want success or retryable revision sequence", err)
		}
	}
	head, err := store.CurrentRegistryHead(context.Background(), initial.TenantID)
	if err != nil || head.Halted {
		t.Fatalf("head after concurrent signed-chain submissions = %#v, %v; must remain healthy", head, err)
	}
	if head.Revision == next.Revision {
		if _, err := store.CommitRegistry(context.Background(), afterNext); err != nil {
			t.Fatalf("retry signed successor: %v", err)
		}
	}
	head, err = store.CurrentRegistryHead(context.Background(), initial.TenantID)
	if err != nil || head.Revision != afterNext.Revision || head.Commitment != afterNext.Commitment || head.Halted {
		t.Fatalf("final signed-chain head = %#v, %v; want revision 14 healthy", head, err)
	}
}

func TestStoreConcurrentFinalizationLeavesExactlyOneFinalAdvice(t *testing.T) {
	store, pool := newCaseIntegrationStore(t)
	caseRequest := testCase("case-concurrent", "edge-a", 7, "concurrent")
	if _, err := store.CommitCase(context.Background(), caseRequest); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, request := range []authority.CommitAdviceRequest{
		testAdvice(caseRequest, "advice-concurrent-a", "concurrent-a"),
		testAdvice(caseRequest, "advice-concurrent-b", "concurrent-b"),
	} {
		request := request
		go func() {
			<-start
			_, err := store.CommitAdvice(context.Background(), request)
			results <- err
		}()
	}
	close(start)
	var successes, finals int
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, authority.ErrFinalAdviceAlreadySet) {
			finals++
		} else {
			t.Fatalf("concurrent finalization error = %v", err)
		}
	}
	if successes != 1 || finals != 1 {
		t.Fatalf("concurrent finalization outcomes = success:%d final:%d", successes, finals)
	}
	var adviceCount, deliveryCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_advice WHERE case_id = 'case-concurrent'`).Scan(&adviceCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM authority_edge_deliveries WHERE case_id = 'case-concurrent'`).Scan(&deliveryCount); err != nil {
		t.Fatal(err)
	}
	if adviceCount != 1 || deliveryCount != 2 {
		t.Fatalf("concurrent persisted rows = advice:%d deliveries:%d, want 1/2", adviceCount, deliveryCount)
	}
}

func TestStoreRollsBackCaseWhenOutboxCannotBeWritten(t *testing.T) {
	store, pool := newCaseIntegrationStore(t)
	if _, err := pool.Exec(context.Background(), `ALTER TABLE authority_outbox ADD CONSTRAINT fail_authority_outbox CHECK (FALSE) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitCase(context.Background(), testCase("case-rollback", "edge-a", 7, "rollback")); err == nil {
		t.Fatal("CommitCase unexpectedly succeeded with a rejecting outbox")
	}
	for _, query := range []string{
		"SELECT count(*) FROM authority_cases WHERE case_id = 'case-rollback'",
		"SELECT count(*) FROM authority_audit WHERE entity_kind = 'case' AND entity_id = 'case-rollback'",
		"SELECT count(*) FROM authority_outbox WHERE event_kind = 'case' AND entity_id = 'case-rollback'",
		"SELECT count(*) FROM authority_edge_deliveries WHERE case_id = 'case-rollback'",
	} {
		var count int
		if err := pool.QueryRow(context.Background(), query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s after failed commit = %d, want 0", query, count)
		}
	}
}

func TestStoreOutboxClaimEnrichesRoutesAndFencesClosure(t *testing.T) {
	store, _ := newCaseIntegrationStore(t)
	request := testCase("case-outbox", "edge/a@b", 7, "outbox")
	if _, err := store.CommitCase(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	items, err := store.Claim(context.Background(), "worker-a", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var domain, edge *deliveryoutbox.Item
	for index := range items {
		item := &items[index]
		if item.EventKind != deliveryoutbox.EventCase || string(item.Raw) != string(request.Raw) {
			continue
		}
		switch item.DestinationKind {
		case deliveryoutbox.DestinationDomainDispatch:
			domain = item
		case deliveryoutbox.DestinationEdgeDelivery:
			edge = item
		}
	}
	if domain == nil || edge == nil ||
		domain.DomainID != request.Domain ||
		edge.EdgeID != request.IssuerEdgeID ||
		edge.EdgeGeneration != request.IssuerEdgeGeneration ||
		edge.DeliverySequence != 1 {
		t.Fatalf("claimed route items = %#v", items)
	}
	if err := store.MarkPublished(context.Background(), edge.ID, "wrong-token"); !errors.Is(err, ErrStaleOutboxLease) {
		t.Fatalf("wrong-token mark error = %v", err)
	}
	if err := store.MarkPublished(context.Background(), edge.ID, edge.LeaseToken); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkPublished(context.Background(), edge.ID, edge.LeaseToken); !errors.Is(err, ErrStaleOutboxLease) {
		t.Fatalf("replayed mark error = %v", err)
	}
	if err := store.Release(context.Background(), domain.ID, "wrong-token", time.Now().Add(time.Minute), deliveryoutbox.ReasonPublishFailed); !errors.Is(err, ErrStaleOutboxLease) {
		t.Fatalf("wrong-token release error = %v", err)
	}
	if err := store.Release(context.Background(), domain.ID, domain.LeaseToken, time.Now().Add(-time.Second), deliveryoutbox.ReasonPublishFailed); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := store.Claim(context.Background(), "worker-b", 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range reclaimed {
		if item.ID == domain.ID {
			found = item.LeaseToken != domain.LeaseToken
		}
	}
	if !found {
		t.Fatalf("released domain item was not reclaimed with a new lease: %#v", reclaimed)
	}
}

func newCaseIntegrationStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	store, pool := newIntegrationStore(t)
	if _, err := store.CommitRegistry(context.Background(), testRegistry(12, "a", "")); err != nil {
		t.Fatalf("seed current registry: %v", err)
	}
	return store, pool
}

func newIntegrationStore(t *testing.T) (*Store, *pgxpool.Pool) {
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
	schema := fmt.Sprintf("authority_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path TO `+schema)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	up, err := migrations.FS.ReadFile("0001_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(up), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("apply authority migration: %v", err)
		}
	}
	store, err := New(pool, "postgres-test")
	if err != nil {
		t.Fatal(err)
	}
	return store, pool
}

func testCase(caseID, edgeID string, generation int64, marker string) authority.CommitCaseRequest {
	return authority.CommitCaseRequest{
		TenantID: "tenant-a", CaseID: caseID, EnvelopeID: "case-envelope-" + marker,
		Commitment: commitment("case-" + marker), Raw: []byte(`{"case":"` + marker + `"}`),
		Domain: "support", IssuerEdgeID: edgeID, IssuerEdgeGeneration: generation,
		RoutingEpoch: 7, RegistryRevision: 12, RegistryHash: commitment("registry-a"), ExpiresAt: time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC),
	}
}

func testAdvice(c authority.CommitCaseRequest, envelopeID, marker string) authority.CommitAdviceRequest {
	return authority.CommitAdviceRequest{
		TenantID: c.TenantID, CaseID: c.CaseID, EnvelopeID: envelopeID,
		CaseCommitment: c.Commitment, Commitment: commitment("advice-" + marker), Raw: []byte(`{"advice":"` + marker + `"}`),
		RoutingEpoch: c.RoutingEpoch, RegistryRevision: c.RegistryRevision, RegistryHash: c.RegistryHash,
	}
}

func testRegistry(revision int64, marker, previous string) authority.CommitRegistryRequest {
	return authority.CommitRegistryRequest{
		TenantID: "tenant-a", Revision: revision, EnvelopeID: "registry-envelope-" + marker,
		Commitment: commitment("registry-" + marker), Raw: []byte(`{"registry":"` + marker + `"}`), RoutingEpoch: 7, PreviousCommitment: previous,
		Edges: map[string]authority.RegistryEdge{"edge-a": {PrincipalID: "edge-principal", Generation: 7}},
	}
}

func commitment(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}
