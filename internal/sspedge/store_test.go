package sspedge

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/avivsinai/snagline/internal/deliverystream"
)

func TestProjectionDatabaseIsOpaqueWithoutItsDatabaseKey(t *testing.T) {
	dir, key := privateStorePaths(t)
	path := filepath.Join(dir, "edge.db")
	db, err := Open(context.Background(), OpenOptions{Path: path, KeyFilePath: key, Tenant: "tenant/a.*"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ApplyVerified(
		context.Background(),
		testDelivery(testIdentity(), 1, "known-raw-wire"),
		VerdictAccepted,
		"",
		caseProjection(time.Now().UTC(), testIdentity(), "domain/known-metadata.*", "case/known-metadata.*"),
		time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range [][]byte{
		[]byte("SQLite format 3"),
		[]byte("ssp_edge_delivery_state"),
		[]byte("domain/known-metadata.*"),
		[]byte("case/known-metadata.*"),
	} {
		if bytes.Contains(raw, plaintext) {
			t.Fatalf("database file disclosed plaintext %q", plaintext)
		}
	}

	ordinary, err := sql.Open(registeredSQLiteDriver(t), "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	var tableCount int
	if err := ordinary.QueryRow(`SELECT COUNT(*) FROM sqlite_master`).Scan(&tableCount); err == nil {
		t.Fatalf("ordinary unkeyed SQLite read encrypted schema with %d tables", tableCount)
	}
}

func TestOpenRejectsWrongDatabaseKey(t *testing.T) {
	dir, key := privateStorePaths(t)
	path := filepath.Join(dir, "edge.db")
	db, err := Open(context.Background(), OpenOptions{Path: path, KeyFilePath: key, Tenant: "tenant/a.*"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	wrongKey := filepath.Join(dir, "wrong.key")
	raw := make([]byte, StoreKeyLength)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrongKey, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(context.Background(), OpenOptions{Path: path, KeyFilePath: wrongKey, Tenant: "tenant/a.*"}); err == nil {
		_ = reopened.Close()
		t.Fatal("Open accepted a wrong database key")
	}
}

func TestProjectionDatabaseUsesDeleteJournalWithoutPersistentSidecars(t *testing.T) {
	dir, key := privateStorePaths(t)
	path := filepath.Join(dir, "edge.db")
	db, err := Open(context.Background(), OpenOptions{Path: path, KeyFilePath: key, Tenant: "tenant/a.*"})
	if err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err := db.SQL().QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "delete" {
		t.Fatalf("journal_mode=%q, want delete", journalMode)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("persistent sidecar %q exists while store is open: %v", path+suffix, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			t.Fatalf("persistent sidecar %q exists after close: %v", path+suffix, err)
		}
	}
}

func TestStoreKeyDerivationSeparatesDatabaseAndFieldKeys(t *testing.T) {
	root := bytes.Repeat([]byte{0x42}, StoreKeyLength)
	databaseKey, fieldKey, err := deriveStoreKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(databaseKey)
	defer clear(fieldKey)
	if len(databaseKey) != StoreKeyLength || len(fieldKey) != StoreKeyLength {
		t.Fatalf("derived key lengths = (%d, %d)", len(databaseKey), len(fieldKey))
	}
	if bytes.Equal(databaseKey, root) || bytes.Equal(fieldKey, root) {
		t.Fatal("derived key reused the root store key")
	}
	if bytes.Equal(databaseKey, fieldKey) {
		t.Fatal("database and field encryption keys are identical")
	}
}

func TestPinnedSQLCipherRuntime(t *testing.T) {
	db := newTestDB(t)
	var cipherVersion, sqliteVersion, provider string
	var cipherStatus int
	if err := db.SQL().QueryRow(`PRAGMA cipher_version`).Scan(&cipherVersion); err != nil {
		t.Fatal(err)
	}
	if err := db.SQL().QueryRow(`SELECT sqlite_version()`).Scan(&sqliteVersion); err != nil {
		t.Fatal(err)
	}
	if err := db.SQL().QueryRow(`PRAGMA cipher_provider`).Scan(&provider); err != nil {
		t.Fatal(err)
	}
	if err := db.SQL().QueryRow(`PRAGMA cipher_status`).Scan(&cipherStatus); err != nil {
		t.Fatal(err)
	}
	if cipherVersion != requiredSQLCipherVersion {
		t.Fatalf("cipher_version=%q, want %q", cipherVersion, requiredSQLCipherVersion)
	}
	if sqliteVersion != "3.51.3" {
		t.Fatalf("sqlite_version()=%q, want pinned SQLCipher baseline 3.51.3", sqliteVersion)
	}
	if !strings.HasPrefix(strings.ToLower(provider), "openssl") || cipherStatus != 1 {
		t.Fatalf("cipher provider/status = (%q, %d)", provider, cipherStatus)
	}
}

func TestCloseDestroysRetainedDerivedDatabaseKey(t *testing.T) {
	dir, key := privateStorePaths(t)
	db, err := Open(context.Background(), OpenOptions{
		Path: filepath.Join(dir, "edge.db"), KeyFilePath: key, Tenant: "tenant/a.*",
	})
	if err != nil {
		t.Fatal(err)
	}
	connector := db.connector
	if len(connector.key) != StoreKeyLength || connector.closed {
		t.Fatal("connector did not retain the derived database key while open")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if len(connector.key) != 0 || !connector.closed {
		t.Fatal("connector retained the derived database key after Close")
	}
	if _, err := connector.Connect(context.Background()); err == nil {
		t.Fatal("closed connector reopened the database")
	}
}

func registeredSQLiteDriver(t *testing.T) string {
	t.Helper()
	drivers := sql.Drivers()
	for _, name := range []string{"sqlite3", "sqlite"} {
		if slices.Contains(drivers, name) {
			return name
		}
	}
	t.Fatalf("no SQLite database/sql driver registered: %v", drivers)
	return ""
}

func TestApplyVerifiedRequiresContiguousAuthoritativeDeliverySequence(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	id := testIdentity()

	gap := testDelivery(id, 2, "case-2")
	got, err := db.ApplyVerified(context.Background(), gap, VerdictAccepted, "", caseProjection(now, id, "domain/a.*", "case-2"), now)
	if err != nil || got != ApplyReconciliationRequired {
		t.Fatalf("gap apply = (%q, %v)", got, err)
	}
	state, err := db.DeliveryState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != DeliveryModeReconciliationRequired || state.LastContiguousSeq != 0 || state.HighWatermark != 2 {
		t.Fatalf("gap state = %+v", state)
	}
	if count(t, db, "ssp_edge_cases") != 0 {
		t.Fatal("gap projected a case")
	}
}

func TestCompleteReconciliationCannotLowerPersistedHighWatermark(t *testing.T) {
	db := newTestDB(t)
	id := testIdentity()
	now := time.Now().UTC()
	if err := db.RequireReconciliation(context.Background(), id, 2, "gap", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.applyReconciled(context.Background(), testDelivery(id, 1, "case"), VerdictAccepted, "", caseProjection(now, id, "domain/a.*", "case"), now); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteReconciliation(context.Background(), id, 1, 1, now); err == nil {
		t.Fatal("reconciliation lowered the persisted high watermark")
	}
	state, err := db.DeliveryState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode != DeliveryModeReconciliationRequired || state.LastContiguousSeq != 1 || state.HighWatermark != 2 {
		t.Fatalf("failed completion changed state: %+v", state)
	}
}

func TestApplyVerifiedDuplicateExactAuthoritativeDeliveryIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	id := testIdentity()
	delivery := testDelivery(id, 1, "case-1")
	p := caseProjection(now, id, "domain/a.*", "case-1")
	if got, err := db.ApplyVerified(context.Background(), delivery, VerdictAccepted, "", p, now); err != nil || got != ApplyAccepted {
		t.Fatalf("first=(%q,%v)", got, err)
	}
	if got, err := db.ApplyVerified(context.Background(), delivery, VerdictAccepted, "", p, now); err != nil || got != ApplyDuplicate {
		t.Fatalf("duplicate=(%q,%v)", got, err)
	}
	state, _ := db.DeliveryState(context.Background(), id)
	if state.LastContiguousSeq != 1 {
		t.Fatalf("state=%+v", state)
	}
}

func TestApplyVerifiedRejectsConflictingBytesForAuthoritativeDelivery(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	id := testIdentity()
	delivery := testDelivery(id, 1, "case-1")
	p := caseProjection(now, id, "domain/a.*", "case-1")
	if got, err := db.ApplyVerified(context.Background(), delivery, VerdictAccepted, "", p, now); err != nil || got != ApplyAccepted {
		t.Fatalf("first=(%q,%v)", got, err)
	}
	delivery.Raw = []byte("different-authoritative-bytes")
	if _, err := db.ApplyVerified(context.Background(), delivery, VerdictAccepted, "", p, now); err == nil {
		t.Fatal("conflicting bytes accepted for the same authoritative delivery identity")
	}
	state, err := db.DeliveryState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastContiguousSeq != 1 || state.HighWatermark != 1 || state.Mode != DeliveryModeActive {
		t.Fatalf("conflict changed delivery state: %+v", state)
	}
}

func TestAdviceRequiresExactCaseGenerationAndBinding(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().UTC()
	id := testIdentity()
	caseP := caseProjection(now, id, "domain/a.*", "case-1")
	if _, err := db.ApplyVerified(context.Background(), testDelivery(id, 1, "case"), VerdictAccepted, "", caseP, now); err != nil {
		t.Fatal(err)
	}
	advice := adviceProjection(now, id, caseP.Commitment)
	advice.Advice.IssuerEdgeGeneration++
	if _, err := db.ApplyVerified(context.Background(), testDelivery(id, 2, "bad-advice"), VerdictAccepted, "", advice, now); err == nil {
		t.Fatal("advice with wrong edge generation accepted")
	}
	state, _ := db.DeliveryState(context.Background(), id)
	if state.LastContiguousSeq != 1 {
		t.Fatalf("failed advice advanced state: %+v", state)
	}
	advice.Advice.IssuerEdgeGeneration = id.Generation
	if got, err := db.ApplyVerified(context.Background(), testDelivery(id, 2, "advice"), VerdictAccepted, "", advice, now); err != nil || got != ApplyAccepted {
		t.Fatalf("advice=(%q,%v)", got, err)
	}
	if count(t, db, "ssp_edge_front_outbox") != 2 {
		t.Fatal("front outboxes not atomic")
	}
}

func TestEdgeRoutingTokenIncludesPositiveGeneration(t *testing.T) {
	if EdgeRoutingToken("edge/a.*", 1) == EdgeRoutingToken("edge/a.*", 2) {
		t.Fatal("generation omitted from route token")
	}
	if EdgeRoutingToken("edge/a.*", 1) == RoutingToken("edge/a.*") {
		t.Fatal("tuple token collapsed to old edge-only token")
	}
	if got, want := EdgeRoutingToken("edge/a.*", 7), deliverystream.EdgeToken("edge/a.*", 7); got != want {
		t.Fatalf("edge token=%q want live journal token %q", got, want)
	}
}

func TestOpenRejectsSymlinkDatabase(t *testing.T) {
	dir, key := privateStorePaths(t)
	target := filepath.Join(dir, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "edge.db")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), OpenOptions{Path: path, KeyFilePath: key, Tenant: "tenant/a.*"}); err == nil {
		t.Fatal("Open accepted a symlink database path")
	}
}

func TestOpenRejectsGroupOrWorldReadableDatabase(t *testing.T) {
	dir, key := privateStorePaths(t)
	path := filepath.Join(dir, "edge.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), OpenOptions{Path: path, KeyFilePath: key, Tenant: "tenant/a.*"}); err == nil {
		t.Fatal("Open accepted a group/world-readable database")
	}
}

func newTestDB(t *testing.T) *DB {
	t.Helper()
	dir, key := privateStorePaths(t)
	db, err := Open(context.Background(), OpenOptions{Path: filepath.Join(dir, "edge.db"), KeyFilePath: key, Tenant: "tenant/a.*"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func privateStorePaths(t *testing.T) (dir, key string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key = filepath.Join(dir, "edge.key")
	raw := make([]byte, StoreKeyLength)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, key
}
func count(t *testing.T, db *DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func commitment(last string) string {
	return "sha256:" + "000000000000000000000000000000000000000000000000000000000000000" + last
}
func testIdentity() EdgeIdentity {
	return EdgeIdentity{TenantID: "tenant/a.*", EdgeID: "edge/a.*", Generation: 3}
}
func testDelivery(id EdgeIdentity, seq int64, raw string) JournalDelivery {
	return JournalDelivery{Stream: "SNAGLINE_SSP_V1", Sequence: uint64(seq + 10), DeliverySeq: seq, TenantID: id.TenantID, EdgeID: id.EdgeID, EdgeGeneration: id.Generation, Subject: "opaque", Raw: []byte(raw)}
}
func caseProjection(now time.Time, id EdgeIdentity, domain, envelope string) *VerifiedProjection {
	return &VerifiedProjection{EnvelopeID: envelope, Commitment: commitment("a"), Family: FamilyCase, Case: &Case{CaseID: "case/a.*", IssuerEdgeID: id.EdgeID, IssuerEdgeGeneration: id.Generation, Domain: domain, RouteKind: "domain", RouteToken: RoutingToken(domain), SourceToken: EdgeRoutingToken(id.EdgeID, id.Generation), RoutingEpoch: 1, RegistryRevision: 1, RegistryHash: commitment("e"), Summary: "private", ContextManifest: commitment("c"), ExpiresAt: now.Add(time.Hour)}}
}
func adviceProjection(now time.Time, id EdgeIdentity, caseCommitment string) *VerifiedProjection {
	return &VerifiedProjection{EnvelopeID: "advice/a.*", Commitment: commitment("b"), Family: FamilyAdvice, Advice: &Advice{AdviceID: "advice/a.*", CaseID: "case/a.*", CaseCommitment: caseCommitment, IssuerEdgeID: id.EdgeID, IssuerEdgeGeneration: id.Generation, RouteKind: "edge", RouteToken: EdgeRoutingToken(id.EdgeID, id.Generation), RoutingEpoch: 1, RegistryRevision: 1, RegistryHash: commitment("e"), Text: "inert", ExpiresAt: now.Add(time.Hour)}}
}
