// Package sspedge owns an edge's encrypted, replay-safe projection of the
// authoritative PostgreSQL SSP delivery log. JetStream is only an at-least-once
// carrier; its coordinates are evidence, never completeness authority.
package sspedge

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/avivsinai/snagline/internal/privatesqlite"
	sqlcipher "github.com/omnilium/go-sqlcipher"
	"golang.org/x/sys/unix"
)

const (
	StoreKeyLength           = 32
	requiredSQLCipherVersion = "4.14.0 community"
)

var storeKeyDerivationSalt = []byte("snagline/sspedge/store-keys/v1")

type OpenOptions struct{ Path, KeyFilePath, Tenant string }
type DB struct {
	sqlDB     *sql.DB
	connector *sqlCipherConnector
	dirFD     int
	key       cipher.AEAD
	tenant    string
	writeMu   sync.Mutex
}

type sqlCipherConnector struct {
	mu     sync.Mutex
	driver *sqlcipher.SQLiteDriver
	path   string
	key    []byte
	closed bool
}

func Open(ctx context.Context, opts OpenOptions) (*DB, error) {
	if !sqlcipherCGOAvailable {
		return nil, errors.New("sspedge: SQLCipher requires a CGO-enabled build")
	}
	if !filepath.IsAbs(opts.Path) || !filepath.IsAbs(opts.KeyFilePath) || opts.Tenant == "" {
		return nil, errors.New("sspedge: absolute path, key file, and tenant are required")
	}
	raw, err := readKeyFile(opts.KeyFilePath)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	databaseKey, fieldKey, err := deriveStoreKeys(raw)
	if err != nil {
		return nil, err
	}
	defer clear(databaseKey)
	defer clear(fieldKey)
	block, err := aes.NewCipher(fieldKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	namespace, err := privatesqlite.Open(opts.Path)
	if err != nil {
		return nil, err
	}
	connector := newSQLCipherConnector(namespace.Path, databaseKey)
	sqlDB := sql.OpenDB(connector)
	// The store's writer is serialized. A single connection keeps its
	// connection-scoped crash-safety pragmas from drifting.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	db := &DB{sqlDB: sqlDB, connector: connector, dirFD: namespace.DirFD, key: aead, tenant: opts.Tenant}
	if err := db.requireSQLCipher(ctx); err != nil {
		_ = sqlDB.Close()
		connector.destroy()
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	if err := db.configureDurability(ctx); err != nil {
		_ = sqlDB.Close()
		connector.destroy()
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	if err := db.init(ctx); err != nil {
		_ = sqlDB.Close()
		connector.destroy()
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	if err := db.requireCrashSafePragmas(); err != nil {
		_ = sqlDB.Close()
		connector.destroy()
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	if err := unix.Fsync(namespace.DirFD); err != nil {
		_ = sqlDB.Close()
		connector.destroy()
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	return db, nil
}

func deriveStoreKeys(root []byte) ([]byte, []byte, error) {
	databaseKey, err := hkdf.Key(sha256.New, root, storeKeyDerivationSalt, "sqlcipher-database-key", StoreKeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("sspedge: derive database key: %w", err)
	}
	fieldKey, err := hkdf.Key(sha256.New, root, storeKeyDerivationSalt, "field-aead-key", StoreKeyLength)
	if err != nil {
		clear(databaseKey)
		return nil, nil, fmt.Errorf("sspedge: derive field key: %w", err)
	}
	return databaseKey, fieldKey, nil
}

func newSQLCipherConnector(path string, databaseKey []byte) *sqlCipherConnector {
	return &sqlCipherConnector{
		driver: &sqlcipher.SQLiteDriver{},
		path:   path,
		key:    append([]byte(nil), databaseKey...),
	}
}

func (c *sqlCipherConnector) Connect(ctx context.Context) (driver.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.key) != StoreKeyLength {
		return nil, errors.New("sspedge: SQLCipher connector is closed")
	}
	dsn := &url.URL{Scheme: "file", Path: c.path}
	dsn.RawQuery = url.Values{
		"mode":                          {"rwc"},
		"_key":                          {"x'" + hex.EncodeToString(c.key) + "'"},
		"_cipher_plaintext_header_size": {"0"},
		"_journal_mode":                 {"DELETE"},
		"_synchronous":                  {"FULL"},
		"_foreign_keys":                 {"ON"},
		"_busy_timeout":                 {"5000"},
		"_secure_delete":                {"ON"},
		"_txlock":                       {"immediate"},
	}.Encode()
	// The driver applies and strips _key before the first page read. Keeping
	// the mutable derived key in this connector, rather than passing a DSN to
	// sql.Open, avoids retaining an immutable hex key in database/sql for the
	// pool lifetime while still allowing its sole connection to be recreated.
	return c.driver.Open(dsn.String())
}

func (c *sqlCipherConnector) Driver() driver.Driver { return c.driver }

func (c *sqlCipherConnector) destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.key)
	c.key = nil
	c.closed = true
}

func (d *DB) SQL() *sql.DB { return d.sqlDB }
func (d *DB) Close() error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	err := d.sqlDB.Close()
	d.connector.destroy()
	closeErr := unix.Close(d.dirFD)
	if err != nil {
		return err
	}
	return closeErr
}

func (d *DB) init(ctx context.Context) error {
	_, err := d.sqlDB.ExecContext(ctx, schema)
	return err
}

func (d *DB) requireSQLCipher(ctx context.Context) error {
	var version, provider string
	var status, plaintextHeaderSize, schemaCount int
	if err := d.sqlDB.QueryRowContext(ctx, `PRAGMA cipher_version`).Scan(&version); err != nil {
		return fmt.Errorf("sspedge: SQLCipher unavailable: %w", err)
	}
	if version != requiredSQLCipherVersion {
		return fmt.Errorf("sspedge: SQLCipher version %q, require %q", version, requiredSQLCipherVersion)
	}
	if err := d.sqlDB.QueryRowContext(ctx, `PRAGMA cipher_status`).Scan(&status); err != nil {
		return fmt.Errorf("sspedge: read SQLCipher status: %w", err)
	}
	if status != 1 {
		return errors.New("sspedge: SQLCipher encryption is not active")
	}
	if err := d.sqlDB.QueryRowContext(ctx, `PRAGMA cipher_provider`).Scan(&provider); err != nil {
		return fmt.Errorf("sspedge: read SQLCipher provider: %w", err)
	}
	if !strings.HasPrefix(strings.ToLower(provider), "openssl") {
		return fmt.Errorf("sspedge: unsupported SQLCipher provider %q", provider)
	}
	if err := d.sqlDB.QueryRowContext(ctx, `PRAGMA cipher_plaintext_header_size`).Scan(&plaintextHeaderSize); err != nil {
		return fmt.Errorf("sspedge: read SQLCipher plaintext header size: %w", err)
	}
	if plaintextHeaderSize != 0 {
		return fmt.Errorf("sspedge: SQLCipher plaintext header size is %d, require 0", plaintextHeaderSize)
	}
	// SQLCipher defers key validation until the first page read. Reading the
	// schema is therefore mandatory before any migration or write.
	if err := d.sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master`).Scan(&schemaCount); err != nil {
		return fmt.Errorf("sspedge: validate SQLCipher database key: %w", err)
	}
	return nil
}

func (d *DB) configureDurability(ctx context.Context) error {
	for _, pragma := range []string{
		`PRAGMA fullfsync = ON`,
		`PRAGMA checkpoint_fullfsync = ON`,
		`PRAGMA temp_store = MEMORY`,
		`PRAGMA cipher_memory_security = ON`,
	} {
		if _, err := d.sqlDB.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("sspedge: configure encrypted SQLite durability: %w", err)
		}
	}
	return nil
}

func (d *DB) requireCrashSafePragmas() error {
	var journal string
	var synchronous, fullfsync, checkpointFullfsync, tempStore int
	if err := d.sqlDB.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		return err
	}
	if err := d.sqlDB.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		return err
	}
	if err := d.sqlDB.QueryRow(`PRAGMA fullfsync`).Scan(&fullfsync); err != nil {
		return err
	}
	if err := d.sqlDB.QueryRow(`PRAGMA checkpoint_fullfsync`).Scan(&checkpointFullfsync); err != nil {
		return err
	}
	if err := d.sqlDB.QueryRow(`PRAGMA temp_store`).Scan(&tempStore); err != nil {
		return err
	}
	if journal != "delete" || synchronous != 2 || fullfsync != 1 || checkpointFullfsync != 1 || tempStore != 2 {
		return errors.New("sspedge: encrypted SQLite crash-safe durability is unavailable")
	}
	return nil
}

type Family string

const (
	FamilyCase   Family = "case"
	FamilyAdvice Family = "advice"
)

type Verdict string

const (
	VerdictAccepted    Verdict = "accepted"
	VerdictRejected    Verdict = "rejected"
	VerdictQuarantined Verdict = "quarantined"
)

type ApplyOutcome string

const (
	ApplyAccepted               ApplyOutcome = "accepted"
	ApplyRejected               ApplyOutcome = "rejected"
	ApplyQuarantined            ApplyOutcome = "quarantined"
	ApplyDuplicate              ApplyOutcome = "duplicate"
	ApplyReconciliationRequired ApplyOutcome = "reconciliation_required"
	// ApplyIdentityConflict records that the authoritative carrier presented
	// different bytes or subject for an already-recorded delivery sequence.
	// The generation halts visibly; only authority reconciliation may resume it.
	ApplyIdentityConflict ApplyOutcome = "identity_conflict"
)

type EdgeIdentity struct {
	TenantID, EdgeID string
	Generation       int64
}

func (i EdgeIdentity) validate() error {
	if i.TenantID == "" || i.EdgeID == "" || i.Generation <= 0 {
		return errors.New("sspedge: invalid edge identity")
	}
	return nil
}

type JournalDelivery struct {
	Stream           string
	Sequence         uint64 // Carrier sequence is evidence only, never completeness.
	DeliverySeq      int64
	TenantID, EdgeID string
	EdgeGeneration   int64
	Subject          string
	Raw              []byte
}
type Case struct {
	CaseID, IssuerEdgeID, Domain, Summary, ContextManifest string
	IssuerEdgeGeneration                                   int64
	RouteKind, RouteToken, SourceToken                     string
	RoutingEpoch, RegistryRevision                         int64
	RegistryHash                                           string
	ExpiresAt                                              time.Time
}
type Advice struct {
	AdviceID, CaseID, CaseCommitment, Text string
	IssuerEdgeID, RouteKind, RouteToken    string
	IssuerEdgeGeneration                   int64
	RoutingEpoch, RegistryRevision         int64
	RegistryHash                           string
	ExpiresAt                              time.Time
}
type VerifiedProjection struct {
	EnvelopeID, Commitment string
	Family                 Family
	Case                   *Case
	Advice                 *Advice
}

var sha256RE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var routingTokenRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type DeliveryMode string

const (
	DeliveryModeActive                 DeliveryMode = "active"
	DeliveryModeReconciliationRequired DeliveryMode = "reconciliation_required"
)

type GenerationDeliveryState struct {
	EdgeIdentity
	LastContiguousSeq, HighWatermark int64
	Mode                             DeliveryMode
	Reason                           string
}

func (d *DB) ApplyVerified(ctx context.Context, delivery JournalDelivery, verdict Verdict, reason string, p *VerifiedProjection, now time.Time) (ApplyOutcome, error) {
	return d.applyVerified(ctx, delivery, verdict, reason, p, now, false)
}
func (d *DB) applyReconciled(ctx context.Context, delivery JournalDelivery, verdict Verdict, reason string, p *VerifiedProjection, now time.Time) (ApplyOutcome, error) {
	return d.applyVerified(ctx, delivery, verdict, reason, p, now, true)
}
func (d *DB) applyVerified(ctx context.Context, delivery JournalDelivery, verdict Verdict, reason string, p *VerifiedProjection, now time.Time, allowReconciliation bool) (ApplyOutcome, error) {
	if err := validateDelivery(delivery, verdict, reason, p, now); err != nil {
		return "", err
	}
	identity := EdgeIdentity{TenantID: delivery.TenantID, EdgeID: delivery.EdgeID, Generation: delivery.EdgeGeneration}
	if delivery.TenantID != d.tenant {
		return "", errors.New("sspedge: delivery tenant does not own this store")
	}
	rawHash := hash(delivery.Raw)
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	state, exists, err := deliveryStateTx(ctx, tx, identity)
	if err != nil {
		return "", err
	}
	if !exists {
		state = GenerationDeliveryState{EdgeIdentity: identity, Mode: DeliveryModeActive}
	}
	if delivery.DeliverySeq <= state.LastContiguousSeq {
		var existing, subject string
		err = tx.QueryRowContext(ctx, `SELECT raw_sha256,subject FROM ssp_edge_deliveries WHERE tenant_id=? AND edge_id=? AND edge_generation=? AND delivery_seq=?`, identity.TenantID, identity.EdgeID, identity.Generation, delivery.DeliverySeq).Scan(&existing, &subject)
		if err == nil {
			if existing != rawHash || subject != delivery.Subject {
				return haltAndCommitTx(ctx, tx, state, delivery.DeliverySeq, "delivery_identity_conflict", now, ApplyIdentityConflict)
			}
			return ApplyDuplicate, tx.Commit()
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		return haltAndCommitTx(ctx, tx, state, delivery.DeliverySeq, "missing_committed_delivery", now, ApplyReconciliationRequired)
	}
	if delivery.DeliverySeq != state.LastContiguousSeq+1 || state.Mode == DeliveryModeReconciliationRequired && !allowReconciliation {
		return haltAndCommitTx(ctx, tx, state, delivery.DeliverySeq, "delivery_sequence_gap", now, ApplyReconciliationRequired)
	}
	var existing, existingSubject string
	err = tx.QueryRowContext(ctx, `SELECT raw_sha256,subject FROM ssp_edge_deliveries WHERE tenant_id=? AND edge_id=? AND edge_generation=? AND delivery_seq=?`, identity.TenantID, identity.EdgeID, identity.Generation, delivery.DeliverySeq).Scan(&existing, &existingSubject)
	if err == nil {
		if existing != rawHash || existingSubject != delivery.Subject {
			return haltAndCommitTx(ctx, tx, state, delivery.DeliverySeq, "delivery_identity_conflict", now, ApplyIdentityConflict)
		}
		if allowReconciliation {
			// The recorded row is the committed evidence for this sequence.
			// Authority reconciliation must advance a torn contiguous state
			// through the exact recorded row without reapplying its
			// projection, or the halt could never resume.
			if err := advanceDeliveryStateTx(ctx, tx, identity, exists, delivery.DeliverySeq, now); err != nil {
				return "", err
			}
		}
		return ApplyDuplicate, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	outcome := ApplyOutcome(verdict)
	if verdict == VerdictAccepted {
		state, err := d.claimIdentity(ctx, tx, p.EnvelopeID, p.Commitment, delivery, now)
		if err != nil {
			return "", err
		}
		if state == ApplyQuarantined {
			outcome = state
			verdict = VerdictQuarantined
			reason = "semantic_commitment_conflict"
		} else if state == ApplyDuplicate {
			outcome = state
		} else if err := d.persistProjection(ctx, tx, p, now); err != nil {
			return "", err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ssp_edge_deliveries (tenant_id,edge_id,edge_generation,delivery_seq,carrier_stream,carrier_sequence,subject,raw_sha256,envelope_id,family,verdict,reason,received_at,committed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, identity.TenantID, identity.EdgeID, identity.Generation, delivery.DeliverySeq, delivery.Stream, delivery.Sequence, delivery.Subject, rawHash, nullable(p, "id"), nullable(p, "family"), verdict, reason, sqlTime(now), sqlTime(now))
	if err != nil {
		return "", err
	}
	if err := advanceDeliveryStateTx(ctx, tx, identity, exists, delivery.DeliverySeq, now); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return outcome, nil
}

func deliveryStateTx(ctx context.Context, tx *sql.Tx, id EdgeIdentity) (GenerationDeliveryState, bool, error) {
	var s GenerationDeliveryState
	s.EdgeIdentity = id
	err := tx.QueryRowContext(ctx, `SELECT last_contiguous_seq,high_watermark,mode,reason FROM ssp_edge_delivery_state WHERE tenant_id=? AND edge_id=? AND edge_generation=?`, id.TenantID, id.EdgeID, id.Generation).Scan(&s.LastContiguousSeq, &s.HighWatermark, &s.Mode, &s.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return s, false, nil
	}
	return s, err == nil, err
}
func requireReconciliationTx(ctx context.Context, tx *sql.Tx, state GenerationDeliveryState, observed int64, reason string, now time.Time) error {
	high := state.HighWatermark
	if observed > high {
		high = observed
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO ssp_edge_delivery_state (tenant_id,edge_id,edge_generation,last_contiguous_seq,high_watermark,mode,reason,updated_at) VALUES (?,?,?,?,?,'reconciliation_required',?,?) ON CONFLICT(tenant_id,edge_id,edge_generation) DO UPDATE SET high_watermark=MAX(high_watermark,excluded.high_watermark),mode='reconciliation_required',reason=excluded.reason,updated_at=excluded.updated_at`, state.TenantID, state.EdgeID, state.Generation, state.LastContiguousSeq, high, reason, sqlTime(now))
	return err
}

// haltAndCommitTx durably records the visible halt reason, commits, and maps
// the halt to its apply outcome. Every halting branch of applyVerified goes
// through here so the halt semantics cannot drift between branches.
func haltAndCommitTx(ctx context.Context, tx *sql.Tx, state GenerationDeliveryState, observed int64, reason string, now time.Time, outcome ApplyOutcome) (ApplyOutcome, error) {
	if err := requireReconciliationTx(ctx, tx, state, observed, reason, now); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return outcome, nil
}

// advanceDeliveryStateTx moves the contiguous delivery counter through seq
// without touching mode or reason; resume decisions stay with reconciliation.
func advanceDeliveryStateTx(ctx context.Context, tx *sql.Tx, id EdgeIdentity, exists bool, seq int64, now time.Time) error {
	if !exists {
		_, err := tx.ExecContext(ctx, `INSERT INTO ssp_edge_delivery_state (tenant_id,edge_id,edge_generation,last_contiguous_seq,high_watermark,mode,reason,updated_at) VALUES (?,?,?,?,?,'active','',?)`, id.TenantID, id.EdgeID, id.Generation, seq, seq, sqlTime(now))
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE ssp_edge_delivery_state SET last_contiguous_seq=?,high_watermark=MAX(high_watermark,?),updated_at=? WHERE tenant_id=? AND edge_id=? AND edge_generation=?`, seq, seq, sqlTime(now), id.TenantID, id.EdgeID, id.Generation)
	return err
}
func (d *DB) RequireReconciliation(ctx context.Context, id EdgeIdentity, observed int64, reason string, now time.Time) error {
	if err := id.validate(); err != nil {
		return err
	}
	if observed < 0 || reason == "" || now.IsZero() {
		return errors.New("sspedge: invalid reconciliation requirement")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, _, err := deliveryStateTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if err := requireReconciliationTx(ctx, tx, state, observed, reason, now); err != nil {
		return err
	}
	return tx.Commit()
}
func (d *DB) DeliveryState(ctx context.Context, id EdgeIdentity) (GenerationDeliveryState, error) {
	if err := id.validate(); err != nil {
		return GenerationDeliveryState{}, err
	}
	var s GenerationDeliveryState
	s.EdgeIdentity = id
	err := d.sqlDB.QueryRowContext(ctx, `SELECT last_contiguous_seq,high_watermark,mode,reason FROM ssp_edge_delivery_state WHERE tenant_id=? AND edge_id=? AND edge_generation=?`, id.TenantID, id.EdgeID, id.Generation).Scan(&s.LastContiguousSeq, &s.HighWatermark, &s.Mode, &s.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		s.Mode = DeliveryModeActive
		return s, nil
	}
	return s, err
}
func (d *DB) CompleteReconciliation(ctx context.Context, id EdgeIdentity, completeThrough, high int64, now time.Time) error {
	if err := id.validate(); err != nil {
		return err
	}
	if completeThrough < 0 || completeThrough != high || now.IsZero() {
		return errors.New("sspedge: invalid reconciliation completion")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, `UPDATE ssp_edge_delivery_state SET mode='active',reason='',updated_at=? WHERE tenant_id=? AND edge_id=? AND edge_generation=? AND mode='reconciliation_required' AND last_contiguous_seq=? AND high_watermark=?`, sqlTime(now), id.TenantID, id.EdgeID, id.Generation, completeThrough, high)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return errors.New("sspedge: reconciliation is not contiguous through high watermark")
	}
	return nil
}

func (d *DB) claimIdentity(ctx context.Context, tx *sql.Tx, id, commitment string, delivery JournalDelivery, now time.Time) (ApplyOutcome, error) {
	var stored string
	err := tx.QueryRowContext(ctx, `SELECT commitment FROM ssp_edge_envelope_identity WHERE envelope_id=?`, id).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `INSERT INTO ssp_edge_envelope_identity (envelope_id,commitment,state,first_delivery_seq,first_seen_at) VALUES (?,?, 'accepted',?,?)`, id, commitment, delivery.DeliverySeq, sqlTime(now))
		return ApplyAccepted, err
	}
	if err != nil {
		return "", err
	}
	if stored == commitment {
		return ApplyDuplicate, nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE ssp_edge_envelope_identity SET state='quarantined',conflicting_commitment=COALESCE(conflicting_commitment,?),conflicting_delivery_seq=COALESCE(conflicting_delivery_seq,?),quarantined_at=COALESCE(quarantined_at,?) WHERE envelope_id=?`, commitment, delivery.DeliverySeq, sqlTime(now), id)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE ssp_edge_cases SET state='quarantined' WHERE envelope_id=?`, id)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE ssp_edge_advice SET state='quarantined' WHERE envelope_id=?`, id)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE ssp_edge_front_outbox SET state='quarantined' WHERE advice_id IN (SELECT advice_id FROM ssp_edge_advice WHERE envelope_id=?)`, id)
	return ApplyQuarantined, err
}

func (d *DB) persistProjection(ctx context.Context, tx *sql.Tx, p *VerifiedProjection, now time.Time) error {
	switch p.Family {
	case FamilyCase:
		if p.Case == nil {
			return errors.New("sspedge: case projection required")
		}
		plain, err := encodeCasePayload(p.Case.Summary, p.Case.ContextManifest)
		if err != nil {
			return err
		}
		body, err := d.seal("ssp_edge_cases", p.Case.CaseID, plain)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO ssp_edge_cases (case_id,envelope_id,commitment,issuer_edge_id,issuer_edge_generation,route_kind,route_token,source_token,domain,routing_epoch,registry_revision,registry_hash,payload_ciphertext,key_version,expires_at,state) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,'accepted') ON CONFLICT(case_id) DO NOTHING`, p.Case.CaseID, p.EnvelopeID, p.Commitment, p.Case.IssuerEdgeID, p.Case.IssuerEdgeGeneration, p.Case.RouteKind, p.Case.RouteToken, p.Case.SourceToken, p.Case.Domain, p.Case.RoutingEpoch, p.Case.RegistryRevision, p.Case.RegistryHash, body, sqlTime(p.Case.ExpiresAt))
		return err
	case FamilyAdvice:
		if p.Advice == nil {
			return errors.New("sspedge: advice projection required")
		}
		var caseCommitment, issuerEdgeID, sourceToken, registryHash string
		var issuerGeneration, routingEpoch, registryRevision int64
		err := tx.QueryRowContext(ctx, `SELECT commitment,issuer_edge_id,issuer_edge_generation,source_token,routing_epoch,registry_revision,registry_hash FROM ssp_edge_cases WHERE case_id=? AND state='accepted'`, p.Advice.CaseID).Scan(&caseCommitment, &issuerEdgeID, &issuerGeneration, &sourceToken, &routingEpoch, &registryRevision, &registryHash)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("sspedge: advice case is absent or quarantined")
		}
		if err != nil {
			return err
		}
		if caseCommitment != p.Advice.CaseCommitment || issuerEdgeID != p.Advice.IssuerEdgeID || issuerGeneration != p.Advice.IssuerEdgeGeneration || sourceToken != p.Advice.RouteToken || routingEpoch != p.Advice.RoutingEpoch || registryRevision != p.Advice.RegistryRevision || registryHash != p.Advice.RegistryHash {
			return errors.New("sspedge: advice does not bind exact accepted case")
		}
		body, err := d.seal("ssp_edge_advice", p.Advice.AdviceID, []byte(p.Advice.Text))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO ssp_edge_advice (advice_id,envelope_id,case_id,case_commitment,commitment,issuer_edge_id,issuer_edge_generation,route_kind,route_token,routing_epoch,registry_revision,registry_hash,text_ciphertext,key_version,expires_at,received_at,state) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,'accepted') ON CONFLICT(advice_id) DO NOTHING`, p.Advice.AdviceID, p.EnvelopeID, p.Advice.CaseID, p.Advice.CaseCommitment, p.Commitment, p.Advice.IssuerEdgeID, p.Advice.IssuerEdgeGeneration, p.Advice.RouteKind, p.Advice.RouteToken, p.Advice.RoutingEpoch, p.Advice.RegistryRevision, p.Advice.RegistryHash, body, sqlTime(p.Advice.ExpiresAt), sqlTime(now))
		if err != nil {
			return err
		}
		for _, front := range []string{"cli", "amq"} {
			if _, err = tx.ExecContext(ctx, `INSERT INTO ssp_edge_front_outbox (front,advice_id,message_id,state,created_at) VALUES (?,?,?,'pending',?) ON CONFLICT(front,advice_id) DO NOTHING`, front, p.Advice.AdviceID, "snagline."+front+".advice.v1/"+p.Advice.AdviceID, sqlTime(now)); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("sspedge: unknown family")
	}
}

func validateDelivery(d JournalDelivery, v Verdict, reason string, p *VerifiedProjection, now time.Time) error {
	if d.DeliverySeq <= 0 || d.TenantID == "" || d.EdgeID == "" || d.EdgeGeneration <= 0 || d.Subject == "" || len(d.Raw) == 0 || now.IsZero() {
		return errors.New("sspedge: invalid delivery")
	}
	if v != VerdictAccepted && v != VerdictRejected && v != VerdictQuarantined {
		return errors.New("sspedge: invalid verdict")
	}
	if len(reason) > 256 {
		return errors.New("sspedge: rejection reason too long")
	}
	if v == VerdictAccepted {
		if p == nil || p.EnvelopeID == "" || !sha256RE.MatchString(p.Commitment) || (p.Family != FamilyCase && p.Family != FamilyAdvice) {
			return errors.New("sspedge: invalid accepted projection")
		}
		if p.Family == FamilyCase && (p.Case == nil || p.Case.CaseID == "" || p.Case.IssuerEdgeGeneration <= 0 || p.Case.RouteKind != "domain" || !routingTokenRE.MatchString(p.Case.RouteToken) || !routingTokenRE.MatchString(p.Case.SourceToken) || !sha256RE.MatchString(p.Case.RegistryHash) || p.Case.ExpiresAt.IsZero()) {
			return errors.New("sspedge: invalid case")
		}
		if p.Family == FamilyAdvice && (p.Advice == nil || p.Advice.AdviceID == "" || p.Advice.IssuerEdgeID == "" || p.Advice.IssuerEdgeGeneration <= 0 || p.Advice.RouteKind != "edge" || !routingTokenRE.MatchString(p.Advice.RouteToken) || !sha256RE.MatchString(p.Advice.CaseCommitment) || !sha256RE.MatchString(p.Advice.RegistryHash) || p.Advice.ExpiresAt.IsZero()) {
			return errors.New("sspedge: invalid advice")
		}
		if p.Family == FamilyCase && (p.Case.IssuerEdgeID != d.EdgeID || p.Case.IssuerEdgeGeneration != d.EdgeGeneration || p.Case.RouteToken != RoutingToken(p.Case.Domain) || p.Case.SourceToken != EdgeRoutingToken(d.EdgeID, d.EdgeGeneration)) {
			return errors.New("sspedge: case delivery identity mismatch")
		}
		if p.Family == FamilyAdvice && (p.Advice.IssuerEdgeID != d.EdgeID || p.Advice.IssuerEdgeGeneration != d.EdgeGeneration || p.Advice.RouteToken != EdgeRoutingToken(d.EdgeID, d.EdgeGeneration)) {
			return errors.New("sspedge: advice delivery identity mismatch")
		}
	} else if p != nil && (p.EnvelopeID == "" || !sha256RE.MatchString(p.Commitment) || (p.Family != FamilyCase && p.Family != FamilyAdvice)) {
		return errors.New("sspedge: invalid rejected receipt metadata")
	}
	return nil
}
func hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func sqlTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func nullable(p *VerifiedProjection, field string) any {
	if p == nil {
		return nil
	}
	if field == "id" {
		return p.EnvelopeID
	}
	return string(p.Family)
}
func (d *DB) seal(table, key string, plain []byte) ([]byte, error) {
	nonce := make([]byte, d.key.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := []byte(table + "\x00" + key + "\x00" + d.tenant)
	return append(nonce, d.key.Seal(nil, nonce, plain, aad)...), nil
}

func (d *DB) open(table, key string, ciphertext []byte) ([]byte, error) {
	n := d.key.NonceSize()
	if len(ciphertext) < n {
		return nil, errors.New("sspedge: ciphertext is truncated")
	}
	plain, err := d.key.Open(nil, ciphertext[:n], ciphertext[n:], []byte(table+"\x00"+key+"\x00"+d.tenant))
	if err != nil {
		return nil, errors.New("sspedge: ciphertext failed authentication")
	}
	return plain, nil
}

type Front string

const (
	FrontCLI Front = "cli"
	FrontAMQ Front = "amq"
)

type FrontDelivery struct {
	Front                                         Front
	CaseID, AdviceID, MessageID, Text, ClaimToken string
}
type FrontReceipt struct {
	Front                            Front
	MessageID, ClaimToken, ReceiptID string
}
type DeliveryOutcome string

const (
	DeliveryRecorded  DeliveryOutcome = "recorded"
	DeliveryDuplicate DeliveryOutcome = "duplicate"
)

func (d *DB) ClaimFrontDeliveries(ctx context.Context, front Front, owner string, ttl time.Duration, limit int, now time.Time) ([]FrontDelivery, error) {
	if (front != FrontCLI && front != FrontAMQ) || owner == "" || ttl <= 0 || limit <= 0 || now.IsZero() {
		return nil, errors.New("sspedge: invalid front claim")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT a.case_id,o.advice_id,o.message_id,a.text_ciphertext FROM ssp_edge_front_outbox o JOIN ssp_edge_advice a ON a.advice_id=o.advice_id WHERE o.front=? AND a.state='accepted' AND (o.state='pending' OR (o.state='delivering' AND o.lease_expires_at < ?)) ORDER BY o.created_at,o.advice_id LIMIT ?`, string(front), sqlTime(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FrontDelivery
	for rows.Next() {
		var caseID, id, message string
		var ciphertext []byte
		if err := rows.Scan(&caseID, &id, &message, &ciphertext); err != nil {
			return nil, err
		}
		token, err := claimToken()
		if err != nil {
			return nil, err
		}
		res, err := tx.ExecContext(ctx, `UPDATE ssp_edge_front_outbox SET state='delivering',lease_owner=?,lease_expires_at=?,claim_token=? WHERE front=? AND advice_id=? AND (state='pending' OR (state='delivering' AND lease_expires_at < ?))`, owner, sqlTime(now.Add(ttl)), token, string(front), id, sqlTime(now))
		if err != nil {
			return nil, err
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			continue
		}
		text, err := d.open("ssp_edge_advice", id, ciphertext)
		if err != nil {
			return nil, err
		}
		out = append(out, FrontDelivery{Front: front, CaseID: caseID, AdviceID: id, MessageID: message, Text: string(text), ClaimToken: token})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
func (d *DB) MarkFrontDelivered(ctx context.Context, receipt FrontReceipt, now time.Time) (DeliveryOutcome, error) {
	if (receipt.Front != FrontCLI && receipt.Front != FrontAMQ) || receipt.MessageID == "" || receipt.ClaimToken == "" || receipt.ReceiptID == "" || now.IsZero() {
		return "", errors.New("sspedge: invalid delivery receipt")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var state, storedToken, storedReceipt string
	err = tx.QueryRowContext(ctx, `SELECT state,COALESCE(claim_token,''),COALESCE(delivery_receipt,'') FROM ssp_edge_front_outbox WHERE front=? AND message_id=?`, string(receipt.Front), receipt.MessageID).Scan(&state, &storedToken, &storedReceipt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("sspedge: front message not found")
	}
	if err != nil {
		return "", err
	}
	if state == "delivered" {
		if storedReceipt != receipt.ReceiptID {
			return "", errors.New("sspedge: delivered receipt mismatch")
		}
		return DeliveryDuplicate, tx.Commit()
	}
	if state != "delivering" || storedToken != receipt.ClaimToken {
		return "", errors.New("sspedge: lost front delivery claim")
	}
	_, err = tx.ExecContext(ctx, `UPDATE ssp_edge_front_outbox SET state='delivered',delivery_receipt=?,delivered_at=?,lease_owner=NULL,lease_expires_at=NULL WHERE front=? AND message_id=? AND state='delivering' AND claim_token=?`, receipt.ReceiptID, sqlTime(now), string(receipt.Front), receipt.MessageID, receipt.ClaimToken)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return DeliveryRecorded, nil
}
func claimToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func readKeyFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("sspedge: open key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("sspedge: key file rejected")
	}
	if err := requireCurrentOwner(info); err != nil {
		return nil, err
	}
	if info.Size() != StoreKeyLength {
		return nil, errors.New("sspedge: key must be 32 raw bytes")
	}
	raw := make([]byte, StoreKeyLength+1)
	n, err := io.ReadFull(file, raw)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	if n != StoreKeyLength {
		return nil, errors.New("sspedge: key changed while reading")
	}
	return raw[:StoreKeyLength], nil
}
func requireCurrentOwner(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("sspedge: path owner rejected")
	}
	return nil
}

const schema = `
CREATE TABLE IF NOT EXISTS ssp_edge_delivery_state (tenant_id TEXT NOT NULL,edge_id TEXT NOT NULL,edge_generation INTEGER NOT NULL,last_contiguous_seq INTEGER NOT NULL,high_watermark INTEGER NOT NULL,mode TEXT NOT NULL,reason TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,edge_id,edge_generation));
CREATE TABLE IF NOT EXISTS ssp_edge_deliveries (tenant_id TEXT NOT NULL,edge_id TEXT NOT NULL,edge_generation INTEGER NOT NULL,delivery_seq INTEGER NOT NULL,carrier_stream TEXT NOT NULL,carrier_sequence INTEGER NOT NULL,subject TEXT NOT NULL,raw_sha256 TEXT NOT NULL,envelope_id TEXT,family TEXT,verdict TEXT NOT NULL,reason TEXT NOT NULL,received_at TEXT NOT NULL,committed_at TEXT NOT NULL,PRIMARY KEY(tenant_id,edge_id,edge_generation,delivery_seq));
CREATE TABLE IF NOT EXISTS ssp_edge_envelope_identity (envelope_id TEXT PRIMARY KEY,commitment TEXT NOT NULL,state TEXT NOT NULL,first_delivery_seq INTEGER NOT NULL,first_seen_at TEXT NOT NULL,conflicting_commitment TEXT,conflicting_delivery_seq INTEGER,quarantined_at TEXT);
CREATE TABLE IF NOT EXISTS ssp_edge_pending_cases (case_id TEXT PRIMARY KEY,envelope_id TEXT NOT NULL UNIQUE,commitment TEXT NOT NULL,raw_ciphertext BLOB NOT NULL,key_version INTEGER NOT NULL,created_at TEXT NOT NULL,state TEXT NOT NULL,authority_id TEXT,authority_revision INTEGER,accepted_at TEXT);
CREATE TABLE IF NOT EXISTS ssp_edge_pending_advice (case_id TEXT PRIMARY KEY,advice_id TEXT NOT NULL UNIQUE,case_commitment TEXT NOT NULL,commitment TEXT NOT NULL,raw_ciphertext BLOB NOT NULL,key_version INTEGER NOT NULL,created_at TEXT NOT NULL,state TEXT NOT NULL,authority_id TEXT,authority_revision INTEGER,accepted_at TEXT);
CREATE TABLE IF NOT EXISTS ssp_edge_cases (case_id TEXT PRIMARY KEY,envelope_id TEXT NOT NULL UNIQUE,commitment TEXT NOT NULL,issuer_edge_id TEXT NOT NULL,issuer_edge_generation INTEGER NOT NULL,route_kind TEXT NOT NULL,route_token TEXT NOT NULL,source_token TEXT NOT NULL,domain TEXT NOT NULL,routing_epoch INTEGER NOT NULL,registry_revision INTEGER NOT NULL,registry_hash TEXT NOT NULL,payload_ciphertext BLOB NOT NULL,key_version INTEGER NOT NULL,expires_at TEXT NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ssp_edge_advice (advice_id TEXT PRIMARY KEY,envelope_id TEXT NOT NULL UNIQUE,case_id TEXT NOT NULL,case_commitment TEXT NOT NULL,commitment TEXT NOT NULL,issuer_edge_id TEXT NOT NULL,issuer_edge_generation INTEGER NOT NULL,route_kind TEXT NOT NULL,route_token TEXT NOT NULL,routing_epoch INTEGER NOT NULL,registry_revision INTEGER NOT NULL,registry_hash TEXT NOT NULL,text_ciphertext BLOB NOT NULL,key_version INTEGER NOT NULL,expires_at TEXT NOT NULL,received_at TEXT NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ssp_edge_front_outbox (front TEXT NOT NULL,advice_id TEXT NOT NULL,message_id TEXT NOT NULL UNIQUE,state TEXT NOT NULL,created_at TEXT NOT NULL,lease_owner TEXT,lease_expires_at TEXT,claim_token TEXT,delivery_receipt TEXT,delivered_at TEXT,PRIMARY KEY(front,advice_id));`
