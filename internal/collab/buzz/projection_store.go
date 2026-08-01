package buzz

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"

	"github.com/avivsinai/snagline/internal/privatesqlite"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

// ProjectionStore persists the complete projector state as an AES-GCM
// encrypted blob. A descriptor-validated, current-user-owned 0700 directory
// provides the trusted namespace SQLite needs for its crash-safe WAL sidecars.
type ProjectionStore struct {
	mu    sync.Mutex
	db    *sql.DB
	dirFD int
	aead  cipher.AEAD
}

func OpenProjectionStore(path string, key []byte) (*ProjectionStore, error) {
	if len(key) != 32 {
		return nil, errors.New("collab buzz: SQLite encryption key must be 32 bytes")
	}
	namespace, err := privatesqlite.Open(path)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	dsn := &url.URL{Scheme: "file", Path: namespace.Path}
	query := url.Values{"mode": {"rwc"}}
	for _, pragma := range []string{
		"journal_mode(WAL)",
		"synchronous(FULL)",
		"fullfsync(ON)",
		"checkpoint_fullfsync(ON)",
		"foreign_keys(ON)",
		"busy_timeout(5000)",
		"secure_delete(ON)",
	} {
		query.Add("_pragma", pragma)
	}
	dsn.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	// Every pragma above is connection-scoped. A single connection also matches
	// this store's serialized single-writer API and prevents pragma drift.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &ProjectionStore{db: db, dirFD: namespace.DirFD, aead: aead}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS buzz_projector_state (id INTEGER PRIMARY KEY CHECK (id = 1), nonce BLOB NOT NULL, ciphertext BLOB NOT NULL)`); err != nil {
		_ = db.Close()
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	if err := store.requireCrashSafePragmas(); err != nil {
		_ = db.Close()
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	// Persist creation of the database and its WAL namespace before the caller
	// can use it as the pre-publish durability barrier.
	if err := unix.Fsync(namespace.DirFD); err != nil {
		_ = db.Close()
		_ = unix.Close(namespace.DirFD)
		return nil, err
	}
	return store, nil
}

func (s *ProjectionStore) requireCrashSafePragmas() error {
	var journal string
	var synchronous, fullfsync, checkpointFullfsync int
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		return err
	}
	if err := s.db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		return err
	}
	if err := s.db.QueryRow(`PRAGMA fullfsync`).Scan(&fullfsync); err != nil {
		return err
	}
	if err := s.db.QueryRow(`PRAGMA checkpoint_fullfsync`).Scan(&checkpointFullfsync); err != nil {
		return err
	}
	if journal != "wal" || synchronous != 2 || fullfsync != 1 || checkpointFullfsync != 1 {
		return errors.New("collab buzz: SQLite crash-safe durability is unavailable")
	}
	return nil
}

func (s *ProjectionStore) Load(ctx context.Context) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var nonce, ciphertext []byte
	err := s.db.QueryRowContext(ctx, `SELECT nonce, ciphertext FROM buzz_projector_state WHERE id = 1`).Scan(&nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return normalizeState(State{}), nil
	}
	if err != nil {
		return State{}, err
	}
	plain, err := s.aead.Open(nil, nonce, ciphertext, []byte("snagline/collab/buzz/v1"))
	if err != nil {
		return State{}, errors.New("collab buzz: encrypted SQLite state cannot be opened")
	}
	var state State
	if err := json.Unmarshal(plain, &state); err != nil {
		return State{}, fmt.Errorf("collab buzz: decode SQLite state: %w", err)
	}
	return normalizeState(state), nil
}

func (s *ProjectionStore) Save(ctx context.Context, state State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	plain, err := json.Marshal(normalizeState(state))
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := s.aead.Seal(nil, nonce, plain, []byte("snagline/collab/buzz/v1"))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO buzz_projector_state(id, nonce, ciphertext) VALUES(1, ?, ?) ON CONFLICT(id) DO UPDATE SET nonce = excluded.nonce, ciphertext = excluded.ciphertext`, nonce, ciphertext); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *ProjectionStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.db.Close()
	closeErr := unix.Close(s.dirFD)
	if err != nil {
		return err
	}
	return closeErr
}
