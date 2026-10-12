package state

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"modernc.org/sqlite"
)

const (
	sqliteStateFileName     = "state.db"
	sqliteSchemaVersion     = 9
	MaxPersistentStateBytes = 10 << 20
	maxSQLiteStateBytes     = MaxPersistentStateBytes + 8<<20
	maxBrowserSessions      = 4096
)

// SQLiteStore owns one secure, relational state database. The store exposes one
// SQLite connection so aggregate replacement and browser-session operations
// remain serialized even when callers share it across goroutines.
type SQLiteStore struct {
	dir  string
	path string

	mu              sync.Mutex
	db              *sql.DB
	initializeState func(context.Context, *sql.DB, PersistentState) error
	now             func() time.Time
}

// NewSQLiteStore validates an already-provisioned state directory. It never
// creates or weakens the directory; LoadOrCreate creates state.db directly.
func NewSQLiteStore(dir string, options ...StoreOption) (*SQLiteStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("empty state directory: %w", ErrInsecureStatePath)
	}
	clean := filepath.Clean(dir)
	if err := ValidateStateDir(clean); err != nil {
		return nil, err
	}
	store := &SQLiteStore{dir: clean, path: filepath.Join(clean, sqliteStateFileName), initializeState: initializeSQLiteSchemaAndState, now: time.Now}
	for _, option := range options {
		option(store)
	}
	return store, nil
}

type StoreOption func(*SQLiteStore)

// WithClock supplies the clock used by browser-session lifecycle operations.
func WithClock(now func() time.Time) StoreOption {
	return func(store *SQLiteStore) {
		if now != nil {
			store.now = now
		}
	}
}

func (s *SQLiteStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Close releases the SQLite handle. It does not delete durable state.
func (s *SQLiteStore) Close(_ context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	if err != nil {
		return fmt.Errorf("close state database: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ensureOpenLocked(ctx context.Context, create bool, initial *PersistentState) (bool, error) {
	if err := s.validate(); err != nil {
		return false, err
	}
	if s.db != nil {
		if err := validateSecureStateFile(s.path, maxSQLiteStateBytes); err != nil {
			return false, err
		}
		return false, nil
	}
	exists, err := stateFileExists(s.path, maxSQLiteStateBytes)
	if err != nil {
		return false, err
	}
	if !exists {
		if !create || initial == nil {
			return false, ErrStateNotFound
		}
		if err := validateEmptyStateDir(s.dir); err != nil {
			return false, err
		}
		return s.createInitialStateLocked(ctx, *initial)
	}
	if err := s.openExistingLocked(ctx); err != nil {
		return false, err
	}
	return false, nil
}

func (s *SQLiteStore) openExistingLocked(ctx context.Context) error {
	db, err := openSQLite(ctx, s.path, false)
	if err != nil {
		return corruptDatabase(err)
	}
	if err := configureSQLiteReadOnly(ctx, db); err != nil {
		_ = db.Close()
		return corruptDatabase(err)
	}
	if err := validateSQLiteJournalMode(ctx, db); err != nil {
		_ = db.Close()
		return err
	}
	if err := checkSQLiteIntegrity(ctx, db); err != nil {
		_ = db.Close()
		return err
	}
	if err := migrateSQLiteSchema(ctx, db); err != nil {
		_ = db.Close()
		return err
	}
	if err := validateSQLiteSchema(ctx, db); err != nil {
		_ = db.Close()
		return err
	}
	if err := configureSQLiteDurability(ctx, db); err != nil {
		_ = db.Close()
		return corruptDatabase(err)
	}
	if err := validateSecureStateFile(s.path, maxSQLiteStateBytes); err != nil {
		_ = db.Close()
		return err
	}
	s.db = db
	return nil
}

// createInitialStateLocked creates state.db at its final path and removes an
// incomplete database so a later LoadOrCreate can retry safely.
func (s *SQLiteStore) createInitialStateLocked(ctx context.Context, initial PersistentState) (created bool, err error) {
	if s.initializeState == nil {
		return false, ErrInsecureStatePath
	}
	cleanup := false
	defer func() {
		if !cleanup {
			return
		}
		if cleanupErr := removeIncompleteSQLiteState(s.path, s.dir); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()

	file, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return false, fmt.Errorf("create state database: %w", err)
	}
	cleanup = true
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("chmod state database: %w", err)
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("close state database: %w", err)
	}
	if err := validateSecureStateFile(s.path, maxSQLiteStateBytes); err != nil {
		return false, err
	}
	db, err := openSQLite(ctx, s.path, false)
	if err != nil {
		return false, corruptDatabase(err)
	}
	if err := configureSQLiteReadOnly(ctx, db); err != nil {
		_ = db.Close()
		return false, corruptDatabase(err)
	}
	if err := configureSQLiteDurability(ctx, db); err != nil {
		_ = db.Close()
		return false, corruptDatabase(err)
	}
	if err := s.initializeState(ctx, db, initial); err != nil {
		_ = db.Close()
		return false, err
	}
	if err := validateSQLiteSchema(ctx, db); err != nil {
		_ = db.Close()
		return false, err
	}
	if err := db.Close(); err != nil {
		return false, corruptDatabase(err)
	}
	if err := syncStateFile(s.path); err != nil {
		return false, err
	}
	if err := syncDirectory(s.dir); err != nil {
		return false, err
	}
	if err := s.openExistingLocked(ctx); err != nil {
		return false, err
	}
	cleanup = false
	return true, nil
}

func removeIncompleteSQLiteState(path, dir string) error {
	var cleanupErr error
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove incomplete state database: %w", err))
		}
	}
	if err := syncDirectory(dir); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	return cleanupErr
}

func openSQLite(ctx context.Context, path string, readOnly bool) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("_txlock", "immediate")
	for _, pragma := range []string{"busy_timeout=5000", "foreign_keys=ON", "secure_delete=ON", "synchronous=FULL"} {
		query.Add("_pragma", pragma)
	}
	if readOnly {
		query.Set("mode", "ro")
	}
	uri := &url.URL{Scheme: "file", Path: absolute, RawQuery: query.Encode()}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func configureSQLiteReadOnly(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 5000")
	return err
}

func configureSQLiteDurability(ctx context.Context, db *sql.DB) error {
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode = DELETE").Scan(&mode); err != nil {
		return err
	}
	if !strings.EqualFold(mode, "delete") {
		return fmt.Errorf("unexpected SQLite journal mode %q", mode)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA synchronous = FULL"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "PRAGMA secure_delete = ON"); err != nil {
		return err
	}
	var secureDelete int
	if err := db.QueryRowContext(ctx, "PRAGMA secure_delete").Scan(&secureDelete); err != nil {
		return err
	}
	if secureDelete != 1 {
		return fmt.Errorf("secure_delete is not enabled")
	}
	return nil
}

// Load reconstructs an aggregate in a read-only transaction, without pruning.
func (s *SQLiteStore) Load(ctx context.Context) (PersistentState, error) {
	if s == nil {
		return PersistentState{}, ErrInsecureStatePath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.ensureOpenLocked(ctx, false, nil); err != nil {
		return PersistentState{}, err
	}
	return s.loadLocked(ctx)
}

func (s *SQLiteStore) loadLocked(ctx context.Context) (PersistentState, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	defer tx.Rollback()
	state, err := loadPersistentStateTx(ctx, tx)
	if err != nil {
		return PersistentState{}, err
	}
	if err := tx.Commit(); err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	return state, nil
}

// LoadOrCreate loads an existing state.db or transactionally creates a fresh
// SQLite aggregate after its optional semantic validation succeeds.
func (s *SQLiteStore) LoadOrCreate(ctx context.Context, semantic ...func(PersistentState) error) (PersistentState, error) {
	if s == nil {
		return PersistentState{}, ErrInsecureStatePath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validate(); err != nil {
		return PersistentState{}, err
	}
	exists, err := stateFileExists(s.path, maxSQLiteStateBytes)
	if err != nil {
		return PersistentState{}, err
	}
	if exists {
		if _, err := s.ensureOpenLocked(ctx, false, nil); err != nil {
			return PersistentState{}, err
		}
		loaded, err := s.loadLocked(ctx)
		if err != nil {
			return PersistentState{}, err
		}
		if err := validatePersistentStateSemantics(loaded, semantic); err != nil {
			return PersistentState{}, err
		}
		return loaded, nil
	}

	initial, err := NewPersistentState()
	if err != nil {
		return PersistentState{}, err
	}
	if err := validatePersistentStateSemantics(initial, semantic); err != nil {
		return PersistentState{}, err
	}
	created, err := s.ensureOpenLocked(ctx, true, &initial)
	if err != nil {
		return PersistentState{}, err
	}
	if created {
		return initial.Clone(), nil
	}
	loaded, err := s.loadLocked(ctx)
	if err != nil {
		return PersistentState{}, err
	}
	if err := validatePersistentStateSemantics(loaded, semantic); err != nil {
		return PersistentState{}, err
	}
	return loaded, nil
}

// Save atomically replaces only the normalized PersistentState tables. It
// deliberately leaves browser_sessions intact.
func (s *SQLiteStore) Save(ctx context.Context, state PersistentState) error {
	if s == nil {
		return ErrInsecureStatePath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	created, err := s.ensureOpenLocked(ctx, true, &state)
	if err != nil {
		return err
	}
	if created {
		return nil
	}
	return s.saveLocked(ctx, state)
}

func (s *SQLiteStore) saveLocked(ctx context.Context, state PersistentState) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	if err := validateBrowserSessionsTx(ctx, tx, s.now().UTC(), maxBrowserSessions, true); err != nil {
		return err
	}
	if err := replacePersistentStateTx(ctx, tx, state); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return corruptDatabase(err)
	}
	return nil
}

// Update performs load-modify-save as one SQLite transaction. A callback error
// or validation failure rolls back without changing the previous aggregate.
func (s *SQLiteStore) Update(ctx context.Context, change func(*PersistentState) error) (PersistentState, error) {
	if s == nil || change == nil {
		return PersistentState{}, ErrInsecureStatePath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.ensureOpenLocked(ctx, false, nil); err != nil {
		return PersistentState{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	defer tx.Rollback()
	current, err := loadPersistentStateTx(ctx, tx)
	if err != nil {
		return PersistentState{}, err
	}
	if err := validateBrowserSessionsTx(ctx, tx, s.now().UTC(), maxBrowserSessions, true); err != nil {
		return PersistentState{}, err
	}
	candidate := current.Clone()
	if err := change(&candidate); err != nil {
		return PersistentState{}, err
	}
	if err := replacePersistentStateTx(ctx, tx, candidate); err != nil {
		return PersistentState{}, err
	}
	if current.AccessTokenVerifier != nil && candidate.AccessTokenVerifier != nil && subtle.ConstantTimeCompare(current.AccessTokenVerifier.Hash, candidate.AccessTokenVerifier.Hash) != 1 {
		if _, err := tx.ExecContext(ctx, "DELETE FROM browser_sessions"); err != nil {
			return PersistentState{}, corruptDatabase(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	return candidate.Clone(), nil
}

func corruptDatabase(err error) error {
	if err == nil || errors.Is(err, ErrCorruptState) || errors.Is(err, ErrStateBusy) {
		return err
	}
	var sqliteError *sqlite.Error
	if errors.As(err, &sqliteError) && sqliteError.Code()&0xff == 5 {
		return fmt.Errorf("%w: %w", ErrStateBusy, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrCorruptState, err)
}

func syncStateFile(path string) error {
	file, err := openSecureStateFile(path, maxSQLiteStateBytes)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync state database: %w", err)
	}
	return nil
}

func syncDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}
