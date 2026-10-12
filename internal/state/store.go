package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"modernc.org/sqlite"

	"github.com/kfadapter/kfadapter/internal/provider"
)

const (
	sqliteStateFileName     = "state.db"
	sqliteSchemaVersion     = 9
	MaxPersistentStateBytes = 10 << 20
	maxSQLiteStateBytes     = MaxPersistentStateBytes + 8<<20
	maxBrowserSessions      = 4096
)

var sqliteSchemaTables = map[string]int{
	"schema_version": 0, "state_metadata": 1, "access_token_verifier": 2,
	"preferences": 3, "excluded_node_ids": 4, "active_session": 5,
	"active_session_providers": 6, "active_session_authorities": 7,
	"active_session_nodes": 8, "browser_sessions": 9,
}

var sqliteSchemaV8Tables = map[string]int{
	"schema_version": 0, "state_metadata": 1, "access_token_verifier": 2,
	"subscription_authority": 3, "preferences": 4, "excluded_node_ids": 5,
	"last_good": 6, "last_good_nodes": 7, "active_session": 8,
	"active_session_providers": 9, "active_session_authorities": 10,
	"active_session_nodes": 11, "active_session_selectors": 12, "browser_sessions": 13,
}

var sqliteSchemaV5Tables = map[string]int{
	"schema_version": 0, "state_metadata": 1, "access_token_verifier": 2,
	"subscription_generation": 3, "preferences": 4, "excluded_node_ids": 5,
	"last_good": 6, "last_good_nodes": 7, "active_session": 8,
	"active_session_nodes": 9, "active_session_selectors": 10, "browser_sessions": 11,
	"active_session_windows": 12, "active_session_node_profiles": 13,
}

var sqliteSchemaV6Tables = map[string]int{
	"schema_version": 0, "state_metadata": 1, "access_token_verifier": 2,
	"subscription_generation": 3, "preferences": 4, "excluded_node_ids": 5,
	"last_good": 6, "last_good_nodes": 7, "active_session": 8,
	"active_session_providers": 9, "active_session_authorities": 10,
	"active_session_nodes": 11, "active_session_selectors": 12, "browser_sessions": 13,
}

var sqliteSchemaV4Tables = map[string]int{
	"schema_version": 0, "state_metadata": 1, "access_token_verifier": 2,
	"subscription_generation": 3, "preferences": 4, "excluded_node_ids": 5,
	"last_good": 6, "last_good_nodes": 7, "active_session": 8,
	"active_session_nodes": 9, "active_session_selectors": 10, "browser_sessions": 11,
}

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

// ValidateStateDir requires a real, current-user-owned 0700 directory.
func ValidateStateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state directory %q: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("state directory %q: %w", dir, ErrInsecureStatePath)
	}
	if err := ownedByCurrentUser(info); err != nil {
		return fmt.Errorf("state directory %q: %w", dir, err)
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return ErrInsecureStatePath
	}
	return nil
}

func hasSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func (s *SQLiteStore) validate() error {
	if s == nil {
		return ErrInsecureStatePath
	}
	return ValidateStateDir(s.dir)
}

// ValidateSQLiteFile validates an existing state.db without creating or
// modifying it. Optional semantic validators inspect the reconstructed
// aggregate after relational validation succeeds.
func ValidateSQLiteFile(ctx context.Context, path string, semantic ...func(PersistentState) error) error {
	if path == "" {
		return ErrInsecureStatePath
	}
	clean := filepath.Clean(path)
	if err := ValidateStateDir(filepath.Dir(clean)); err != nil {
		return err
	}
	if err := validateSecureStateFile(clean, maxSQLiteStateBytes); err != nil {
		return err
	}
	db, err := openSQLite(ctx, clean, true)
	if err != nil {
		return corruptDatabase(err)
	}
	defer func() { _ = db.Close() }()
	if err := configureSQLiteReadOnly(ctx, db); err != nil {
		return corruptDatabase(err)
	}
	if err := checkSQLiteIntegrity(ctx, db); err != nil {
		return err
	}
	if err := validateSQLiteJournalMode(ctx, db); err != nil {
		return err
	}
	if err := validateSQLiteSchema(ctx, db); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	state, err := loadPersistentStateTx(ctx, tx)
	if err != nil {
		return err
	}
	if err := validateBrowserSessionsTx(ctx, tx, time.Now().UTC(), maxBrowserSessions, false); err != nil {
		return err
	}
	if err := validatePersistentStateSemantics(state, semantic); err != nil {
		return err
	}
	return corruptDatabase(tx.Commit())
}

func validatePersistentStateSemantics(state PersistentState, validators []func(PersistentState) error) error {
	for _, validator := range validators {
		if validator == nil {
			continue
		}
		if err := validator(state.Clone()); err != nil {
			return err
		}
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

func validateEmptyStateDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read state directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("state directory contains an unexpected artifact: %w", ErrInsecureStatePath)
	}
	return nil
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

func stateFileExists(path string, maximum int64) (bool, error) {
	err := validateSecureStateFile(path, maximum)
	if errors.Is(err, ErrStateNotFound) {
		return false, nil
	}
	return err == nil, err
}

func validateSecureStateFile(path string, maximum int64) error {
	file, err := openSecureStateFile(path, maximum)
	if err != nil {
		return err
	}
	return file.Close()
}

func openSecureStateFile(path string, maximum int64) (*os.File, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("stat state file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !hasSingleLink(info) {
		return nil, ErrInsecureStatePath
	}
	if err := ownedByCurrentUser(info); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrStateNotFound
	}
	if errors.Is(err, syscall.ELOOP) {
		return nil, ErrInsecureStatePath
	}
	if err != nil {
		return nil, fmt.Errorf("open state file: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened state file: %w", err)
	}
	if !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 || opened.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !hasSingleLink(opened) {
		_ = file.Close()
		return nil, ErrInsecureStatePath
	}
	if err := ownedByCurrentUser(opened); err != nil {
		_ = file.Close()
		return nil, err
	}
	if opened.Size() < 0 || opened.Size() > maximum {
		_ = file.Close()
		return nil, fmt.Errorf("%w: state file exceeds maximum size", ErrCorruptState)
	}
	return file, nil
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

func validateSQLiteJournalMode(ctx context.Context, db *sql.DB) error {
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return corruptDatabase(err)
	}
	if !strings.EqualFold(mode, "delete") {
		return corruptDatabase(fmt.Errorf("unexpected SQLite journal mode %q", mode))
	}
	return nil
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

func initializeSQLiteSchemaAndState(ctx context.Context, db *sql.DB, initial PersistentState) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	for _, statement := range sqliteSchemaStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return corruptDatabase(err)
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_version (id, version) VALUES (1, ?)", sqliteSchemaVersion); err != nil {
		return corruptDatabase(err)
	}
	if err := replacePersistentStateTx(ctx, tx, initial); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return corruptDatabase(err)
	}
	return nil
}

var sqliteSchemaV8Statements = []string{
	`CREATE TABLE schema_version (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)`,
	`CREATE TABLE state_metadata (id INTEGER PRIMARY KEY CHECK (id = 1), installation_id TEXT NOT NULL)`,
	`CREATE TABLE access_token_verifier (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, memory_kib INTEGER NOT NULL, iterations INTEGER NOT NULL, parallelism INTEGER NOT NULL, salt BLOB NOT NULL, hash BLOB NOT NULL)`,
	`CREATE TABLE subscription_authority (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, selector_key BLOB NOT NULL, proxy_auth_key BLOB NOT NULL, account_binding BLOB, activated_at_ns INTEGER NOT NULL)`,
	`CREATE TABLE preferences (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, reveal_endpoints INTEGER NOT NULL, refresh_policy TEXT NOT NULL)`,
	`CREATE TABLE excluded_node_ids (node_id TEXT PRIMARY KEY, preference_id INTEGER NOT NULL REFERENCES preferences(id) ON DELETE CASCADE)`,
	`CREATE TABLE last_good (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, created_at_ns INTEGER, rendered_subscription TEXT NOT NULL)`,
	`CREATE TABLE last_good_nodes (position INTEGER PRIMARY KEY, last_good_id INTEGER NOT NULL REFERENCES last_good(id) ON DELETE CASCADE, node_id TEXT NOT NULL, selector TEXT NOT NULL, provider TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, name TEXT NOT NULL, group_name TEXT NOT NULL, eligible INTEGER NOT NULL, excluded INTEGER NOT NULL)`,
	`CREATE TABLE active_session (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, generation INTEGER NOT NULL, created_at_ns INTEGER NOT NULL, expires_at_ns INTEGER NOT NULL)`,
	`CREATE TABLE active_session_providers (provider_id TEXT PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES active_session(id) ON DELETE CASCADE, expires_at_ns INTEGER NOT NULL, user_id TEXT NOT NULL, account_display TEXT NOT NULL, account_tier TEXT NOT NULL, subscription_active INTEGER NOT NULL, subscription_ends_at_ns INTEGER, refresh_state BLOB NOT NULL)`,
	`CREATE TABLE active_session_authorities (provider_id TEXT NOT NULL REFERENCES active_session_providers(provider_id) ON DELETE CASCADE, authority_id TEXT NOT NULL, protocol TEXT NOT NULL, authority BLOB NOT NULL, PRIMARY KEY (provider_id, authority_id))`,
	`CREATE TABLE active_session_nodes (position INTEGER PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES active_session(id) ON DELETE CASCADE, node_id TEXT NOT NULL, selector TEXT NOT NULL, provider_id TEXT NOT NULL REFERENCES active_session_providers(provider_id) ON DELETE CASCADE, protocol TEXT NOT NULL, authority_id TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, name TEXT NOT NULL, group_name TEXT NOT NULL, model TEXT NOT NULL, weight INTEGER NOT NULL, auto INTEGER NOT NULL, eligible INTEGER NOT NULL, excluded INTEGER NOT NULL, health TEXT NOT NULL, udp_health TEXT NOT NULL, tcp_rtt_ns INTEGER NOT NULL, probed_at_ns INTEGER)`,
	`CREATE TABLE active_session_selectors (selector TEXT PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES active_session(id) ON DELETE CASCADE, node_id TEXT NOT NULL)`,
	`CREATE TABLE browser_sessions (token TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires_at_ns INTEGER NOT NULL)`,
}

var sqliteSchemaStatements = func() []string {
	statements := make([]string, 0, len(sqliteSchemaTables))
	for _, index := range []int{0, 1, 2, 4, 5, 8, 9, 10, 11, 13} {
		statements = append(statements, sqliteSchemaV8Statements[index])
	}
	statements[8] = strings.Replace(statements[8], "selector TEXT NOT NULL, ", "", 1)
	statements[9] = `CREATE TABLE browser_sessions (token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32), csrf TEXT NOT NULL, expires_at_ns INTEGER NOT NULL)`
	return statements
}()

// Historical definitions are retained only for exact schema validation.
var sqliteSchemaV7Statements = func() []string {
	statements := append([]string(nil), sqliteSchemaV8Statements...)
	statements[3] = `CREATE TABLE subscription_generation (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, generation INTEGER NOT NULL, selector_key BLOB NOT NULL, proxy_auth_key BLOB NOT NULL, account_binding BLOB, activated_at_ns INTEGER NOT NULL)`
	statements[6] = `CREATE TABLE last_good (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, generation INTEGER NOT NULL, created_at_ns INTEGER, rendered_subscription TEXT NOT NULL, fetched_generation INTEGER NOT NULL, fetched_at_ns INTEGER, fetched_body_hash BLOB)`
	statements[12] = `CREATE TABLE active_session_selectors (selector TEXT PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES active_session(id) ON DELETE CASCADE, node_id TEXT NOT NULL, generation INTEGER NOT NULL, tombstoned INTEGER NOT NULL, tombstone_until_ns INTEGER)`
	return statements
}()

var sqliteSchemaV6Statements = func() []string {
	statements := append([]string(nil), sqliteSchemaV7Statements...)
	statements[9] = `CREATE TABLE active_session_providers (provider_id TEXT PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES active_session(id) ON DELETE CASCADE, expires_at_ns INTEGER NOT NULL, user_id TEXT NOT NULL, account_display TEXT NOT NULL, account_is_vip INTEGER NOT NULL, account_vip_ends_at_ns INTEGER, refresh_state BLOB NOT NULL)`
	return statements
}()

var sqliteSchemaV5Statements = []string{
	`CREATE TABLE schema_version (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)`,
	`CREATE TABLE state_metadata (id INTEGER PRIMARY KEY CHECK (id = 1), installation_id TEXT NOT NULL)`,
	`CREATE TABLE access_token_verifier (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, memory_kib INTEGER NOT NULL, iterations INTEGER NOT NULL, parallelism INTEGER NOT NULL, salt BLOB NOT NULL, hash BLOB NOT NULL)`,
	`CREATE TABLE subscription_generation (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, generation INTEGER NOT NULL, selector_key BLOB NOT NULL, proxy_auth_key BLOB NOT NULL, account_binding BLOB, activated_at_ns INTEGER NOT NULL)`,
	`CREATE TABLE preferences (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, reveal_endpoints INTEGER NOT NULL, refresh_policy TEXT NOT NULL)`,
	`CREATE TABLE excluded_node_ids (node_id TEXT PRIMARY KEY, preference_id INTEGER NOT NULL REFERENCES preferences(id) ON DELETE CASCADE)`,
	`CREATE TABLE last_good (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, generation INTEGER NOT NULL, created_at_ns INTEGER, rendered_subscription TEXT NOT NULL, fetched_generation INTEGER NOT NULL, fetched_at_ns INTEGER, fetched_body_hash BLOB)`,
	`CREATE TABLE last_good_nodes (position INTEGER PRIMARY KEY, last_good_id INTEGER NOT NULL REFERENCES last_good(id) ON DELETE CASCADE, node_id TEXT NOT NULL, selector TEXT NOT NULL, provider TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, name TEXT NOT NULL, group_name TEXT NOT NULL, eligible INTEGER NOT NULL, excluded INTEGER NOT NULL)`,
	`CREATE TABLE active_session (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES state_metadata(id) ON DELETE CASCADE, generation INTEGER NOT NULL, created_at_ns INTEGER NOT NULL, expires_at_ns INTEGER NOT NULL, account_display TEXT NOT NULL, account_is_vip INTEGER NOT NULL, account_vip_ends_at_ns INTEGER, session_user_id TEXT NOT NULL, session_login_token TEXT NOT NULL, session_provider_token TEXT NOT NULL, session_tunnel_password TEXT NOT NULL, session_tunnel_method TEXT NOT NULL, session_provider_extension TEXT NOT NULL)`,
	`CREATE TABLE active_session_nodes (position INTEGER PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES active_session(id) ON DELETE CASCADE, node_id TEXT NOT NULL, selector TEXT NOT NULL, provider TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, name TEXT NOT NULL, group_name TEXT NOT NULL, model TEXT NOT NULL, weight INTEGER NOT NULL, auto INTEGER NOT NULL, eligible INTEGER NOT NULL, excluded INTEGER NOT NULL, health TEXT NOT NULL, udp_health TEXT NOT NULL, tcp_rtt_ns INTEGER NOT NULL, probed_at_ns INTEGER)`,
	`CREATE TABLE active_session_selectors (selector TEXT PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES active_session(id) ON DELETE CASCADE, node_id TEXT NOT NULL, generation INTEGER NOT NULL, tombstoned INTEGER NOT NULL, tombstone_until_ns INTEGER)`,
	`CREATE TABLE browser_sessions (token TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires_at_ns INTEGER NOT NULL)`,
	`CREATE TABLE active_session_windows (id INTEGER PRIMARY KEY CHECK (id = 1) REFERENCES active_session(id) ON DELETE CASCADE, session_user_id TEXT NOT NULL, session_login_token TEXT NOT NULL, session_provider_token TEXT NOT NULL, session_tunnel_password TEXT NOT NULL, session_tunnel_method TEXT NOT NULL, session_provider_extension TEXT NOT NULL)`,
	`CREATE TABLE active_session_node_profiles (position INTEGER PRIMARY KEY REFERENCES active_session_nodes(position) ON DELETE CASCADE, client_profile TEXT NOT NULL)`,
}

func migrateSQLiteSchema(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, "SELECT version FROM schema_version WHERE id = 1").Scan(&version); err != nil {
		return corruptDatabase(err)
	}
	if version == sqliteSchemaVersion {
		return nil
	}
	if version == 4 {
		if err := validateSQLiteSchemaDefinition(ctx, db, 4, sqliteSchemaV4Tables, sqliteSchemaV5Statements[:len(sqliteSchemaV4Tables)]); err != nil {
			return err
		}
		if err := migrateSQLiteV4ToV5(ctx, db); err != nil {
			return err
		}
		version = 5
	}
	if version == 5 {
		if err := validateSQLiteSchemaDefinition(ctx, db, 5, sqliteSchemaV5Tables, sqliteSchemaV5Statements); err != nil {
			return err
		}
		if err := migrateSQLiteV5ToV6(ctx, db); err != nil {
			return err
		}
		version = 6
	}
	if version != 6 && version != 7 && version != 8 {
		return corruptDatabase(errors.New("unsupported SQLite schema version"))
	}
	if version == 6 {
		if err := validateSQLiteSchemaDefinition(ctx, db, 6, sqliteSchemaV6Tables, sqliteSchemaV6Statements); err != nil {
			return err
		}
		if err := migrateSQLiteV6ToV7(ctx, db); err != nil {
			return err
		}
		version = 7
	}
	if version == 7 {
		if err := validateSQLiteSchemaDefinition(ctx, db, 7, sqliteSchemaV6Tables, sqliteSchemaV7Statements); err != nil {
			return err
		}
		if err := migrateSQLiteV7ToV8(ctx, db); err != nil {
			return err
		}
	}
	if err := validateSQLiteSchemaDefinition(ctx, db, 8, sqliteSchemaV8Tables, sqliteSchemaV8Statements); err != nil {
		return err
	}
	return migrateSQLiteV8ToV9(ctx, db)
}

func migrateSQLiteV4ToV5(ctx context.Context, db *sql.DB) error {
	if err := configureSQLiteDurability(ctx, db); err != nil {
		return corruptDatabase(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	for _, statement := range sqliteSchemaV5Statements[len(sqliteSchemaV4Tables):] {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return corruptDatabase(err)
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO active_session_node_profiles (position, client_profile) SELECT position, 'ios' FROM active_session_nodes"); err != nil {
		return corruptDatabase(err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE schema_version SET version = 5 WHERE id = 1"); err != nil {
		return corruptDatabase(err)
	}
	if err := tx.Commit(); err != nil {
		return corruptDatabase(err)
	}
	return nil
}

func migrateSQLiteV5ToV6(ctx context.Context, db *sql.DB) error {
	if err := configureSQLiteDurability(ctx, db); err != nil {
		return corruptDatabase(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	// The v5 authority schema was inseparable from one provider account. A v6
	// migration securely discards only that renewable authority while retaining
	// access control, preferences, browser sessions, and last-good metadata.
	for _, table := range []string{"active_session_node_profiles", "active_session_windows", "active_session_selectors", "active_session_nodes", "active_session"} {
		if _, err := tx.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			return corruptDatabase(err)
		}
	}
	for _, statement := range sqliteSchemaV6Statements[8:13] {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return corruptDatabase(err)
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE schema_version SET version = 6 WHERE id = 1"); err != nil {
		return corruptDatabase(err)
	}
	if err := tx.Commit(); err != nil {
		return corruptDatabase(err)
	}
	return nil
}

func migrateSQLiteV6ToV7(ctx context.Context, db *sql.DB) error {
	if err := configureSQLiteDurability(ctx, db); err != nil {
		return corruptDatabase(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	// v6 stored one provider-neutral VIP bit that could not distinguish
	// QuickFox's Standard, VIP, and SVIP tiers. Discard renewable provider
	// authority and account-bound output rather than granting stale eligibility.
	for _, table := range []string{"active_session_selectors", "active_session_nodes", "active_session_authorities", "active_session_providers", "active_session"} {
		if _, err := tx.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			return corruptDatabase(err)
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM last_good_nodes"); err != nil {
		return corruptDatabase(err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE last_good SET generation = 0, created_at_ns = NULL, rendered_subscription = '', fetched_generation = 0, fetched_at_ns = NULL, fetched_body_hash = NULL WHERE id = 1"); err != nil {
		return corruptDatabase(err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE subscription_generation SET account_binding = NULL WHERE id = 1"); err != nil {
		return corruptDatabase(err)
	}
	for _, statement := range sqliteSchemaV7Statements[8:13] {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return corruptDatabase(err)
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE schema_version SET version = 7 WHERE id = 1"); err != nil {
		return corruptDatabase(err)
	}
	if err := tx.Commit(); err != nil {
		return corruptDatabase(err)
	}
	return nil
}

func migrateSQLiteV7ToV8(ctx context.Context, db *sql.DB) error {
	if err := configureSQLiteDurability(ctx, db); err != nil {
		return corruptDatabase(err)
	}
	selectorKey, err := randomBytes(32)
	if err != nil {
		return err
	}
	defer wipeBytes(selectorKey)
	proxyKey, err := randomBytes(32)
	if err != nil {
		return err
	}
	defer wipeBytes(proxyKey)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	// Historical provider IDs and selector derivations cannot be safely converted.
	for _, table := range []string{"active_session_selectors", "active_session_nodes", "active_session_authorities", "active_session_providers", "active_session", "last_good_nodes", "last_good", "subscription_generation"} {
		if _, err := tx.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			return corruptDatabase(err)
		}
	}
	for _, index := range []int{3, 6, 7, 8, 9, 10, 11, 12} {
		if _, err := tx.ExecContext(ctx, sqliteSchemaV8Statements[index]); err != nil {
			return corruptDatabase(err)
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO subscription_authority (id, selector_key, proxy_auth_key, account_binding, activated_at_ns) VALUES (1, ?, ?, NULL, ?)", selectorKey, proxyKey, nanos(time.Now().UTC())); err != nil {
		return corruptDatabase(err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO last_good (id, created_at_ns, rendered_subscription) VALUES (1, NULL, '')"); err != nil {
		return corruptDatabase(err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE schema_version SET version = 8 WHERE id = 1"); err != nil {
		return corruptDatabase(err)
	}
	if err := tx.Commit(); err != nil {
		return corruptDatabase(err)
	}
	return nil
}

func validateSQLiteSchema(ctx context.Context, db *sql.DB) error {
	return validateSQLiteSchemaDefinition(ctx, db, sqliteSchemaVersion, sqliteSchemaTables, sqliteSchemaStatements)
}

func validateSQLiteSchemaDefinition(ctx context.Context, db *sql.DB, expectedVersion int, expectedTables map[string]int, expectedStatements []string) error {
	if err := validateSQLiteJournalMode(ctx, db); err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
	if err != nil {
		return corruptDatabase(err)
	}
	defer rows.Close()
	tables := make(map[string]struct{}, len(expectedTables))
	for rows.Next() {
		var objectType, name, tableName string
		var definition sql.NullString
		if err := rows.Scan(&objectType, &name, &tableName, &definition); err != nil {
			return corruptDatabase(err)
		}
		statementIndex, expected := expectedTables[name]
		if !expected || objectType != "table" || tableName != name || !definition.Valid || statementIndex >= len(expectedStatements) || definition.String != expectedStatements[statementIndex] {
			return corruptDatabase(fmt.Errorf("unexpected SQLite schema object %q", name))
		}
		if _, duplicate := tables[name]; duplicate {
			return corruptDatabase(fmt.Errorf("duplicate SQLite table %q", name))
		}
		tables[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return corruptDatabase(err)
	}
	if len(tables) != len(expectedTables) {
		return corruptDatabase(errors.New("missing SQLite schema tables"))
	}
	versions, err := db.QueryContext(ctx, "SELECT id, version FROM schema_version")
	if err != nil {
		return corruptDatabase(err)
	}
	defer versions.Close()
	count := 0
	for versions.Next() {
		var id, version int
		if err := versions.Scan(&id, &version); err != nil {
			return corruptDatabase(err)
		}
		if id != 1 || version != expectedVersion {
			return corruptDatabase(errors.New("unsupported SQLite schema version"))
		}
		count++
	}
	if err := versions.Err(); err != nil || count != 1 {
		if err != nil {
			return corruptDatabase(err)
		}
		return corruptDatabase(errors.New("missing SQLite schema version"))
	}
	foreign, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return corruptDatabase(err)
	}
	defer foreign.Close()
	if foreign.Next() {
		return corruptDatabase(errors.New("foreign key violation"))
	}
	if err := foreign.Err(); err != nil {
		return corruptDatabase(err)
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

func replacePersistentStateTx(ctx context.Context, tx *sql.Tx, state PersistentState) error {
	if err := ValidatePersistentState(state); err != nil {
		return fmt.Errorf("refusing invalid persistent state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM state_metadata WHERE id = 1"); err != nil {
		return corruptDatabase(err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO state_metadata (id, installation_id) VALUES (1, ?)", state.InstallationID); err != nil {
		return corruptDatabase(err)
	}
	if state.AccessTokenVerifier != nil {
		verifier := state.AccessTokenVerifier
		if _, err := tx.ExecContext(ctx, "INSERT INTO access_token_verifier (id, memory_kib, iterations, parallelism, salt, hash) VALUES (1, ?, ?, ?, ?, ?)", verifier.Parameters.MemoryKiB, verifier.Parameters.Iterations, verifier.Parameters.Parallelism, verifier.Salt, verifier.Hash); err != nil {
			return corruptDatabase(err)
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO preferences (id, reveal_endpoints, refresh_policy) VALUES (1, ?, ?)", boolInt(state.Preferences.RevealEndpoints), state.Preferences.RefreshPolicy); err != nil {
		return corruptDatabase(err)
	}
	excluded := make([]string, 0, len(state.Preferences.ExcludedNodeIDs))
	for nodeID := range state.Preferences.ExcludedNodeIDs {
		excluded = append(excluded, nodeID)
	}
	sort.Strings(excluded)
	excludedStatement, err := tx.PrepareContext(ctx, "INSERT INTO excluded_node_ids (node_id, preference_id) VALUES (?, 1)")
	if err != nil {
		return corruptDatabase(err)
	}
	defer func() { _ = excludedStatement.Close() }()
	for _, nodeID := range excluded {
		if _, err := excludedStatement.ExecContext(ctx, nodeID); err != nil {
			return corruptDatabase(err)
		}
	}
	if state.ActiveSession != nil {
		if err := insertActiveSessionTx(ctx, tx, state.ActiveSession); err != nil {
			return err
		}
	}
	return nil
}

func insertActiveSessionTx(ctx context.Context, tx *sql.Tx, snapshot *RuntimeSnapshot) error {
	if snapshot == nil {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO active_session (id, generation, created_at_ns, expires_at_ns) VALUES (1, ?, ?, ?)", snapshot.Generation, nanos(snapshot.CreatedAt), nanos(snapshot.ExpiresAt)); err != nil {
		return corruptDatabase(err)
	}
	providerIDs := make([]string, 0, len(snapshot.Providers))
	for id := range snapshot.Providers {
		providerIDs = append(providerIDs, string(id))
	}
	sort.Strings(providerIDs)
	providerStatement, err := tx.PrepareContext(ctx, "INSERT INTO active_session_providers (provider_id, session_id, expires_at_ns, user_id, account_display, account_tier, subscription_active, subscription_ends_at_ns, refresh_state) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return corruptDatabase(err)
	}
	defer func() { _ = providerStatement.Close() }()
	authorityStatement, err := tx.PrepareContext(ctx, "INSERT INTO active_session_authorities (provider_id, authority_id, protocol, authority) VALUES (?, ?, ?, ?)")
	if err != nil {
		return corruptDatabase(err)
	}
	defer func() { _ = authorityStatement.Close() }()
	for _, rawID := range providerIDs {
		providerSnapshot := snapshot.Providers[provider.ID(rawID)]
		account := providerSnapshot.Account
		if _, err := providerStatement.ExecContext(ctx, rawID, nanos(providerSnapshot.ExpiresAt), account.UserID, account.Display, account.Tier, boolInt(account.SubscriptionActive), nullableNanos(account.SubscriptionEndsAt), providerSnapshot.RefreshState); err != nil {
			return corruptDatabase(err)
		}
		authorityIDs := make([]string, 0, len(providerSnapshot.Authorities))
		for authorityID := range providerSnapshot.Authorities {
			authorityIDs = append(authorityIDs, authorityID)
		}
		sort.Strings(authorityIDs)
		for _, authorityID := range authorityIDs {
			authority := providerSnapshot.Authorities[authorityID]
			if _, err := authorityStatement.ExecContext(ctx, rawID, authorityID, string(authority.Protocol), authority.Data); err != nil {
				return corruptDatabase(err)
			}
		}
	}
	nodeStatement, err := tx.PrepareContext(ctx, "INSERT INTO active_session_nodes (position, session_id, node_id, provider_id, protocol, authority_id, host, port, name, group_name, model, weight, auto, eligible, excluded, health, udp_health, tcp_rtt_ns, probed_at_ns) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return corruptDatabase(err)
	}
	defer func() { _ = nodeStatement.Close() }()
	for index, node := range snapshot.Nodes {
		if _, err := nodeStatement.ExecContext(ctx, index, node.ID, string(node.Provider), string(node.Protocol), node.AuthorityID, node.Host, node.Port, node.Name, node.Group, node.Model, node.Weight, boolInt(node.Auto), boolInt(node.Eligible), boolInt(node.Excluded), string(node.Health), string(node.UDPHealth), int64(node.TCPRTT), nullableNanos(node.ProbedAt)); err != nil {
			return corruptDatabase(err)
		}
	}
	return nil
}

func loadPersistentStateTx(ctx context.Context, tx *sql.Tx) (PersistentState, error) {
	var state PersistentState
	if err := tx.QueryRowContext(ctx, "SELECT installation_id FROM state_metadata WHERE id = 1").Scan(&state.InstallationID); err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	var memory, iterations, parallelism int64
	var salt, hash []byte
	err := tx.QueryRowContext(ctx, "SELECT memory_kib, iterations, parallelism, salt, hash FROM access_token_verifier WHERE id = 1").Scan(&memory, &iterations, &parallelism, &salt, &hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return PersistentState{}, corruptDatabase(err)
	default:
		if memory < 0 || memory > int64(^uint32(0)) || iterations < 0 || iterations > int64(^uint32(0)) || parallelism < 0 || parallelism > int64(^uint8(0)) {
			return PersistentState{}, corruptDatabase(errors.New("invalid verifier parameters"))
		}
		state.AccessTokenVerifier = &AccessTokenVerifier{Parameters: Argon2idParameters{MemoryKiB: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallelism)}, Salt: append([]byte(nil), salt...), Hash: append([]byte(nil), hash...)}
	}
	var reveal int64
	if err := tx.QueryRowContext(ctx, "SELECT reveal_endpoints, refresh_policy FROM preferences WHERE id = 1").Scan(&reveal, &state.Preferences.RefreshPolicy); err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	value, err := intBool(reveal)
	if err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	state.Preferences.RevealEndpoints = value
	state.Preferences.ExcludedNodeIDs = make(map[string]bool)
	excludedRows, err := tx.QueryContext(ctx, "SELECT node_id FROM excluded_node_ids WHERE preference_id = 1")
	if err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	defer excludedRows.Close()
	for excludedRows.Next() {
		var nodeID string
		if err := excludedRows.Scan(&nodeID); err != nil {
			return PersistentState{}, corruptDatabase(err)
		}
		if _, duplicate := state.Preferences.ExcludedNodeIDs[nodeID]; duplicate {
			return PersistentState{}, corruptDatabase(errors.New("duplicate excluded node id"))
		}
		state.Preferences.ExcludedNodeIDs[nodeID] = true
	}
	if err := excludedRows.Close(); err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	if err := excludedRows.Err(); err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	active, err := loadActiveSessionTx(ctx, tx)
	if err != nil {
		return PersistentState{}, err
	}
	state.ActiveSession = active
	if state.ActiveSession != nil {
		authority, err := state.Identity()
		if err != nil {
			return PersistentState{}, corruptDatabase(err)
		}
		state.ActiveSession.Selectors, err = BuildSelectors(state.ActiveSession.Nodes, authority)
		if err != nil {
			return PersistentState{}, corruptDatabase(err)
		}
		state.ActiveSession.nodeIndex = make(map[string]int, len(state.ActiveSession.Nodes))
		for index := range state.ActiveSession.Nodes {
			state.ActiveSession.nodeIndex[state.ActiveSession.Nodes[index].ID] = index
			credentials, _ := authority.Credentials(state.ActiveSession.Nodes[index].Route())
			state.ActiveSession.Nodes[index].Selector = credentials.Username
		}
	}
	if err := ValidatePersistentState(state); err != nil {
		return PersistentState{}, corruptDatabase(err)
	}
	return state, nil
}

func loadActiveSessionTx(ctx context.Context, tx *sql.Tx) (*RuntimeSnapshot, error) {
	var snapshot RuntimeSnapshot
	var created, expires int64
	err := tx.QueryRowContext(ctx, "SELECT generation, created_at_ns, expires_at_ns FROM active_session WHERE id = 1").Scan(&snapshot.Generation, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, corruptDatabase(err)
	}
	snapshot.CreatedAt = time.Unix(0, created).UTC()
	snapshot.ExpiresAt = time.Unix(0, expires).UTC()
	snapshot.Providers = make(map[provider.ID]provider.Snapshot)
	providerRows, err := tx.QueryContext(ctx, "SELECT provider_id, expires_at_ns, user_id, account_display, account_tier, subscription_active, subscription_ends_at_ns, refresh_state FROM active_session_providers WHERE session_id = 1 ORDER BY provider_id")
	if err != nil {
		return nil, corruptDatabase(err)
	}
	defer providerRows.Close()
	for providerRows.Next() {
		var rawID, userID, display, tier string
		var providerExpires, activeValue int64
		var subscriptionEnds sql.NullInt64
		var refreshState []byte
		if err := providerRows.Scan(&rawID, &providerExpires, &userID, &display, &tier, &activeValue, &subscriptionEnds, &refreshState); err != nil {
			return nil, corruptDatabase(err)
		}
		active, err := intBool(activeValue)
		if err != nil {
			return nil, corruptDatabase(err)
		}
		id := provider.ID(rawID)
		if _, duplicate := snapshot.Providers[id]; duplicate {
			return nil, corruptDatabase(errors.New("duplicate provider session"))
		}
		snapshot.Providers[id] = provider.Snapshot{
			Provider: id, ExpiresAt: time.Unix(0, providerExpires).UTC(), RefreshState: append([]byte(nil), refreshState...),
			Account:     provider.Account{UserID: userID, Display: display, Tier: tier, SubscriptionActive: active, SubscriptionEndsAt: timeFromNullable(subscriptionEnds)},
			Authorities: make(map[string]provider.Authority),
		}
	}
	if err := providerRows.Close(); err != nil {
		return nil, corruptDatabase(err)
	}
	if err := providerRows.Err(); err != nil {
		return nil, corruptDatabase(err)
	}
	authorityRows, err := tx.QueryContext(ctx, "SELECT provider_id, authority_id, protocol, authority FROM active_session_authorities ORDER BY provider_id, authority_id")
	if err != nil {
		return nil, corruptDatabase(err)
	}
	defer authorityRows.Close()
	for authorityRows.Next() {
		var rawID, authorityID, rawProtocol string
		var authorityData []byte
		if err := authorityRows.Scan(&rawID, &authorityID, &rawProtocol, &authorityData); err != nil {
			return nil, corruptDatabase(err)
		}
		id := provider.ID(rawID)
		providerSnapshot, available := snapshot.Providers[id]
		if !available {
			return nil, corruptDatabase(errors.New("authority references absent provider"))
		}
		if _, duplicate := providerSnapshot.Authorities[authorityID]; duplicate {
			return nil, corruptDatabase(errors.New("duplicate provider authority"))
		}
		providerSnapshot.Authorities[authorityID] = provider.Authority{Protocol: provider.Protocol(rawProtocol), Data: append([]byte(nil), authorityData...)}
		snapshot.Providers[id] = providerSnapshot
	}
	if err := authorityRows.Close(); err != nil {
		return nil, corruptDatabase(err)
	}
	if err := authorityRows.Err(); err != nil {
		return nil, corruptDatabase(err)
	}
	nodeRows, err := tx.QueryContext(ctx, "SELECT node_id, provider_id, protocol, authority_id, host, port, name, group_name, model, weight, auto, eligible, excluded, health, udp_health, tcp_rtt_ns, probed_at_ns FROM active_session_nodes WHERE session_id = 1 ORDER BY position")
	if err != nil {
		return nil, corruptDatabase(err)
	}
	defer nodeRows.Close()
	for nodeRows.Next() {
		var node Node
		var rawProvider, rawProtocol string
		var port, auto, eligible, excluded, rtt int64
		var probed sql.NullInt64
		var health, udp string
		if err := nodeRows.Scan(&node.ID, &rawProvider, &rawProtocol, &node.AuthorityID, &node.Host, &port, &node.Name, &node.Group, &node.Model, &node.Weight, &auto, &eligible, &excluded, &health, &udp, &rtt, &probed); err != nil {
			return nil, corruptDatabase(err)
		}
		if port < 0 || port > 65535 {
			return nil, corruptDatabase(errors.New("invalid active node port"))
		}
		var conversionErr error
		if node.Auto, conversionErr = intBool(auto); conversionErr != nil {
			return nil, corruptDatabase(conversionErr)
		}
		if node.Eligible, conversionErr = intBool(eligible); conversionErr != nil {
			return nil, corruptDatabase(conversionErr)
		}
		if node.Excluded, conversionErr = intBool(excluded); conversionErr != nil {
			return nil, corruptDatabase(conversionErr)
		}
		node.Provider, node.Protocol = provider.ID(rawProvider), provider.Protocol(rawProtocol)
		node.Port, node.Health, node.UDPHealth, node.TCPRTT, node.ProbedAt = uint16(port), NodeHealth(health), UDPHealth(udp), time.Duration(rtt), timeFromNullable(probed)
		snapshot.Nodes = append(snapshot.Nodes, node)
		providerSnapshot, available := snapshot.Providers[node.Provider]
		if !available {
			return nil, corruptDatabase(errors.New("node references absent provider"))
		}
		providerSnapshot.Nodes = append(providerSnapshot.Nodes, provider.Node{
			ID: node.ID, AuthorityID: node.AuthorityID, Protocol: node.Protocol, Host: node.Host, Port: node.Port,
			Name: node.Name, Group: node.Group, Model: node.Model, Weight: node.Weight, Auto: node.Auto, Eligible: node.Eligible,
		})
		snapshot.Providers[node.Provider] = providerSnapshot
	}
	if err := nodeRows.Close(); err != nil {
		return nil, corruptDatabase(err)
	}
	if err := nodeRows.Err(); err != nil {
		return nil, corruptDatabase(err)
	}
	return &snapshot, nil
}

// RestoreBrowserSessions restores hashed cookie identities and CSRF values.
func (s *SQLiteStore) RestoreBrowserSessions(ctx context.Context, now time.Time, max int, add func(tokenHash []byte, csrf string, expiresAt time.Time) error) error {
	if s == nil || add == nil || !validBrowserSessionLimit(max) {
		return ErrInsecureStatePath
	}
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.ensureOpenLocked(ctx, false, nil); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	if err := pruneBrowserSessionsTx(ctx, tx, now, max); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT token_hash, csrf, expires_at_ns FROM browser_sessions ORDER BY expires_at_ns DESC, token_hash")
	if err != nil {
		return corruptDatabase(err)
	}
	defer rows.Close()
	for rows.Next() {
		var tokenHash []byte
		var csrf string
		var expires int64
		if err := rows.Scan(&tokenHash, &csrf, &expires); err != nil {
			return corruptDatabase(err)
		}
		expiresAt := time.Unix(0, expires).UTC()
		if !validHashedBrowserSession(tokenHash, csrf, expiresAt, now) {
			return corruptDatabase(errors.New("malformed browser session"))
		}
		if err := add(tokenHash, csrf, expiresAt); err != nil {
			return err
		}
	}
	if err := rows.Close(); err != nil {
		return corruptDatabase(err)
	}
	if err := rows.Err(); err != nil {
		return corruptDatabase(err)
	}
	return corruptDatabase(tx.Commit())
}

// SaveBrowserSession persists one unexpired opaque cookie/CSRF pair, pruning
// expired sessions and respecting the caller's configured maximum.
func (s *SQLiteStore) SaveBrowserSession(ctx context.Context, token, csrf string, expiresAt time.Time, max int) error {
	if s == nil || !validBrowserSessionLimit(max) {
		return ErrInsecureStatePath
	}
	now := s.now().UTC()
	expiresAt = expiresAt.UTC()
	if !validBrowserSession(token, csrf, expiresAt, now) {
		return ErrCorruptState
	}
	hash := BrowserSessionTokenHash(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.ensureOpenLocked(ctx, false, nil); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	if err := pruneBrowserSessionsTx(ctx, tx, now, max); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM browser_sessions WHERE token_hash = ?", hash[:]).Scan(&exists); err != nil {
		return corruptDatabase(err)
	}
	if exists == 0 {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM browser_sessions").Scan(&count); err != nil {
			return corruptDatabase(err)
		}
		if count >= max {
			return fmt.Errorf("browser session limit reached")
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO browser_sessions (token_hash, csrf, expires_at_ns) VALUES (?, ?, ?) ON CONFLICT(token_hash) DO UPDATE SET csrf = excluded.csrf, expires_at_ns = excluded.expires_at_ns", hash[:], csrf, nanos(expiresAt)); err != nil {
		return corruptDatabase(err)
	}
	return corruptDatabase(tx.Commit())
}

// DeleteBrowserSession durably revokes a hashed browser cookie identity.
func (s *SQLiteStore) DeleteBrowserSession(ctx context.Context, hash []byte) error {
	if s == nil || len(hash) != sha256.Size {
		return ErrCorruptState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.ensureOpenLocked(ctx, false, nil); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return corruptDatabase(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM browser_sessions WHERE token_hash = ?", hash); err != nil {
		return corruptDatabase(err)
	}
	return corruptDatabase(tx.Commit())
}

// DeleteAllBrowserSessions durably invalidates every local browser session.
func (s *SQLiteStore) DeleteAllBrowserSessions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.ensureOpenLocked(ctx, false, nil); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM browser_sessions")
	return corruptDatabase(err)
}

func BrowserSessionTokenHash(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

func validHashedBrowserSession(hash []byte, csrf string, expiresAt, now time.Time) bool {
	return len(hash) == sha256.Size && validOpaqueBrowserToken(csrf) && !expiresAt.IsZero() && expiresAt.After(now) && !expiresAt.After(now.Add(maxSessionLifetime))
}

func validateBrowserSessionsTx(ctx context.Context, tx *sql.Tx, now time.Time, max int, prune bool) error {
	if prune {
		if err := pruneBrowserSessionsTx(ctx, tx, now, max); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT token_hash, csrf, expires_at_ns FROM browser_sessions")
	if err != nil {
		return corruptDatabase(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var tokenHash []byte
		var csrf string
		var expires int64
		if err := rows.Scan(&tokenHash, &csrf, &expires); err != nil {
			return corruptDatabase(err)
		}
		expiresAt := time.Unix(0, expires).UTC()
		if !expiresAt.After(now) {
			if prune {
				return corruptDatabase(errors.New("expired browser session remained after prune"))
			}
			continue
		}
		if !validHashedBrowserSession(tokenHash, csrf, expiresAt, now) {
			return corruptDatabase(errors.New("malformed browser session"))
		}
		count++
	}
	if err := rows.Close(); err != nil {
		return corruptDatabase(err)
	}
	if err := rows.Err(); err != nil {
		return corruptDatabase(err)
	}
	if count > max {
		return corruptDatabase(errors.New("browser session limit exceeded"))
	}
	return nil
}

func pruneBrowserSessionsTx(ctx context.Context, tx *sql.Tx, now time.Time, max int) error {
	if !validBrowserSessionLimit(max) {
		return ErrCorruptState
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM browser_sessions WHERE expires_at_ns <= ?", nanos(now)); err != nil {
		return corruptDatabase(err)
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM browser_sessions WHERE token_hash IN (SELECT token_hash FROM browser_sessions ORDER BY expires_at_ns DESC, token_hash LIMIT -1 OFFSET ?)", max)
	return corruptDatabase(err)
}

func validBrowserSessionLimit(max int) bool { return max > 0 && max <= maxBrowserSessions }

func validBrowserSession(token, csrf string, expiresAt, now time.Time) bool {
	return validOpaqueBrowserToken(token) && validOpaqueBrowserToken(csrf) && !expiresAt.IsZero() && expiresAt.After(now) && !expiresAt.After(now.Add(maxSessionLifetime))
}

func validOpaqueBrowserToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func intBool(value int64) (bool, error) {
	switch value {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("invalid boolean value")
	}
}

func nanos(value time.Time) int64 { return value.UTC().UnixNano() }

func nullableNanos(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return nanos(value)
}

func timeFromNullable(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(0, value.Int64).UTC()
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

func checkSQLiteIntegrity(ctx context.Context, db *sql.DB) error {
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check(1)").Scan(&integrity); err != nil {
		return corruptDatabase(err)
	}
	if integrity != "ok" {
		return corruptDatabase(errors.New("SQLite integrity check failed"))
	}
	return nil
}
