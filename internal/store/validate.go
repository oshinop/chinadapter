package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	domain "github.com/kfadapter/kfadapter/internal/state"
)

// ValidateStateDir requires a real, current-user-owned 0700 directory.
func ValidateStateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state directory %q: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("state directory %q: %w", dir, domain.ErrInsecureStatePath)
	}
	if err := ownedByCurrentUser(info); err != nil {
		return fmt.Errorf("state directory %q: %w", dir, err)
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return domain.ErrInsecureStatePath
	}
	return nil
}

func hasSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func (s *SQLiteStore) validate() error {
	if s == nil {
		return domain.ErrInsecureStatePath
	}
	return ValidateStateDir(s.dir)
}

func validatePersistentStateSemantics(state domain.PersistentState, validators []func(domain.PersistentState) error) error {
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

func validateEmptyStateDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read state directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("state directory contains an unexpected artifact: %w", domain.ErrInsecureStatePath)
	}
	return nil
}

func stateFileExists(path string, maximum int64) (bool, error) {
	err := validateSecureStateFile(path, maximum)
	if errors.Is(err, domain.ErrStateNotFound) {
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
		return nil, domain.ErrStateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("stat state file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !hasSingleLink(info) {
		return nil, domain.ErrInsecureStatePath
	}
	if err := ownedByCurrentUser(info); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, domain.ErrStateNotFound
	}
	if errors.Is(err, syscall.ELOOP) {
		return nil, domain.ErrInsecureStatePath
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
		return nil, domain.ErrInsecureStatePath
	}
	if err := ownedByCurrentUser(opened); err != nil {
		_ = file.Close()
		return nil, err
	}
	if opened.Size() < 0 || opened.Size() > maximum {
		_ = file.Close()
		return nil, fmt.Errorf("%w: state file exceeds maximum size", domain.ErrCorruptState)
	}
	return file, nil
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
