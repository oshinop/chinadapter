package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	domain "github.com/oshinop/chinadapter/internal/state"
)

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
	selectorKey, err := domain.RandomBytes(32)
	if err != nil {
		return err
	}
	defer domain.WipeBytes(selectorKey)
	proxyKey, err := domain.RandomBytes(32)
	if err != nil {
		return err
	}
	defer domain.WipeBytes(proxyKey)
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
