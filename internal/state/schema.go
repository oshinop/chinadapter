package state

import (
	"context"
	"database/sql"
	"strings"
)

var sqliteSchemaTables = map[string]int{
	"schema_version": 0, "state_metadata": 1, "access_token_verifier": 2,
	"preferences": 3, "excluded_node_ids": 4, "active_session": 5,
	"active_session_providers": 6, "active_session_authorities": 7,
	"active_session_nodes": 8, "browser_sessions": 9,
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
