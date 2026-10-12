package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
	domain "github.com/oshinop/chinadapter/internal/state"
)

func TestV8FixtureMigrationPreservesProvidersAndSessions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/v8.db")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, sqliteStateFileName)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	store, err := NewSQLiteStore(directory, WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(t.Context())
	loaded, err := store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.InstallationID != "00112233445566778899aabbccddeeff" || !loaded.VerifyAccessToken("v8 fixture access token") || loaded.Preferences.RefreshPolicy != "1h" || !loaded.Preferences.RevealEndpoints {
		t.Fatal("durable local authority or preferences lost")
	}
	if loaded.ActiveSession == nil || len(loaded.ActiveSession.Providers) != 2 || len(loaded.ActiveSession.Nodes) != 2 {
		t.Fatal("migration requires provider re-login")
	}
	for _, id := range []provider.ID{"kuaifan", "quickfox"} {
		snapshot, exists := loaded.ActiveSession.Providers[id]
		if !exists || !snapshot.Valid() || snapshot.Account.UserID != string(id)+"-fixture-user" || len(snapshot.RefreshState) == 0 || len(snapshot.Authorities) != 1 {
			t.Fatalf("provider %s not preserved", id)
		}
		if authority, exists := snapshot.Authorities["default"]; !exists || len(authority.Data) == 0 {
			t.Fatal("tunnel authority lost")
		}
		expected, err := provider.NodeID(provider.Route{Provider: id, Protocol: snapshot.Nodes[0].Protocol, Host: snapshot.Nodes[0].Host, Port: snapshot.Nodes[0].Port})
		if err != nil || snapshot.Nodes[0].ID != expected {
			t.Fatal("node ID not remapped from persisted route")
		}
		if node, found := loaded.ActiveSession.NodeByID(expected); !found || node.Provider != id {
			t.Fatal("loaded catalog node lookup not indexed")
		}
		if id == "kuaifan" && !loaded.Preferences.ExcludedNodeIDs[expected] {
			t.Fatal("excluded ID not remapped")
		}
	}
	if len(loaded.Preferences.ExcludedNodeIDs) != 1 {
		t.Fatal("unmapped exclusion retained")
	}
	if len(loaded.ActiveSession.Selectors) != 2 {
		t.Fatal("live credential map not rebuilt")
	}
	var version int
	if err := store.db.QueryRowContext(t.Context(), "SELECT version FROM schema_version WHERE id = 1").Scan(&version); err != nil || version != 9 {
		t.Fatalf("schema version %d: %v", version, err)
	}
	if err := validateSQLiteSchema(t.Context(), store.db); err != nil {
		t.Fatal(err)
	}
	rawToken := "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	expectedHash := BrowserSessionTokenHash(rawToken)
	var hash []byte
	var expires int64
	if err := store.db.QueryRowContext(t.Context(), "SELECT token_hash, expires_at_ns FROM browser_sessions").Scan(&hash, &expires); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash, expectedHash[:]) {
		t.Fatal("raw browser session token not hashed")
	}
	restored := false
	if err := store.RestoreBrowserSessions(t.Context(), time.Unix(0, expires).Add(-time.Hour), 4096, func(hash []byte, _ time.Time) error {
		restored = bytes.Equal(hash, expectedHash[:])
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !restored {
		t.Fatal("existing browser session invalidated")
	}
}

func TestHistoricalSchemasMigrateToExactV9(t *testing.T) {
	for _, fixture := range []struct {
		version    int
		statements []string
	}{
		{4, sqliteSchemaV5Statements[:len(sqliteSchemaV4Tables)]}, {5, sqliteSchemaV5Statements}, {6, sqliteSchemaV6Statements}, {7, sqliteSchemaV7Statements},
	} {
		t.Run(fmt.Sprintf("v%d", fixture.version), func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, sqliteStateFileName)
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			for _, statement := range fixture.statements {
				if _, err := db.ExecContext(t.Context(), statement); err != nil {
					t.Fatal(err)
				}
			}
			for _, query := range []string{
				fmt.Sprintf("INSERT INTO schema_version (id,version) VALUES (1,%d)", fixture.version),
				"INSERT INTO state_metadata (id,installation_id) VALUES (1,'00112233445566778899aabbccddeeff')",
				"INSERT INTO preferences (id,reveal_endpoints,refresh_policy) VALUES (1,1,'1h')",
				"INSERT INTO subscription_generation (id,generation,selector_key,proxy_auth_key,account_binding,activated_at_ns) VALUES (1,1,zeroblob(32),zeroblob(32),NULL,1)",
				"INSERT INTO last_good (id,generation,created_at_ns,rendered_subscription,fetched_generation) VALUES (1,0,NULL,'',0)",
			} {
				if _, err := db.ExecContext(t.Context(), query); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			store, err := NewSQLiteStore(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close(t.Context())
			loaded, err := store.Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if loaded.ActiveSession != nil || !loaded.Preferences.RevealEndpoints {
				t.Fatal("historical migration changed durable preferences")
			}
			if err := validateSQLiteSchema(t.Context(), store.db); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoreLoadIsReadOnlyAndContextAware(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	store, err := NewSQLiteStore(directory, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(t.Context())
	if _, err := store.LoadOrCreate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(t.Context(), "INSERT INTO browser_sessions (token_hash,csrf,expires_at_ns) VALUES (zeroblob(32),'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI',1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM browser_sessions").Scan(&count); err != nil || count != 1 {
		t.Fatal("Load pruned expired sessions")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Load = %v", err)
	}
}

func newClockedStore(t *testing.T) (*SQLiteStore, time.Time) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	store, err := NewSQLiteStore(directory, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return store, now
}

func TestBrowserSessionEvictionKeepsNewestExpiry(t *testing.T) {
	store, now := newClockedStore(t)
	tokens := make([]string, 3)
	for index := range tokens {
		tokens[index] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32))
		if err := store.SaveBrowserSession(t.Context(), tokens[index], now.Add(time.Duration(index+1)*time.Hour), 4096); err != nil {
			t.Fatal(err)
		}
	}
	restored := make(map[string]bool)
	if err := store.RestoreBrowserSessions(t.Context(), now, 2, func(hash []byte, _ time.Time) error { restored[string(hash)] = true; return nil }); err != nil {
		t.Fatal(err)
	}
	oldest := BrowserSessionTokenHash(tokens[0])
	if len(restored) != 2 || restored[string(oldest[:])] {
		t.Fatal("eviction retained oldest session")
	}
	for _, token := range tokens[1:] {
		hash := BrowserSessionTokenHash(token)
		if !restored[string(hash[:])] {
			t.Fatal("newest session evicted")
		}
	}
}

func TestBrowserSessionPersistenceIgnoresLegacyCSRFColumn(t *testing.T) {
	store, now := newClockedStore(t)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	expiresAt := now.Add(time.Hour)
	if err := store.SaveBrowserSession(t.Context(), token, expiresAt, 4096); err != nil {
		t.Fatal(err)
	}
	var legacyValue string
	if err := store.db.QueryRowContext(t.Context(), "SELECT csrf FROM browser_sessions").Scan(&legacyValue); err != nil {
		t.Fatal(err)
	}
	if legacyValue != "" {
		t.Fatal("new session persisted unused legacy material")
	}
	if _, err := store.db.ExecContext(t.Context(), "UPDATE browser_sessions SET csrf = 'unused legacy value'"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(t.Context()); err != nil {
		t.Fatalf("legacy column prevented state validation: %v", err)
	}
	expectedHash := BrowserSessionTokenHash(token)
	restored := false
	if err := store.RestoreBrowserSessions(t.Context(), now, 4096, func(hash []byte, expires time.Time) error {
		restored = bytes.Equal(hash, expectedHash[:]) && expires.Equal(expiresAt)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !restored {
		t.Fatal("legacy column prevented session restoration")
	}
}

func TestVerifierChangeRevokesDurableSessionsAtomically(t *testing.T) {
	store, now := newClockedStore(t)
	if _, err := store.Update(t.Context(), func(candidate *domain.PersistentState) error {
		return candidate.SetAccessToken("original fixture access token")
	}); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if err := store.SaveBrowserSession(t.Context(), token, now.Add(time.Hour), 4096); err != nil {
		t.Fatal(err)
	}
	original, err := store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(t.Context(), func(candidate *domain.PersistentState) error {
		return candidate.ChangeAccessToken("incorrect fixture access token", "replacement fixture access token")
	}); !errors.Is(err, domain.ErrInvalidAccessToken) {
		t.Fatalf("wrong-current change = %v", err)
	}
	if _, err := store.Update(t.Context(), func(candidate *domain.PersistentState) error {
		return candidate.ChangeAccessToken("original fixture access token", "original fixture access token")
	}); !errors.Is(err, domain.ErrInvalidNextAccessToken) {
		t.Fatalf("same-token change = %v", err)
	}
	changed, err := store.Update(t.Context(), func(candidate *domain.PersistentState) error {
		return candidate.ChangeAccessToken("original fixture access token", "replacement fixture access token")
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original.AccessTokenVerifier.Salt, changed.AccessTokenVerifier.Salt) || bytes.Equal(original.AccessTokenVerifier.Hash, changed.AccessTokenVerifier.Hash) {
		t.Fatal("verifier salt or derived hash reused")
	}
	var count int
	if err := store.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM browser_sessions").Scan(&count); err != nil || count != 0 {
		t.Fatal("verifier update left durable sessions")
	}
}

func TestStateBusyIsNotCorruption(t *testing.T) {
	store, _ := newClockedStore(t)
	if _, err := store.db.ExecContext(t.Context(), "PRAGMA busy_timeout = 1"); err != nil {
		t.Fatal(err)
	}
	external, err := sql.Open("sqlite", store.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer external.Close()
	connection, err := external.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = connection.ExecContext(context.Background(), "ROLLBACK") }()
	_, err = store.Update(t.Context(), func(*domain.PersistentState) error { return nil })
	if !errors.Is(err, domain.ErrStateBusy) || errors.Is(err, domain.ErrCorruptState) {
		t.Fatalf("busy state classification = %v", err)
	}
}
