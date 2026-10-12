package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	domain "github.com/oshinop/chinadapter/internal/state"
)

// RestoreBrowserSessions restores hashed cookie identities and expiry.
func (s *SQLiteStore) RestoreBrowserSessions(ctx context.Context, now time.Time, max int, add func(tokenHash []byte, expiresAt time.Time) error) error {
	if s == nil || add == nil || !validBrowserSessionLimit(max) {
		return domain.ErrInsecureStatePath
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
	rows, err := tx.QueryContext(ctx, "SELECT token_hash, expires_at_ns FROM browser_sessions ORDER BY expires_at_ns DESC, token_hash")
	if err != nil {
		return corruptDatabase(err)
	}
	defer rows.Close()
	for rows.Next() {
		var tokenHash []byte
		var expires int64
		if err := rows.Scan(&tokenHash, &expires); err != nil {
			return corruptDatabase(err)
		}
		expiresAt := time.Unix(0, expires).UTC()
		if !validHashedBrowserSession(tokenHash, expiresAt, now) {
			return corruptDatabase(errors.New("malformed browser session"))
		}
		if err := add(tokenHash, expiresAt); err != nil {
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

// SaveBrowserSession persists one unexpired opaque cookie identity, pruning
// expired sessions and respecting the caller's configured maximum.
func (s *SQLiteStore) SaveBrowserSession(ctx context.Context, token string, expiresAt time.Time, max int) error {
	if s == nil || !validBrowserSessionLimit(max) {
		return domain.ErrInsecureStatePath
	}
	now := s.now().UTC()
	expiresAt = expiresAt.UTC()
	if !validBrowserSession(token, expiresAt, now) {
		return domain.ErrCorruptState
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
	// Retain the unused legacy column to preserve the schema without a migration.
	if _, err := tx.ExecContext(ctx, "INSERT INTO browser_sessions (token_hash, csrf, expires_at_ns) VALUES (?, '', ?) ON CONFLICT(token_hash) DO UPDATE SET csrf = '', expires_at_ns = excluded.expires_at_ns", hash[:], nanos(expiresAt)); err != nil {
		return corruptDatabase(err)
	}
	return corruptDatabase(tx.Commit())
}

// DeleteBrowserSession durably revokes a hashed browser cookie identity.
func (s *SQLiteStore) DeleteBrowserSession(ctx context.Context, hash []byte) error {
	if s == nil || len(hash) != sha256.Size {
		return domain.ErrCorruptState
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

func validHashedBrowserSession(hash []byte, expiresAt, now time.Time) bool {
	return len(hash) == sha256.Size && !expiresAt.IsZero() && expiresAt.After(now) && !expiresAt.After(now.Add(maxSessionLifetime))
}

func validateBrowserSessionsTx(ctx context.Context, tx *sql.Tx, now time.Time, max int, prune bool) error {
	if prune {
		if err := pruneBrowserSessionsTx(ctx, tx, now, max); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT token_hash, expires_at_ns FROM browser_sessions")
	if err != nil {
		return corruptDatabase(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var tokenHash []byte
		var expires int64
		if err := rows.Scan(&tokenHash, &expires); err != nil {
			return corruptDatabase(err)
		}
		expiresAt := time.Unix(0, expires).UTC()
		if !expiresAt.After(now) {
			if prune {
				return corruptDatabase(errors.New("expired browser session remained after prune"))
			}
			continue
		}
		if !validHashedBrowserSession(tokenHash, expiresAt, now) {
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
		return domain.ErrCorruptState
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM browser_sessions WHERE expires_at_ns <= ?", nanos(now)); err != nil {
		return corruptDatabase(err)
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM browser_sessions WHERE token_hash IN (SELECT token_hash FROM browser_sessions ORDER BY expires_at_ns DESC, token_hash LIMIT -1 OFFSET ?)", max)
	return corruptDatabase(err)
}

func validBrowserSessionLimit(max int) bool { return max > 0 && max <= maxBrowserSessions }

func validBrowserSession(token string, expiresAt, now time.Time) bool {
	return validOpaqueBrowserToken(token) && !expiresAt.IsZero() && expiresAt.After(now) && !expiresAt.After(now.Add(maxSessionLifetime))
}

func validOpaqueBrowserToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}
