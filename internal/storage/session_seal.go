package storage

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ---- Session seals: memory ----

func cloneSeal(sl *SessionSeal) *SessionSeal {
	out := *sl
	out.Sealed = bytes.Clone(sl.Sealed)
	return &out
}

func (m *MemoryStorage) UpsertSessionSeal(ctx context.Context, seal *SessionSeal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropSessionSealsLocked(func(sl *SessionSeal) bool {
		return sl.SessionID == seal.SessionID && sl.KeyID == seal.KeyID
	})
	m.sessionSeals[seal.ID] = cloneSeal(seal)
	return nil
}

func (m *MemoryStorage) listSeals(match func(*SessionSeal) bool) []*SessionSeal {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	var out []*SessionSeal
	for _, sl := range m.sessionSeals {
		if sl.ExpiresAt.After(now) && match(sl) {
			out = append(out, cloneSeal(sl))
		}
	}
	return out
}

func (m *MemoryStorage) ListLiveSessionSeals(ctx context.Context) ([]*SessionSeal, error) {
	return m.listSeals(func(*SessionSeal) bool { return true }), nil
}

func (m *MemoryStorage) ListSessionSealsBySession(ctx context.Context, sessionID string) ([]*SessionSeal, error) {
	return m.listSeals(func(sl *SessionSeal) bool { return sl.SessionID == sessionID }), nil
}

func (m *MemoryStorage) ListSessionSealsByUser(ctx context.Context, userID string) ([]*SessionSeal, error) {
	return m.listSeals(func(sl *SessionSeal) bool { return sl.UserID == userID }), nil
}

func (m *MemoryStorage) UpdateSessionSealBlob(ctx context.Context, id string, sealed []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sl, ok := m.sessionSeals[id]
	if !ok {
		return fmt.Errorf("session seal %s not found", id)
	}
	sl.Sealed = bytes.Clone(sealed)
	return nil
}

func (m *MemoryStorage) DeleteSessionSealsBySession(ctx context.Context, sessionID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropSessionSealsLocked(func(sl *SessionSeal) bool { return sl.SessionID == sessionID }), nil
}

func (m *MemoryStorage) DeleteSessionSealsByUser(ctx context.Context, userID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropSessionSealsLocked(func(sl *SessionSeal) bool { return sl.UserID == userID }), nil
}

func (m *MemoryStorage) ExtendSessionSeals(ctx context.Context, sessionID string, expiresAt time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, sl := range m.sessionSeals {
		if sl.SessionID == sessionID {
			sl.ExpiresAt = expiresAt
			n++
		}
	}
	return n, nil
}

func (m *MemoryStorage) ExtendUserSession(ctx context.Context, id string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.userSessions[id]
	if !ok || time.Now().After(s.ExpiresAt) {
		return ErrSessionNotFound
	}
	s.ExpiresAt = expiresAt
	return nil
}

func (m *MemoryStorage) DeleteExpiredSessionSeals(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	return m.dropSessionSealsLocked(func(sl *SessionSeal) bool { return !sl.ExpiresAt.After(now) }), nil
}

// dropSessionSealsLocked deletes matching seals. Caller holds m.mu for writing.
func (m *MemoryStorage) dropSessionSealsLocked(match func(*SessionSeal) bool) int {
	n := 0
	for id, sl := range m.sessionSeals {
		if match(sl) {
			delete(m.sessionSeals, id)
			n++
		}
	}
	return n
}

// ---- Session seals: SQL (Postgres and SQLite share the statements) ----

const sessionSealCols = `id, user_id, key_id, pubkey, session_id, mode, sealed, expires_at, created_at, sliding`

type sealDB interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// sqlSeals implements the seal methods over a *sql.DB. ph renders the n-th
// placeholder ($n for Postgres, ? for SQLite); now is the "current time" expression
// as a bound parameter, so both engines compare like with like.
type sqlSeals struct {
	db    sealDB
	ph    func(n int) string
	scanT func(any) (time.Time, error) // converts a scanned timestamp column
	fmtT  func(time.Time) any          // renders a time for a parameter
}

func (q sqlSeals) upsert(ctx context.Context, sl *SessionSeal) error {
	p := q.ph
	_, err := q.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO signer_session_seals (`+sessionSealCols+`)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
		ON CONFLICT (session_id, key_id) DO UPDATE SET
			id = excluded.id, user_id = excluded.user_id, pubkey = excluded.pubkey,
			mode = excluded.mode, sealed = excluded.sealed,
			expires_at = excluded.expires_at, created_at = excluded.created_at,
			sliding = excluded.sliding`,
		p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10)),
		sl.ID, sl.UserID, sl.KeyID, sl.Pubkey, sl.SessionID, sl.Mode, sl.Sealed,
		q.fmtT(sl.ExpiresAt), q.fmtT(sl.CreatedAt), sl.Sliding)
	if err != nil {
		return fmt.Errorf("upsert session seal: %w", err)
	}
	return nil
}

func (q sqlSeals) list(ctx context.Context, where string, arg ...any) ([]*SessionSeal, error) {
	cond := "expires_at > " + q.ph(1)
	args := []any{q.fmtT(time.Now())}
	if where != "" {
		cond += " AND " + where + " = " + q.ph(2)
		args = append(args, arg...)
	}
	rows, err := q.db.QueryContext(ctx, `SELECT `+sessionSealCols+` FROM signer_session_seals WHERE `+cond, args...)
	if err != nil {
		return nil, fmt.Errorf("list session seals: %w", err)
	}
	defer rows.Close()
	var out []*SessionSeal
	for rows.Next() {
		var sl SessionSeal
		var exp, created any
		if err := rows.Scan(&sl.ID, &sl.UserID, &sl.KeyID, &sl.Pubkey, &sl.SessionID, &sl.Mode, &sl.Sealed, &exp, &created, &sl.Sliding); err != nil {
			return nil, fmt.Errorf("scan session seal: %w", err)
		}
		if sl.ExpiresAt, err = q.scanT(exp); err != nil {
			return nil, err
		}
		if sl.CreatedAt, err = q.scanT(created); err != nil {
			return nil, err
		}
		out = append(out, &sl)
	}
	return out, rows.Err()
}

func (q sqlSeals) exec(ctx context.Context, what, query string, args ...any) (int, error) {
	res, err := q.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", what, err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (q sqlSeals) updateBlob(ctx context.Context, id string, sealed []byte) error {
	n, err := q.exec(ctx, "update session seal", `UPDATE signer_session_seals SET sealed = `+q.ph(1)+` WHERE id = `+q.ph(2), sealed, id)
	if err == nil && n == 0 {
		err = fmt.Errorf("session seal %s not found", id)
	}
	return err
}

func (q sqlSeals) deleteBy(ctx context.Context, col, val string) (int, error) {
	return q.exec(ctx, "delete session seals", `DELETE FROM signer_session_seals WHERE `+col+` = `+q.ph(1), val)
}

func (q sqlSeals) extend(ctx context.Context, sessionID string, exp time.Time) (int, error) {
	return q.exec(ctx, "extend session seals", `UPDATE signer_session_seals SET expires_at = `+q.ph(1)+` WHERE session_id = `+q.ph(2), q.fmtT(exp), sessionID)
}

func (q sqlSeals) deleteExpired(ctx context.Context) (int, error) {
	return q.exec(ctx, "delete expired session seals", `DELETE FROM signer_session_seals WHERE expires_at <= `+q.ph(1), q.fmtT(time.Now()))
}

// ---- Postgres ----

func (ps *PostgresStorage) seals() sqlSeals {
	return sqlSeals{
		db: ps.db,
		ph: func(n int) string { return fmt.Sprintf("$%d", n) },
		scanT: func(v any) (time.Time, error) {
			t, ok := v.(time.Time)
			if !ok {
				return time.Time{}, fmt.Errorf("session seal: unexpected time value %T", v)
			}
			return t, nil
		},
		fmtT: func(t time.Time) any { return t },
	}
}

func (ps *PostgresStorage) UpsertSessionSeal(ctx context.Context, sl *SessionSeal) error {
	return ps.seals().upsert(ctx, sl)
}
func (ps *PostgresStorage) ListLiveSessionSeals(ctx context.Context) ([]*SessionSeal, error) {
	return ps.seals().list(ctx, "")
}
func (ps *PostgresStorage) ListSessionSealsBySession(ctx context.Context, sessionID string) ([]*SessionSeal, error) {
	return ps.seals().list(ctx, "session_id", sessionID)
}
func (ps *PostgresStorage) ListSessionSealsByUser(ctx context.Context, userID string) ([]*SessionSeal, error) {
	return ps.seals().list(ctx, "user_id", userID)
}
func (ps *PostgresStorage) UpdateSessionSealBlob(ctx context.Context, id string, sealed []byte) error {
	return ps.seals().updateBlob(ctx, id, sealed)
}
func (ps *PostgresStorage) DeleteSessionSealsBySession(ctx context.Context, sessionID string) (int, error) {
	return ps.seals().deleteBy(ctx, "session_id", sessionID)
}
func (ps *PostgresStorage) DeleteSessionSealsByUser(ctx context.Context, userID string) (int, error) {
	return ps.seals().deleteBy(ctx, "user_id", userID)
}
func (ps *PostgresStorage) DeleteExpiredSessionSeals(ctx context.Context) (int, error) {
	return ps.seals().deleteExpired(ctx)
}
func (ps *PostgresStorage) ExtendSessionSeals(ctx context.Context, sessionID string, exp time.Time) (int, error) {
	return ps.seals().extend(ctx, sessionID, exp)
}
func (ps *PostgresStorage) ExtendUserSession(ctx context.Context, id string, exp time.Time) error {
	res, err := ps.db.ExecContext(ctx, `UPDATE signer_web_sessions SET expires_at = $1 WHERE id = $2 AND expires_at > NOW()`, exp, id)
	if err != nil {
		return fmt.Errorf("extend user session: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// ---- SQLite ----

func (ss *SQLiteStorage) seals() sqlSeals {
	return sqlSeals{
		db: ss.db,
		ph: func(int) string { return "?" },
		scanT: func(v any) (time.Time, error) {
			switch x := v.(type) {
			case time.Time:
				return x, nil
			case string:
				return time.Parse(time.RFC3339Nano, x)
			case []byte:
				return time.Parse(time.RFC3339Nano, string(x))
			}
			return time.Time{}, fmt.Errorf("session seal: unexpected time value %T", v)
		},
		// Fixed-width UTC text sorts and compares correctly as a string.
		fmtT: func(t time.Time) any { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") },
	}
}

func (ss *SQLiteStorage) UpsertSessionSeal(ctx context.Context, sl *SessionSeal) error {
	return ss.seals().upsert(ctx, sl)
}
func (ss *SQLiteStorage) ListLiveSessionSeals(ctx context.Context) ([]*SessionSeal, error) {
	return ss.seals().list(ctx, "")
}
func (ss *SQLiteStorage) ListSessionSealsBySession(ctx context.Context, sessionID string) ([]*SessionSeal, error) {
	return ss.seals().list(ctx, "session_id", sessionID)
}
func (ss *SQLiteStorage) ListSessionSealsByUser(ctx context.Context, userID string) ([]*SessionSeal, error) {
	return ss.seals().list(ctx, "user_id", userID)
}
func (ss *SQLiteStorage) UpdateSessionSealBlob(ctx context.Context, id string, sealed []byte) error {
	return ss.seals().updateBlob(ctx, id, sealed)
}
func (ss *SQLiteStorage) DeleteSessionSealsBySession(ctx context.Context, sessionID string) (int, error) {
	return ss.seals().deleteBy(ctx, "session_id", sessionID)
}
func (ss *SQLiteStorage) DeleteSessionSealsByUser(ctx context.Context, userID string) (int, error) {
	return ss.seals().deleteBy(ctx, "user_id", userID)
}
func (ss *SQLiteStorage) DeleteExpiredSessionSeals(ctx context.Context) (int, error) {
	return ss.seals().deleteExpired(ctx)
}
func (ss *SQLiteStorage) ExtendSessionSeals(ctx context.Context, sessionID string, exp time.Time) (int, error) {
	return ss.seals().extend(ctx, sessionID, exp)
}
func (ss *SQLiteStorage) ExtendUserSession(ctx context.Context, id string, exp time.Time) error {
	if s, err := ss.GetUserSession(ctx, id); err != nil || s == nil {
		return ErrSessionNotFound
	}
	_, err := ss.db.ExecContext(ctx, `UPDATE signer_web_sessions SET expires_at = ? WHERE id = ?`, formatTime(exp), id)
	if err != nil {
		return fmt.Errorf("extend user session: %w", err)
	}
	return nil
}
