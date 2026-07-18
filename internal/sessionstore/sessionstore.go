// Package sessionstore provides a Dragonfly/Redis-backed implementation of the
// user-session portion of storage.Storage.
//
// User sessions are ephemeral, high-churn, and latency-sensitive: they are
// created on every login and read on every authenticated request. Storing them
// in the shared camelot Postgres cluster puts a synchronous cross-node commit
// on the login critical path — under camelot's inherent write latency that
// stalls logins for many seconds and the edge returns 502. Dragonfly is
// in-cluster, HA, and sub-millisecond, which is the right home for this data.
//
// Store embeds a storage.Storage and overrides only the UserSession methods, so
// every other operation (keys, users, policies, …) still goes to the underlying
// Postgres store unchanged. Wrap the base store once at startup.
package sessionstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

const (
	sessPrefix   = "signer:sess:"  // sessPrefix+<id> -> JSON sessionRecord (TTL = session expiry)
	userPrefix   = "signer:usess:" // userPrefix+<userID> -> SET of session IDs
	userIndexTTL = 31 * 24 * time.Hour
	opTimeout    = 3 * time.Second
	connTimeout  = 5 * time.Second
)

// Store is a storage.Storage whose user-session methods are served by Dragonfly.
type Store struct {
	storage.Storage // underlying store; all non-session methods delegate here
	rdb             *redis.Client
}

// New wraps underlying so that user sessions are stored in Dragonfly/Redis at
// url. When url is empty it returns underlying unchanged (sessions stay in
// Postgres — correct for local/dev without a cache). A connection failure is a
// hard error: sessions are auth-critical, so we surface it at startup rather
// than silently fall back to the slow path.
func New(underlying storage.Storage, url string) (storage.Storage, error) {
	if url == "" {
		return underlying, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("invalid CACHE_URL: %w", err)
	}
	rdb := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), connTimeout)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("failed to connect to Dragonfly at %s: %w", opts.Addr, err)
	}
	return &Store{Storage: underlying, rdb: rdb}, nil
}

type sessionRecord struct {
	ID                   string     `json:"id"`
	UserID               string     `json:"user_id"`
	Token                string     `json:"token"`
	VaultToken           string     `json:"vault_token"`
	CosignListenerPubkey string     `json:"cosign_listener_pubkey"`
	UserAgent            string     `json:"user_agent"`
	IPAddress            string     `json:"ip_address"`
	RememberDevice       bool       `json:"remember_device"`
	LastActivity         *time.Time `json:"last_activity"`
	ExpiresAt            time.Time  `json:"expires_at"`
	CreatedAt            time.Time  `json:"created_at"`
}

// toRecord captures every field, including the ones the storage struct marks
// json:"-" (Token, VaultToken, CosignListenerPubkey) which we must persist.
func toRecord(s *storage.UserSession) sessionRecord {
	return sessionRecord{
		ID: s.ID, UserID: s.UserID, Token: s.Token, VaultToken: s.VaultToken,
		CosignListenerPubkey: s.CosignListenerPubkey, UserAgent: s.UserAgent,
		IPAddress: s.IPAddress, RememberDevice: s.RememberDevice,
		LastActivity: s.LastActivity, ExpiresAt: s.ExpiresAt, CreatedAt: s.CreatedAt,
	}
}

func (r *sessionRecord) toSession() *storage.UserSession {
	return &storage.UserSession{
		ID: r.ID, UserID: r.UserID, Token: r.Token, VaultToken: r.VaultToken,
		CosignListenerPubkey: r.CosignListenerPubkey, UserAgent: r.UserAgent,
		IPAddress: r.IPAddress, RememberDevice: r.RememberDevice,
		LastActivity: r.LastActivity, ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt,
	}
}

func (s *Store) sessKey(id string) string  { return sessPrefix + id }
func (s *Store) userKey(uid string) string { return userPrefix + uid }

func (s *Store) CreateUserSession(ctx context.Context, session *storage.UserSession) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Minute // never persist with a non-positive TTL (would be immortal)
	}
	data, err := json.Marshal(toRecord(session))
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, s.sessKey(session.ID), data, ttl)
	pipe.SAdd(ctx, s.userKey(session.UserID), session.ID)
	pipe.Expire(ctx, s.userKey(session.UserID), userIndexTTL)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *Store) GetUserSession(ctx context.Context, id string) (*storage.UserSession, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	data, err := s.rdb.Get(ctx, s.sessKey(id)).Bytes()
	if err == redis.Nil {
		return nil, storage.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	var r sessionRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	if time.Now().After(r.ExpiresAt) {
		return nil, storage.ErrSessionNotFound
	}
	return r.toSession(), nil
}

func (s *Store) ListUserSessions(ctx context.Context, userID string) ([]*storage.UserSession, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	ids, err := s.rdb.SMembers(ctx, s.userKey(userID)).Result()
	if err != nil {
		return nil, err
	}
	sessions := make([]*storage.UserSession, 0, len(ids))
	now := time.Now()
	var stale []string
	for _, id := range ids {
		data, err := s.rdb.Get(ctx, s.sessKey(id)).Bytes()
		if err == redis.Nil {
			stale = append(stale, id) // session expired; prune from the index
			continue
		}
		if err != nil {
			return nil, err
		}
		var r sessionRecord
		if err := json.Unmarshal(data, &r); err != nil {
			continue
		}
		if now.After(r.ExpiresAt) {
			stale = append(stale, id)
			continue
		}
		sessions = append(sessions, r.toSession())
	}
	if len(stale) > 0 {
		_ = s.rdb.SRem(ctx, s.userKey(userID), toAny(stale)...).Err()
	}
	return sessions, nil
}

// mutate reads a session, applies fn, and writes it back preserving the TTL.
func (s *Store) mutate(ctx context.Context, id string, fn func(*storage.UserSession)) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	sess, err := s.getRaw(ctx, id)
	if err != nil {
		return err
	}
	fn(sess)
	data, err := json.Marshal(toRecord(sess))
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	// KeepTTL leaves the existing expiry untouched.
	return s.rdb.Set(ctx, s.sessKey(id), data, redis.KeepTTL).Err()
}

func (s *Store) getRaw(ctx context.Context, id string) (*storage.UserSession, error) {
	data, err := s.rdb.Get(ctx, s.sessKey(id)).Bytes()
	if err == redis.Nil {
		return nil, storage.ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	var r sessionRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return r.toSession(), nil
}

func (s *Store) UpdateUserSessionActivity(ctx context.Context, id string) error {
	return s.mutate(ctx, id, func(sess *storage.UserSession) {
		now := time.Now()
		sess.LastActivity = &now
	})
}

func (s *Store) UpdateUserSessionVaultToken(ctx context.Context, id, vaultToken string) error {
	return s.mutate(ctx, id, func(sess *storage.UserSession) {
		sess.VaultToken = vaultToken
	})
}

func (s *Store) DeleteUserSession(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	// Look up the owning user so we can prune the index; best-effort.
	userID := ""
	if sess, err := s.getRaw(ctx, id); err == nil {
		userID = sess.UserID
	}
	pipe := s.rdb.TxPipeline()
	pipe.Del(ctx, s.sessKey(id))
	if userID != "" {
		pipe.SRem(ctx, s.userKey(userID), id)
	}
	_, err := pipe.Exec(ctx)
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	ids, err := s.rdb.SMembers(ctx, s.userKey(userID)).Result()
	if err != nil {
		return err
	}
	pipe := s.rdb.TxPipeline()
	for _, id := range ids {
		pipe.Del(ctx, s.sessKey(id))
	}
	pipe.Del(ctx, s.userKey(userID))
	_, err = pipe.Exec(ctx)
	return err
}

// CleanExpiredUserSessions is a no-op: Dragonfly expires session keys via TTL.
// Stale entries left in a user index set are pruned lazily by ListUserSessions.
func (s *Store) CleanExpiredUserSessions(ctx context.Context) error {
	return nil
}

// Close releases the Dragonfly connection.
func (s *Store) Close() error {
	if s.rdb != nil {
		_ = s.rdb.Close()
	}
	if c, ok := s.Storage.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
