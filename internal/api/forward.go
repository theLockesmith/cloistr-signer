package api

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Cross-replica forwarding of POST /api/v1/nostrconnect/session.
//
// A user's key is unlocked only in the memory of the replica that ran their
// login. When the session request lands on another replica, that replica looks
// up the holder in the key-location registry (internal/keyloc, Dragonfly) and
// forwards the request to it pod-to-pod.
//
// The location record is a routing hint written to a store whose password is
// not a strong secret, so the forward itself carries all the trust:
//   - the request (body AND the user's session credential) is sealed with
//     AES-256-GCM under a key derived from SIGNER_FORWARD_SECRET, which
//     Dragonfly never sees; a planted record can at worst send ciphertext to
//     the wrong place;
//   - the seal binds a timestamp (±forwardSkew) and a one-time nonce
//     (replay cache);
//   - the receiver re-validates the user's session itself, by running the
//     ordinary session handler on the unsealed request;
//   - the response is sealed too, bound to the request nonce, so an impostor
//     cannot answer "success";
//   - a forwarded request is never forwarded again;
//   - any failure falls back to the 409 key_locked the client gets today.

const (
	forwardPath      = "/internal/v1/nostrconnect/session"
	evictPath        = "/internal/v1/keys/evict"
	hdrFwdTs         = "X-Signer-Fwd-Ts"
	hdrFwdNonce      = "X-Signer-Fwd-Nonce"
	forwardSkew      = 30 * time.Second
	forwardTimeout   = 10 * time.Second // covers the holder's own keyUnlockWait
	maxForwardBody   = 64 << 10
	lookupPatience   = 2 * time.Second // holder may still be publishing right after its login
	lookupPoll       = 250 * time.Millisecond
	minForwardSecret = 32
)

var errNoHolder = errors.New("no other replica holds this key")

// KeyLocator finds the forward address of the replica holding a key.
type KeyLocator interface {
	Lookup(ctx context.Context, pubkey string) (string, bool)
}

// keyPublisher is implemented by locators that can also record this
// replica's own keys (internal/keyloc.Registry).
type keyPublisher interface {
	Publish(ctx context.Context, pubkeys ...string) error
	Forget(ctx context.Context, pubkey string) error
}

// forwardedRequest is the sealed payload: everything the holder needs to
// re-run the session request as the user.
type forwardedRequest struct {
	Authorization string `json:"a,omitempty"`
	AuthCookie    string `json:"c,omitempty"`
	Body          []byte `json:"b"`
}

type forwardedResponse struct {
	Status int    `json:"s"`
	Body   []byte `json:"b"`
}

type forwarder struct {
	aead         cipher.AEAD
	locator      KeyLocator
	client       *http.Client
	allowAnyAddr bool // tests only: httptest listens on loopback
	serve        http.HandlerFunc
	evictLocal   func(ctx context.Context, pubkeys []string)

	mu   sync.Mutex
	seen map[string]time.Time
}

type forwardedCtxKey struct{}

func isForwarded(ctx context.Context) bool {
	v, _ := ctx.Value(forwardedCtxKey{}).(bool)
	return v
}

// SetForwarding enables cross-replica forwarding of session requests. secret
// must be the same on every replica and at least 32 bytes.
func (h *Handler) SetForwarding(secret []byte, loc KeyLocator) error {
	if len(secret) < minForwardSecret {
		return fmt.Errorf("forward secret must be at least %d bytes", minForwardSecret)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("cloistr-signer nostrconnect forward v1"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	h.forward = &forwarder{
		aead:    aead,
		locator: loc,
		client:  &http.Client{Timeout: forwardTimeout},
		serve:   h.handleNostrConnectSession,
		evictLocal: func(ctx context.Context, pubkeys []string) {
			for _, pk := range pubkeys {
				h.signer.UnregisterKey(pk)
				h.forgetKeyLocation(ctx, pk)
			}
		},
		seen: make(map[string]time.Time),
	}
	return nil
}

// ForwardHandler serves the pod-to-pod forward endpoint. It belongs on its own
// listener (SIGNER_FORWARD_PORT), not behind the public ingress.
func (h *Handler) ForwardHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(forwardPath, func(w http.ResponseWriter, r *http.Request) {
		if h.forward == nil {
			http.NotFound(w, r)
			return
		}
		h.forward.receive(w, r)
	})
	mux.HandleFunc(evictPath, func(w http.ResponseWriter, r *http.Request) {
		if h.forward == nil {
			http.NotFound(w, r)
			return
		}
		h.forward.receiveEvict(w, r)
	})
	return mux
}

// publishLoadedKeys records the keys this replica now holds, if a registry is
// configured. Called after a login unlocks keys.
func (h *Handler) publishLoadedKeys(ctx context.Context) {
	if h.forward == nil {
		return
	}
	if p, ok := h.forward.locator.(keyPublisher); ok {
		_ = p.Publish(ctx, h.signer.LoadedKeyPubkeys()...)
	}
}

// forgetKeyLocation drops this replica's record for a key it evicted.
func (h *Handler) forgetKeyLocation(ctx context.Context, pubkey string) {
	if h.forward == nil {
		return
	}
	if p, ok := h.forward.locator.(keyPublisher); ok {
		_ = p.Forget(ctx, pubkey)
	}
}

func (f *forwarder) sealRequest(fr forwardedRequest) (sealed []byte, ts, nonceHex string, err error) {
	plain, err := json.Marshal(fr)
	if err != nil {
		return nil, "", "", err
	}
	nonce := make([]byte, f.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", "", err
	}
	ts = strconv.FormatInt(time.Now().Unix(), 10)
	return f.aead.Seal(nil, nonce, plain, []byte("req|"+ts)), ts, hex.EncodeToString(nonce), nil
}

// forwardSession sends fr to the replica holding pubkey and returns the
// holder's answer. Any error means the caller should answer key_locked.
func (f *forwarder) forwardSession(ctx context.Context, pubkey string, fr forwardedRequest) (int, []byte, error) {
	addr, ok := f.locator.Lookup(ctx, pubkey)
	for deadline := time.Now().Add(lookupPatience); !ok && time.Now().Before(deadline); {
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(lookupPoll):
		}
		addr, ok = f.locator.Lookup(ctx, pubkey)
	}
	if !ok {
		return 0, nil, errNoHolder
	}
	if !f.allowAnyAddr {
		host, _, err := net.SplitHostPort(addr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsPrivate() {
			return 0, nil, fmt.Errorf("refusing forward to non-pod address %q", addr)
		}
	}

	sealed, ts, nonceHex, err := f.sealRequest(fr)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+forwardPath, bytes.NewReader(sealed))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set(hdrFwdTs, ts)
	req.Header.Set(hdrFwdNonce, nonceHex)
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("holder refused forward: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxForwardBody))
	if err != nil {
		return 0, nil, err
	}
	respNonce, err := hex.DecodeString(resp.Header.Get(hdrFwdNonce))
	if err != nil || len(respNonce) != f.aead.NonceSize() {
		return 0, nil, errors.New("forward response not sealed")
	}
	plain, err := f.aead.Open(nil, respNonce, raw, []byte("resp|"+nonceHex))
	if err != nil {
		return 0, nil, errors.New("forward response failed authentication")
	}
	var out forwardedResponse
	if err := json.Unmarshal(plain, &out); err != nil {
		return 0, nil, err
	}
	return out.Status, out.Body, nil
}

func (f *forwarder) receive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ts := r.Header.Get(hdrFwdTs)
	nonceHex := r.Header.Get(hdrFwdNonce)
	sent, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(sent, 0)).Abs() > forwardSkew {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != f.aead.NonceSize() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxForwardBody))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	plain, err := f.aead.Open(nil, nonce, raw, []byte("req|"+ts))
	if err != nil || !f.firstUse(nonceHex) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var fr forwardedRequest
	if err := json.Unmarshal(plain, &fr); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Re-run the ordinary session handler as the user. It validates the
	// session credential itself; the forwarder's word counts for nothing.
	inner, err := http.NewRequestWithContext(context.WithValue(r.Context(), forwardedCtxKey{}, true),
		http.MethodPost, "/api/v1/nostrconnect/session", bytes.NewReader(fr.Body))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	inner.Header.Set("Content-Type", "application/json")
	if fr.Authorization != "" {
		inner.Header.Set("Authorization", fr.Authorization)
	}
	if fr.AuthCookie != "" {
		inner.AddCookie(&http.Cookie{Name: "auth_token", Value: fr.AuthCookie})
	}
	rec := &bufferedResponse{header: http.Header{}, status: http.StatusOK}
	f.serve(rec, inner)

	out, err := json.Marshal(forwardedResponse{Status: rec.status, Body: rec.body.Bytes()})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	respNonce := make([]byte, f.aead.NonceSize())
	if _, err := rand.Read(respNonce); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set(hdrFwdNonce, hex.EncodeToString(respNonce))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(f.aead.Seal(nil, respNonce, out, []byte("resp|"+nonceHex)))
}

// firstUse records nonce and reports whether it had not been seen within the
// replay window.
func (f *forwarder) firstUse(nonce string) bool {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	for n, at := range f.seen {
		if now.Sub(at) > 2*forwardSkew {
			delete(f.seen, n)
		}
	}
	if _, dup := f.seen[nonce]; dup {
		return false
	}
	f.seen[nonce] = now
	return true
}

// bufferedResponse captures the inner handler's answer so it can be sealed.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedResponse) WriteHeader(code int)        { b.status = code }

// evictRequest is the sealed payload of an eviction: keys whose account was
// deleted, which the holding replica must drop from memory.
type evictRequest struct {
	Pubkeys []string `json:"pubkeys"`
}

// evictRemote tells the replica(s) holding these keys to drop them. Best
// effort: account deletion has already removed the account, grants and
// sessions, and a replica that misses this evicts the key on its next use
// (Signer.evictIfKeyDeleted) or restart.
func (f *forwarder) evictRemote(ctx context.Context, pubkeys []string) {
	byAddr := map[string][]string{}
	for _, pk := range pubkeys {
		if addr, ok := f.locator.Lookup(ctx, pk); ok {
			byAddr[addr] = append(byAddr[addr], pk)
		}
	}
	for addr, pks := range byAddr {
		if !f.allowAnyAddr {
			host, _, err := net.SplitHostPort(addr)
			if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsPrivate() {
				continue
			}
		}
		plain, err := json.Marshal(evictRequest{Pubkeys: pks})
		if err != nil {
			continue
		}
		nonce := make([]byte, f.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			continue
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		sealed := f.aead.Seal(nil, nonce, plain, []byte("evict|"+ts))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+evictPath, bytes.NewReader(sealed))
		if err != nil {
			continue
		}
		req.Header.Set(hdrFwdTs, ts)
		req.Header.Set(hdrFwdNonce, hex.EncodeToString(nonce))
		resp, err := f.client.Do(req)
		if err != nil {
			slog.Warn("remote key eviction failed", "addr", addr, "keys", len(pks), "error", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			slog.Warn("remote key eviction refused", "addr", addr, "status", resp.StatusCode)
		}
	}
}

func (f *forwarder) receiveEvict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ts := r.Header.Get(hdrFwdTs)
	nonceHex := r.Header.Get(hdrFwdNonce)
	sent, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(sent, 0)).Abs() > forwardSkew {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != f.aead.NonceSize() {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxForwardBody))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// "evict|" binds the seal to this endpoint: a sealed session forward
	// cannot be replayed here, nor the reverse.
	plain, err := f.aead.Open(nil, nonce, raw, []byte("evict|"+ts))
	if err != nil || !f.firstUse(nonceHex) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var er evictRequest
	if err := json.Unmarshal(plain, &er); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.evictLocal(r.Context(), er.Pubkeys)
	slog.Info("evicted keys at another replica's request", "keys", len(er.Pubkeys))
	w.WriteHeader(http.StatusNoContent)
}
