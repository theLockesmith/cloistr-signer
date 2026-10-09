package api

import (
	"context"
	"sync"
	"time"
)

// keyUnlockWait bounds how long a session request waits for an unlock already
// in flight on this replica. Unlocking is PBKDF2 at 600k iterations plus a
// storage read: ~1s measured in production.
const keyUnlockWait = 5 * time.Second

// keyLoadTracker records which users have a key unlock in flight on this
// replica. Login answers before the passphrase-wrapped keys are unlocked (that
// work runs in the background), so a request that needs the key right after
// login must wait for it rather than report the key as locked.
//
// The zero value is ready to use.
type keyLoadTracker struct {
	mu       sync.Mutex
	inflight map[string]chan struct{}
}

// begin marks an unlock for userID as in flight and returns the function that
// marks it finished. A newer begin for the same user supersedes an older one;
// each done closes only its own channel.
func (t *keyLoadTracker) begin(userID string) (done func()) {
	ch := make(chan struct{})
	t.mu.Lock()
	if t.inflight == nil {
		t.inflight = make(map[string]chan struct{})
	}
	t.inflight[userID] = ch
	t.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			close(ch)
			t.mu.Lock()
			if t.inflight[userID] == ch {
				delete(t.inflight, userID)
			}
			t.mu.Unlock()
		})
	}
}

// wait blocks until the unlock in flight for userID finishes, max elapses, or
// ctx is done. It returns at once when nothing is in flight.
func (t *keyLoadTracker) wait(ctx context.Context, userID string, max time.Duration) {
	t.mu.Lock()
	ch := t.inflight[userID]
	t.mu.Unlock()
	if ch == nil {
		return
	}
	timer := time.NewTimer(max)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	case <-ctx.Done():
	}
}
