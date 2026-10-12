package signer

import "context"

// KeyRestorer tries to put a locked user-held key back in memory without the user
// (stay signed in: open a session seal and RegisterKey it). It returns true if the
// key is now loaded.
type KeyRestorer func(ctx context.Context, pubkey string) bool

// SetKeyRestorer installs the restorer resolveSigningKey consults for user-held
// keys that are not in memory. Call before Start.
func (s *Signer) SetKeyRestorer(r KeyRestorer) {
	s.keysLock.Lock()
	s.keyRestorer = r
	s.keysLock.Unlock()
}

// LoadedPrivateKey returns the in-memory private key for pubkey, if loaded. Used
// only to seal a key the user has just unlocked.
func (s *Signer) LoadedPrivateKey(pubkey string) (string, bool) {
	s.keysLock.RLock()
	defer s.keysLock.RUnlock()
	priv, ok := s.keys[pubkey]
	return priv, ok && priv != ""
}

// restoreUserHeldKey asks the restorer, if any, and re-reads the map.
func (s *Signer) restoreUserHeldKey(ctx context.Context, pubkey string) (string, bool) {
	s.keysLock.RLock()
	r := s.keyRestorer
	s.keysLock.RUnlock()
	if r == nil || !r(ctx, pubkey) {
		return "", false
	}
	return s.LoadedPrivateKey(pubkey)
}
