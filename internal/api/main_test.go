package api

import (
	"os"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
)

// TestMain lowers the passphrase-KEK cost for this package's suite.
//
// The registration, recovery and password-change tests exercise the passphrase
// path heavily — 50+ Encrypt/Decrypt/ReWrap calls between them — and each one
// pays 600k PBKDF2 rounds at production cost. That is what made internal/crypto
// and internal/api the slowest packages in CI and pushed the suite past Go's
// default 10-minute test timeout.
//
// Correctness is unaffected: the KEK is the same construction at any count, and
// internal/crypto keeps one round trip at the real 600k plus a test pinning the
// production constant.
func TestMain(m *testing.M) {
	restore := crypto.LowerIterationsForTesting()
	code := m.Run()
	restore()
	os.Exit(code)
}
