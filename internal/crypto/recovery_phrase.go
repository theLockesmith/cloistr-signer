// Package crypto recovery_phrase: BIP39 24-word recovery phrase primitives.
//
// This is the user-held secret from which the user-side FROST share will
// eventually be derived (privacy-architecture §3.1, §3.3). For now the
// primitive ships in isolation: phrase generation, validation, and a
// keyed seed-extraction function for downstream use. The share-derivation
// wiring binds to FROST 2-of-N which is a separate, larger work item.
//
// The 256-bit entropy variant is required (24 words). 256-bit entropy gives
// 8 bits of checksum and well-exceeds the security level of any single
// secp256k1 private key.
package crypto

import (
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// PhraseWordCount is the required word count for cloistr recovery phrases.
// We only support the 24-word (256-bit entropy) variant; shorter phrases
// are weaker than the secp256k1 key they protect and not worth supporting.
const PhraseWordCount = 24

// PhraseEntropyBits is the entropy bit-length corresponding to PhraseWordCount.
const PhraseEntropyBits = 256

// GenerateRecoveryPhrase returns a fresh 24-word BIP39 phrase using
// cryptographic randomness. The phrase MUST be shown to the user exactly
// once at registration; the server must NEVER persist it in plaintext.
func GenerateRecoveryPhrase() (string, error) {
	entropy, err := bip39.NewEntropy(PhraseEntropyBits)
	if err != nil {
		return "", fmt.Errorf("phrase entropy: %w", err)
	}
	phrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("phrase mnemonic: %w", err)
	}
	return phrase, nil
}

// ValidateRecoveryPhrase returns nil if the phrase has the correct word
// count, every word is in the BIP39 English wordlist, and the checksum
// verifies. Returns a descriptive error otherwise. Does not reveal which
// word is invalid to avoid leaking dictionary-attack signal.
func ValidateRecoveryPhrase(phrase string) error {
	if phrase == "" {
		return fmt.Errorf("recovery phrase: empty")
	}
	// bip39.IsMnemonicValid returns false for any of: wrong word count,
	// unknown word, bad checksum. Treat as one failure mode.
	if !bip39.IsMnemonicValid(phrase) {
		return fmt.Errorf("recovery phrase: invalid (check word count, spelling, and order)")
	}
	// Belt-and-braces: explicitly require 24 words even if the library
	// would also accept 12/15/18/21. Keeps a single configuration in this
	// codebase.
	wordCount := countWords(phrase)
	if wordCount != PhraseWordCount {
		return fmt.Errorf("recovery phrase: expected %d words, got %d", PhraseWordCount, wordCount)
	}
	return nil
}

// PhraseToSeed returns the 64-byte BIP39 seed derived from the phrase plus
// an optional passphrase (BIP39's optional 25th-word). The passphrase
// extends the secret: same phrase + different passphrase = different seed.
// Empty passphrase is fine; it just uses BIP39's default "mnemonic" salt.
//
// This seed is the input to whatever downstream key-derivation function
// the share-binding code uses. Per privacy-architecture §3.1, the phrase
// is the only thing the user holds; the seed is computed client-side at
// recovery time and never stored.
func PhraseToSeed(phrase, passphrase string) ([]byte, error) {
	if err := ValidateRecoveryPhrase(phrase); err != nil {
		return nil, err
	}
	return bip39.NewSeed(phrase, passphrase), nil
}

// countWords counts space-separated words. Trims surrounding spaces but
// does not normalize internal whitespace (BIP39 phrases are canonical
// single-space-separated; pathological inputs are caught by
// IsMnemonicValid before this gets called).
func countWords(s string) int {
	n := 0
	inWord := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			if inWord {
				n++
				inWord = false
			}
		} else {
			inWord = true
		}
	}
	if inWord {
		n++
	}
	return n
}
