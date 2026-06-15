package crypto

import (
	"strings"
	"testing"
)

func TestGenerateRecoveryPhrase_Shape(t *testing.T) {
	phrase, err := GenerateRecoveryPhrase()
	if err != nil {
		t.Fatalf("GenerateRecoveryPhrase: %v", err)
	}
	words := strings.Fields(phrase)
	if len(words) != PhraseWordCount {
		t.Errorf("expected %d words, got %d", PhraseWordCount, len(words))
	}
	for i, w := range words {
		if w == "" {
			t.Errorf("word %d is empty", i)
		}
		if strings.ContainsAny(w, " \t\n") {
			t.Errorf("word %d contains whitespace: %q", i, w)
		}
	}
}

func TestGenerateRecoveryPhrase_Unique(t *testing.T) {
	// Two fresh phrases must differ. If the RNG is broken we want to know.
	a, err := GenerateRecoveryPhrase()
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := GenerateRecoveryPhrase()
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b {
		t.Errorf("two generated phrases were identical")
	}
}

func TestValidateRecoveryPhrase(t *testing.T) {
	good, err := GenerateRecoveryPhrase()
	if err != nil {
		t.Fatalf("GenerateRecoveryPhrase: %v", err)
	}

	cases := []struct {
		name    string
		phrase  string
		wantErr bool
	}{
		{"valid 24 words", good, false},
		{"empty", "", true},
		{"random words not in wordlist", "this is not a bip39 phrase at all just words", true},
		{"truncated to 12 words", strings.Join(strings.Fields(good)[:12], " "), true},
		{"truncated to 23 words", strings.Join(strings.Fields(good)[:23], " "), true},
		{"valid words but bad checksum", strings.Join([]string{
			"abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
			"abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
			"abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
			"abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
		}, " "), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRecoveryPhrase(tc.phrase)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateRecoveryPhrase(%q) error = %v, wantErr = %v", tc.phrase, err, tc.wantErr)
			}
		})
	}
}

func TestPhraseToSeed_Deterministic(t *testing.T) {
	// Use a freshly generated phrase as the test fixture (avoids relying on
	// brittle hand-typed BIP39 test vectors, which differ by wordlist
	// version and are easy to typo). Determinism is the property under
	// test: same input -> same output, different input -> different output.
	phrase, err := GenerateRecoveryPhrase()
	if err != nil {
		t.Fatalf("GenerateRecoveryPhrase: %v", err)
	}
	passphrase := "TREZOR"

	seed1, err := PhraseToSeed(phrase, passphrase)
	if err != nil {
		t.Fatalf("PhraseToSeed: %v", err)
	}
	if len(seed1) != 64 {
		t.Errorf("seed length = %d, want 64", len(seed1))
	}

	seed2, err := PhraseToSeed(phrase, passphrase)
	if err != nil {
		t.Fatalf("PhraseToSeed (second call): %v", err)
	}
	if string(seed1) != string(seed2) {
		t.Errorf("phrase+passphrase produced different seeds on repeat invocation")
	}

	// Different passphrase must produce a different seed.
	seedDiff, err := PhraseToSeed(phrase, "different")
	if err != nil {
		t.Fatalf("PhraseToSeed (diff passphrase): %v", err)
	}
	if string(seed1) == string(seedDiff) {
		t.Errorf("different passphrase produced identical seed")
	}
}

func TestPhraseToSeed_RejectsInvalidPhrase(t *testing.T) {
	if _, err := PhraseToSeed("not a real phrase", ""); err == nil {
		t.Errorf("PhraseToSeed should reject invalid phrase")
	}
}
