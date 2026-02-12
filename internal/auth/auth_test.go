package auth

import (
	"strings"
	"testing"
	"time"
)

func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password, 0)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	// Should start with bcrypt prefix
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("HashPassword() result should be bcrypt hash, got %q", hash)
	}

	// Should generate different hashes for same password (due to salt)
	hash2, err := HashPassword(password, 0)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hash == hash2 {
		t.Error("HashPassword() should generate different hashes due to salt")
	}
}

func TestHashPasswordCustomCost(t *testing.T) {
	password := "testpassword"

	// Low cost for faster tests
	hash, err := HashPassword(password, 4)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword() should return true for correct password")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "correctpassword"
	hash, err := HashPassword(password, 4) // Low cost for faster tests
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"correct password", "correctpassword", true},
		{"wrong password", "wrongpassword", false},
		{"empty password", "", false},
		{"similar password", "correctpassword1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyPassword(tt.password, hash)
			if got != tt.want {
				t.Errorf("VerifyPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateJWT(t *testing.T) {
	cfg := &Config{
		JWTSecret:   "testsecret123",
		JWTIssuer:   "test-issuer",
		TokenExpiry: time.Hour,
	}

	token, expiresAt, err := GenerateJWT(cfg, "user123", "testuser")
	if err != nil {
		t.Fatalf("GenerateJWT() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateJWT() returned empty token")
	}

	// Token should have 3 parts (header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("GenerateJWT() token has %d parts, want 3", len(parts))
	}

	// ExpiresAt should be approximately 1 hour from now
	expectedExpiry := time.Now().Add(time.Hour)
	if expiresAt.Before(expectedExpiry.Add(-time.Minute)) || expiresAt.After(expectedExpiry.Add(time.Minute)) {
		t.Errorf("GenerateJWT() expiresAt = %v, want approximately %v", expiresAt, expectedExpiry)
	}
}

func TestGenerateJWTNoSecret(t *testing.T) {
	cfg := &Config{
		JWTSecret: "",
	}

	_, _, err := GenerateJWT(cfg, "user123", "testuser")
	if err == nil {
		t.Error("GenerateJWT() should return error when JWTSecret is empty")
	}
}

func TestValidateJWT(t *testing.T) {
	cfg := &Config{
		JWTSecret:   "testsecret123",
		JWTIssuer:   "test-issuer",
		TokenExpiry: time.Hour,
	}

	token, _, err := GenerateJWT(cfg, "user123", "testuser")
	if err != nil {
		t.Fatalf("GenerateJWT() error = %v", err)
	}

	claims, err := ValidateJWT(cfg, token)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}

	if claims.UserID != "user123" {
		t.Errorf("ValidateJWT().UserID = %q, want %q", claims.UserID, "user123")
	}
	if claims.Username != "testuser" {
		t.Errorf("ValidateJWT().Username = %q, want %q", claims.Username, "testuser")
	}
}

func TestValidateJWTInvalid(t *testing.T) {
	cfg := &Config{
		JWTSecret:   "testsecret123",
		JWTIssuer:   "test-issuer",
		TokenExpiry: time.Hour,
	}

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"invalid format", "notavalidtoken"},
		{"wrong signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlcjEyMyJ9.invalidsignature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateJWT(cfg, tt.token)
			if err == nil {
				t.Error("ValidateJWT() should return error for invalid token")
			}
		})
	}
}

func TestValidateJWTWrongSecret(t *testing.T) {
	cfg := &Config{
		JWTSecret:   "testsecret123",
		JWTIssuer:   "test-issuer",
		TokenExpiry: time.Hour,
	}

	token, _, err := GenerateJWT(cfg, "user123", "testuser")
	if err != nil {
		t.Fatalf("GenerateJWT() error = %v", err)
	}

	wrongCfg := &Config{
		JWTSecret: "wrongsecret",
	}

	_, err = ValidateJWT(wrongCfg, token)
	if err == nil {
		t.Error("ValidateJWT() should return error for wrong secret")
	}
}

func TestValidateJWTExpired(t *testing.T) {
	cfg := &Config{
		JWTSecret:   "testsecret123",
		JWTIssuer:   "test-issuer",
		TokenExpiry: -time.Hour, // Expired 1 hour ago
	}

	token, _, err := GenerateJWT(cfg, "user123", "testuser")
	if err != nil {
		t.Fatalf("GenerateJWT() error = %v", err)
	}

	_, err = ValidateJWT(cfg, token)
	if err != ErrTokenExpired {
		t.Errorf("ValidateJWT() error = %v, want %v", err, ErrTokenExpired)
	}
}

func TestGenerateMFASecret(t *testing.T) {
	secret, url, err := GenerateMFASecret("TestIssuer", "testuser")
	if err != nil {
		t.Fatalf("GenerateMFASecret() error = %v", err)
	}

	if secret == "" {
		t.Error("GenerateMFASecret() returned empty secret")
	}

	if !strings.HasPrefix(url, "otpauth://totp/") {
		t.Errorf("GenerateMFASecret() URL = %q, should start with otpauth://totp/", url)
	}

	if !strings.Contains(url, "TestIssuer") {
		t.Errorf("GenerateMFASecret() URL = %q, should contain issuer", url)
	}
}

func TestGenerateBackupCodes(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes(5)
	if err != nil {
		t.Fatalf("GenerateBackupCodes() error = %v", err)
	}

	if len(codes) != 5 {
		t.Errorf("GenerateBackupCodes() codes length = %d, want 5", len(codes))
	}
	if len(hashes) != 5 {
		t.Errorf("GenerateBackupCodes() hashes length = %d, want 5", len(hashes))
	}

	// Each code should be 16 hex characters (8 bytes)
	for i, code := range codes {
		if len(code) != 16 {
			t.Errorf("GenerateBackupCodes() code[%d] length = %d, want 16", i, len(code))
		}
	}

	// Codes should be unique
	seen := make(map[string]bool)
	for _, code := range codes {
		if seen[code] {
			t.Error("GenerateBackupCodes() generated duplicate codes")
		}
		seen[code] = true
	}
}

func TestGenerateBackupCodesDefault(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes(0)
	if err != nil {
		t.Fatalf("GenerateBackupCodes() error = %v", err)
	}

	if len(codes) != DefaultBackupCodeCount {
		t.Errorf("GenerateBackupCodes(0) codes length = %d, want %d", len(codes), DefaultBackupCodeCount)
	}
	if len(hashes) != DefaultBackupCodeCount {
		t.Errorf("GenerateBackupCodes(0) hashes length = %d, want %d", len(hashes), DefaultBackupCodeCount)
	}
}

func TestValidateBackupCode(t *testing.T) {
	codes, hashes, err := GenerateBackupCodes(3)
	if err != nil {
		t.Fatalf("GenerateBackupCodes() error = %v", err)
	}

	// Valid codes should match
	for i, code := range codes {
		idx := ValidateBackupCode(code, hashes)
		if idx != i {
			t.Errorf("ValidateBackupCode() = %d, want %d for code %d", idx, i, i)
		}
	}

	// Invalid code should return -1
	idx := ValidateBackupCode("invalidcode12345", hashes)
	if idx != -1 {
		t.Errorf("ValidateBackupCode() = %d, want -1 for invalid code", idx)
	}
}

func TestGenerateSessionID(t *testing.T) {
	id1, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error = %v", err)
	}

	if len(id1) == 0 {
		t.Error("GenerateSessionID() returned empty string")
	}

	// Should be base32 encoded (32 bytes = ~52 chars without padding)
	if len(id1) < 50 {
		t.Errorf("GenerateSessionID() length = %d, expected ~52", len(id1))
	}

	// Should generate unique IDs
	id2, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error = %v", err)
	}
	if id1 == id2 {
		t.Error("GenerateSessionID() generated duplicate IDs")
	}
}

func TestGenerateUserID(t *testing.T) {
	id1, err := GenerateUserID()
	if err != nil {
		t.Fatalf("GenerateUserID() error = %v", err)
	}

	// Should be 32 hex characters (16 bytes)
	if len(id1) != 32 {
		t.Errorf("GenerateUserID() length = %d, want 32", len(id1))
	}

	// Should be valid hex
	for _, c := range id1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("GenerateUserID() contains invalid hex character: %c", c)
		}
	}

	// Should generate unique IDs
	id2, err := GenerateUserID()
	if err != nil {
		t.Fatalf("GenerateUserID() error = %v", err)
	}
	if id1 == id2 {
		t.Error("GenerateUserID() generated duplicate IDs")
	}
}

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"equal strings", "hello", "hello", true},
		{"different strings", "hello", "world", false},
		{"different lengths", "hello", "hello!", false},
		{"empty strings", "", "", true},
		{"one empty", "hello", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SecureCompare(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("SecureCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.JWTIssuer != "coldforge-signer" {
		t.Errorf("DefaultConfig().JWTIssuer = %q, want %q", cfg.JWTIssuer, "coldforge-signer")
	}
	if cfg.TokenExpiry != DefaultTokenExpiry {
		t.Errorf("DefaultConfig().TokenExpiry = %v, want %v", cfg.TokenExpiry, DefaultTokenExpiry)
	}
	if cfg.BcryptCost != DefaultBcryptCost {
		t.Errorf("DefaultConfig().BcryptCost = %d, want %d", cfg.BcryptCost, DefaultBcryptCost)
	}
	if cfg.LockoutDuration != DefaultLockoutDuration {
		t.Errorf("DefaultConfig().LockoutDuration = %v, want %v", cfg.LockoutDuration, DefaultLockoutDuration)
	}
	if cfg.MaxFailedAttempts != DefaultMaxFailedAttempts {
		t.Errorf("DefaultConfig().MaxFailedAttempts = %d, want %d", cfg.MaxFailedAttempts, DefaultMaxFailedAttempts)
	}
	if cfg.MFAIssuer != "Coldforge" {
		t.Errorf("DefaultConfig().MFAIssuer = %q, want %q", cfg.MFAIssuer, "Coldforge")
	}
}
