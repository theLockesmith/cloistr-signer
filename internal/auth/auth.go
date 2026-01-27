package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	// DefaultBcryptCost is the default cost for bcrypt hashing
	DefaultBcryptCost = 12

	// DefaultTokenExpiry is the default JWT token expiry
	DefaultTokenExpiry = 24 * time.Hour

	// DefaultLockoutDuration is the default account lockout duration
	DefaultLockoutDuration = 15 * time.Minute

	// DefaultMaxFailedAttempts is the max failed login attempts before lockout
	DefaultMaxFailedAttempts = 5

	// DefaultBackupCodeCount is the number of backup codes to generate
	DefaultBackupCodeCount = 10
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidSignature = errors.New("invalid signature")
)

// Config holds authentication configuration
type Config struct {
	JWTSecret         string
	JWTIssuer         string
	TokenExpiry       time.Duration
	BcryptCost        int
	LockoutDuration   time.Duration
	MaxFailedAttempts int
	MFAIssuer         string
}

// DefaultConfig returns a default auth config
func DefaultConfig() *Config {
	return &Config{
		JWTSecret:         "", // Must be set
		JWTIssuer:         "coldforge-signer",
		TokenExpiry:       DefaultTokenExpiry,
		BcryptCost:        DefaultBcryptCost,
		LockoutDuration:   DefaultLockoutDuration,
		MaxFailedAttempts: DefaultMaxFailedAttempts,
		MFAIssuer:         "Coldforge",
	}
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string, cost int) (string, error) {
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifies a password against a bcrypt hash
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateJWT generates a new JWT token for a user
func GenerateJWT(cfg *Config, userID, username string) (string, time.Time, error) {
	if cfg.JWTSecret == "" {
		return "", time.Time{}, errors.New("JWT secret not configured")
	}

	expiresAt := time.Now().Add(cfg.TokenExpiry)
	claims := JWTClaims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    cfg.JWTIssuer,
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// ValidateJWT validates a JWT token and returns the claims
func ValidateJWT(cfg *Config, tokenString string) (*JWTClaims, error) {
	if cfg.JWTSecret == "" {
		return nil, errors.New("JWT secret not configured")
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(cfg.JWTSecret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// GenerateMFASecret generates a new TOTP secret for MFA
func GenerateMFASecret(issuer, username string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}

	return key.Secret(), key.URL(), nil
}

// ValidateMFACode validates a TOTP code against a secret
func ValidateMFACode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes generates a set of backup codes
func GenerateBackupCodes(count int) ([]string, []string, error) {
	if count == 0 {
		count = DefaultBackupCodeCount
	}

	codes := make([]string, count)
	hashes := make([]string, count)

	for i := 0; i < count; i++ {
		// Generate 8-byte random code
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		code := hex.EncodeToString(b)
		codes[i] = code

		// Hash the code for storage
		hash, err := HashPassword(code, DefaultBcryptCost)
		if err != nil {
			return nil, nil, err
		}
		hashes[i] = hash
	}

	return codes, hashes, nil
}

// ValidateBackupCode validates a backup code against a list of hashed codes
// Returns the index of the matched code, or -1 if not found
func ValidateBackupCode(code string, hashedCodes []string) int {
	for i, hash := range hashedCodes {
		if VerifyPassword(code, hash) {
			return i
		}
	}
	return -1
}

// GenerateSessionID generates a random session ID
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateUserID generates a random user ID
func GenerateUserID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate user ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// SecureCompare performs a constant-time comparison of two strings
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
