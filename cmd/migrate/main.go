// Migration tool for cloistr-signer
// Re-encrypts existing keys from local AES-GCM encryption to Vault transit encryption
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

func main() {
	// Parse flags
	dryRun := flag.Bool("dry-run", false, "Show what would be migrated without making changes")
	userID := flag.String("user", "", "Migrate only a specific user ID (empty = all users)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	rotate := flag.Bool("rotate", false, "Rotate Vault transit keys and rewrap existing ciphertext to the new version (privacy-architecture §3.7). Does not require ENCRYPTION_KEY because no local decryption is needed.")
	flag.Parse()

	// Setup logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	mode := "migrate"
	if *rotate {
		mode = "rotate"
	}
	slog.Info("starting vault tool",
		"mode", mode,
		"dry_run", *dryRun,
		"user_filter", *userID,
	)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Validate Vault configuration
	if !cfg.Vault.Enabled || cfg.Vault.Address == "" {
		slog.Error("Vault is not configured", "vault_enabled", cfg.Vault.Enabled, "vault_address", cfg.Vault.Address)
		fmt.Println("Error: Vault must be enabled and configured")
		fmt.Println("Set VAULT_ENABLED=true and VAULT_ADDRESS=<url>")
		os.Exit(1)
	}

	// The local encryption key is only needed for the migrate path (which
	// decrypts locally-encrypted ciphertext before re-encrypting via Vault).
	// The rotate path operates entirely on Vault-side ciphertext, so it
	// skips this check.
	if !*rotate && cfg.Storage.EncryptionKey == "" {
		slog.Error("local encryption key not configured")
		fmt.Println("Error: ENCRYPTION_KEY must be set to decrypt existing keys")
		os.Exit(1)
	}

	// Initialize storage
	store, err := storage.New(cfg.Storage)
	if err != nil {
		slog.Error("failed to initialize storage", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	// Initialize local encryptor only when needed (migrate path).
	var localEncryptor *crypto.Encryptor
	if !*rotate {
		localEncryptor, err = crypto.NewEncryptor(cfg.Storage.EncryptionKey)
		if err != nil {
			slog.Error("failed to initialize local encryptor", "error", err)
			os.Exit(1)
		}
	}

	// Initialize Vault client (with service account token)
	vaultClient, err := vault.NewClient(&vault.Config{
		Address:    cfg.Vault.Address,
		Token:      cfg.Vault.Token, // Service account token
		MountPath:  cfg.Vault.MountPath,
		SkipVerify: cfg.Vault.SkipVerify,
	})
	if err != nil {
		slog.Error("failed to initialize vault client", "error", err)
		os.Exit(1)
	}

	// Verify Vault connectivity
	if err := vaultClient.HealthCheck(context.Background()); err != nil {
		slog.Error("vault health check failed", "error", err)
		os.Exit(1)
	}
	slog.Info("vault connected", "address", cfg.Vault.Address)

	ctx := context.Background()

	// Get all users
	users, err := store.ListUsers(ctx)
	if err != nil {
		slog.Error("failed to list users", "error", err)
		os.Exit(1)
	}

	if *userID != "" {
		// Filter to specific user
		filtered := []*storage.User{}
		for _, u := range users {
			if u.ID == *userID {
				filtered = append(filtered, u)
				break
			}
		}
		if len(filtered) == 0 {
			slog.Error("user not found", "user_id", *userID)
			os.Exit(1)
		}
		users = filtered
	}

	slog.Info("found users to process", "count", len(users))

	// Rotate path is independent of the migrate path: it operates entirely
	// on Vault-side ciphertext (no local plaintext exposure) and is
	// scheduled separately as ops hygiene per privacy-architecture §3.7.
	if *rotate {
		if err := runRotate(ctx, store, vaultClient, users, *dryRun); err != nil {
			slog.Error("rotate failed", "error", err)
			os.Exit(1)
		}
		return
	}

	// Track statistics
	var stats struct {
		usersProcessed    int
		keysTotal         int
		keysMigrated      int
		keysAlreadyVault  int
		keysSkippedNoData int
		errors            int
	}

	for _, user := range users {
		slog.Info("processing user", "user_id", user.ID, "username", user.Username)

		// Ensure user has Vault resources (transit key, userpass account, policy)
		// Note: For migration, we use a temp password - user will reset on first login
		if !*dryRun {
			if err := ensureUserVaultResources(ctx, vaultClient, user.ID); err != nil {
				slog.Error("failed to ensure vault resources for user", "error", err, "user_id", user.ID)
				stats.errors++
				continue
			}
		}

		// Get user's keys
		keys, err := store.ListKeys(ctx, user.ID)
		if err != nil {
			slog.Error("failed to list keys for user", "error", err, "user_id", user.ID)
			stats.errors++
			continue
		}

		stats.usersProcessed++
		stats.keysTotal += len(keys)

		for _, key := range keys {
			// Skip keys without encrypted data
			if key.EncryptedNsec == "" {
				slog.Debug("skipping key with no encrypted data", "key_id", key.ID)
				stats.keysSkippedNoData++
				continue
			}

			// Check if already Vault-encrypted
			if crypto.IsVaultEncrypted(key.EncryptedNsec) {
				slog.Debug("key already vault-encrypted", "key_id", key.ID)
				stats.keysAlreadyVault++
				continue
			}

			// Check if locally encrypted
			if !crypto.IsEncrypted(key.EncryptedNsec) {
				slog.Warn("key has unknown encryption format, skipping", "key_id", key.ID)
				continue
			}

			slog.Info("migrating key",
				"key_id", key.ID,
				"pubkey", truncatePubkey(key.Pubkey),
				"user_id", user.ID,
				"dry_run", *dryRun,
			)

			if *dryRun {
				stats.keysMigrated++
				continue
			}

			// Decrypt with local encryptor
			decrypted, err := localEncryptor.Decrypt(key.EncryptedNsec)
			if err != nil {
				slog.Error("failed to decrypt key", "error", err, "key_id", key.ID)
				stats.errors++
				continue
			}

			// Re-encrypt with Vault transit. Vault transit expects the
			// `plaintext` field to be base64-encoded; sending the raw
			// hex string here would corrupt the key (Vault stores it
			// verbatim and returns it un-base64 on decrypt, so the
			// VaultEncryptor.Decrypt path would base64-decode it into
			// garbage).
			transitKeyName := vault.UserTransitKeyName(user.ID)
			b64Plaintext := base64.StdEncoding.EncodeToString([]byte(decrypted))
			encrypted, err := vaultClient.TransitEncrypt(ctx, transitKeyName, b64Plaintext)
			if err != nil {
				slog.Error("failed to encrypt with vault", "error", err, "key_id", key.ID)
				stats.errors++
				continue
			}

			// Update key in database
			key.EncryptedNsec = encrypted
			key.EncryptionMethod = "vault"
			if err := store.UpdateKeyEncryption(ctx, key.ID, key.EncryptedNsec, key.EncryptionMethod); err != nil {
				slog.Error("failed to update key in database", "error", err, "key_id", key.ID)
				stats.errors++
				continue
			}

			stats.keysMigrated++
			slog.Info("migrated key successfully", "key_id", key.ID, "pubkey", truncatePubkey(key.Pubkey))
		}
	}

	// Print summary
	fmt.Println("\n=== Migration Summary ===")
	fmt.Printf("Users processed:        %d\n", stats.usersProcessed)
	fmt.Printf("Total keys found:       %d\n", stats.keysTotal)
	fmt.Printf("Keys migrated:          %d\n", stats.keysMigrated)
	fmt.Printf("Already Vault-encrypted: %d\n", stats.keysAlreadyVault)
	fmt.Printf("Skipped (no data):      %d\n", stats.keysSkippedNoData)
	fmt.Printf("Errors:                 %d\n", stats.errors)
	if *dryRun {
		fmt.Println("\n(Dry run - no changes made)")
	}

	if stats.errors > 0 {
		os.Exit(1)
	}
}

// ensureUserVaultResources creates Vault transit key, policy, and userpass account for user if they don't exist
func ensureUserVaultResources(ctx context.Context, client *vault.Client, userID string) error {
	// Create transit key (idempotent)
	keyName := vault.UserTransitKeyName(userID)
	if err := client.CreateTransitKey(ctx, keyName); err != nil {
		// Ignore "key already exists" errors
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("create transit key: %w", err)
		}
	}

	// Create policy (idempotent)
	policyName := vault.UserPolicyName(userID)
	policy := vault.GenerateUserPolicy(userID)
	if err := client.CreatePolicy(ctx, policyName, policy); err != nil {
		return fmt.Errorf("create policy: %w", err)
	}

	// Note: We don't create userpass account here since we don't have the user's password
	// Users will need to reset their password or re-register after migration
	// The userpass account will be created on next login if auth is updated to handle this

	return nil
}

func truncatePubkey(pubkey string) string {
	if len(pubkey) > 16 {
		return pubkey[:16] + "..."
	}
	return pubkey
}

// runRotate rotates each user's Vault transit key and rewraps existing
// ciphertext to the new key version. Operates entirely on Vault-side
// ciphertext: plaintext is never exposed to this process. Implements
// privacy-architecture §3.7 "Vault rewrap" as ops hygiene.
//
// The admin policy update is applied as a side effect (idempotent
// CreatePolicy with the current GenerateUserPolicy, which grants rewrap
// capability for end-user-initiated refreshes).
func runRotate(ctx context.Context, store storage.Storage, vaultClient *vault.Client, users []*storage.User, dryRun bool) error {
	var stats struct {
		usersRotated     int
		policiesUpdated  int
		keysRewrapped    int
		keysSkippedEmpty int
		keysSkippedNon   int
		errors           int
	}

	for _, user := range users {
		keyName := vault.UserTransitKeyName(user.ID)
		policyName := vault.UserPolicyName(user.ID)
		policy := vault.GenerateUserPolicy(user.ID)

		slog.Info("rotating user transit key",
			"user_id", user.ID,
			"username", user.Username,
			"dry_run", dryRun,
		)

		if !dryRun {
			// Ensure the policy reflects the current GenerateUserPolicy output
			// (which includes rewrap capability).
			if err := vaultClient.CreatePolicy(ctx, policyName, policy); err != nil {
				slog.Error("policy update failed", "error", err, "user_id", user.ID)
				stats.errors++
				// Continue: policy update is not strictly required for the rotate
				// itself; failures here are usually permission issues.
			} else {
				stats.policiesUpdated++
			}

			if err := vaultClient.TransitRotateKey(ctx, keyName); err != nil {
				slog.Error("rotate failed", "error", err, "user_id", user.ID)
				stats.errors++
				continue
			}
		}
		stats.usersRotated++

		keys, err := store.ListKeys(ctx, user.ID)
		if err != nil {
			slog.Error("list keys failed", "error", err, "user_id", user.ID)
			stats.errors++
			continue
		}

		for _, key := range keys {
			if key.EncryptedNsec == "" {
				stats.keysSkippedEmpty++
				continue
			}
			if !crypto.IsVaultEncrypted(key.EncryptedNsec) {
				slog.Debug("skipping non-Vault-encrypted key",
					"key_id", key.ID,
					"encryption_method", key.EncryptionMethod,
				)
				stats.keysSkippedNon++
				continue
			}

			if dryRun {
				slog.Info("would rewrap key",
					"key_id", key.ID,
					"pubkey", truncatePubkey(key.Pubkey),
				)
				stats.keysRewrapped++
				continue
			}

			newCiphertext, err := vaultClient.TransitRewrap(ctx, keyName, key.EncryptedNsec)
			if err != nil {
				slog.Error("rewrap failed", "error", err, "key_id", key.ID)
				stats.errors++
				continue
			}

			if err := store.UpdateKeyEncryption(ctx, key.ID, newCiphertext, "vault"); err != nil {
				slog.Error("update key encryption failed", "error", err, "key_id", key.ID)
				stats.errors++
				continue
			}

			stats.keysRewrapped++
			slog.Info("rewrapped key", "key_id", key.ID, "pubkey", truncatePubkey(key.Pubkey))
		}
	}

	fmt.Println("\n=== Rotate Summary ===")
	fmt.Printf("Users rotated:           %d\n", stats.usersRotated)
	fmt.Printf("Policies updated:        %d\n", stats.policiesUpdated)
	fmt.Printf("Keys rewrapped:          %d\n", stats.keysRewrapped)
	fmt.Printf("Skipped (empty):         %d\n", stats.keysSkippedEmpty)
	fmt.Printf("Skipped (non-Vault):     %d\n", stats.keysSkippedNon)
	fmt.Printf("Errors:                  %d\n", stats.errors)
	if dryRun {
		fmt.Println("\n(Dry run - no changes made)")
	}

	if stats.errors > 0 {
		return fmt.Errorf("%d errors during rotate", stats.errors)
	}
	return nil
}
