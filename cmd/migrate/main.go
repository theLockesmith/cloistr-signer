// Migration tool for cloistr-signer
// Re-encrypts existing keys from local AES-GCM encryption to Vault transit encryption
package main

import (
	"context"
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

	slog.Info("starting vault migration",
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
		fmt.Println("Error: Vault must be enabled and configured to run migration")
		fmt.Println("Set VAULT_ENABLED=true and VAULT_ADDRESS=<url>")
		os.Exit(1)
	}

	// Validate local encryption key (needed to decrypt existing keys)
	if cfg.Storage.EncryptionKey == "" {
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

	// Initialize local encryptor (for decrypting existing keys)
	localEncryptor, err := crypto.NewEncryptor(cfg.Storage.EncryptionKey)
	if err != nil {
		slog.Error("failed to initialize local encryptor", "error", err)
		os.Exit(1)
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

			// Re-encrypt with Vault transit
			transitKeyName := vault.UserTransitKeyName(user.ID)
			encrypted, err := vaultClient.TransitEncrypt(ctx, transitKeyName, decrypted)
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
