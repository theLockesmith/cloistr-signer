package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/admin"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/api"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/config"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/metrics"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/nostr"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/signer"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/storage"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/web"
)

func main() {
	// Setup structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("starting coldforge-signer")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Initialize storage backend
	store, err := storage.New(cfg.Storage)
	if err != nil {
		slog.Error("failed to initialize storage", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	// Initialize relay client
	relayClient := nostr.NewClient(cfg.Relays)

	// Initialize encryptor for key encryption at rest
	var encryptor *crypto.Encryptor
	if cfg.Storage.EncryptionKey != "" {
		var err error
		encryptor, err = crypto.NewEncryptor(cfg.Storage.EncryptionKey)
		if err != nil {
			slog.Error("failed to initialize encryptor", "error", err)
			os.Exit(1)
		}
		slog.Info("key encryption enabled")
	} else {
		slog.Warn("ENCRYPTION_KEY not set, keys will be stored unencrypted")
	}

	// Load or generate signer identity keypair
	// This is a dedicated key for the signer itself (NIP-42 auth, admin DMs, etc.)
	signerPrivkey, signerPubkey := loadOrGenerateSignerIdentity(context.Background(), store, encryptor)

	// Set auth key for NIP-42 relay authentication
	// Priority: RELAY_AUTH_KEY env var > signer identity
	if cfg.RelayAuthKey != "" {
		relayClient.SetAuthKey(cfg.RelayAuthKey)
		slog.Info("NIP-42 relay auth enabled with explicit key")
	} else if signerPrivkey != "" {
		relayClient.SetAuthKey(signerPrivkey)
		slog.Info("NIP-42 relay auth enabled with signer identity", "pubkey", signerPubkey[:16]+"...")
	} else {
		slog.Warn("no relay auth key available for NIP-42 auth")
	}

	// Initialize NIP-46 signer
	nip46Signer := signer.New(cfg, store, relayClient, encryptor)

	// Initialize HTTP API
	apiHandler := api.NewHandler(cfg, nip46Signer, store, encryptor)

	// Initialize Web UI
	webHandler, err := web.New(cfg, store, nip46Signer, nip46Signer)
	if err != nil {
		slog.Error("failed to initialize web handler", "error", err)
		os.Exit(1)
	}

	// Create HTTP server
	mux := http.NewServeMux()
	apiHandler.RegisterRoutes(mux)
	webHandler.RegisterRoutes(mux)

	// Add Prometheus metrics endpoint
	mux.Handle("/metrics", metrics.Handler())

	// Wrap with metrics middleware
	handler := metrics.Middleware(mux)

	server := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start relay connections
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := nip46Signer.Start(ctx); err != nil {
		slog.Error("failed to start signer", "error", err)
		os.Exit(1)
	}

	// Initialize admin handler for DM-based management
	adminHandler := admin.New(cfg, store, relayClient, nip46Signer, nip46Signer)

	// Set the admin communication key using signer identity
	if cfg.RelayAuthKey != "" {
		pubkey, err := gonostr.GetPublicKey(cfg.RelayAuthKey)
		if err == nil {
			adminHandler.SetSignerKey(pubkey, cfg.RelayAuthKey)
			slog.Info("admin handler using explicit relay auth key", "pubkey", pubkey[:16]+"...")
		}
	} else if signerPrivkey != "" {
		adminHandler.SetSignerKey(signerPubkey, signerPrivkey)
		slog.Info("admin handler using signer identity", "pubkey", signerPubkey[:16]+"...")
	}

	// Start admin DM listener
	if err := adminHandler.Start(ctx); err != nil {
		slog.Warn("failed to start admin handler", "error", err)
	}

	// Send boot notification to admins (async)
	go func() {
		// Give relays a moment to connect
		time.Sleep(2 * time.Second)
		adminHandler.SendBootNotification(ctx)
	}()

	// Start HTTP server in goroutine
	go func() {
		slog.Info("starting HTTP server", "address", cfg.Server.Address)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop signer (disconnect from relays)
	nip46Signer.Stop()

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}

	slog.Info("shutdown complete")
}

const signerIdentityKey = "signer_identity_privkey"

// loadOrGenerateSignerIdentity loads the signer's dedicated identity keypair from storage,
// or generates a new one if it doesn't exist. This key is used for NIP-42 relay auth
// and admin DM communication.
func loadOrGenerateSignerIdentity(ctx context.Context, store storage.Storage, encryptor *crypto.Encryptor) (privkey, pubkey string) {
	// Try to load existing identity
	storedPrivkey, err := store.GetSetting(ctx, signerIdentityKey)
	if err == nil {
		// Decrypt if encrypted
		if encryptor != nil && crypto.IsEncrypted(storedPrivkey) {
			decrypted, err := encryptor.Decrypt(storedPrivkey)
			if err != nil {
				slog.Error("failed to decrypt signer identity", "error", err)
				return "", ""
			}
			storedPrivkey = decrypted
		}

		pubkey, err := gonostr.GetPublicKey(storedPrivkey)
		if err == nil {
			slog.Info("loaded signer identity", "pubkey", pubkey)
			return storedPrivkey, pubkey
		}
		slog.Warn("stored signer identity invalid, regenerating", "error", err)
	}

	// Generate new identity
	privkey = gonostr.GeneratePrivateKey()
	pubkey, err = gonostr.GetPublicKey(privkey)
	if err != nil {
		slog.Error("failed to derive pubkey from generated key", "error", err)
		return "", ""
	}

	// Encrypt before storing
	toStore := privkey
	if encryptor != nil {
		encrypted, err := encryptor.Encrypt(privkey)
		if err != nil {
			slog.Error("failed to encrypt signer identity", "error", err)
			return "", ""
		}
		toStore = encrypted
	}

	// Store the identity
	if err := store.SetSetting(ctx, signerIdentityKey, toStore); err != nil {
		slog.Error("failed to store signer identity", "error", err)
		return "", ""
	}

	slog.Info("generated new signer identity", "pubkey", pubkey)
	return privkey, pubkey
}
