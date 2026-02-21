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

	// Set auth key for NIP-42 relay authentication
	// If RELAY_AUTH_KEY is set, use it. Otherwise, use the first signing key.
	if cfg.RelayAuthKey != "" {
		relayClient.SetAuthKey(cfg.RelayAuthKey)
		slog.Info("NIP-42 relay auth enabled")
	} else {
		// Try to use the first available signing key for relay auth
		keys, err := store.ListKeys(context.Background())
		if err == nil && len(keys) > 0 {
			privateKey := keys[0].EncryptedNsec
			// Decrypt if encrypted
			if encryptor != nil && crypto.IsEncrypted(privateKey) {
				decrypted, err := encryptor.Decrypt(privateKey)
				if err != nil {
					slog.Warn("failed to decrypt key for relay auth", "error", err)
				} else {
					privateKey = decrypted
				}
			}
			if privateKey != "" {
				relayClient.SetAuthKey(privateKey)
				slog.Info("NIP-42 relay auth enabled using first signing key", "pubkey", keys[0].Pubkey[:16]+"...")
			}
		} else {
			slog.Warn("no RELAY_AUTH_KEY set and no signing keys available for NIP-42 auth")
		}
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

	// Set the admin communication key (prefer relay auth key, fallback to first stored key)
	if cfg.RelayAuthKey != "" {
		pubkey, err := gonostr.GetPublicKey(cfg.RelayAuthKey)
		if err == nil {
			adminHandler.SetSignerKey(pubkey, cfg.RelayAuthKey)
			slog.Info("admin handler using relay auth key", "pubkey", pubkey[:16]+"...")
		}
	} else {
		// Try to use the first available key
		keys, err := store.ListKeys(ctx)
		if err == nil && len(keys) > 0 {
			privateKey := keys[0].EncryptedNsec
			// Decrypt if encrypted
			if crypto.IsEncrypted(privateKey) && encryptor != nil {
				decrypted, err := encryptor.Decrypt(privateKey)
				if err != nil {
					slog.Warn("failed to decrypt key for admin handler", "error", err)
				} else {
					privateKey = decrypted
				}
			}
			adminHandler.SetSignerKey(keys[0].Pubkey, privateKey)
			slog.Info("admin handler using first stored key", "pubkey", keys[0].Pubkey[:16]+"...")
		}
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
