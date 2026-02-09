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
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/admin"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/api"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/config"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/metrics"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/nostr"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/signer"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/storage"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/web"
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

	// Set auth key for NIP-42 relay authentication
	if cfg.RelayAuthKey != "" {
		relayClient.SetAuthKey(cfg.RelayAuthKey)
		slog.Info("NIP-42 relay auth enabled")
	}

	// Initialize NIP-46 signer
	nip46Signer := signer.New(cfg, store, relayClient)

	// Initialize HTTP API
	apiHandler := api.NewHandler(cfg, nip46Signer, store)

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
			adminHandler.SetSignerKey(keys[0].Pubkey, keys[0].EncryptedNsec)
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
