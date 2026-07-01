package signer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// benchmarkSetup creates a signer with a test key for benchmarking
func benchmarkSetup(b *testing.B) (*Signer, string, string, *storage.Permission) {
	b.Helper()

	store := storage.NewMemoryStorage()
	signer := New(&config.Config{}, store, nil, nil, nil, nil, nil)

	// Use a valid secp256k1 test key
	pubkey := "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	privateKey := "0000000000000000000000000000000000000000000000000000000000000001"
	signer.RegisterKey(pubkey, privateKey)

	perm := &storage.Permission{
		Methods:      []string{"sign_event"},
		AllowedKinds: []int{}, // Allow all kinds
	}

	return signer, pubkey, privateKey, perm
}

// BenchmarkSignEvent benchmarks single event signing
func BenchmarkSignEvent(b *testing.B) {
	signer, pubkey, privateKey, perm := benchmarkSetup(b)
	ctx := context.Background()

	// Realistic kind:1 text note event
	eventJSON := fmt.Sprintf(`{"kind":1,"content":"benchmark test event %d","tags":[],"created_at":%d}`,
		time.Now().UnixNano(), time.Now().Unix())

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := signer.handleSignEvent(ctx, pubkey, privateKey, "", []string{eventJSON}, perm)
		if err != nil {
			b.Fatalf("handleSignEvent() error = %v", err)
		}
	}
}

// BenchmarkSignEvent_LargeContent benchmarks signing events with larger content
func BenchmarkSignEvent_LargeContent(b *testing.B) {
	signer, pubkey, privateKey, perm := benchmarkSetup(b)
	ctx := context.Background()

	// 4KB content (realistic for long-form notes)
	largeContent := make([]byte, 4096)
	for i := range largeContent {
		largeContent[i] = 'a' + byte(i%26)
	}

	eventJSON := fmt.Sprintf(`{"kind":30023,"content":"%s","tags":[],"created_at":%d}`,
		string(largeContent), time.Now().Unix())

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := signer.handleSignEvent(ctx, pubkey, privateKey, "", []string{eventJSON}, perm)
		if err != nil {
			b.Fatalf("handleSignEvent() error = %v", err)
		}
	}
}

// BenchmarkBatchSign benchmarks batch signing with various batch sizes
func BenchmarkBatchSign(b *testing.B) {
	batchSizes := []int{1, 5, 10, 25, 50}

	for _, size := range batchSizes {
		b.Run(fmt.Sprintf("batch_%d", size), func(b *testing.B) {
			signer, pubkey, privateKey, perm := benchmarkSetup(b)
			ctx := context.Background()

			// Create batch of events
			events := make([]string, size)
			baseTime := time.Now().Unix()
			for i := 0; i < size; i++ {
				events[i] = fmt.Sprintf(`{"kind":1,"content":"batch event %d","tags":[],"created_at":%d}`,
					i, baseTime+int64(i))
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := signer.handleBatchSign(ctx, pubkey, privateKey, events, perm)
				if err != nil {
					b.Fatalf("handleBatchSign() error = %v", err)
				}
			}
		})
	}
}

// BenchmarkConcurrentSigning benchmarks parallel signing operations
func BenchmarkConcurrentSigning(b *testing.B) {
	signer, pubkey, privateKey, perm := benchmarkSetup(b)
	ctx := context.Background()

	eventJSON := fmt.Sprintf(`{"kind":1,"content":"concurrent test","tags":[],"created_at":%d}`,
		time.Now().Unix())

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := signer.handleSignEvent(ctx, pubkey, privateKey, "", []string{eventJSON}, perm)
			if err != nil {
				b.Fatalf("handleSignEvent() error = %v", err)
			}
		}
	})
}

// BenchmarkBatchVsSequential compares batch signing vs sequential signing
func BenchmarkBatchVsSequential(b *testing.B) {
	const eventCount = 10

	b.Run("sequential_10", func(b *testing.B) {
		signer, pubkey, privateKey, perm := benchmarkSetup(b)
		ctx := context.Background()

		events := make([]string, eventCount)
		baseTime := time.Now().Unix()
		for i := 0; i < eventCount; i++ {
			events[i] = fmt.Sprintf(`{"kind":1,"content":"sequential event %d","tags":[],"created_at":%d}`,
				i, baseTime+int64(i))
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, event := range events {
				_, err := signer.handleSignEvent(ctx, pubkey, privateKey, "", []string{event}, perm)
				if err != nil {
					b.Fatalf("handleSignEvent() error = %v", err)
				}
			}
		}
	})

	b.Run("batch_10", func(b *testing.B) {
		signer, pubkey, privateKey, perm := benchmarkSetup(b)
		ctx := context.Background()

		events := make([]string, eventCount)
		baseTime := time.Now().Unix()
		for i := 0; i < eventCount; i++ {
			events[i] = fmt.Sprintf(`{"kind":1,"content":"batch event %d","tags":[],"created_at":%d}`,
				i, baseTime+int64(i))
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := signer.handleBatchSign(ctx, pubkey, privateKey, events, perm)
			if err != nil {
				b.Fatalf("handleBatchSign() error = %v", err)
			}
		}
	})
}

// BenchmarkNIP44Operations benchmarks NIP-44 encryption/decryption
func BenchmarkNIP44Operations(b *testing.B) {
	signer, _, privateKey, _ := benchmarkSetup(b)

	// Use a different test pubkey for the third party
	thirdPartyPubkey := "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	plaintext := "Hello, this is a test message for NIP-44 encryption benchmark"

	b.Run("nip44_encrypt", func(b *testing.B) {
		params := []string{thirdPartyPubkey, plaintext}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := signer.handleNIP44Encrypt(privateKey, params)
			if err != nil {
				b.Fatalf("handleNIP44Encrypt() error = %v", err)
			}
		}
	})

	b.Run("nip44_decrypt", func(b *testing.B) {
		// First encrypt to get a valid ciphertext
		encryptParams := []string{thirdPartyPubkey, plaintext}
		ciphertext, err := signer.handleNIP44Encrypt(privateKey, encryptParams)
		if err != nil {
			b.Fatalf("setup: handleNIP44Encrypt() error = %v", err)
		}

		params := []string{thirdPartyPubkey, ciphertext}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := signer.handleNIP44Decrypt(privateKey, params)
			if err != nil {
				b.Fatalf("handleNIP44Decrypt() error = %v", err)
			}
		}
	})
}
