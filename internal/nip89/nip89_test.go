package nip89

import (
	"testing"
)

func TestNewPublisher(t *testing.T) {
	relays := []string{"wss://relay1.example.com", "wss://relay2.example.com"}
	p := NewPublisher(relays)

	if p == nil {
		t.Fatal("NewPublisher() returned nil")
	}

	if len(p.relays) != 2 {
		t.Errorf("relays length = %d, want 2", len(p.relays))
	}
}

func TestPublisher_SetSignerKey(t *testing.T) {
	p := NewPublisher([]string{"wss://relay.example.com"})
	p.SetSignerKey("pubkey123", "privatekey456")

	if p.signerPub != "pubkey123" {
		t.Errorf("signerPub = %q, want %q", p.signerPub, "pubkey123")
	}
	if p.signerKey != "privatekey456" {
		t.Errorf("signerKey = %q, want %q", p.signerKey, "privatekey456")
	}
}

func TestPublisher_CreateHandlerEvent_NoKey(t *testing.T) {
	p := NewPublisher([]string{"wss://relay.example.com"})
	// Don't set signer key

	info := &AppHandlerInfo{
		Name:        "test-signer",
		Description: "Test",
	}

	_, err := p.CreateHandlerEvent(info)
	if err == nil {
		t.Error("CreateHandlerEvent() should return error when no signer key set")
	}
}

func TestPublisher_CreateHandlerEvent(t *testing.T) {
	p := NewPublisher([]string{"wss://relay1.example.com", "wss://relay2.example.com"})

	// Use a valid test key (go-nostr will derive the correct pubkey from it)
	privateKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// The pubkey we set here will be used in the event, but go-nostr.Sign()
	// will verify/derive it from the private key
	p.SetSignerKey("4646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff", privateKey)

	info := &AppHandlerInfo{
		Name:        "coldforge-signer",
		DisplayName: "Coldforge Signer",
		Description: "NIP-46 Remote Signing Service",
		Website:     "https://signer.example.com",
	}

	event, err := p.CreateHandlerEvent(info)
	if err != nil {
		t.Fatalf("CreateHandlerEvent() error = %v", err)
	}

	if event.Kind != KindAppHandler {
		t.Errorf("event.Kind = %d, want %d", event.Kind, KindAppHandler)
	}

	// Verify pubkey is set (don't check exact value as it's derived from privkey)
	if event.PubKey == "" {
		t.Error("event.PubKey should not be empty")
	}
	if len(event.PubKey) != 64 {
		t.Errorf("event.PubKey length = %d, want 64", len(event.PubKey))
	}

	// Check for d tag
	foundDTag := false
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "d" && tag[1] == "coldforge-signer" {
			foundDTag = true
		}
	}
	if !foundDTag {
		t.Error("event should have d tag with 'coldforge-signer'")
	}

	// Check for k tag (NIP-46 kind)
	foundKTag := false
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "k" && tag[1] == "24133" {
			foundKTag = true
		}
	}
	if !foundKTag {
		t.Error("event should have k tag with '24133'")
	}

	// Check for relay tags
	relayCount := 0
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "relay" {
			relayCount++
		}
	}
	if relayCount != 2 {
		t.Errorf("relay tag count = %d, want 2", relayCount)
	}

	// Check for web tag
	foundWebTag := false
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "web" && tag[1] == "https://signer.example.com" {
			foundWebTag = true
		}
	}
	if !foundWebTag {
		t.Error("event should have web tag with website URL")
	}

	// Content should be JSON of info
	if event.Content == "" {
		t.Error("event.Content should not be empty")
	}

	// Event should be signed
	if event.ID == "" {
		t.Error("event.ID should not be empty (event should be signed)")
	}
	if event.Sig == "" {
		t.Error("event.Sig should not be empty (event should be signed)")
	}
}

func TestDefaultHandlerInfo(t *testing.T) {
	website := "https://signer.example.com"
	info := DefaultHandlerInfo(website)

	if info.Name != "coldforge-signer" {
		t.Errorf("Name = %q, want %q", info.Name, "coldforge-signer")
	}
	if info.DisplayName != "Coldforge Signer" {
		t.Errorf("DisplayName = %q, want %q", info.DisplayName, "Coldforge Signer")
	}
	if info.Description == "" {
		t.Error("Description should not be empty")
	}
	if info.Website != website {
		t.Errorf("Website = %q, want %q", info.Website, website)
	}
	if len(info.Kinds) != 1 || info.Kinds[0] != 24133 {
		t.Errorf("Kinds = %v, want [24133]", info.Kinds)
	}
}

func TestAppHandlerInfo_Fields(t *testing.T) {
	info := AppHandlerInfo{
		Name:        "test-app",
		DisplayName: "Test App",
		Description: "A test application",
		Picture:     "https://example.com/pic.png",
		Website:     "https://example.com",
		Nip05:       "test@example.com",
		LUD16:       "test@getalby.com",
		Kinds:       []int{1, 4, 30023},
	}

	if info.Name != "test-app" {
		t.Errorf("Name = %q, want %q", info.Name, "test-app")
	}
	if info.DisplayName != "Test App" {
		t.Errorf("DisplayName = %q, want %q", info.DisplayName, "Test App")
	}
	if info.Picture != "https://example.com/pic.png" {
		t.Errorf("Picture = %q", info.Picture)
	}
	if info.Nip05 != "test@example.com" {
		t.Errorf("Nip05 = %q", info.Nip05)
	}
	if info.LUD16 != "test@getalby.com" {
		t.Errorf("LUD16 = %q", info.LUD16)
	}
	if len(info.Kinds) != 3 {
		t.Errorf("Kinds length = %d, want 3", len(info.Kinds))
	}
}

func TestKindConstants(t *testing.T) {
	if KindAppHandler != 31990 {
		t.Errorf("KindAppHandler = %d, want 31990", KindAppHandler)
	}
	if KindAppRecommendation != 31989 {
		t.Errorf("KindAppRecommendation = %d, want 31989", KindAppRecommendation)
	}
}
