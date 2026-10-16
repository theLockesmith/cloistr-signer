package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

const (
	slotKeyID    = "slotkey123456789"
	slotKeyPub   = "7777777777777777777777777777777777777777777777777777777777777777"
	everydayCli  = "8888888888888888888888888888888888888888888888888888888888888888"
	publisherCli = "9999999999999999999999999999999999999999999999999999999999999999"
	newcomerCli  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// A role key with both connections live, as the fleet kit leaves it: an
// everyday grant in the default slot and a publisher grant, each expiring.
func slottedRoleKey(t *testing.T) (*Handler, storage.Storage, time.Time) {
	t.Helper()
	h, store := testHandler(t)
	ctx := context.Background()
	if err := store.CreateKey(ctx, &storage.Key{ID: slotKeyID, Name: "role", Pubkey: slotKeyPub, OwnerID: testUserID, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(20 * 24 * time.Hour).UTC().Truncate(time.Second)
	for _, p := range []*storage.Permission{
		{KeyID: slotKeyPub, UserPubkey: everydayCli, Slot: storage.SlotDefault, Methods: []string{"sign_event"}, AllowedKinds: []int{1111}, ExpiresAt: &exp},
		{KeyID: slotKeyPub, UserPubkey: publisherCli, Slot: storage.SlotPublisher, Methods: []string{"sign_event"}, AllowedKinds: []int{33301}, ExpiresAt: &exp, AppName: "pages"},
	} {
		if err := store.SetPermission(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	return h, store, exp
}

func postPermission(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+slotKeyID+"/permissions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addAuthHeader(t, h, req)
	rr := httptest.NewRecorder()
	h.handleSetPermission(rr, req, slotKeyID)
	return rr
}

func mustLive(t *testing.T, store storage.Storage, client string) *storage.Permission {
	t.Helper()
	p, err := store.GetPermission(context.Background(), slotKeyPub, client)
	if err != nil {
		t.Fatalf("grant for %s.. is no longer live: %v", client[:8], err)
	}
	return p
}

// Widening the publisher grant's kinds (no slot named) amends it in place:
// it stays in the publisher slot with its expiry and app name, and the
// everyday grant is untouched. Before the fix this revoked the everyday grant
// and left a never-expiring default-slot grant.
func TestSetPermission_AmendKeepsSlotExpiryAndOtherGrant(t *testing.T) {
	h, store, exp := slottedRoleKey(t)
	rr := postPermission(t, h, `{"user_pubkey":"`+publisherCli+`","methods":["sign_event"],"allowed_kinds":[33301,35128,5128]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("amend: %d %s", rr.Code, rr.Body.String())
	}
	var resp PermissionResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Slot != storage.SlotPublisher {
		t.Fatalf("response slot = %q, want publisher", resp.Slot)
	}
	pub := mustLive(t, store, publisherCli)
	if pub.Slot != storage.SlotPublisher || pub.ExpiresAt == nil || !pub.ExpiresAt.Equal(exp) || pub.AppName != "pages" {
		t.Fatalf("publisher grant after amend = slot %q expiry %v app %q, want publisher / %v / pages", pub.Slot, pub.ExpiresAt, pub.AppName, exp)
	}
	if len(pub.AllowedKinds) != 3 {
		t.Fatalf("kinds = %v, want the three requested", pub.AllowedKinds)
	}
	every := mustLive(t, store, everydayCli)
	if len(every.AllowedKinds) != 1 || every.AllowedKinds[0] != 1111 {
		t.Fatalf("everyday grant changed: %v", every.AllowedKinds)
	}
}

func TestSetPermission_AmendCanMoveExpiry(t *testing.T) {
	h, store, _ := slottedRoleKey(t)
	later := time.Now().Add(40 * 24 * time.Hour).UTC().Truncate(time.Second)
	rr := postPermission(t, h, `{"user_pubkey":"`+everydayCli+`","methods":["sign_event"],"allowed_kinds":[1111],"expires_at":"`+later.Format(time.RFC3339)+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if p := mustLive(t, store, everydayCli); !p.ExpiresAt.Equal(later) || p.Slot != storage.SlotDefault {
		t.Fatalf("got slot %q expiry %v, want default / %v", p.Slot, p.ExpiresAt, later)
	}
	mustLive(t, store, publisherCli)
}

// A new client into an occupied slot is refused unless replace is sent.
func TestSetPermission_NewClientIntoOccupiedSlotNeedsReplace(t *testing.T) {
	h, store, _ := slottedRoleKey(t)
	rr := postPermission(t, h, `{"user_pubkey":"`+newcomerCli+`","methods":["sign_event"]}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("no replace: %d %s, want 409", rr.Code, rr.Body.String())
	}
	mustLive(t, store, everydayCli)
	if _, err := store.GetPermission(context.Background(), slotKeyPub, newcomerCli); err == nil {
		t.Fatal("refused grant was stored anyway")
	}

	rr = postPermission(t, h, `{"user_pubkey":"`+newcomerCli+`","methods":["sign_event"],"slot":"publisher","replace":true}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", rr.Code, rr.Body.String())
	}
	if p := mustLive(t, store, newcomerCli); p.Slot != storage.SlotPublisher {
		t.Fatalf("new grant slot = %q", p.Slot)
	}
	if _, err := store.GetPermission(context.Background(), slotKeyPub, publisherCli); err == nil {
		t.Fatal("replace=true did not displace the old publisher grant")
	}
	mustLive(t, store, everydayCli) // other slot untouched
}

func TestSetPermission_Refusals(t *testing.T) {
	h, store, _ := slottedRoleKey(t)
	for name, body := range map[string]string{
		"move slot":   `{"user_pubkey":"` + publisherCli + `","methods":["sign_event"],"slot":"default"}`,
		"bad slot":    `{"user_pubkey":"` + publisherCli + `","methods":["sign_event"],"slot":"everyday"}`,
		"upper hex":   `{"user_pubkey":"` + strings.ToUpper(newcomerCli) + `","methods":["sign_event"],"slot":"publisher","replace":true}`,
		"past expiry": `{"user_pubkey":"` + publisherCli + `","methods":["sign_event"],"expires_at":"2020-01-01T00:00:00Z"}`,
	} {
		rr := postPermission(t, h, body)
		if rr.Code != http.StatusConflict && rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want a refusal", name, rr.Code, rr.Body.String())
		}
	}
	if p := mustLive(t, store, publisherCli); p.Slot != storage.SlotPublisher || len(p.AllowedKinds) != 1 {
		t.Fatalf("a refused request changed the grant: %+v", p)
	}
	mustLive(t, store, everydayCli)
}

// A lapsed (expired, not revoked) publisher grant re-granted without a slot
// stays in the publisher slot, and naming another slot is refused.
func TestSetPermission_LapsedGrantKeepsSlot(t *testing.T) {
	h, store, _ := slottedRoleKey(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	lapsed := mustLive(t, store, publisherCli)
	lapsed.ExpiresAt = &past
	if err := store.SetPermission(ctx, lapsed); err != nil {
		t.Fatal(err)
	}
	if rr := postPermission(t, h, `{"user_pubkey":"`+publisherCli+`","methods":["sign_event"],"slot":"default"}`); rr.Code != http.StatusConflict {
		t.Fatalf("slot move of a lapsed grant: %d %s, want 409", rr.Code, rr.Body.String())
	}
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	if rr := postPermission(t, h, `{"user_pubkey":"`+publisherCli+`","methods":["sign_event"],"allowed_kinds":[33301],"expires_at":"`+future+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("re-grant: %d %s", rr.Code, rr.Body.String())
	}
	if p := mustLive(t, store, publisherCli); p.Slot != storage.SlotPublisher {
		t.Fatalf("re-granted lapsed grant moved to slot %q", p.Slot)
	}
	mustLive(t, store, everydayCli)
}

// permLookupFails: the grant lookup hits a storage failure; writes are counted.
type permLookupFails struct {
	storage.Storage
	writes int
}

func (s *permLookupFails) GetPermission(context.Context, string, string) (*storage.Permission, error) {
	return nil, errors.New("connection reset by peer")
}

func (s *permLookupFails) SetPermission(ctx context.Context, p *storage.Permission) error {
	s.writes++
	return s.Storage.SetPermission(ctx, p)
}

// A storage failure while looking up the client's grant is a 500 with no
// write. Treating it as "no grant" would store a fresh grant over the real one
// (amend in place skipped, slot and expiry lost).
func TestSetPermission_LookupFailureIsServerErrorNoWrite(t *testing.T) {
	h, store, _ := slottedRoleKey(t)
	failing := &permLookupFails{Storage: store}
	h.storage = failing
	rr := postPermission(t, h, `{"user_pubkey":"`+publisherCli+`","methods":["sign_event"],"allowed_kinds":[1]}`)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("lookup failure: %d %s, want 500", rr.Code, rr.Body.String())
	}
	if failing.writes != 0 {
		t.Fatalf("%d permission writes after a failed lookup, want none", failing.writes)
	}
	if p := mustLive(t, store, publisherCli); len(p.AllowedKinds) != 1 || p.AllowedKinds[0] != 33301 {
		t.Fatalf("grant changed after a failed lookup: %v", p.AllowedKinds)
	}
}
