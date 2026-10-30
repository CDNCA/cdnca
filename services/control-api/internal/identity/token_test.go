package identity

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAccessTokenRoundTrip(t *testing.T) {
	manager, err := NewTokenManager("test-secret-with-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	userID := uuid.New()
	scopeID := uuid.New()
	sessionID := uuid.New()
	raw, _, err := manager.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	gotUserID, gotScopeID, gotSessionID, err := manager.Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if gotUserID != userID || gotScopeID != scopeID || gotSessionID != sessionID {
		t.Fatalf("Parse() = (%s, %s, %s), want (%s, %s, %s)",
			gotUserID, gotScopeID, gotSessionID, userID, scopeID, sessionID)
	}
	if _, _, _, err := manager.Parse(raw + "tampered"); err == nil {
		t.Fatal("Parse() accepted a tampered token")
	}
}
