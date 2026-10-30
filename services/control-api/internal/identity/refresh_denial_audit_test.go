package identity

import (
	"testing"

	"github.com/google/uuid"
)

func TestRefreshPrincipalDisabledAuditEvent(t *testing.T) {
	userID := uuid.New()
	scopeID := uuid.New()
	familyID := uuid.New()
	sessionID := uuid.New()
	refresh := RotatedSession{
		ID: sessionID, FamilyID: familyID, UserID: userID, ScopeID: scopeID,
	}

	for _, reason := range []string{"account_disabled", "membership_disabled"} {
		t.Run(reason, func(t *testing.T) {
			event := refreshPrincipalDisabledAuditEvent(refresh, "refresh-denied-request", reason)
			if event.ScopeID != scopeID || event.ActorUserID == nil || *event.ActorUserID != userID {
				t.Fatalf("audit principal = scope %s actor %v", event.ScopeID, event.ActorUserID)
			}
			if event.Action != "auth.refresh" || event.Result != "denied" ||
				event.ResourceType != "session_family" || event.ResourceID != familyID.String() ||
				event.RequestID != "refresh-denied-request" {
				t.Fatalf("audit identity = %#v", event)
			}
			if event.Payload["reason_code"] != reason || event.Payload["revoked_session_id"] != sessionID.String() {
				t.Fatalf("audit payload = %#v", event.Payload)
			}
			for _, forbidden := range []string{"refresh_token", "access_token", "password", "credential"} {
				if _, exists := event.Payload[forbidden]; exists {
					t.Fatalf("audit payload contains %q", forbidden)
				}
			}
		})
	}
}
