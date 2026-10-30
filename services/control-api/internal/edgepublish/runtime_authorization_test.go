package edgepublish

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
)

func TestNewSessionActorRequiresCompleteServerAuthenticatedSession(t *testing.T) {
	userID := uuid.New()
	scopeID := uuid.New()
	sessionID := uuid.New()

	actor, err := NewSessionActor(userID, scopeID, ScopeKindPlatform, sessionID, "signed-access-token")
	if err != nil {
		t.Fatal(err)
	}
	if actor.UserID != userID || actor.ScopeID != scopeID || actor.ScopeKind != ScopeKindPlatform || actor.SessionID != sessionID {
		t.Fatalf("actor = %+v", actor)
	}
	tenantActor, err := NewSessionActor(userID, scopeID, ScopeKindTenant, sessionID, "signed-access-token")
	if err != nil || tenantActor.ScopeKind != ScopeKindTenant {
		t.Fatalf("tenant actor = (%+v, %v)", tenantActor, err)
	}

	for _, test := range []struct {
		name      string
		userID    uuid.UUID
		scopeID   uuid.UUID
		scopeKind string
		sessionID uuid.UUID
		token     string
	}{
		{name: "missing user", scopeID: scopeID, scopeKind: ScopeKindPlatform, sessionID: sessionID, token: "token"},
		{name: "missing scope", userID: userID, scopeKind: ScopeKindPlatform, sessionID: sessionID, token: "token"},
		{name: "unknown scope", userID: userID, scopeID: scopeID, scopeKind: "unknown", sessionID: sessionID, token: "token"},
		{name: "missing session", userID: userID, scopeID: scopeID, scopeKind: ScopeKindPlatform, token: "token"},
		{name: "missing token", userID: userID, scopeID: scopeID, scopeKind: ScopeKindPlatform, sessionID: sessionID},
		{name: "whitespace token", userID: userID, scopeID: scopeID, scopeKind: ScopeKindPlatform, sessionID: sessionID, token: "token with space"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewSessionActor(test.userID, test.scopeID, test.scopeKind, test.sessionID, test.token)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want invalid input", err)
			}
		})
	}
}

func TestSessionActorRedactsAllFormattingAndJSON(t *testing.T) {
	rawToken := "signed-access-token-secret"
	actor, err := NewSessionActor(uuid.New(), uuid.New(), ScopeKindPlatform, uuid.New(), rawToken)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{
		fmt.Sprintf("%v", actor), fmt.Sprintf("%+v", actor), fmt.Sprintf("%#v", actor),
		fmt.Sprintf("%s", actor), fmt.Sprintf("%q", actor), fmt.Sprintf("%x", actor),
		fmt.Sprintf("%d", actor), fmt.Sprintf("%p", actor), actor.String(), actor.GoString(), string(encoded),
	} {
		if strings.Contains(output, rawToken) || strings.Contains(output, hex.EncodeToString([]byte(rawToken))) {
			t.Fatalf("actor leaked session through %q", output)
		}
	}
}

func TestIAMAuthorizationErrorsRemainStable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "revoked session", err: iamlock.ErrInvalidCredential, want: ErrUnauthenticated},
		{name: "permission", err: iamlock.ErrPermissionDenied, want: ErrPermissionDenied},
		{name: "invalid input", err: iamlock.ErrInvalidInput, want: ErrPermissionDenied},
		{name: "unavailable", err: iamlock.ErrUnavailable, want: ErrPersistence},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := mapIAMAuthorizationError(context.Background(), test.err); !errors.Is(got, test.want) {
				t.Fatalf("error=%v, want %v", got, test.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := mapIAMAuthorizationError(ctx, iamlock.ErrInvalidCredential); !errors.Is(got, context.Canceled) {
		t.Fatalf("cancelled error=%v", got)
	}
}
