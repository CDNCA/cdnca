package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestSiteWriteActorSessionAuthority(t *testing.T) {
	fixture := newUserMetadataHTTPFixture(t)
	server := &Server{identity: fixture.service}
	session, err := fixture.service.AuthenticateSession(t.Context(), fixture.admin)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/sites", nil)
	request.Header.Set("Authorization", "Bearer "+fixture.admin)
	actor, err := server.siteWriteActor(request, session.Principal)
	if err != nil || actor.UserID != session.Principal.UserID || actor.ScopeID != session.Principal.ScopeID || actor.SessionID != session.SessionID {
		t.Fatalf("trusted session identity was not preserved: %v", err)
	}
	encoded, err := json.Marshal(actor)
	if err != nil || bytes.Contains(encoded, []byte(session.SessionID.String())) || bytes.Contains(encoded, []byte("SessionID")) {
		t.Fatalf("private session identity must not enter JSON: %v", err)
	}
	for _, field := range []string{"user", "scope"} {
		t.Run("mismatched "+field, func(t *testing.T) {
			principal := session.Principal
			if field == "user" {
				principal.UserID = uuid.New()
			} else {
				principal.ScopeID = uuid.New()
			}
			if _, err := server.siteWriteActor(request, principal); !errors.Is(err, identity.ErrInvalidSession) {
				t.Fatalf("mismatched principal accepted: %v", err)
			}
		})
	}
	t.Run("existing non-session behavior", func(t *testing.T) {
		for _, header := range []string{"", "CdncaKey not-a-session"} {
			request := httptest.NewRequest(http.MethodPost, "/v1/admin/sites", nil)
			request.Header.Set("Authorization", header)
			actor, err := server.siteWriteActor(request, session.Principal)
			if err != nil || actor.SessionID != uuid.Nil || actor.UserID != session.Principal.UserID || actor.ScopeID != session.Principal.ScopeID {
				t.Fatalf("non-session authority changed: %v", err)
			}
		}
		principal := session.Principal
		principal.ScopeKind = "tenant"
		actor, err := server.siteWriteActor(request, principal)
		if err != nil || actor.SessionID != uuid.Nil || actor.ScopeKind != "tenant" {
			t.Fatalf("tenant actor unexpectedly gained session authority: %v", err)
		}
	})
	t.Run("invalid bearer", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/sites", nil)
		request.Header.Set("Authorization", "Bearer invalid")
		if _, err := server.siteWriteActor(request, session.Principal); !errors.Is(err, identity.ErrInvalidSession) {
			t.Fatalf("invalid token accepted: %v", err)
		}
		if _, err := (&Server{}).siteWriteActor(request, session.Principal); !errors.Is(err, identity.ErrInvalidSession) {
			t.Fatalf("missing session verifier accepted: %v", err)
		}
	})
	for _, state := range []string{"revoked", "expired"} {
		t.Run(state, func(t *testing.T) {
			login, _ := loginWithPassword(t, fixture.server.Client(), fixture.server.URL, "metadata-admin", testPassword)
			authenticated, err := fixture.service.AuthenticateSession(t.Context(), login.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			query := `UPDATE auth_sessions SET revoked_at=clock_timestamp(),revocation_reason='logout' WHERE id=$1`
			if state == "expired" {
				query = `UPDATE auth_sessions SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1`
			}
			if _, err := fixture.pool.Exec(t.Context(), query, authenticated.SessionID); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/admin/sites", nil)
			request.Header.Set("Authorization", "Bearer "+login.AccessToken)
			if _, err := server.siteWriteActor(request, authenticated.Principal); !errors.Is(err, identity.ErrInvalidSession) {
				t.Fatalf("inactive session accepted: %v", err)
			}
		})
	}
}
