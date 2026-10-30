package rbacmanagerhttp

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RuntimeConfig struct {
	Enabled   bool
	CursorKey []byte
	Handler   HandlerConfig
}

type RuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	StepUp   rbacmanager.StepUpVerifier
}

func NewRuntimeHandler(config RuntimeConfig, dependencies RuntimeDependencies) (http.Handler, error) {
	if !config.Enabled {
		return http.NotFoundHandler(), nil
	}
	if dependencies.Pool == nil || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.StepUp == nil {
		return nil, ErrInvalidRequest
	}
	service, err := NewService(dependencies.Pool, dependencies.StepUp, ServiceConfig{CursorKey: config.CursorKey})
	if err != nil {
		return nil, err
	}
	return NewHandler(service, runtimeSessionAuthenticator{identity: dependencies.Identity}.Authenticate, config.Handler)
}

type runtimeSessionAuthenticator struct {
	identity *identity.Service
}

func (authenticator runtimeSessionAuthenticator) Authenticate(request *http.Request) (AuthenticatedSession, error) {
	if request == nil || authenticator.identity == nil || !authenticator.identity.Configured() {
		return AuthenticatedSession{}, ErrUnauthenticated
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return AuthenticatedSession{}, ErrUnauthenticated
	}
	scheme, raw, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	raw = strings.TrimSpace(raw)
	if !found || !strings.EqualFold(scheme, "Bearer") || raw == "" || len(raw) > 8192 ||
		strings.ContainsAny(raw, " \t\r\n") {
		return AuthenticatedSession{}, ErrUnauthenticated
	}
	session, err := authenticator.identity.AuthenticateSession(request.Context(), raw)
	if errors.Is(err, identity.ErrInvalidSession) {
		return AuthenticatedSession{}, ErrUnauthenticated
	}
	if err != nil {
		return AuthenticatedSession{}, err
	}
	principal := session.Principal
	if session.SessionID == uuid.Nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil ||
		principal.ScopeKind != "tenant" || principal.TenantID == nil || *principal.TenantID == uuid.Nil {
		return AuthenticatedSession{}, ErrUnauthenticated
	}
	return AuthenticatedSession{
		UserID: principal.UserID, ScopeID: principal.ScopeID, SessionID: session.SessionID,
		ScopeKind: principal.ScopeKind, IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}, nil
}
