package openrestysecurityhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	APIKeys  *apikey.Service
	IAM      *iamlock.Authorizer
	Sealer   openrestysecurity.SecretSealer
	Now      func() time.Time
	// Catalog serves the signed system rule catalog; optional.
	Catalog SystemRuleCatalog
}

func NewRuntimeHandler(dependencies RuntimeDependencies) (http.Handler, error) {
	if dependencies.Pool == nil || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.APIKeys == nil || dependencies.IAM == nil || !dependencies.IAM.Configured() ||
		dependencies.Sealer == nil || dependencies.Now == nil {
		return nil, errors.New("invalid OpenResty security runtime dependencies")
	}
	authorizer, err := openrestysecurity.NewIAMTxAuthorizer(dependencies.IAM)
	if err != nil {
		return nil, err
	}
	store, err := openrestysecurity.NewStore(dependencies.Pool, authorizer, dependencies.Sealer, dependencies.Now)
	if err != nil {
		return nil, err
	}
	handler, err := NewHandler(store, runtimeAuthenticator{identity: dependencies.Identity, apiKeys: dependencies.APIKeys}.Authenticate)
	if err != nil {
		return nil, err
	}
	if dependencies.Catalog != nil {
		ruleGroups, ok := authorizer.(ruleGroupTxAuthorizer)
		if !ok {
			return nil, errors.New("OpenResty security authorizer cannot authorize system rules")
		}
		handler.catalog, handler.catalogAuthorizer = dependencies.Catalog, ruleGroups
	}
	return handler, nil
}

type runtimeAuthenticator struct {
	identity *identity.Service
	apiKeys  *apikey.Service
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request) (openrestysecurity.Actor, error) {
	if request == nil || authenticator.identity == nil || authenticator.apiKeys == nil {
		return openrestysecurity.Actor{}, openrestysecurity.ErrUnauthenticated
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return openrestysecurity.Actor{}, openrestysecurity.ErrUnauthenticated
	}
	scheme, raw, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	raw = strings.TrimSpace(raw)
	if !found || raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, " \t\r\n") {
		return openrestysecurity.Actor{}, openrestysecurity.ErrUnauthenticated
	}
	var principal identity.Principal
	credentialKind := openrestysecurity.CredentialSession
	credentialID := uuid.Nil
	var err error
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		var session identity.AuthenticatedSession
		session, err = authenticator.identity.AuthenticateSession(request.Context(), raw)
		principal, credentialID = session.Principal, session.SessionID
	case strings.EqualFold(scheme, "CdncaKey"):
		credentialKind = openrestysecurity.CredentialAPIKey
		principal, err = authenticator.apiKeys.Authenticate(request.Context(), raw)
	default:
		return openrestysecurity.Actor{}, openrestysecurity.ErrUnauthenticated
	}
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, apikey.ErrInvalidCredential) {
		return openrestysecurity.Actor{}, openrestysecurity.ErrUnauthenticated
	}
	if err != nil {
		return openrestysecurity.Actor{}, err
	}
	return actorFromPrincipal(principal, credentialKind, credentialID, raw)
}

func actorFromPrincipal(principal identity.Principal, credentialKind string, credentialID uuid.UUID, raw string) (openrestysecurity.Actor, error) {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil ||
		(principal.ScopeKind != openrestysecurity.ScopeTenant && principal.ScopeKind != openrestysecurity.ScopePlatform) {
		return openrestysecurity.Actor{}, openrestysecurity.ErrUnauthenticated
	}
	if principal.ScopeKind == openrestysecurity.ScopePlatform && (principal.TenantID != nil || credentialKind != openrestysecurity.CredentialSession) {
		return openrestysecurity.Actor{}, openrestysecurity.ErrPermissionDenied
	}
	if principal.ScopeKind == openrestysecurity.ScopeTenant && principal.TenantID == nil {
		return openrestysecurity.Actor{}, openrestysecurity.ErrPermissionDenied
	}
	return openrestysecurity.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		Permissions: append([]string(nil), principal.Permissions...)}.
		WithCredential(credentialKind, credentialID, raw, principal.TenantID), nil
}
