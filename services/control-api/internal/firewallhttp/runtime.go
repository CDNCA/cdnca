package firewallhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	APIKeys  *apikey.Service
	IAM      *iamlock.Authorizer
	Hits     firewallcontrol.HitReader
	Now      func() time.Time
}

func NewRuntimeHandler(dependencies RuntimeDependencies) (http.Handler, error) {
	if dependencies.Pool == nil || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.APIKeys == nil || dependencies.IAM == nil || !dependencies.IAM.Configured() || dependencies.Now == nil {
		return nil, errors.New("invalid firewall runtime dependencies")
	}
	authorizer, err := firewallcontrol.NewIAMTxAuthorizer(dependencies.IAM)
	if err != nil {
		return nil, err
	}
	store := firewallcontrol.NewStore(dependencies.Pool, authorizer, dependencies.Hits, dependencies.Now)
	service := firewallcontrol.NewService(store, dependencies.Now)
	return NewHandler(service, runtimeAuthenticator{identity: dependencies.Identity, apiKeys: dependencies.APIKeys}.Authenticate)
}

type runtimeAuthenticator struct {
	identity *identity.Service
	apiKeys  *apikey.Service
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request) (firewallcontrol.Actor, error) {
	if request == nil || authenticator.identity == nil || authenticator.apiKeys == nil {
		return firewallcontrol.Actor{}, firewallcontrol.ErrUnauthenticated
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return firewallcontrol.Actor{}, firewallcontrol.ErrUnauthenticated
	}
	scheme, raw, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	raw = strings.TrimSpace(raw)
	if !found || raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, " \t\r\n") {
		return firewallcontrol.Actor{}, firewallcontrol.ErrUnauthenticated
	}
	var principal identity.Principal
	credentialKind := firewallcontrol.CredentialSession
	credentialID := uuid.Nil
	var err error
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		var session identity.AuthenticatedSession
		session, err = authenticator.identity.AuthenticateSession(request.Context(), raw)
		principal, credentialID = session.Principal, session.SessionID
	case strings.EqualFold(scheme, "CdncaKey"):
		credentialKind = firewallcontrol.CredentialAPIKey
		principal, err = authenticator.apiKeys.Authenticate(request.Context(), raw)
	default:
		return firewallcontrol.Actor{}, firewallcontrol.ErrUnauthenticated
	}
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, apikey.ErrInvalidCredential) {
		return firewallcontrol.Actor{}, firewallcontrol.ErrUnauthenticated
	}
	if err != nil {
		return firewallcontrol.Actor{}, err
	}
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil ||
		(principal.ScopeKind != firewallcontrol.ScopeTenant && principal.ScopeKind != firewallcontrol.ScopePlatform) ||
		(principal.ScopeKind == firewallcontrol.ScopeTenant && (principal.TenantID == nil || *principal.TenantID == uuid.Nil)) ||
		(principal.ScopeKind == firewallcontrol.ScopePlatform && (principal.TenantID != nil || credentialKind != firewallcontrol.CredentialSession)) {
		return firewallcontrol.Actor{}, firewallcontrol.ErrUnauthenticated
	}
	return runtimeActor(principal, credentialKind, credentialID, raw), nil
}

// runtimeActor 传入本次凭据的真实有效权限（API 密钥为 key.scopes 与用户权限的交集），
// 不再写死 read+manage，防止只看 Actor.Permissions 的代码越权；store 内 iamlock 复核不变（API-JOBS-02）。
func runtimeActor(principal identity.Principal, credentialKind string, credentialID uuid.UUID, raw string) firewallcontrol.Actor {
	return firewallcontrol.Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		Permissions: append([]string(nil), principal.Permissions...),
	}.WithCredential(credentialKind, credentialID, raw, principal.TenantID)
}
