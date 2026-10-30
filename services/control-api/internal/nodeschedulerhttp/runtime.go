package nodeschedulerhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	APIKeys  *apikey.Service
	IAM      *iamlock.Authorizer
	Loads    nodescheduler.LoadProvider
	Now      func() time.Time
	// Publications queues automatic republication when a line group's node
	// set changes (FX02); nil leaves it to each scope's operator.
	Publications nodescheduler.PublicationTrigger
}

// NewRuntimeHandler assembles the package-owned runtime without mounting it in
// the shared control-api router.
func NewRuntimeHandler(dependencies RuntimeDependencies) (http.Handler, error) {
	if dependencies.Pool == nil || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.APIKeys == nil || dependencies.IAM == nil || !dependencies.IAM.Configured() || dependencies.Now == nil {
		return nil, ErrInvalidHandlerConfig
	}
	loads := dependencies.Loads
	if loads == nil {
		loads = nodescheduler.NewPostgresLoadProvider(dependencies.Pool)
	}
	service, err := nodescheduler.NewIAMService(dependencies.Pool, dependencies.Now, dependencies.IAM, loads)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	if dependencies.Publications != nil {
		service.SetPublicationTrigger(dependencies.Publications)
	}
	return NewHandler(service, runtimeAuthenticator{identity: dependencies.Identity, apiKeys: dependencies.APIKeys})
}

type runtimeAuthenticator struct {
	identity *identity.Service
	apiKeys  *apikey.Service
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request) (nodescheduler.Actor, error) {
	if request == nil || authenticator.identity == nil || authenticator.apiKeys == nil {
		return nodescheduler.Actor{}, ErrUnauthenticated
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return nodescheduler.Actor{}, ErrUnauthenticated
	}
	scheme, raw, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	raw = strings.TrimSpace(raw)
	if !found || raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, " \t\r\n") {
		return nodescheduler.Actor{}, ErrUnauthenticated
	}
	var principal identity.Principal
	var err error
	credentialKind := nodescheduler.CredentialSession
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		var session identity.AuthenticatedSession
		session, err = authenticator.identity.AuthenticateSession(request.Context(), raw)
		principal = session.Principal
	case strings.EqualFold(scheme, "CdncaKey"):
		credentialKind = nodescheduler.CredentialAPIKey
		principal, err = authenticator.apiKeys.Authenticate(request.Context(), raw)
	default:
		return nodescheduler.Actor{}, ErrUnauthenticated
	}
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, apikey.ErrInvalidCredential) {
		return nodescheduler.Actor{}, ErrUnauthenticated
	}
	if err != nil {
		return nodescheduler.Actor{}, err
	}
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil ||
		principal.ScopeKind != "tenant" && principal.ScopeKind != "platform" {
		return nodescheduler.Actor{}, ErrUnauthenticated
	}
	if credentialKind == nodescheduler.CredentialAPIKey && principal.ScopeKind == "platform" {
		return nodescheduler.Actor{}, ErrUnauthenticated
	}
	if principal.ScopeKind == "tenant" && (principal.TenantID == nil || *principal.TenantID == uuid.Nil) ||
		principal.ScopeKind == "platform" && principal.TenantID != nil {
		return nodescheduler.Actor{}, ErrUnauthenticated
	}
	return nodescheduler.Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		Credential: nodescheduler.Credential{Kind: credentialKind, Raw: raw},
	}, nil
}
