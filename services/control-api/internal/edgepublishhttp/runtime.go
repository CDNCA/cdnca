package edgepublishhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RuntimeConfig struct {
	Enabled                   bool
	SecurityActivationEnabled bool
	CursorActiveKey           CursorKey
	CursorVerificationKeys    []CursorKey
}

type RuntimeDependencies struct {
	Pool               *pgxpool.Pool
	Identity           *identity.Service
	APIKeys            *apikey.Service
	IAM                *iamlock.Authorizer
	Publisher          *edgepublish.Runtime
	SecurityActivation *securityactivation.Store
}

func NewRuntimeHandler(config RuntimeConfig, dependencies RuntimeDependencies) (http.Handler, error) {
	if !config.Enabled {
		return http.NotFoundHandler(), nil
	}
	if !runtimePoolConfigured(dependencies.Pool) || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.APIKeys == nil || dependencies.IAM == nil || !dependencies.IAM.Configured() ||
		dependencies.Publisher == nil || !dependencies.Publisher.ConfiguredFor(dependencies.Pool, dependencies.IAM) {
		return nil, ErrInvalidRuntimeConfig
	}
	publisher, deployments := dependencies.Publisher.Publisher(), dependencies.Publisher.RolloutCommands()
	cursors, err := NewHMACCursorCodec(config.CursorActiveKey, config.CursorVerificationKeys...)
	if err != nil {
		return nil, ErrInvalidRuntimeConfig
	}
	domain, err := newIAMReadDomain(
		dependencies.Pool, dependencies.IAM, dependencies.Identity, publisher,
	)
	if err != nil {
		return nil, ErrInvalidRuntimeConfig
	}
	service, err := newRuntimeService(domain, domain, deployments, cursors)
	if err != nil {
		return nil, ErrInvalidRuntimeConfig
	}
	authenticate := credentialAuthenticator(dependencies.Identity, dependencies.APIKeys)
	publicationHandler, err := newSessionHandler(service, authenticate, nil)
	if err != nil {
		return nil, ErrInvalidRuntimeConfig
	}
	if !config.SecurityActivationEnabled {
		return publicationHandler, nil
	}
	if dependencies.SecurityActivation == nil {
		return nil, ErrInvalidRuntimeConfig
	}
	activationHandler, err := NewSecurityActivationHandler(dependencies.SecurityActivation, authenticate, nil)
	if err != nil {
		return nil, ErrInvalidRuntimeConfig
	}
	routes := http.NewServeMux()
	routes.Handle("/v1/site-publications/security-activations", activationHandler)
	routes.Handle("/v1/site-publications/security-activations/", activationHandler)
	routes.Handle("/", publicationHandler)
	return routes, nil
}

func runtimePoolConfigured(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	config := pool.Config()
	return config != nil && config.MaxConns > 0
}

func credentialAuthenticator(identityService *identity.Service, apiKeyService *apikey.Service) AuthenticateSessionFunc {
	return func(request *http.Request) (AuthenticatedSession, error) {
		if request == nil || identityService == nil || apiKeyService == nil {
			return AuthenticatedSession{}, ErrUnauthenticated
		}
		values := request.Header.Values("Authorization")
		if len(values) != 1 {
			return AuthenticatedSession{}, ErrUnauthenticated
		}
		authorization := strings.TrimSpace(values[0])
		scheme, rawToken, found := strings.Cut(authorization, " ")
		rawToken = strings.TrimSpace(rawToken)
		if !found || rawToken == "" || strings.ContainsAny(rawToken, " \t\r\n") {
			return AuthenticatedSession{}, ErrUnauthenticated
		}
		switch {
		case strings.EqualFold(scheme, "Bearer"):
			session, err := authenticateRuntimeSession(request.Context(), identityService, rawToken)
			if err == nil {
				return newAuthenticatedSession(session.Principal, session.SessionID, rawToken)
			}
			if errors.Is(err, identity.ErrInvalidSession) {
				return AuthenticatedSession{}, ErrUnauthenticated
			}
			if request.Context().Err() != nil {
				return AuthenticatedSession{}, request.Context().Err()
			}
			return AuthenticatedSession{}, edgepublish.ErrPersistence
		case strings.EqualFold(scheme, "CdncaKey"):
			principal, err := authenticateRuntimeAPIKey(request.Context(), apiKeyService, rawToken)
			if err == nil {
				return newAuthenticatedAPIKey(principal, rawToken)
			}
			if errors.Is(err, apikey.ErrInvalidCredential) {
				return AuthenticatedSession{}, ErrUnauthenticated
			}
			if request.Context().Err() != nil {
				return AuthenticatedSession{}, request.Context().Err()
			}
			return AuthenticatedSession{}, edgepublish.ErrPersistence
		default:
			return AuthenticatedSession{}, ErrUnauthenticated
		}
	}
}

func authenticateRuntimeSession(
	ctx context.Context,
	service *identity.Service,
	rawToken string,
) (session identity.AuthenticatedSession, err error) {
	if service == nil || !service.Configured() {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}
	defer func() {
		if recover() != nil {
			session = identity.AuthenticatedSession{}
			err = edgepublish.ErrPersistence
		}
	}()
	return service.AuthenticateSession(ctx, rawToken)
}

func authenticateRuntimeAPIKey(
	ctx context.Context,
	service *apikey.Service,
	rawToken string,
) (principal identity.Principal, err error) {
	if service == nil {
		return identity.Principal{}, apikey.ErrInvalidCredential
	}
	defer func() {
		if recover() != nil {
			principal = identity.Principal{}
			err = edgepublish.ErrPersistence
		}
	}()
	return service.Authenticate(ctx, rawToken)
}
