package analyticsdiagnostichttp

import (
	"net/http"
	"regexp"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsdiagnostic"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnostics"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnosticshttp"
	"github.com/google/uuid"
)

var finalizedProductionPermissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

type finalizedProductionHandler struct{ next http.Handler }

func NewFinalizedProductionHandler(
	client *analyticslog.Client,
	authenticate Authenticator,
	config qualitydiagnosticshttp.ProductionConfig,
) (http.Handler, error) {
	if authenticate == nil {
		return nil, qualitydiagnostics.ErrInvalidConfiguration
	}
	handler, err := qualitydiagnosticshttp.NewProductionHandler(config, qualitydiagnosticshttp.ProductionDependencies{
		Client: client,
		Authenticate: func(request *http.Request) (identity.Principal, error) {
			actor, authErr := authenticate(request)
			if authErr != nil {
				return identity.Principal{}, authErr
			}
			return finalizedProductionPrincipal(actor)
		},
	})
	if err != nil {
		return nil, err
	}
	return &finalizedProductionHandler{next: handler}, nil
}

func (handler *finalizedProductionHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.next == nil || request == nil || request.URL == nil {
		http.NotFound(writer, request)
		return
	}
	canonical := ""
	switch request.URL.Path {
	case "/v1/analytics/site-quality-diagnostics":
		canonical = "/v1/analytics/quality-diagnostics"
	case "/v1/admin/analytics/site-quality-diagnostics":
		canonical = "/v1/admin/analytics/quality-diagnostics"
	default:
		http.NotFound(writer, request)
		return
	}
	forwarded := request.Clone(request.Context())
	forwardedURL := *request.URL
	forwardedURL.Path, forwardedURL.RawPath = canonical, ""
	forwarded.URL = &forwardedURL
	handler.next.ServeHTTP(writer, forwarded)
}

func finalizedProductionPrincipal(actor analyticsdiagnostic.Actor) (identity.Principal, error) {
	userID, userOK := finalizedProductionUUID(actor.ActorID)
	scopeID, scopeOK := finalizedProductionUUID(actor.ScopeID)
	if !userOK || !scopeOK {
		return identity.Principal{}, identity.ErrInvalidSession
	}
	permissions := make([]string, len(actor.Permissions))
	seen := make(map[string]struct{}, len(actor.Permissions))
	for index, permission := range actor.Permissions {
		if !finalizedProductionPermissionPattern.MatchString(permission) {
			return identity.Principal{}, identity.ErrInvalidSession
		}
		if _, duplicate := seen[permission]; duplicate {
			return identity.Principal{}, identity.ErrInvalidSession
		}
		seen[permission] = struct{}{}
		permissions[index] = permission
	}
	principal := identity.Principal{
		UserID: userID, ScopeID: scopeID, ScopeKind: actor.ScopeKind, Permissions: permissions,
	}
	switch actor.ScopeKind {
	case "tenant":
		tenantID, ok := finalizedProductionUUID(actor.TenantID)
		if !ok {
			return identity.Principal{}, identity.ErrInvalidSession
		}
		principal.TenantID = &tenantID
	case "platform":
		if actor.TenantID != "" {
			return identity.Principal{}, identity.ErrInvalidSession
		}
	default:
		return identity.Principal{}, identity.ErrInvalidSession
	}
	return principal, nil
}

func finalizedProductionUUID(value string) (uuid.UUID, bool) {
	parsed, err := uuid.Parse(value)
	return parsed, err == nil && parsed != uuid.Nil && parsed.String() == value
}
