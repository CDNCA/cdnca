// Package rumhttp serves the 真实用户体验 report:
// GET /v1/analytics/rum (tenant, sites.read) and /v1/admin/analytics/rum
// (platform.admin + sites.read, with tenant_scope_id). Same authentication
// and error shape as ccstatshttp.
package rumhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/google/uuid"
)

const (
	TenantRoute     = "/v1/analytics/rum"
	AdminRoute      = "/v1/admin/analytics/rum"
	PermissionRead  = "sites.read"
	PermissionAdmin = "platform.admin"
)

var (
	ErrInvalidDependencies = errors.New("RUM report HTTP dependencies are invalid")
	requestIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Ranges are the report windows and their steps (§11: at most 30 days).
var Ranges = map[string]struct{ Window, Step time.Duration }{
	"1h":  {time.Hour, time.Minute},
	"24h": {24 * time.Hour, time.Hour},
	"7d":  {7 * 24 * time.Hour, 6 * time.Hour},
	"30d": {30 * 24 * time.Hour, 24 * time.Hour},
}

type Reader interface {
	SiteRUMReport(ctx context.Context, tenant, site uuid.UUID, from, to time.Time, step time.Duration) (securityanalytics.RUMSiteReport, error)
}

// SiteRUMFunc: whether the site exists in the tenant and its sample rate
// (nil: RUM is off, the page says so).
type SiteRUMFunc func(ctx context.Context, tenant, site uuid.UUID) (exists bool, samplePercent *int, err error)

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type Dependencies struct {
	Reader              Reader
	SiteRUM             SiteRUMFunc
	AuthenticateSession AuthenticateSessionFunc
	Now                 func() time.Time
}

type Handler struct {
	reader       Reader
	siteRUM      SiteRUMFunc
	authenticate AuthenticateSessionFunc
	now          func() time.Time
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.Reader == nil || dependencies.SiteRUM == nil || dependencies.AuthenticateSession == nil {
		return nil, ErrInvalidDependencies
	}
	now := dependencies.Now
	if now == nil {
		now = time.Now
	}
	return &Handler{reader: dependencies.Reader, siteRUM: dependencies.SiteRUM,
		authenticate: dependencies.AuthenticateSession, now: now}, nil
}

type Response struct {
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	Range         string    `json:"range"`
	// RUMSamplePercent is the site's current setting (null: off).
	RUMSamplePercent *int `json:"rum_sample_percent"`
	securityanalytics.RUMSiteReport
}

type errorBody struct {
	Error struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := request.Header.Get("X-Request-ID")
	validRequestID := len(request.Header.Values("X-Request-ID")) <= 1 && (requestID == "" || requestIDPattern.MatchString(requestID))
	if requestID == "" || !validRequestID {
		requestID = uuid.NewString()
	}
	writer.Header().Set("X-Request-ID", requestID)
	fail := func(status int, code string) {
		var body errorBody
		body.Error.Code, body.Error.RequestID = code, requestID
		writeJSON(writer, status, body)
	}
	admin := request.URL.Path == AdminRoute
	if !admin && request.URL.Path != TenantRoute {
		fail(http.StatusNotFound, "rum_not_found")
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		fail(http.StatusMethodNotAllowed, "rum_method_not_allowed")
		return
	}
	if !validRequestID {
		fail(http.StatusBadRequest, "rum_invalid_request")
		return
	}
	principal, status, code := handler.principal(request)
	if status != 0 {
		fail(status, code)
		return
	}
	if admin {
		if principal.ScopeKind != "platform" || principal.TenantID != nil ||
			!slices.Contains(principal.Permissions, PermissionAdmin) || !slices.Contains(principal.Permissions, PermissionRead) {
			fail(http.StatusForbidden, "rum_permission_denied")
			return
		}
	} else if principal.ScopeKind != "tenant" || principal.TenantID == nil || !slices.Contains(principal.Permissions, PermissionRead) {
		fail(http.StatusForbidden, "rum_permission_denied")
		return
	}
	query := request.URL.Query()
	allowed := []string{"site_id", "range"}
	if admin {
		allowed = append(allowed, "tenant_scope_id")
	}
	for key, values := range query {
		if !slices.Contains(allowed, key) || len(values) != 1 {
			fail(http.StatusBadRequest, "rum_invalid_request")
			return
		}
	}
	tenant := principal.ScopeID
	if admin {
		parsed, err := canonicalUUID(query.Get("tenant_scope_id"))
		if err != nil {
			fail(http.StatusBadRequest, "rum_invalid_request")
			return
		}
		tenant = parsed
	}
	site, err := canonicalUUID(query.Get("site_id"))
	rangeName := query.Get("range")
	if rangeName == "" {
		rangeName = "24h"
	}
	window, known := Ranges[rangeName]
	if err != nil || !known {
		fail(http.StatusBadRequest, "rum_invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	exists, percent, err := handler.siteRUM(ctx, tenant, site)
	if err != nil {
		fail(http.StatusServiceUnavailable, "rum_unavailable")
		return
	}
	if !exists {
		fail(http.StatusNotFound, "rum_site_not_found")
		return
	}
	// [from, to): the current partial step is included
	to := handler.now().UTC().Truncate(window.Step).Add(window.Step)
	report, err := handler.reader.SiteRUMReport(ctx, tenant, site, to.Add(-window.Window), to, window.Step)
	if err != nil {
		fail(http.StatusServiceUnavailable, "rum_unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, Response{TenantScopeID: tenant, Range: rangeName, RUMSamplePercent: percent, RUMSiteReport: report})
}

func (handler *Handler) principal(request *http.Request) (identity.Principal, int, string) {
	if len(request.Header.Values("X-API-Key")) != 0 {
		return identity.Principal{}, http.StatusUnauthorized, "rum_authentication_required"
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return identity.Principal{}, http.StatusUnauthorized, "rum_authentication_required"
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	token = strings.TrimSpace(token)
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return identity.Principal{}, http.StatusUnauthorized, "rum_authentication_required"
	}
	session, err := handler.authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrAccountDisabled) ||
			errors.Is(err, identity.ErrMembershipDisabled) {
			return identity.Principal{}, http.StatusUnauthorized, "rum_authentication_required"
		}
		return identity.Principal{}, http.StatusServiceUnavailable, "rum_unavailable"
	}
	if session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		return identity.Principal{}, http.StatusUnauthorized, "rum_authentication_required"
	}
	return session.Principal, 0, ""
}

func canonicalUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, errors.New("invalid UUID")
	}
	return parsed, nil
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}
