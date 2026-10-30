// Package ccstatshttp serves the CC rule statistics of a site:
// what the CC rules of the site matched,
// triggered, challenged, blocked and let through, per step and per rule,
// and the triggered top clients and paths, for the CC page (manual tuning).
// Automatic defense reads the same ClickHouse table directly.
//
//	GET /v1/security/cc-stats?site_id=&range=           tenant session (own scope)
//	GET /v1/admin/security/cc-stats?tenant_scope_id=&site_id=&range=   platform admin
//
// range is 1h (1 minute steps), 6h (5 minutes) or 24h (15 minutes).
package ccstatshttp

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
	TenantRoute     = "/v1/security/cc-stats"
	AdminRoute      = "/v1/admin/security/cc-stats"
	PermissionRead  = "security_policies.read"
	PermissionAdmin = "platform.admin"
)

var (
	ErrInvalidDependencies = errors.New("CC statistics HTTP dependencies are invalid")
	requestIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Ranges: the window and its step.
var Ranges = map[string]struct{ Window, Step time.Duration }{
	"1h":  {time.Hour, time.Minute},
	"6h":  {6 * time.Hour, 5 * time.Minute},
	"24h": {24 * time.Hour, 15 * time.Minute},
}

// Reader reads one site's statistics (securityanalytics.ClickHouse).
type Reader interface {
	SiteCCStats(ctx context.Context, tenant, site uuid.UUID, from, to time.Time, step time.Duration) (securityanalytics.CCSiteStats, error)
}

// SiteExistsFunc reports whether site is a live site of the tenant scope.
type SiteExistsFunc func(ctx context.Context, tenant, site uuid.UUID) (bool, error)

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type Dependencies struct {
	Reader              Reader
	SiteExists          SiteExistsFunc
	AuthenticateSession AuthenticateSessionFunc
	Now                 func() time.Time
}

type Handler struct {
	reader       Reader
	siteExists   SiteExistsFunc
	authenticate AuthenticateSessionFunc
	now          func() time.Time
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.Reader == nil || dependencies.SiteExists == nil || dependencies.AuthenticateSession == nil {
		return nil, ErrInvalidDependencies
	}
	now := dependencies.Now
	if now == nil {
		now = time.Now
	}
	return &Handler{reader: dependencies.Reader, siteExists: dependencies.SiteExists,
		authenticate: dependencies.AuthenticateSession, now: now}, nil
}

// Response is the body of a successful request.
type Response struct {
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	Range         string    `json:"range"`
	securityanalytics.CCSiteStats
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
		fail(http.StatusNotFound, "cc_stats_not_found")
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		fail(http.StatusMethodNotAllowed, "cc_stats_method_not_allowed")
		return
	}
	if !validRequestID {
		fail(http.StatusBadRequest, "cc_stats_invalid_request")
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
			fail(http.StatusForbidden, "cc_stats_permission_denied")
			return
		}
	} else if principal.ScopeKind != "tenant" || principal.TenantID == nil ||
		!slices.Contains(principal.Permissions, PermissionRead) {
		fail(http.StatusForbidden, "cc_stats_permission_denied")
		return
	}

	query := request.URL.Query()
	allowed := []string{"site_id", "range"}
	if admin {
		allowed = append(allowed, "tenant_scope_id")
	}
	for key, values := range query {
		if !slices.Contains(allowed, key) || len(values) != 1 {
			fail(http.StatusBadRequest, "cc_stats_invalid_request")
			return
		}
	}
	tenant := principal.ScopeID
	if admin {
		parsed, err := canonicalUUID(query.Get("tenant_scope_id"))
		if err != nil {
			fail(http.StatusBadRequest, "cc_stats_invalid_request")
			return
		}
		tenant = parsed
	}
	site, err := canonicalUUID(query.Get("site_id"))
	rangeName := query.Get("range")
	if rangeName == "" {
		rangeName = "1h"
	}
	window, known := Ranges[rangeName]
	if err != nil || !known {
		fail(http.StatusBadRequest, "cc_stats_invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	exists, err := handler.siteExists(ctx, tenant, site)
	if err != nil {
		fail(http.StatusServiceUnavailable, "cc_stats_unavailable")
		return
	}
	if !exists {
		fail(http.StatusNotFound, "cc_stats_site_not_found")
		return
	}
	// [from, to): to is the start of the next step, so the current partial
	// step is included.
	to := handler.now().UTC().Truncate(window.Step).Add(window.Step)
	stats, err := handler.reader.SiteCCStats(ctx, tenant, site, to.Add(-window.Window), to, window.Step)
	if err != nil {
		fail(http.StatusServiceUnavailable, "cc_stats_unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, Response{TenantScopeID: tenant, Range: rangeName, CCSiteStats: stats})
}

func (handler *Handler) principal(request *http.Request) (identity.Principal, int, string) {
	if len(request.Header.Values("X-API-Key")) != 0 {
		return identity.Principal{}, http.StatusUnauthorized, "cc_stats_authentication_required"
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return identity.Principal{}, http.StatusUnauthorized, "cc_stats_authentication_required"
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	token = strings.TrimSpace(token)
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return identity.Principal{}, http.StatusUnauthorized, "cc_stats_authentication_required"
	}
	session, err := handler.authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrAccountDisabled) ||
			errors.Is(err, identity.ErrMembershipDisabled) {
			return identity.Principal{}, http.StatusUnauthorized, "cc_stats_authentication_required"
		}
		return identity.Principal{}, http.StatusServiceUnavailable, "cc_stats_unavailable"
	}
	if session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		return identity.Principal{}, http.StatusUnauthorized, "cc_stats_authentication_required"
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
