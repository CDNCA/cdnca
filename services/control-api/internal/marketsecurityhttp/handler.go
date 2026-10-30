// Package marketsecurityhttp serves the attack log lines a leaf supplier
// relayed for this controller's market-supplied sites (ADR 0012 §19.1,
// ML-21; ClickHouse market_security_events_v1). The block event page lists
// them with the source "market supply · leaf number".
//
//	GET /v1/analytics/market-security?from=&to=[&site_id=&client_ip=&host=&cursor=&limit=]                tenant session
//	GET /v1/admin/analytics/market-security?tenant_id=&from=&to=[...]                                     platform admin
//
// from/to are RFC 3339, at most 31 days apart; limit 1–100 (default 10).
package marketsecurityhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/google/uuid"
)

const (
	TenantRoute     = "/v1/analytics/market-security"
	AdminRoute      = "/v1/admin/analytics/market-security"
	PermissionRead  = "sites.read"
	PermissionAdmin = "platform.admin"
	maxWindow       = 31 * 24 * time.Hour
	defaultLimit    = 10
	maxLimit        = 100
)

var (
	ErrInvalidDependencies = errors.New("market security HTTP dependencies are invalid")
	requestIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	hostPattern            = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// Reader is securityanalytics.ClickHouse.
type Reader interface {
	ListMarketSecurityLogs(ctx context.Context, tenant uuid.UUID, filter securityanalytics.MarketSecurityFilter,
		from, to time.Time, after string, limit int) ([]securityanalytics.MarketSecurityLog, error)
}

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type Handler struct {
	reader       Reader
	authenticate AuthenticateSessionFunc
}

func NewHandler(reader Reader, authenticate AuthenticateSessionFunc) (*Handler, error) {
	if reader == nil || authenticate == nil {
		return nil, ErrInvalidDependencies
	}
	return &Handler{reader: reader, authenticate: authenticate}, nil
}

// Response is the body of a successful request.
type Response struct {
	Data []securityanalytics.MarketSecurityLog `json:"data"`
	Meta struct {
		NextCursor string `json:"next_cursor,omitempty"`
	} `json:"meta"`
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
		fail(http.StatusNotFound, "market_security_not_found")
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		fail(http.StatusMethodNotAllowed, "market_security_method_not_allowed")
		return
	}
	if !validRequestID {
		fail(http.StatusBadRequest, "market_security_invalid_request")
		return
	}
	principal, status, code := handler.principal(request)
	if status != 0 {
		fail(status, code)
		return
	}
	if admin {
		if principal.ScopeKind != "platform" || principal.TenantID != nil || !slices.Contains(principal.Permissions, PermissionAdmin) {
			fail(http.StatusForbidden, "market_security_permission_denied")
			return
		}
	} else if principal.ScopeKind != "tenant" || principal.TenantID == nil || !slices.Contains(principal.Permissions, PermissionRead) {
		fail(http.StatusForbidden, "market_security_permission_denied")
		return
	}
	query := request.URL.Query()
	allowed := []string{"from", "to", "site_id", "client_ip", "host", "cursor", "limit"}
	if admin {
		allowed = append(allowed, "tenant_id")
	}
	for key, values := range query {
		if !slices.Contains(allowed, key) || len(values) != 1 {
			fail(http.StatusBadRequest, "market_security_invalid_request")
			return
		}
	}
	var tenant uuid.UUID
	if admin {
		parsed, err := canonicalUUID(query.Get("tenant_id"))
		if err != nil {
			fail(http.StatusBadRequest, "market_security_invalid_request")
			return
		}
		tenant = parsed
	} else {
		tenant = *principal.TenantID
	}
	from, errFrom := time.Parse(time.RFC3339Nano, query.Get("from"))
	to, errTo := time.Parse(time.RFC3339Nano, query.Get("to"))
	if errFrom != nil || errTo != nil || !from.Before(to) || to.Sub(from) > maxWindow {
		fail(http.StatusBadRequest, "market_security_invalid_window")
		return
	}
	var filter securityanalytics.MarketSecurityFilter
	if raw := query.Get("site_id"); raw != "" {
		site, err := canonicalUUID(raw)
		if err != nil {
			fail(http.StatusBadRequest, "market_security_invalid_request")
			return
		}
		filter.Site = site
	}
	if raw := query.Get("client_ip"); raw != "" {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			fail(http.StatusBadRequest, "market_security_invalid_request")
			return
		}
		filter.ClientIP = addr.Unmap().String()
	}
	if raw := query.Get("host"); raw != "" {
		if len(raw) > 253 || !hostPattern.MatchString(raw) {
			fail(http.StatusBadRequest, "market_security_invalid_request")
			return
		}
		filter.Host = raw
	}
	limit := defaultLimit
	if raw := query.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxLimit || strconv.Itoa(n) != raw {
			fail(http.StatusBadRequest, "market_security_invalid_request")
			return
		}
		limit = n
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	// One extra row tells whether there is a next page.
	rows, err := handler.reader.ListMarketSecurityLogs(ctx, tenant, filter, from.UTC(), to.UTC(), query.Get("cursor"), limit+1)
	if errors.Is(err, securityanalytics.ErrMarketCursor) {
		fail(http.StatusBadRequest, "market_security_invalid_cursor")
		return
	}
	if err != nil {
		fail(http.StatusServiceUnavailable, "market_security_unavailable")
		return
	}
	var response Response
	if len(rows) > limit {
		rows = rows[:limit]
		response.Meta.NextCursor = rows[limit-1].Cursor
	}
	response.Data = rows
	if response.Data == nil {
		response.Data = []securityanalytics.MarketSecurityLog{}
	}
	writeJSON(writer, http.StatusOK, response)
}

func (handler *Handler) principal(request *http.Request) (identity.Principal, int, string) {
	if len(request.Header.Values("X-API-Key")) != 0 {
		return identity.Principal{}, http.StatusUnauthorized, "market_security_authentication_required"
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return identity.Principal{}, http.StatusUnauthorized, "market_security_authentication_required"
	}
	scheme, token, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	token = strings.TrimSpace(token)
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return identity.Principal{}, http.StatusUnauthorized, "market_security_authentication_required"
	}
	session, err := handler.authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrAccountDisabled) ||
			errors.Is(err, identity.ErrMembershipDisabled) {
			return identity.Principal{}, http.StatusUnauthorized, "market_security_authentication_required"
		}
		return identity.Principal{}, http.StatusServiceUnavailable, "market_security_unavailable"
	}
	if session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		return identity.Principal{}, http.StatusUnauthorized, "market_security_authentication_required"
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
