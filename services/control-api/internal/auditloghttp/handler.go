// Package auditloghttp serves the log center (unified-log): the event
// categories, the rendered operation log filtered by category, and its CSV
// export. Platform administrators may read any scope; tenants read their own.
package auditloghttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/auditlog"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// ExportAction is written once per CSV export, before the file is returned.
const ExportAction = "system.audit_log.export"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

// Reader is auditlog.Store.
type Reader interface {
	List(ctx context.Context, filter auditlog.Filter, locale audit.Locale, location *time.Location) (auditlog.Page, error)
	Export(ctx context.Context, filter auditlog.Filter, locale audit.Locale, location *time.Location, out io.Writer) (int, error)
}

// AuditFunc appends event in its own transaction.
type AuditFunc func(ctx context.Context, event audit.Event) error

type Dependencies struct {
	Reader       Reader
	Authenticate AuthenticateSessionFunc
	Audit        AuditFunc
	// DefaultLocation formats times when the request has no tz (nil = Asia/Shanghai, else UTC).
	DefaultLocation *time.Location
}

type Handler struct {
	reader       Reader
	authenticate AuthenticateSessionFunc
	audit        AuditFunc
	location     *time.Location
}

var ErrInvalidConfig = errors.New("audit log handler dependencies are incomplete")

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.Reader == nil || dependencies.Authenticate == nil || dependencies.Audit == nil {
		return nil, ErrInvalidConfig
	}
	location := dependencies.DefaultLocation
	if location == nil {
		if loaded, err := time.LoadLocation("Asia/Shanghai"); err == nil {
			location = loaded
		} else {
			location = time.UTC
		}
	}
	return &Handler{reader: dependencies.Reader, authenticate: dependencies.Authenticate,
		audit: dependencies.Audit, location: location}, nil
}

type actor struct {
	session  identity.AuthenticatedSession
	platform bool
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := request.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	response.Header().Set("X-Request-ID", requestID)
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", requestID)
		return
	}
	token, ok := strictBearer(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication_required", requestID)
		return
	}
	session, err := handler.authenticate(request.Context(), token)
	if err != nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		writeError(response, http.StatusUnauthorized, "authentication_required", requestID)
		return
	}
	who, ok := authorize(session)
	if !ok {
		writeError(response, http.StatusForbidden, "permission_denied", requestID)
		return
	}
	query := request.URL.Query()
	locale := audit.ParseLocale(firstNonEmpty(query.Get("lang"), request.Header.Get("Accept-Language")))
	switch request.URL.Path {
	case "/v1/audit-logs/categories":
		writeJSON(response, http.StatusOK, categoriesResponse(locale))
		return
	case "/v1/audit-logs", "/v1/audit-logs/export":
	default:
		writeError(response, http.StatusNotFound, "not_found", requestID)
		return
	}
	filter, location, err := handler.parseFilter(query, who)
	if err != nil {
		writeError(response, http.StatusBadRequest, "audit_log_invalid_request", requestID)
		return
	}
	if request.URL.Path == "/v1/audit-logs" {
		page, err := handler.reader.List(request.Context(), filter, locale, location)
		if err != nil {
			writeReadError(response, requestID, err)
			return
		}
		writeJSON(response, http.StatusOK, page)
		return
	}
	var buffer bytes.Buffer
	buffer.WriteString("\ufeff") // spreadsheet apps read the CSV as UTF-8
	rows, err := handler.reader.Export(request.Context(), filter, locale, location, &buffer)
	if err != nil {
		writeReadError(response, requestID, err)
		return
	}
	// The export is audited before any row leaves the server.
	userID := session.Principal.UserID
	if err := handler.audit(request.Context(), audit.Event{ScopeID: session.Principal.ScopeID, ActorUserID: &userID,
		Action: ExportAction, ResourceType: "audit_log", ResourceID: exportResourceID(filter),
		RequestID: requestID, Result: "success",
		Payload: map[string]any{"category": firstNonEmpty(filter.Category, "all"), "rows": rows, "since": timeText(filter.Since),
			"until": timeText(filter.Until)}}); err != nil {
		writeError(response, http.StatusServiceUnavailable, "audit_log_unavailable", requestID)
		return
	}
	response.Header().Set("Content-Type", "text/csv; charset=utf-8")
	response.Header().Set("Content-Disposition", `attachment; filename="audit-logs.csv"`)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(buffer.Bytes())
}

// authorize: platform administrators read every scope, tenant users their own.
func authorize(session identity.AuthenticatedSession) (actor, bool) {
	principal := session.Principal
	switch principal.ScopeKind {
	case "platform":
		return actor{session: session, platform: true}, hasPermission(principal.Permissions, "platform.admin")
	case "tenant":
		return actor{session: session}, hasPermission(principal.Permissions, "identity.self.read")
	}
	return actor{}, false
}

func (handler *Handler) parseFilter(values url.Values, who actor) (auditlog.Filter, *time.Location, error) {
	filter := auditlog.Filter{Category: values.Get("category"), ExcludeCategory: values.Get("exclude_category"), SourceIP: values.Get("source_ip"),
		ActorName: values.Get("actor"), ResourceType: values.Get("resource_type"), ResourceID: values.Get("resource_id"),
		Result: values.Get("result"), Action: values.Get("action"), Cursor: values.Get("cursor")}
	if filter.Category == "all" {
		filter.Category = ""
	}
	scope := values.Get("scope_id")
	switch {
	case !who.platform && scope != "" && scope != who.session.Principal.ScopeID.String():
		return filter, nil, auditlog.ErrInvalidFilter
	case !who.platform:
		filter.ScopeIDs = []uuid.UUID{who.session.Principal.ScopeID}
	case scope != "":
		parsed, err := uuid.Parse(scope)
		if err != nil || parsed == uuid.Nil {
			return filter, nil, auditlog.ErrInvalidFilter
		}
		filter.ScopeIDs = []uuid.UUID{parsed}
	}
	if raw := values.Get("actor_user_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return filter, nil, auditlog.ErrInvalidFilter
		}
		filter.ActorUserID = &parsed
	}
	for key, target := range map[string]*time.Time{"since": &filter.Since, "until": &filter.Until} {
		if raw := values.Get(key); raw != "" {
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return filter, nil, auditlog.ErrInvalidFilter
			}
			*target = parsed
		}
	}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			return filter, nil, auditlog.ErrInvalidFilter
		}
		filter.Limit = limit
	}
	location := handler.location
	if raw := values.Get("tz"); raw != "" {
		loaded, err := time.LoadLocation(raw)
		if err != nil || len(raw) > 64 {
			return filter, nil, auditlog.ErrInvalidFilter
		}
		location = loaded
	}
	return filter, location, filter.Validate()
}

type categoryView struct {
	Category    string `json:"category"`
	Label       string `json:"label"`
	DefaultDays int    `json:"default_retention_days"`
	Actions     int    `json:"actions"`
}

func categoriesResponse(locale audit.Locale) map[string]any {
	items := make([]categoryView, 0)
	for _, info := range audit.Categories() {
		label := info.LabelZH
		if locale == audit.LocaleEN {
			label = info.LabelEN
		}
		items = append(items, categoryView{Category: string(info.Category), Label: label,
			DefaultDays: info.RetentionDays, Actions: len(audit.ActionsIn(info.Category))})
	}
	return map[string]any{"items": items}
}

func exportResourceID(filter auditlog.Filter) string {
	if len(filter.ScopeIDs) == 1 {
		return filter.ScopeIDs[0].String()
	}
	return "all"
}

func timeText(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func hasPermission(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func strictBearer(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || len(token) >= 8192 || strings.ContainsFunc(token, unicode.IsSpace) {
		return "", false
	}
	return token, true
}

func writeReadError(response http.ResponseWriter, requestID string, err error) {
	if errors.Is(err, auditlog.ErrInvalidFilter) {
		writeError(response, http.StatusBadRequest, "audit_log_invalid_request", requestID)
		return
	}
	writeError(response, http.StatusServiceUnavailable, "audit_log_unavailable", requestID)
}

func writeError(response http.ResponseWriter, status int, code, requestID string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{"code": code, "request_id": requestID}})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
