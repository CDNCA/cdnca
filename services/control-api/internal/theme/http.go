package theme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	adminRoute  = "/v1/admin/themes"
	publicRoute = "/v1/theme"
)

// HTTPRoutes are the mount patterns.
var HTTPRoutes = []string{adminRoute, adminRoute + "/", publicRoute + "/"}

var (
	fileRoutePattern  = regexp.MustCompile(`^/v1/theme/theme\.([0-9a-f]{64})\.(css|json)$`)
	assetRoutePattern = regexp.MustCompile(`^/v1/theme/assets/([0-9a-f]{64})$`)
	// authStyleAssetPattern: an image of the sign-in page style (site theme C).
	authStyleAssetPattern = regexp.MustCompile(`^/v1/theme/auth-style/assets/([0-9a-f]{64})$`)
	shaPathPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	themeIDPathRegexp     = regexp.MustCompile(`^(default|official\.[a-z][a-z0-9-]{0,31})$`)
)

type HTTPService interface {
	Catalog(context.Context, Actor) (CatalogView, error)
	Download(context.Context, Actor, string) (PackageView, error)
	Upload(context.Context, Actor, []byte) (PackageView, error)
	Activate(context.Context, Actor, string, int64) (ActivationResult, error)
	ActivateSlot(context.Context, Actor, string, int64, string) (ActivationResult, error)
	Remove(context.Context, Actor, string) error
	PackageBody(context.Context, Actor, string) ([]byte, error)
	Current(context.Context, CurrentRequest) (Current, error)
	File(context.Context, string, string) ([]byte, error)
	Asset(context.Context, string) (string, []byte, error)
	UserAuthStyle(context.Context) (AuthStyle, error)
	AuthStyleAsset(context.Context, string) (string, []byte, error)
}

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type Handler struct {
	service      HTTPService
	authenticate AuthenticateFunc
	timeout      time.Duration
}

func NewHandler(service HTTPService, authenticate AuthenticateFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrUnavailable
	}
	return &Handler{service: service, authenticate: authenticate, timeout: 30 * time.Second}, nil
}

// Routes:
//
//	GET    /v1/theme/current                      active theme pointer (public, no-store)
//	GET    /v1/theme/theme.<sha>.css|json         rendered files (public, immutable)
//	GET    /v1/theme/assets/<sha>                 brand images (public, immutable)
//	GET    /v1/admin/themes                       catalog + downloaded packages
//	POST   /v1/admin/themes/catalog/<id>/download download a catalog theme
//	POST   /v1/admin/themes/packages              upload a custom package (application/json)
//	POST   /v1/admin/themes/packages/<sha>/activate  activate; If-Match: "<activation revision>"
//	GET    /v1/admin/themes/packages/<sha>        the package JSON itself (customize)
//	DELETE /v1/admin/themes/packages/<sha>        remove an inactive download
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	if r.URL.RawQuery != "" || r.URL.Fragment != "" {
		h.error(w, r, http.StatusNotFound, "theme_not_found", nil)
		return
	}
	if strings.HasPrefix(r.URL.Path, publicRoute+"/") {
		h.servePublic(w, r)
		return
	}
	header.Set("Cache-Control", "no-store")
	raw, ok := bearer(r)
	if !ok {
		h.error(w, r, http.StatusUnauthorized, "theme_unauthenticated", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	session, err := h.authenticate(r.WithContext(ctx), raw)
	if err != nil || session.SessionID == uuid.Nil {
		h.error(w, r, http.StatusUnauthorized, "theme_unauthenticated", nil)
		return
	}
	principal := session.Principal
	if principal.UserID == uuid.Nil || principal.ScopeKind != "platform" || principal.TenantID != nil {
		h.error(w, r, http.StatusForbidden, "theme_permission_denied", nil)
		return
	}
	actor := Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		RequestID: requestID(r), IP: apikeycredential.ClientIP(r.Context())}
	path := strings.TrimPrefix(r.URL.Path, adminRoute)
	switch {
	case path == "" && r.Method == http.MethodGet:
		value, err := h.service.Catalog(ctx, actor)
		h.write(w, r, http.StatusOK, value, err)
	case strings.HasPrefix(path, "/catalog/") && strings.HasSuffix(path, "/download") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/catalog/"), "/download")
		if !themeIDPathRegexp.MatchString(id) || !emptyBody(r) {
			h.error(w, r, http.StatusBadRequest, "theme_invalid_request", nil)
			return
		}
		value, err := h.service.Download(ctx, actor, id)
		h.write(w, r, http.StatusOK, value, err)
	case path == "/packages" && r.Method == http.MethodPost:
		if strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]) != "application/json" {
			h.error(w, r, http.StatusUnsupportedMediaType, "theme_unsupported_media", nil)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxPackageSize+1))
		if err != nil || len(body) > MaxPackageSize {
			h.error(w, r, http.StatusRequestEntityTooLarge, "theme_package_too_large", nil)
			return
		}
		value, err := h.service.Upload(ctx, actor, body)
		h.write(w, r, http.StatusCreated, value, err)
	case strings.HasPrefix(path, "/packages/") && strings.HasSuffix(path, "/activate") && r.Method == http.MethodPost:
		sha := strings.TrimSuffix(strings.TrimPrefix(path, "/packages/"), "/activate")
		expected, ok := parseIfMatch(r.Header.Values("If-Match"))
		slot, slotOK := activationSlot(w, r)
		if !shaPathPattern.MatchString(sha) || !ok || !slotOK {
			h.error(w, r, http.StatusBadRequest, "theme_invalid_request", nil)
			return
		}
		value, err := h.service.ActivateSlot(ctx, actor, sha, expected, slot)
		if err == nil {
			w.Header().Set("ETag", `"`+strconv.FormatInt(value.Revision, 10)+`"`)
		}
		h.write(w, r, http.StatusOK, value, err)
	case strings.HasPrefix(path, "/packages/") && r.Method == http.MethodGet:
		sha := strings.TrimPrefix(path, "/packages/")
		if !shaPathPattern.MatchString(sha) {
			h.error(w, r, http.StatusBadRequest, "theme_invalid_request", nil)
			return
		}
		body, err := h.service.PackageBody(ctx, actor, sha)
		if err != nil {
			h.write(w, r, http.StatusOK, nil, err)
			return
		}
		// The stored bytes as they are: their SHA-256 is the package digest.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", `"`+sha+`"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	case strings.HasPrefix(path, "/packages/") && r.Method == http.MethodDelete:
		sha := strings.TrimPrefix(path, "/packages/")
		if !shaPathPattern.MatchString(sha) || !emptyBody(r) {
			h.error(w, r, http.StatusBadRequest, "theme_invalid_request", nil)
			return
		}
		err := h.service.Remove(ctx, actor, sha)
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.write(w, r, http.StatusNoContent, nil, err)
	default:
		h.error(w, r, http.StatusNotFound, "theme_not_found", nil)
	}
}

func (h *Handler) servePublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		h.error(w, r, http.StatusMethodNotAllowed, "theme_method_not_allowed", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	if r.URL.Path == publicRoute+"/current" {
		// Varies by session and Host (PA-26): never cached.
		w.Header().Set("Cache-Control", "no-store")
		value, err := h.service.Current(ctx, h.currentRequest(ctx, r))
		h.write(w, r, http.StatusOK, value, err)
		return
	}
	if r.URL.Path == AuthStylePath {
		// The sign-in page style: CSS only, applied by the console's own
		// sign-in forms. Changes with activations, so revalidated.
		w.Header().Set("Cache-Control", "no-cache")
		value, err := h.service.UserAuthStyle(ctx)
		h.write(w, r, http.StatusOK, value, err)
		return
	}
	var mime string
	var body []byte
	var sha string
	var err error
	if match := fileRoutePattern.FindStringSubmatch(r.URL.Path); match != nil {
		sha = match[1]
		body, err = h.service.File(ctx, match[2], sha)
		mime = "text/css; charset=utf-8"
		if match[2] == FileTokens {
			mime = "application/json; charset=utf-8"
		}
	} else if match := assetRoutePattern.FindStringSubmatch(r.URL.Path); match != nil {
		sha = match[1]
		mime, body, err = h.service.Asset(ctx, sha)
	} else if match := authStyleAssetPattern.FindStringSubmatch(r.URL.Path); match != nil {
		sha = match[1]
		mime, body, err = h.service.AuthStyleAsset(ctx, sha)
		// An image opened directly runs nothing (an SVG included).
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	} else {
		err = ErrNotFound
	}
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		h.write(w, r, http.StatusOK, nil, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("ETag", `"`+sha+`"`)
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Header.Get("If-None-Match") == `"`+sha+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

func (h *Handler) write(w http.ResponseWriter, r *http.Request, status int, value any, err error) {
	if err != nil {
		var validation *ValidationError
		switch {
		case errors.As(err, &validation):
			h.error(w, r, http.StatusUnprocessableEntity, "theme_package_invalid", validation)
		case errors.Is(err, ErrPermissionDenied):
			h.error(w, r, http.StatusForbidden, "theme_permission_denied", nil)
		case errors.Is(err, ErrNotFound):
			h.error(w, r, http.StatusNotFound, "theme_not_found", nil)
		case errors.Is(err, ErrRevisionConflict):
			h.error(w, r, http.StatusPreconditionFailed, "theme_revision_conflict", nil)
		case errors.Is(err, ErrActivePackage):
			h.error(w, r, http.StatusConflict, "theme_package_active", nil)
		case errors.Is(err, ErrEntitlementDenied):
			h.error(w, r, http.StatusForbidden, "entitlement_feature_denied", nil)
		case errors.Is(err, ErrInvalidRequest):
			h.error(w, r, http.StatusBadRequest, "theme_invalid_request", nil)
		default:
			h.error(w, r, http.StatusServiceUnavailable, "theme_unavailable", nil)
		}
		return
	}
	writeJSON(w, status, value)
}

func (h *Handler) error(w http.ResponseWriter, r *http.Request, status int, code string, detail *ValidationError) {
	body := map[string]any{"code": code, "request_id": requestID(r)}
	if detail != nil {
		body["reason"] = detail.Code
		if detail.Field != "" {
			body["field"] = detail.Field
		}
	}
	writeJSON(w, status, map[string]any{"error": body})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		status, encoded = http.StatusInternalServerError, []byte(`{"error":{"code":"theme_unavailable"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(encoded, '\n'))
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if !requestIDPattern.MatchString(id) {
		id = "theme-" + uuid.NewString()
	}
	return id
}

func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 8192 {
		return "", false
	}
	return parts[1], true
}

func parseIfMatch(values []string) (int64, bool) {
	if len(values) != 1 {
		return 0, false
	}
	value := strings.TrimSpace(values[0])
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, false
	}
	raw := value[1 : len(value)-1]
	if raw == "" || len(raw) > 1 && raw[0] == '0' {
		return 0, false
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	return parsed, err == nil && parsed >= 0
}

// activationSlot reads the console an activation applies to: no body is
// both consoles (as before slots existed); {"slot":"admin"|"user"|"all"}
// names one. The admin console takes official themes only (service).
func activationSlot(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Body == nil {
		return SlotAll, true
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil {
		return "", false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return SlotAll, true
	}
	var value struct {
		Slot string `json:"slot"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || (value.Slot != SlotAll && value.Slot != SlotAdmin && value.Slot != SlotUser) {
		return "", false
	}
	return value.Slot, true
}

func emptyBody(r *http.Request) bool {
	if r.Body == nil {
		return true
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 1))
	return err == nil && len(b) == 0
}

// currentRequest resolves whose theme /v1/theme/current shows: a signed-in
// platform administrator sees the admin console theme, everyone else the user
// console theme. A bad or absent token is not an error: the endpoint is public.
func (h *Handler) currentRequest(ctx context.Context, r *http.Request) CurrentRequest {
	if raw, ok := bearer(r); ok {
		if session, err := h.authenticate(r.WithContext(ctx), raw); err == nil && session.SessionID != uuid.Nil &&
			session.Principal.ScopeKind == "platform" {
			return CurrentRequest{Platform: true}
		}
	}
	return CurrentRequest{}
}
