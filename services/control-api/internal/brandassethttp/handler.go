package brandassethttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/brandasset"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	baseRoute       = "/v1/admin/brand-assets"
	publicRoute     = "/v1/brand-assets"
	maxRequestBytes = 2 << 20
)

type Service interface {
	Get(context.Context, brandasset.Actor, brandasset.Slot) (brandasset.Asset, error)
	List(context.Context, brandasset.Actor) ([]brandasset.Asset, error)
	Upload(context.Context, brandasset.Actor, brandasset.UploadRequest) (brandasset.Asset, error)
	OpenPublic(context.Context, brandasset.Slot) (brandasset.PublicAsset, error)
}

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type Handler struct {
	service      Service
	authenticate AuthenticateFunc
	timeout      time.Duration
}

func New(service Service, authenticate AuthenticateFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, errors.New("brand asset HTTP dependencies are required")
	}
	return &Handler{service: service, authenticate: authenticate, timeout: 30 * time.Second}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setHeaders(w.Header())
	if h == nil || r == nil || r.URL == nil {
		h.error(w, "brand-assets-http", http.StatusNotFound, "brand_asset_not_found")
		return
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if !validMetadata(requestID) {
		requestID = "brand-assets-http"
	}
	w.Header().Set("X-Request-ID", requestID)
	if slot, ok := parsePublicPath(r.URL.Path); ok {
		h.servePublic(w, r, slot)
		return
	}
	if strings.HasPrefix(r.URL.Path, publicRoute+"/") {
		h.error(w, requestID, http.StatusNotFound, "brand_asset_not_found")
		return
	}
	raw, ok := bearer(r)
	if !ok {
		h.error(w, requestID, http.StatusUnauthorized, "brand_asset_unauthenticated")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	session, err := h.authenticate(r.WithContext(ctx), raw)
	if err != nil {
		h.error(w, requestID, http.StatusUnauthorized, "brand_asset_unauthenticated")
		return
	}
	if session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		h.error(w, requestID, http.StatusUnauthorized, "brand_asset_unauthenticated")
		return
	}
	actor, ok := actorFromSession(session)
	if !ok {
		h.error(w, requestID, http.StatusForbidden, "brand_asset_permission_denied")
		return
	}
	slot, hasSlot, validPath := parsePath(r.URL.Path)
	if !validPath || r.URL.RawQuery != "" || r.URL.Fragment != "" {
		h.error(w, requestID, http.StatusNotFound, "brand_asset_not_found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !emptyBody(r.Body) {
			h.error(w, requestID, http.StatusBadRequest, "brand_asset_invalid_request")
			return
		}
		if hasSlot {
			value, err := h.service.Get(ctx, actor, slot)
			h.writeResult(w, requestID, value, err)
			return
		}
		values, err := h.service.List(ctx, actor)
		h.writeResult(w, requestID, map[string]any{"schema": brandasset.Schema(), "assets": values}, err)
	case http.MethodPut:
		if !hasSlot {
			h.error(w, requestID, http.StatusMethodNotAllowed, "brand_asset_method_not_allowed")
			return
		}
		if len(r.Header.Values("X-Request-ID")) != 1 || len(r.Header.Values("Idempotency-Key")) != 1 ||
			!validMetadata(r.Header.Get("Idempotency-Key")) {
			h.error(w, requestID, http.StatusBadRequest, "brand_asset_invalid_request")
			return
		}
		expected, err := parseIfMatch(r.Header.Get("If-Match"))
		if err != nil {
			h.error(w, requestID, http.StatusBadRequest, "brand_asset_invalid_request")
			return
		}
		mimeType := strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0])
		if r.ContentLength < 1 || r.ContentLength > maxRequestBytes {
			h.error(w, requestID, http.StatusRequestEntityTooLarge, "brand_asset_too_large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes+1)
		body, err := io.ReadAll(r.Body)
		if err != nil || int64(len(body)) != r.ContentLength {
			h.error(w, requestID, http.StatusBadRequest, "brand_asset_invalid_request")
			return
		}
		value, err := h.service.Upload(ctx, actor, brandasset.UploadRequest{ExpectedRevision: expected, Slot: slot,
			MIMEType: mimeType, Body: body, IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: requestID})
		h.writeResult(w, requestID, value, err)
	default:
		w.Header().Set("Allow", "GET, PUT")
		h.error(w, requestID, http.StatusMethodNotAllowed, "brand_asset_method_not_allowed")
	}
}

func (h *Handler) servePublic(w http.ResponseWriter, r *http.Request, slot brandasset.Slot) {
	if r.Method != http.MethodGet || !validPublicQuery(r.URL.RawQuery) || r.URL.Fragment != "" || !emptyBody(r.Body) {
		w.Header().Set("Allow", http.MethodGet)
		h.error(w, "brand-assets-public", http.StatusMethodNotAllowed, "brand_asset_method_not_allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	value, err := h.service.OpenPublic(ctx, slot)
	if err != nil {
		status, code := http.StatusInternalServerError, "brand_asset_unavailable"
		if errors.Is(err, brandasset.ErrNotFound) {
			status, code = http.StatusNotFound, "brand_asset_not_found"
		}
		h.error(w, "brand-assets-public", status, code)
		return
	}
	defer value.Body.Close()
	w.Header().Set("Cache-Control", "public, max-age=300, immutable")
	w.Header().Set("Content-Type", value.MIMEType)
	w.Header().Set("Content-Length", strconv.FormatInt(value.SizeBytes, 10))
	w.Header().Set("ETag", `"`+value.SHA256+`"`)
	if r.Header.Get("If-None-Match") == `"`+value.SHA256+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = io.CopyN(w, value.Body, value.SizeBytes)
}

func validPublicQuery(rawQuery string) bool {
	if rawQuery == "" {
		return true
	}
	parts := strings.Split(rawQuery, "=")
	if len(parts) != 2 || parts[0] != "v" || parts[1] == "" {
		return false
	}
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func parsePath(path string) (brandasset.Slot, bool, bool) {
	if path == baseRoute {
		return "", false, true
	}
	if !strings.HasPrefix(path, baseRoute+"/") {
		return "", false, false
	}
	value := strings.TrimPrefix(path, baseRoute+"/")
	if value == "" || strings.Contains(value, "/") {
		return "", false, false
	}
	slot := brandasset.Slot(value)
	return slot, true, slot.Valid()
}

func parsePublicPath(path string) (brandasset.Slot, bool) {
	if !strings.HasPrefix(path, publicRoute+"/") {
		return "", false
	}
	value := strings.TrimPrefix(path, publicRoute+"/")
	if value == "" || strings.Contains(value, "/") {
		return "", false
	}
	slot := brandasset.Slot(value)
	return slot, slot.Valid()
}

func actorFromSession(session identity.AuthenticatedSession) (brandasset.Actor, bool) {
	p := session.Principal
	if session.SessionID == uuid.Nil || p.UserID == uuid.Nil || p.ScopeID == uuid.Nil || p.ScopeKind != "platform" || p.TenantID != nil {
		return brandasset.Actor{}, false
	}
	return brandasset.Actor{UserID: p.UserID, ScopeID: p.ScopeID, ScopeKind: p.ScopeKind}, true
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

func parseIfMatch(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, errors.New("invalid If-Match")
	}
	raw := value[1 : len(value)-1]
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return 0, errors.New("invalid If-Match")
	}
	return strconv.ParseInt(raw, 10, 64)
}

func validMetadata(value string) bool {
	if value == "" || len(value) > 128 || !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z') || (value[0] >= '0' && value[0] <= '9')) {
		return false
	}
	for _, c := range value[1:] {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.ContainsRune("._:-", c)) {
			return false
		}
	}
	return true
}

func emptyBody(r io.ReadCloser) bool {
	if r == nil {
		return true
	}
	b, err := io.ReadAll(io.LimitReader(r, 1))
	return err == nil && len(b) == 0
}

func setHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
}

func (h *Handler) writeResult(w http.ResponseWriter, requestID string, value any, err error) {
	if err != nil {
		status, code := http.StatusInternalServerError, "brand_asset_unavailable"
		switch {
		case errors.Is(err, brandasset.ErrInvalidInput), errors.Is(err, brandasset.ErrUnsupportedMedia), errors.Is(err, brandasset.ErrUnsafeContent):
			status, code = http.StatusBadRequest, "brand_asset_invalid_request"
		case errors.Is(err, brandasset.ErrPermissionDenied):
			status, code = http.StatusForbidden, "brand_asset_permission_denied"
		case errors.Is(err, brandasset.ErrRevisionConflict):
			status, code = http.StatusConflict, "brand_asset_revision_conflict"
		case errors.Is(err, brandasset.ErrIdempotencyConflict):
			status, code = http.StatusConflict, "brand_asset_idempotency_conflict"
		case errors.Is(err, brandasset.ErrNotFound):
			status, code = http.StatusNotFound, "brand_asset_not_found"
		}
		h.error(w, requestID, status, code)
		return
	}
	b, err := json.Marshal(value)
	if err != nil {
		h.error(w, requestID, http.StatusInternalServerError, "brand_asset_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if asset, ok := value.(brandasset.Asset); ok {
		w.Header().Set("ETag", `"`+strconv.FormatInt(asset.Revision, 10)+`"`)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(b, '\n'))
}

func (h *Handler) error(w http.ResponseWriter, requestID string, status int, code string) {
	h.writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "request_id": requestID}})
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, value any) {
	b, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"error":{"code":"brand_asset_unavailable"}}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
