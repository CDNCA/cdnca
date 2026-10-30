package entitlementrefreshhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

const (
	Route  = "/v1/admin/entitlement/refresh"
	Schema = "cdnca.entitlement-refresh/v1"
)

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type Syncer interface {
	SyncOnce(context.Context) (entitlementguard.Snapshot, error)
}

// AuditFunc records one refresh: requestID, result (success/failure), the
// failure outcome (not_applied/unknown; empty on success) and the snapshot.
type AuditFunc func(context.Context, identity.AuthenticatedSession, string, string, string, entitlementguard.Snapshot) error

// Refresh error outcomes (error.outcome).
const (
	outcomeNotApplied = "not_applied"
	outcomeUnknown    = "unknown"
	outcomeApplied    = "applied"
)

type Handler struct {
	syncer       Syncer
	authenticate AuthenticateFunc
	audit        AuditFunc
	timeout      time.Duration
	mu           sync.Mutex
	inFlight     bool
}

type snapshotResponse struct {
	InstallationID string    `json:"installation_id"`
	Serial         uint64    `json:"serial"`
	KeyID          string    `json:"key_id"`
	Status         string    `json:"status"`
	VerifiedAt     time.Time `json:"verified_at"`
}

func New(syncer Syncer, authenticate AuthenticateFunc, audits ...AuditFunc) (*Handler, error) {
	if syncer == nil || authenticate == nil {
		return nil, errors.New("entitlement refresh HTTP dependencies are required")
	}
	if len(audits) > 1 {
		return nil, errors.New("entitlement refresh HTTP accepts at most one audit callback")
	}
	var audit AuditFunc
	if len(audits) == 1 {
		audit = audits[0]
	}
	return &Handler{syncer: syncer, authenticate: authenticate, audit: audit, timeout: 30 * time.Second}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	if h == nil || r == nil || r.URL == nil || r.URL.Path != Route || r.URL.RawQuery != "" || r.URL.Fragment != "" {
		writeError(w, http.StatusNotFound, "entitlement_refresh_not_found", "授权刷新资源不存在")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "entitlement_refresh_method_not_allowed", "请求方法不受支持")
		return
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if !metadata(requestID) || !metadata(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "entitlement_refresh_invalid_request", "授权刷新请求元数据无效")
		return
	}
	raw, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "entitlement_refresh_unauthenticated", "需要有效的管理员会话")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	session, err := h.authenticate(r.WithContext(ctx), raw)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "entitlement_refresh_unauthenticated", "需要有效的管理员会话")
		return
	}
	if session.Principal.ScopeKind != "platform" || identity.Authorize(session.Principal, "platform.admin") != nil {
		writeError(w, http.StatusForbidden, "entitlement_refresh_permission_denied", "没有授权刷新操作权限")
		return
	}
	// B18: every outcome carries the request ID. In progress, a definite sync
	// failure and an unknown result (audit write failed, or the deadline hit
	// while the new lease may already be installed) stay distinct so the page
	// re-reads the current serial instead of offering a blind retry.
	// LIC-REC-03: each error also says whether the lease was not applied, may
	// have been applied (COMMIT answer lost, deadline) or was applied (only the
	// audit failed); only not_applied may tell the user nothing changed.
	if !h.start() {
		writeRequestError(w, http.StatusConflict, "entitlement_refresh_in_progress", "授权刷新正在进行，请等候并查看最新状态", requestID, "")
		return
	}
	defer h.finish()
	snapshot, err := h.syncer.SyncOnce(ctx)
	if err != nil {
		outcome := outcomeNotApplied
		timedOut := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || ctx.Err() != nil
		if timedOut || errors.Is(err, entitlementguard.ErrInstallOutcomeUnknown) {
			outcome = outcomeUnknown
		}
		if h.audit != nil && h.audit(ctx, session, requestID, "failure", outcome, snapshot) != nil {
			writeRequestError(w, http.StatusServiceUnavailable, "entitlement_refresh_audit_failed", "授权刷新结果待确认", requestID, outcomeUnknown)
			return
		}
		switch {
		case timedOut:
			writeRequestError(w, http.StatusGatewayTimeout, "entitlement_refresh_timeout", "授权刷新结果待确认", requestID, outcome)
		case outcome == outcomeUnknown:
			writeRequestError(w, http.StatusBadGateway, "entitlement_refresh_unknown", "授权刷新结果待确认", requestID, outcome)
		default:
			writeRequestError(w, http.StatusBadGateway, "entitlement_refresh_failed", "授权刷新未完成", requestID, outcome)
		}
		return
	}
	if h.audit != nil && h.audit(ctx, session, requestID, "success", "", snapshot) != nil {
		writeRequestError(w, http.StatusServiceUnavailable, "entitlement_refresh_audit_failed", "授权已更新，审计记录写入失败", requestID, outcomeApplied)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema":     Schema,
		"request_id": requestID,
		"snapshot": snapshotResponse{
			InstallationID: snapshot.InstallationID,
			Serial:         snapshot.Serial,
			KeyID:          snapshot.KeyID,
			Status:         string(snapshot.Status),
			VerifiedAt:     snapshot.VerifiedAt,
		},
	})
}

func (h *Handler) start() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inFlight {
		return false
	}
	h.inFlight = true
	return true
}

func (h *Handler) finish() {
	h.mu.Lock()
	h.inFlight = false
	h.mu.Unlock()
}

func metadata(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '.' && char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" || len(parts[1]) > 8192 {
		return "", false
	}
	return parts[1], true
}

func setHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeRequestError(w http.ResponseWriter, status int, code, message, requestID, outcome string) {
	body := map[string]string{"code": code, "message": message, "request_id": requestID}
	if outcome != "" {
		body["outcome"] = outcome
	}
	writeJSON(w, status, map[string]any{"error": body})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
