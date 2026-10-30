package approvalcenter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Service is the part of Store the routes use (a fake in unit tests).
type Service interface {
	Settings(context.Context) (Settings, error)
	SaveSettings(context.Context, Session, Settings, string) (Settings, error)
	List(context.Context, Session, string, int) ([]Request, error)
	Get(context.Context, Session, uuid.UUID) (Request, error)
	MFAActive(context.Context, Session) (bool, error)
	Approve(context.Context, Session, uuid.UUID, int64, string, string, string) (Request, error)
	Reject(context.Context, Session, uuid.UUID, int64, string, string) (Request, error)
	Finish(context.Context, Session, uuid.UUID, []StepResult, string) (Request, error)
}

// Handler serves /v1/admin/approval-center/* and /v1/admin/approval-requests/*.
type Handler struct {
	Service   Service
	Session   func(*http.Request) (Session, bool)
	RequestID func(context.Context) string
	// Target is the full control API handler approved requests replay through.
	Target func() http.Handler
}

type settingsView struct {
	Settings
	Catalog []Rule `json:"catalog"`
}

type decisionBody struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Note             string `json:"note"`
	StepUpToken      string `json:"step_up_token"`
}

func (h Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/admin/approval-center/settings", h.getSettings)
	mux.HandleFunc("PUT /v1/admin/approval-center/settings", h.putSettings)
	mux.HandleFunc("GET /v1/admin/approval-requests", h.list)
	mux.HandleFunc("GET /v1/admin/approval-requests/{id}", h.get)
	mux.HandleFunc("POST /v1/admin/approval-requests/{id}/approve", h.decide(true))
	mux.HandleFunc("POST /v1/admin/approval-requests/{id}/reject", h.decide(false))
}

func (h Handler) session(w http.ResponseWriter, r *http.Request) (Session, bool) {
	session, ok := h.Session(r)
	if !ok {
		writeError(w, h.requestID(r), http.StatusUnauthorized, "unauthenticated", "a platform session is required")
		return Session{}, false
	}
	if session.ScopeKind != "platform" {
		writeError(w, h.requestID(r), http.StatusForbidden, "permission_denied", "platform administration only")
		return Session{}, false
	}
	return session, true
}

func (h Handler) getSettings(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	if !session.has(PermissionManage) && !session.has(PermissionRead) && !session.has(PermissionApprove) {
		h.fail(w, r, ErrPermissionDenied)
		return
	}
	settings, err := h.Service.Settings(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, settingsView{Settings: settings, Catalog: Catalog})
}

func (h Handler) putSettings(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	var body Settings
	if !decode(w, r, &body) {
		writeError(w, h.requestID(r), http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	saved, err := h.Service.SaveSettings(r.Context(), session, body, h.requestID(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, settingsView{Settings: saved, Catalog: Catalog})
}

func (h Handler) list(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			h.fail(w, r, ErrInvalidInput)
			return
		}
		limit = parsed
	}
	items, err := h.Service.List(r.Context(), session, r.URL.Query().Get("state"), limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h Handler) get(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.fail(w, r, ErrInvalidInput)
		return
	}
	item, err := h.Service.Get(r.Context(), session, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	active, err := h.Service.MFAActive(r.Context(), session)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// step_up_required tells the approver's page whether to ask for a code (Q3).
	writeJSON(w, http.StatusOK, map[string]any{"approval": item, "step_up_required": active})
}

// decide approves (and at once replays with the approver's session, Q2) or rejects.
func (h Handler) decide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := h.session(w, r)
		if !ok {
			return
		}
		id, err := uuid.Parse(r.PathValue("id"))
		var body decisionBody
		if err != nil || !decode(w, r, &body) || body.ExpectedRevision < 1 ||
			body.Note != "" && !validNote(strings.TrimSpace(body.Note), 0) {
			h.fail(w, r, ErrInvalidInput)
			return
		}
		note := strings.TrimSpace(body.Note)
		if !approve {
			result, err := h.Service.Reject(r.Context(), session, id, body.ExpectedRevision, note, h.requestID(r))
			if err != nil {
				h.fail(w, r, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"approval": result})
			return
		}
		approved, err := h.Service.Approve(r.Context(), session, id, body.ExpectedRevision, note, body.StepUpToken, h.requestID(r))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		// The replay must finish even if the approver's browser goes away.
		ctx := context.WithoutCancel(r.Context())
		results := Replay(ctx, h.Target(), r.Header.Get("Authorization"), approved.Steps)
		finished, err := h.Service.Finish(ctx, session, id, results, h.requestID(r))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"approval": finished})
	}
}

func (h Handler) requestID(r *http.Request) string {
	if h.RequestID == nil {
		return ""
	}
	return h.RequestID(r.Context())
}

func (h Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	id := h.requestID(r)
	switch {
	case errors.Is(err, ErrInvalidInput):
		writeError(w, id, http.StatusBadRequest, "validation_error", "request is invalid")
	case errors.Is(err, ErrPermissionDenied):
		writeError(w, id, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, ErrSameOperator):
		writeError(w, id, http.StatusForbidden, "approval_same_operator", "the requester cannot approve its own request")
	case errors.Is(err, ErrNotFound):
		writeError(w, id, http.StatusNotFound, "not_found", "approval request not found")
	case errors.Is(err, ErrExpired):
		writeError(w, id, http.StatusConflict, "approval_expired", "the approval request has expired")
	case errors.Is(err, ErrConflict):
		writeError(w, id, http.StatusConflict, "revision_conflict", "the approval request changed; reload it")
	case errors.Is(err, ErrStepUpRequired):
		writeError(w, id, http.StatusPreconditionRequired, "mfa_step_up_required", "a valid MFA step-up proof is required")
	default:
		writeError(w, id, http.StatusServiceUnavailable, "approval_center_unavailable", "approval center is unavailable")
	}
}

func decode(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination) == nil
}
