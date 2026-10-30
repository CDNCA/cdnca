package nodegatewayaddr

// HTTP (platform scope, Bearer session):
//
//	GET  /v1/admin/node-gateway-address-changes              newest changes with counts (nodes.read)
//	POST /v1/admin/node-gateway-address-changes              create (nodes.manage + MFA step-up)
//	GET  /v1/admin/node-gateway-address-changes/{id}         one change with every node's state (nodes.read)
//	POST /v1/admin/node-gateway-address-changes/{id}/retry   retry failed nodes (nodes.manage + MFA step-up)

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	Route            = "/v1/admin/node-gateway-address-changes"
	PermissionRead   = "nodes.read"
	PermissionManage = "nodes.manage"
	PermissionAdmin  = "platform.admin"
	maxBody          = 1 << 20
)

// HandlerStore is what the handler needs from Store.
type HandlerStore interface {
	Create(ctx context.Context, actor Actor, request CreateRequest) (Change, error)
	Retry(ctx context.Context, actor Actor, changeID uuid.UUID, nodeIDs []uuid.UUID) (int, error)
	List(ctx context.Context, scopeID uuid.UUID, limit int) ([]Change, error)
	Get(ctx context.Context, scopeID, changeID uuid.UUID) (Change, error)
}

type Handler struct {
	Store        HandlerStore
	Authenticate func(context.Context, string) (identity.AuthenticatedSession, error)
	StepUp       StepUp // nil (MFA off): every write is step_up_required
	// Ready: the edge signer and edge messaging are configured (nil: writes unavailable).
	Ready func() bool
	// OnChange runs after a create or retry (wakes the distributor).
	OnChange func()
}

type createBody struct {
	Address     string   `json:"address"`
	ServerName  string   `json:"server_name"`
	TargetKind  string   `json:"target_kind"`
	Region      string   `json:"region"`
	NodeIDs     []string `json:"node_ids"`
	StepUpToken string   `json:"step_up_token"`
}

type retryBody struct {
	NodeIDs     []string `json:"node_ids"`
	StepUpToken string   `json:"step_up_token"`
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	session, ok := h.session(writer, request)
	if !ok {
		return
	}
	actor := Actor{ScopeID: session.Principal.ScopeID, UserID: session.Principal.UserID, SessionID: session.SessionID,
		RequestID: requestID(request)} // source IP: the audit middleware context
	rest := strings.TrimPrefix(request.URL.Path, Route)
	switch {
	case rest == "" && request.Method == http.MethodGet:
		if !h.allowed(writer, session.Principal, PermissionRead) {
			return
		}
		changes, err := h.Store.List(request.Context(), actor.ScopeID, 20)
		if err != nil {
			writeError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"items": changes})
	case rest == "" && request.Method == http.MethodPost:
		if !h.allowed(writer, session.Principal, PermissionManage) || !h.ready(writer) {
			return
		}
		var body createBody
		if !decode(writer, request, &body) {
			return
		}
		ids, ok := parseIDs(body.NodeIDs)
		if !ok {
			writeError(writer, ErrInvalidInput)
			return
		}
		normalized, err := CreateRequest{Address: body.Address, ServerName: body.ServerName, TargetKind: body.TargetKind,
			Region: body.Region, NodeIDs: ids}.Normalize()
		if err != nil {
			writeError(writer, err)
			return
		}
		if err := h.stepUp(request.Context(), actor, body.StepUpToken, StepUpAction, StepUpBinding(normalized)); err != nil {
			writeError(writer, err)
			return
		}
		change, err := h.Store.Create(request.Context(), actor, normalized)
		if err != nil {
			writeError(writer, err)
			return
		}
		h.changed()
		writeJSON(writer, http.StatusCreated, change)
	default:
		id, action, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
		changeID, err := uuid.Parse(id)
		if !strings.HasPrefix(rest, "/") || err != nil || changeID.String() != id {
			writeJSON(writer, http.StatusNotFound, errorBody("not_found"))
			return
		}
		switch {
		case action == "" && request.Method == http.MethodGet:
			if !h.allowed(writer, session.Principal, PermissionRead) {
				return
			}
			change, err := h.Store.Get(request.Context(), actor.ScopeID, changeID)
			if err != nil {
				writeError(writer, err)
				return
			}
			writeJSON(writer, http.StatusOK, change)
		case action == "retry" && request.Method == http.MethodPost:
			if !h.allowed(writer, session.Principal, PermissionManage) || !h.ready(writer) {
				return
			}
			var body retryBody
			if !decode(writer, request, &body) {
				return
			}
			ids, ok := parseIDs(body.NodeIDs)
			if !ok {
				writeError(writer, ErrInvalidInput)
				return
			}
			if err := h.stepUp(request.Context(), actor, body.StepUpToken, StepUpAction, RetryBinding(changeID)); err != nil {
				writeError(writer, err)
				return
			}
			retried, err := h.Store.Retry(request.Context(), actor, changeID, ids)
			if err != nil {
				writeError(writer, err)
				return
			}
			h.changed()
			writeJSON(writer, http.StatusOK, map[string]any{"retried": retried})
		default:
			writeJSON(writer, http.StatusMethodNotAllowed, errorBody("method_not_allowed"))
		}
	}
}

func (h *Handler) session(writer http.ResponseWriter, request *http.Request) (identity.AuthenticatedSession, bool) {
	token, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !found || token == "" || h.Authenticate == nil {
		writeJSON(writer, http.StatusUnauthorized, errorBody("unauthenticated"))
		return identity.AuthenticatedSession{}, false
	}
	session, err := h.Authenticate(request.Context(), token)
	if err != nil {
		writeJSON(writer, http.StatusUnauthorized, errorBody("unauthenticated"))
		return identity.AuthenticatedSession{}, false
	}
	return session, true
}

func (h *Handler) allowed(writer http.ResponseWriter, principal identity.Principal, permission string) bool {
	if principal.ScopeKind != "platform" || !slices.Contains(principal.Permissions, permission) && !slices.Contains(principal.Permissions, PermissionAdmin) {
		writeJSON(writer, http.StatusForbidden, errorBody("permission_denied"))
		return false
	}
	return true
}

func (h *Handler) ready(writer http.ResponseWriter) bool {
	if h.Ready == nil || !h.Ready() {
		writeError(writer, ErrSignerUnavailable)
		return false
	}
	return true
}

func (h *Handler) stepUp(ctx context.Context, actor Actor, token, action string, binding [32]byte) error {
	if h.StepUp == nil || token == "" {
		return ErrStepUpRequired
	}
	if err := h.StepUp.Consume(ctx, actor, token, action, binding); err != nil {
		return ErrStepUpRequired
	}
	return nil
}

func (h *Handler) changed() {
	if h.OnChange != nil {
		h.OnChange()
	}
}

func parseIDs(values []string) ([]uuid.UUID, bool) {
	if len(values) > MaxNodes {
		return nil, false
	}
	var ids []uuid.UUID
	for _, value := range values {
		id, err := uuid.Parse(value)
		if err != nil || id.String() != value {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

func decode(writer http.ResponseWriter, request *http.Request, target any) bool {
	if !strings.HasPrefix(request.Header.Get("Content-Type"), "application/json") {
		writeJSON(writer, http.StatusUnsupportedMediaType, errorBody("invalid_request"))
		return false
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxBody+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(writer, http.StatusBadRequest, errorBody("invalid_request"))
		return false
	}
	if _, err := decoder.Token(); err != io.EOF {
		writeJSON(writer, http.StatusBadRequest, errorBody("invalid_request"))
		return false
	}
	return true
}

func writeError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidInput):
		writeJSON(writer, http.StatusBadRequest, errorBody("invalid_request"))
	case errors.Is(err, ErrNoNodes):
		writeJSON(writer, http.StatusUnprocessableEntity, errorBody("gateway_address_no_nodes"))
	case errors.Is(err, ErrTooManyNodes):
		writeJSON(writer, http.StatusUnprocessableEntity, errorBody("gateway_address_too_many_nodes"))
	case errors.Is(err, ErrNotFound):
		writeJSON(writer, http.StatusNotFound, errorBody("not_found"))
	case errors.Is(err, ErrNothingToRetry):
		writeJSON(writer, http.StatusConflict, errorBody("gateway_address_nothing_to_retry"))
	case errors.Is(err, ErrStepUpRequired):
		writeJSON(writer, http.StatusForbidden, errorBody("mfa_step_up_required"))
	case errors.Is(err, ErrSignerUnavailable):
		writeJSON(writer, http.StatusServiceUnavailable, errorBody("gateway_address_unavailable"))
	default:
		writeJSON(writer, http.StatusServiceUnavailable, errorBody("unavailable"))
	}
}

func errorBody(code string) map[string]any {
	return map[string]any{"error": map[string]any{"code": code}}
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}

func requestID(request *http.Request) string {
	if value := strings.TrimSpace(request.Header.Get("X-Request-ID")); value != "" && len(value) <= 128 {
		return value
	}
	return "ngw-" + uuid.NewString()
}
