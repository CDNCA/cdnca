package dnspupprobe

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (handler *Handler) purposes(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	view, err := handler.service.Purposes(request.Context(), actor)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, view)
}

func (handler *Handler) purposesUpdate(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var body struct {
		Purposes []PurposeInput `json:"purposes"`
	}
	if !decode(response, request, &body) {
		return
	}
	view, err := handler.service.UpdatePurposes(request.Context(), actor, key, body.Purposes)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, view)
}

func (handler *Handler) matrix(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	window := query.Get("window")
	if window == "" {
		window = "24h"
	}
	matrix, err := handler.service.ReadMatrix(request.Context(), actor, query.Get("subject"), query.Get("id"), window)
	if errors.Is(err, ErrMatrixSubject) {
		writeError(response, http.StatusUnprocessableEntity, "invalid_input")
		return
	}
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, matrix)
}

func (handler *Handler) edgeSubjects(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	subjects, err := handler.service.EdgeSubjects(request.Context(), actor)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"items": subjects})
}

func (handler *Handler) overrides(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	if handler.nodes == nil {
		writeError(response, http.StatusServiceUnavailable, "probe_dnspup_node_monitoring_unavailable")
		return
	}
	items, err := handler.nodes.Overrides(request.Context(), actor)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, items)
}

func (handler *Handler) overridePut(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	if handler.nodes == nil {
		writeError(response, http.StatusServiceUnavailable, "probe_dnspup_node_monitoring_unavailable")
		return
	}
	var raw json.RawMessage
	if !decode(response, request, &raw) {
		return
	}
	item, err := handler.nodes.PutOverride(request.Context(), actor, key, raw)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, item)
}

func (handler *Handler) overrideDelete(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	id, err := uuid.Parse(request.PathValue("id"))
	if err != nil {
		writeError(response, http.StatusNotFound, "not_found")
		return
	}
	if handler.nodes == nil {
		writeError(response, http.StatusServiceUnavailable, "probe_dnspup_node_monitoring_unavailable")
		return
	}
	if err := handler.nodes.DeleteOverride(request.Context(), actor, key, id); err != nil {
		if errors.Is(err, ErrRequestNotFound) {
			writeError(response, http.StatusNotFound, "not_found")
			return
		}
		writeServiceError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) diagnoseCreate(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var input DiagnoseInput
	if !decode(response, request, &input) {
		return
	}
	view, err := handler.service.CreateDiagnose(request.Context(), actor, key, input)
	if err != nil {
		writeProbeError(response, err)
		return
	}
	writeRequestView(response, http.StatusAccepted, view)
}

func (handler *Handler) diagnoseGet(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	id, err := uuid.Parse(request.PathValue("id"))
	if err != nil {
		writeError(response, http.StatusNotFound, "not_found")
		return
	}
	view, err := handler.service.GetDiagnose(request.Context(), actor, id)
	if err != nil {
		writeProbeError(response, err)
		return
	}
	writeRequestView(response, http.StatusOK, view)
}

// pluginActor authenticates the plugin API: a tenant API key only.
func (handler *Handler) pluginActor(response http.ResponseWriter, request *http.Request) (PluginActor, bool) {
	values := request.Header.Values("Authorization")
	if handler.apiKey == nil || len(values) != 1 || !strings.HasPrefix(values[0], "CdncaKey ") {
		writeError(response, http.StatusUnauthorized, "unauthorized")
		return PluginActor{}, false
	}
	raw := values[0][len("CdncaKey "):]
	if raw == "" || strings.TrimSpace(raw) != raw {
		writeError(response, http.StatusUnauthorized, "unauthorized")
		return PluginActor{}, false
	}
	principal, keyID, err := handler.apiKey(request.Context(), raw)
	if err != nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil || keyID == uuid.Nil {
		writeError(response, http.StatusUnauthorized, "unauthorized")
		return PluginActor{}, false
	}
	if principal.ScopeKind != "tenant" {
		writeError(response, http.StatusForbidden, "permission_denied")
		return PluginActor{}, false
	}
	return PluginActor{ScopeID: principal.ScopeID, UserID: principal.UserID, KeyID: keyID,
		Permissions: append([]string(nil), principal.Permissions...)}, true
}

func (handler *Handler) pluginStatus(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.pluginActor(response, request)
	if !ok {
		return
	}
	status, err := handler.service.PluginStatus(request.Context(), actor)
	if err != nil {
		writeProbeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (handler *Handler) pluginCreate(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.pluginActor(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var input ProbeInput
	if !decode(response, request, &input) {
		return
	}
	view, err := handler.service.CreatePluginRequest(request.Context(), actor, key, input)
	if err != nil {
		writeProbeError(response, err)
		return
	}
	writeRequestView(response, http.StatusAccepted, view)
}

func (handler *Handler) pluginGet(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.pluginActor(response, request)
	if !ok {
		return
	}
	id, err := uuid.Parse(request.PathValue("id"))
	if err != nil {
		writeError(response, http.StatusNotFound, "not_found")
		return
	}
	view, err := handler.service.GetPluginRequest(request.Context(), actor, id)
	if err != nil {
		writeProbeError(response, err)
		return
	}
	writeRequestView(response, http.StatusOK, view)
}

func writeRequestView(response http.ResponseWriter, status int, view ProbeRequestView) {
	if view.Status == "pending" && view.RetryAfter > 0 {
		response.Header().Set("Retry-After", strconv.Itoa(int(max(view.RetryAfter/time.Second, 1))))
	}
	writeJSON(response, status, view)
}

// writeProbeError maps the plugin / diagnose errors (docs/architecture/
// probe-dnspup-unified.md §7), then the shared ones.
func writeProbeError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPluginIdentity):
		writeError(response, http.StatusForbidden, "probe_dnspup_plugin_identity_required")
	case errors.Is(err, ErrNotInstalled):
		writeError(response, http.StatusConflict, ReasonNotInstalled)
	case errors.Is(err, ErrNotConfigured):
		writeError(response, http.StatusConflict, ReasonNotConfigured)
	case errors.Is(err, ErrPaused):
		response.Header().Set("Retry-After", "60")
		writeError(response, http.StatusServiceUnavailable, ReasonPaused)
	case errors.Is(err, ErrPluginRateLimited):
		response.Header().Set("Retry-After", "60")
		writeError(response, http.StatusTooManyRequests, "probe_dnspup_rate_limited")
	case errors.Is(err, ErrPluginQuota):
		writeError(response, http.StatusTooManyRequests, "probe_dnspup_quota_exceeded")
	case errors.Is(err, ErrTargetRestricted):
		writeError(response, http.StatusUnprocessableEntity, "probe_dnspup_target_restricted")
	case errors.Is(err, ErrRequestNotFound):
		writeError(response, http.StatusNotFound, "not_found")
	default:
		writeServiceError(response, err)
	}
}
