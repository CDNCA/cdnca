package firewallhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
)

type API interface {
	Put(context.Context, firewallcontrol.PutRequest) (firewallcontrol.WriteResult, error)
	Get(context.Context, firewallcontrol.ReadRequest) (firewallcontrol.Policy, error)
	Recover(context.Context, firewallcontrol.RecoverRequest) (firewallcontrol.WriteResult, error)
	ListHits(context.Context, firewallcontrol.HitFilter) (firewallcontrol.HitPage, error)
}

type Authenticator func(*http.Request) (firewallcontrol.Actor, error)

type Handler struct {
	api          API
	authenticate Authenticator
}

func NewHandler(api API, authenticate Authenticator) (*Handler, error) {
	if api == nil || authenticate == nil {
		return nil, errors.New("invalid firewall HTTP dependencies")
	}
	return &Handler{api: api, authenticate: authenticate}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	actor, err := handler.authenticate(request)
	if err != nil {
		writeError(response, err)
		return
	}
	targetScopeID, err := uuid.Parse(request.URL.Query().Get("target_scope_id"))
	if err != nil || targetScopeID == uuid.Nil || targetScopeID.String() != request.URL.Query().Get("target_scope_id") {
		writeError(response, firewallcontrol.ErrInvalidInput)
		return
	}
	switch {
	case request.URL.Path == "/v1/firewall/policy" && request.Method == http.MethodGet:
		policy, err := handler.api.Get(request.Context(), firewallcontrol.ReadRequest{Actor: actor, TargetScopeID: targetScopeID})
		if err != nil {
			writeError(response, err)
			return
		}
		response.Header().Set("ETag", fmt.Sprintf(`"%d"`, policy.Revision))
		writeJSON(response, http.StatusOK, policy)
	case request.URL.Path == "/v1/firewall/policy" && request.Method == http.MethodPut:
		expected, err := parseETag(request.Header.Get("If-Match"), true)
		if err != nil {
			writeError(response, firewallcontrol.ErrInvalidInput)
			return
		}
		var input firewallcontrol.PolicyInput
		if err := decodeBody(response, request, &input); err != nil {
			writeError(response, firewallcontrol.ErrInvalidInput)
			return
		}
		result, err := handler.api.Put(request.Context(), firewallcontrol.PutRequest{Actor: actor, TargetScopeID: targetScopeID,
			ExpectedRevision: expected, IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"), Policy: input})
		if err != nil {
			writeError(response, err)
			return
		}
		response.Header().Set("ETag", fmt.Sprintf(`"%d"`, result.Policy.Revision))
		writeJSON(response, http.StatusOK, result.Policy)
	case request.URL.Path == "/v1/firewall/policy/recover" && request.Method == http.MethodPost:
		expected, err := parseETag(request.Header.Get("If-Match"), false)
		if err != nil {
			writeError(response, firewallcontrol.ErrInvalidInput)
			return
		}
		var input struct {
			RecoverRevision int64  `json:"recover_revision"`
			Reason          string `json:"reason"`
		}
		if err := decodeBody(response, request, &input); err != nil {
			writeError(response, firewallcontrol.ErrInvalidInput)
			return
		}
		result, err := handler.api.Recover(request.Context(), firewallcontrol.RecoverRequest{Actor: actor, TargetScopeID: targetScopeID,
			ExpectedRevision: expected, RecoverRevision: input.RecoverRevision, Reason: input.Reason,
			IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID")})
		if err != nil {
			writeError(response, err)
			return
		}
		response.Header().Set("ETag", fmt.Sprintf(`"%d"`, result.Policy.Revision))
		writeJSON(response, http.StatusOK, result.Policy)
	case request.URL.Path == "/v1/firewall/hits" && request.Method == http.MethodGet:
		limit := 50
		if raw := request.URL.Query().Get("limit"); raw != "" {
			limit, err = strconv.Atoi(raw)
			if err != nil {
				writeError(response, firewallcontrol.ErrInvalidInput)
				return
			}
		}
		siteID := uuid.Nil
		if raw := request.URL.Query().Get("site_id"); raw != "" {
			siteID, err = uuid.Parse(raw)
			if err != nil || siteID.String() != raw {
				writeError(response, firewallcontrol.ErrInvalidInput)
				return
			}
		}
		page, err := handler.api.ListHits(request.Context(), firewallcontrol.HitFilter{Actor: actor, TargetScopeID: targetScopeID,
			SiteID: siteID, Limit: limit, Cursor: request.URL.Query().Get("cursor")})
		if err != nil {
			writeError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, page)
	default:
		writeJSON(response, http.StatusNotFound, map[string]any{"code": "not_found"})
	}
}

func decodeBody(response http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(response, request.Body, 1<<20)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON document")
	}
	return nil
}

func parseETag(value string, allowZero bool) (int64, error) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' || strings.TrimSpace(value) != value {
		return 0, errors.New("invalid ETag")
	}
	parsed, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || parsed < 0 || !allowZero && parsed == 0 {
		return 0, errors.New("invalid ETag")
	}
	return parsed, nil
}

func writeError(response http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "firewall_unavailable"
	switch {
	case errors.Is(err, firewallcontrol.ErrUnauthenticated):
		status, code = http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, firewallcontrol.ErrPermissionDenied):
		status, code = http.StatusForbidden, "permission_denied"
	case errors.Is(err, firewallcontrol.ErrNotFound):
		status, code = http.StatusNotFound, "firewall_not_found"
	case errors.Is(err, firewallcontrol.ErrInvalidInput):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, firewallcontrol.ErrRevisionConflict):
		status, code = http.StatusConflict, "revision_conflict"
	case errors.Is(err, firewallcontrol.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "idempotency_conflict"
	case errors.Is(err, firewallcontrol.ErrSharedNodeOnly):
		status, code = http.StatusConflict, "shared_node_host_firewall_unsupported"
	case errors.Is(err, firewallcontrol.ErrOutcomeUnknown):
		status, code = http.StatusAccepted, "outcome_unknown"
	}
	writeJSON(response, status, map[string]any{"code": code})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
