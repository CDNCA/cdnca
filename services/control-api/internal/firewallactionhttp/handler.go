package firewallactionhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallactioncontrol"
	"github.com/google/uuid"
)

type API interface {
	Put(context.Context, firewallactioncontrol.PutRequest) (firewallactioncontrol.WriteResult, error)
	Get(context.Context, firewallactioncontrol.ReadRequest) (firewallactioncontrol.Policy, error)
	Recover(context.Context, firewallactioncontrol.RecoverRequest) (firewallactioncontrol.WriteResult, error)
}

type Authenticator func(*http.Request) (firewallactioncontrol.Actor, error)

type Handler struct {
	api          API
	authenticate Authenticator
}

func NewHandler(api API, authenticate Authenticator) (*Handler, error) {
	if api == nil || authenticate == nil {
		return nil, errors.New("invalid firewall action HTTP dependencies")
	}
	return &Handler{api: api, authenticate: authenticate}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	actor, err := handler.authenticate(request)
	if err != nil {
		writeError(response, err)
		return
	}
	targetScopeID, siteID, err := parseTarget(request)
	if err != nil {
		writeError(response, err)
		return
	}
	switch {
	case request.URL.Path == "/v1/firewall-actions/policy" && request.Method == http.MethodGet:
		policy, err := handler.api.Get(request.Context(), firewallactioncontrol.ReadRequest{Actor: actor, TargetScopeID: targetScopeID, SiteID: siteID})
		if err != nil {
			writeError(response, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(policy.Revision))
		writeJSON(response, http.StatusOK, policy)
	case request.URL.Path == "/v1/firewall-actions/policy" && request.Method == http.MethodPut:
		expected, err := parseETag(request.Header.Get("If-Match"), true)
		if err != nil {
			writeError(response, firewallactioncontrol.ErrInvalidInput)
			return
		}
		var input firewallactioncontrol.PolicyInput
		if err := decodeBody(response, request, &input); err != nil {
			writeError(response, firewallactioncontrol.ErrInvalidInput)
			return
		}
		result, err := handler.api.Put(request.Context(), firewallactioncontrol.PutRequest{
			Actor: actor, TargetScopeID: targetScopeID, SiteID: siteID, ExpectedRevision: expected,
			IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"), Policy: input,
		})
		if err != nil {
			writeError(response, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Policy.Revision))
		if result.Replayed {
			response.Header().Set("Idempotent-Replay", "true")
		}
		writeJSON(response, http.StatusOK, result.Policy)
	case request.URL.Path == "/v1/firewall-actions/policy/recover" && request.Method == http.MethodPost:
		expected, err := parseETag(request.Header.Get("If-Match"), false)
		if err != nil {
			writeError(response, firewallactioncontrol.ErrInvalidInput)
			return
		}
		var body struct{}
		if err := decodeBody(response, request, &body); err != nil {
			writeError(response, firewallactioncontrol.ErrInvalidInput)
			return
		}
		result, err := handler.api.Recover(request.Context(), firewallactioncontrol.RecoverRequest{
			Actor: actor, TargetScopeID: targetScopeID, SiteID: siteID, ExpectedRevision: expected,
			IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeError(response, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Policy.Revision))
		if result.Replayed {
			response.Header().Set("Idempotent-Replay", "true")
		}
		writeJSON(response, http.StatusOK, result.Policy)
	default:
		writeJSON(response, http.StatusNotFound, map[string]string{"code": "not_found"})
	}
}

func parseTarget(request *http.Request) (uuid.UUID, uuid.UUID, error) {
	query := request.URL.Query()
	if len(query) != 2 || len(query["target_scope_id"]) != 1 || len(query["site_id"]) != 1 {
		return uuid.Nil, uuid.Nil, firewallactioncontrol.ErrInvalidInput
	}
	scope, err := strictUUID(query.Get("target_scope_id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	site, err := strictUUID(query.Get("site_id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return scope, site, nil
}

func strictUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, firewallactioncontrol.ErrInvalidInput
	}
	return parsed, nil
}

func decodeBody(response http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(response, request.Body, 64<<10)
	decoder := json.NewDecoder(request.Body)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if len(raw) == 0 || raw[0] != '{' {
		return errors.New("request body must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON document")
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(target); err != nil {
		return err
	}
	if err := strict.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON document")
	}
	return nil
}

func parseETag(value string, allowZero bool) (int64, error) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' || strings.TrimSpace(value) != value {
		return 0, errors.New("invalid ETag")
	}
	parsed, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || parsed < 0 || !allowZero && parsed == 0 || parsed > 1<<53-1 {
		return 0, errors.New("invalid ETag")
	}
	return parsed, nil
}

func quoteRevision(revision int64) string { return fmt.Sprintf(`"%d"`, revision) }

func writeError(response http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "firewall_action_unavailable"
	switch {
	case errors.Is(err, firewallactioncontrol.ErrUnauthenticated):
		status, code = http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, firewallactioncontrol.ErrPermissionDenied):
		status, code = http.StatusForbidden, "permission_denied"
	case errors.Is(err, firewallactioncontrol.ErrNotFound):
		status, code = http.StatusNotFound, "firewall_action_not_found"
	case errors.Is(err, firewallactioncontrol.ErrNoLKG):
		status, code = http.StatusConflict, "firewall_action_lkg_unavailable"
	case errors.Is(err, firewallactioncontrol.ErrInvalidInput):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, firewallactioncontrol.ErrRevisionConflict):
		status, code = http.StatusConflict, "revision_conflict"
	case errors.Is(err, firewallactioncontrol.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "idempotency_conflict"
	}
	writeJSON(response, status, map[string]string{"code": code})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
