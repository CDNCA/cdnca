package pluginwebhookhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookcontrol"
	"github.com/google/uuid"
)

var (
	ErrValidation           = errors.New("plugin webhook HTTP validation failed")
	ErrAuthentication       = errors.New("plugin webhook authentication required")
	ErrPreconditionRequired = errors.New("plugin webhook precondition required")
	ErrRevisionConflict     = errors.New("plugin webhook revision conflict")
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

const maxRequestBody = 16 << 10

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type Dependencies struct {
	AuthenticateSession AuthenticateSessionFunc
	Store               pluginwebhookcontrol.Domain
}

type Handler struct {
	authenticate AuthenticateSessionFunc
	store        pluginwebhookcontrol.Domain
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id"`
	Params    map[string]any `json:"params"`
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.AuthenticateSession == nil || dependencies.Store == nil {
		return nil, pluginwebhookcontrol.ErrInvalidConfig
	}
	return &Handler{authenticate: dependencies.AuthenticateSession, store: dependencies.Store}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if !prepareRequestID(response, request) {
		writeError(response, http.StatusBadRequest, "plugin_webhook_validation_error", nil)
		return
	}
	route := matchRoute(request.Method, request.URL.Path)
	if !route.matched {
		writeError(response, http.StatusNotFound, "plugin_webhook_not_found", nil)
		return
	}
	rawSession, err := strictBearer(request)
	if err != nil {
		writeError(response, http.StatusUnauthorized, "authentication_required", nil)
		return
	}
	session, err := handler.authenticate(request.Context(), rawSession)
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil ||
		session.Principal.ScopeID == uuid.Nil ||
		(session.Principal.ScopeKind != pluginwebhookcontrol.ScopeTenant && session.Principal.ScopeKind != pluginwebhookcontrol.ScopePlatform) {
		writeError(response, http.StatusUnauthorized, "authentication_required", nil)
		return
	}
	actor, err := pluginwebhookcontrol.NewActor(session.Principal.UserID, session.Principal.ScopeID,
		route.targetScopeID, session.Principal.ScopeKind, rawSession)
	if err != nil {
		writeError(response, http.StatusForbidden, "permission_denied", nil)
		return
	}
	handler.dispatch(response, request, route, actor)
}

type routeMatch struct {
	matched        bool
	targetScopeID  uuid.UUID
	subscriptionID uuid.UUID
	deliveryID     uuid.UUID
	rotationID     uuid.UUID
	action         string
}

func matchRoute(method, path string) routeMatch {
	if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return routeMatch{}
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "tenant-scopes" || parts[3] != "plugin-webhook-subscriptions" {
		return routeMatch{}
	}
	target, err := strictUUID(parts[2])
	if err != nil {
		return routeMatch{}
	}
	result := routeMatch{targetScopeID: target}
	if len(parts) == 4 && (method == http.MethodGet || method == http.MethodPost) {
		result.matched, result.action = true, map[bool]string{true: "subscriptions.list", false: "subscriptions.create"}[method == http.MethodGet]
		return result
	}
	if len(parts) < 5 {
		return routeMatch{}
	}
	result.subscriptionID, err = strictUUID(parts[4])
	if err != nil {
		return routeMatch{}
	}
	switch {
	case len(parts) == 5 && method == http.MethodGet:
		result.matched, result.action = true, "subscriptions.get"
	case len(parts) == 6 && parts[5] == "test-deliveries" && method == http.MethodPost:
		result.matched, result.action = true, "deliveries.test"
	case len(parts) == 6 && parts[5] == "deliveries" && method == http.MethodGet:
		result.matched, result.action = true, "deliveries.list"
	case len(parts) == 7 && parts[5] == "deliveries" && method == http.MethodGet:
		result.deliveryID, err = strictUUID(parts[6])
		result.matched, result.action = err == nil, "deliveries.get"
	case len(parts) == 8 && parts[5] == "deliveries" && parts[7] == "replays" && method == http.MethodPost:
		result.deliveryID, err = strictUUID(parts[6])
		result.matched, result.action = err == nil, "deliveries.replay"
	case len(parts) == 6 && parts[5] == "delivery-replays" && method == http.MethodPost:
		result.matched, result.action = true, "deliveries.replay_range"
	case len(parts) == 6 && parts[5] == "secret-rotations" && method == http.MethodPost:
		result.matched, result.action = true, "secrets.rotate"
	case len(parts) == 8 && parts[5] == "secret-rotations" && parts[7] == "activate" && method == http.MethodPost:
		result.rotationID, err = strictUUID(parts[6])
		result.matched, result.action = err == nil, "secrets.activate"
	case len(parts) == 6 && parts[5] == "revoke" && method == http.MethodPost:
		result.matched, result.action = true, "subscriptions.revoke"
	}
	return result
}

func (handler *Handler) dispatch(response http.ResponseWriter, request *http.Request, route routeMatch, actor pluginwebhookcontrol.Actor) {
	if request.URL.RawPath != "" || !onlyQuery(request.URL.Query(), route.action == "subscriptions.list" || route.action == "deliveries.list") {
		writeError(response, http.StatusBadRequest, "plugin_webhook_validation_error", nil)
		return
	}
	switch route.action {
	case "subscriptions.list":
		query, err := listQuery(request.URL.Query())
		if err != nil {
			writeDomainError(response, err)
			return
		}
		value, err := handler.store.ListSubscriptions(request.Context(), actor, query)
		writeValue(response, http.StatusOK, value, err, 0)
	case "subscriptions.create":
		key, err := writeHeaders(request, false)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		var body createSubscriptionBody
		if err := decodeJSONObject(request, &body); err != nil || !validName(body.Name) {
			writeDomainError(response, ErrValidation)
			return
		}
		eventTypes, validEvents := pluginwebhookcontrol.NormalizeEventTypes(body.EventTypes)
		if !validEvents {
			writeDomainError(response, ErrValidation)
			return
		}
		var installationAuthorizationID *uuid.UUID
		if body.InstallationAuthorizationID != nil {
			parsed, parseErr := strictUUID(*body.InstallationAuthorizationID)
			if parseErr != nil {
				writeDomainError(response, ErrValidation)
				return
			}
			installationAuthorizationID = &parsed
		}
		var siteIDs []uuid.UUID
		if body.SiteIDs != nil {
			siteIDs = make([]uuid.UUID, 0, len(*body.SiteIDs))
			for _, raw := range *body.SiteIDs {
				parsed, parseErr := strictUUID(raw)
				if parseErr != nil {
					writeDomainError(response, ErrValidation)
					return
				}
				siteIDs = append(siteIDs, parsed)
			}
		}
		value, err := handler.store.CreateSubscription(request.Context(), actor, pluginwebhookcontrol.CreateSubscriptionRequest{Name: body.Name, TargetURL: body.TargetURL, EventTypes: eventTypes, InstallationAuthorizationID: installationAuthorizationID, SiteIDs: siteIDs, IdempotencyKey: key})
		writeValue(response, http.StatusCreated, value.Value, err, value.Value.Subscription.Revision)
	case "subscriptions.get":
		value, err := handler.store.GetSubscription(request.Context(), actor, route.subscriptionID)
		writeValue(response, http.StatusOK, value, err, value.Revision)
	case "deliveries.test":
		handler.emptyWrite(response, request, false, func(key string, _ uint64) (any, error) {
			result, err := handler.store.CreateTestDelivery(request.Context(), actor, route.subscriptionID, pluginwebhookcontrol.WriteRequest{IdempotencyKey: key})
			return result.Value, err
		}, http.StatusAccepted)
	case "deliveries.list":
		query, err := listQuery(request.URL.Query())
		if err != nil {
			writeDomainError(response, err)
			return
		}
		value, err := handler.store.ListDeliveries(request.Context(), actor, route.subscriptionID, query)
		writeValue(response, http.StatusOK, value, err, 0)
	case "deliveries.get":
		value, err := handler.store.GetDelivery(request.Context(), actor, route.subscriptionID, route.deliveryID)
		writeValue(response, http.StatusOK, value, err, 0)
	case "deliveries.replay":
		handler.emptyWrite(response, request, false, func(key string, _ uint64) (any, error) {
			result, err := handler.store.ReplayDelivery(request.Context(), actor, route.subscriptionID, route.deliveryID, pluginwebhookcontrol.WriteRequest{IdempotencyKey: key})
			return result.Value, err
		}, http.StatusAccepted)
	case "deliveries.replay_range":
		key, err := writeHeaders(request, false)
		if err != nil {
			writeDomainError(response, err)
			return
		}
		var body replayRangeBody
		if err := decodeJSONObject(request, &body); err != nil {
			writeDomainError(response, ErrValidation)
			return
		}
		from, fromErr := time.Parse(time.RFC3339, body.From)
		to, toErr := time.Parse(time.RFC3339, body.To)
		if fromErr != nil || toErr != nil || body.Limit == nil {
			writeDomainError(response, ErrValidation)
			return
		}
		value, err := handler.store.ReplayRange(request.Context(), actor, route.subscriptionID, pluginwebhookcontrol.ReplayRangeRequest{
			From: from, To: to, Statuses: body.Statuses, EventTypes: body.EventTypes, Limit: *body.Limit, IdempotencyKey: key,
		})
		writeValue(response, http.StatusAccepted, value, err, 0)
	case "secrets.rotate":
		handler.emptyWrite(response, request, true, func(key string, revision uint64) (any, error) {
			result, err := handler.store.RotateSecret(request.Context(), actor, route.subscriptionID, pluginwebhookcontrol.WriteRequest{IdempotencyKey: key, Revision: revision})
			return result.Value, err
		}, http.StatusCreated)
	case "secrets.activate":
		handler.emptyWrite(response, request, true, func(key string, revision uint64) (any, error) {
			result, err := handler.store.ActivateSecret(request.Context(), actor, route.subscriptionID, route.rotationID, pluginwebhookcontrol.WriteRequest{IdempotencyKey: key, Revision: revision})
			return result.Value, err
		}, http.StatusOK)
	case "subscriptions.revoke":
		handler.emptyWrite(response, request, true, func(key string, revision uint64) (any, error) {
			result, err := handler.store.RevokeSubscription(request.Context(), actor, route.subscriptionID, pluginwebhookcontrol.WriteRequest{IdempotencyKey: key, Revision: revision})
			return result.Value, err
		}, http.StatusOK)
	}
}

type createSubscriptionBody struct {
	Name                        string    `json:"name"`
	TargetURL                   string    `json:"target_url"`
	EventTypes                  []string  `json:"event_types"`
	InstallationAuthorizationID *string   `json:"installation_authorization_id"`
	SiteIDs                     *[]string `json:"site_ids"`
}

type replayRangeBody struct {
	From       string   `json:"from"`
	To         string   `json:"to"`
	Statuses   []string `json:"statuses"`
	EventTypes []string `json:"event_types"`
	Limit      *int     `json:"limit"`
}

func (handler *Handler) emptyWrite(response http.ResponseWriter, request *http.Request, revisionRequired bool, invoke func(string, uint64) (any, error), status int) {
	key, err := writeHeaders(request, revisionRequired)
	if err != nil {
		writeDomainError(response, err)
		return
	}
	if err := decodeEmptyObject(request); err != nil {
		writeDomainError(response, err)
		return
	}
	revision := uint64(0)
	if revisionRequired {
		revision, err = parseIfMatch(request.Header.Get("If-Match"))
		if err != nil {
			writeDomainError(response, err)
			return
		}
	}
	value, err := invoke(key, revision)
	writeValue(response, status, value, err, subscriptionRevision(value))
}

func strictBearer(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", ErrAuthentication
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || len(token) >= 8192 || strings.ContainsFunc(token, unicode.IsSpace) {
		return "", ErrAuthentication
	}
	return token, nil
}

func writeHeaders(request *http.Request, revision bool) (string, error) {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json" {
		return "", ErrValidation
	}
	keys := request.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		return "", errors.New("idempotency_key_required")
	}
	key := keys[0]
	if !idempotencyKeyPattern.MatchString(key) {
		return "", errors.New("idempotency_key_required")
	}
	if revision {
		values := request.Header.Values("If-Match")
		if len(values) == 0 {
			return "", ErrPreconditionRequired
		}
		if len(values) != 1 {
			return "", ErrRevisionConflict
		}
		if _, err := parseIfMatch(values[0]); err != nil {
			return "", err
		}
	}
	return key, nil
}

func parseIfMatch(value string) (uint64, error) {
	if value == "" {
		return 0, ErrPreconditionRequired
	}
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' || strings.Contains(value, ",") {
		return 0, ErrRevisionConflict
	}
	raw := value[1 : len(value)-1]
	if raw == "" || raw == "0" || len(raw) > 1 && raw[0] == '0' {
		return 0, ErrRevisionConflict
	}
	for _, current := range raw {
		if current < '0' || current > '9' {
			return 0, ErrRevisionConflict
		}
	}
	result, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || result == 0 {
		return 0, ErrRevisionConflict
	}
	return result, nil
}

func decodeEmptyObject(request *http.Request) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return ErrValidation
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 3))
	if err != nil || !bytes.Equal(body, []byte("{}")) {
		return ErrValidation
	}
	return nil
}

func decodeJSONObject(request *http.Request, output any) error {
	mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(params) != 0 {
		return ErrValidation
	}
	limited := &io.LimitedReader{R: request.Body, N: maxRequestBody + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return ErrValidation
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrValidation
	}
	if limited.N == 0 {
		return ErrValidation
	}
	return nil
}

func listQuery(values url.Values) (pluginwebhookcontrol.ListQuery, error) {
	if !onlyQuery(values, true) {
		return pluginwebhookcontrol.ListQuery{}, ErrValidation
	}
	limit := 50
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return pluginwebhookcontrol.ListQuery{}, ErrValidation
		}
		limit = parsed
	}
	cursor := values.Get("cursor")
	if len(cursor) > 1024 || strings.ContainsFunc(cursor, unicode.IsControl) {
		return pluginwebhookcontrol.ListQuery{}, ErrValidation
	}
	return pluginwebhookcontrol.ListQuery{Cursor: cursor, Limit: limit}, nil
}

func onlyQuery(values url.Values, list bool) bool {
	if !list {
		return len(values) == 0
	}
	for key, entries := range values {
		if key != "cursor" && key != "limit" || len(entries) != 1 {
			return false
		}
	}
	return true
}

func validName(name string) bool {
	return name == strings.TrimSpace(name) && utf8.ValidString(name) && len([]rune(name)) >= 1 && len([]rune(name)) <= 128 && !strings.ContainsFunc(name, unicode.IsControl)
}

func strictUUID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || id.String() != strings.ToLower(raw) {
		return uuid.Nil, ErrValidation
	}
	return id, nil
}

func subscriptionRevision(value any) uint64 {
	switch current := value.(type) {
	case pluginwebhookcontrol.SubscriptionResult:
		return current.Subscription.Revision
	case pluginwebhookcontrol.SubscriptionReceipt:
		return current.Subscription.Revision
	case pluginwebhookcontrol.RotationReceipt:
		return current.SubscriptionRevision
	}
	return 0
}

func writeValue(response http.ResponseWriter, status int, value any, err error, revision uint64) {
	if err != nil {
		writeDomainError(response, err)
		return
	}
	if revision > 0 {
		response.Header().Set("ETag", `"`+strconv.FormatUint(revision, 10)+`"`)
	}
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeDomainError(response http.ResponseWriter, err error) {
	status, code, params := http.StatusServiceUnavailable, "plugin_webhook_store_unavailable", map[string]any{}
	switch {
	case errors.Is(err, ErrAuthentication):
		status, code = 401, "authentication_required"
	case errors.Is(err, pluginwebhookcontrol.ErrPermissionDenied):
		status, code = 403, "permission_denied"
	case errors.Is(err, pluginwebhookcontrol.ErrNotFound):
		status, code = 404, "plugin_webhook_not_found"
	case err != nil && err.Error() == "idempotency_key_required":
		status, code = 400, "idempotency_key_required"
	case errors.Is(err, ErrValidation), errors.Is(err, pluginwebhookcontrol.ErrInvalidInput):
		status, code = 400, "plugin_webhook_validation_error"
	case errors.Is(err, pluginwebhookcontrol.ErrIdempotencyConflict):
		status, code = 409, "idempotency_conflict"
	case errors.Is(err, pluginwebhookcontrol.ErrIdempotencyExpired):
		status, code = 409, "idempotency_expired"
	case errors.Is(err, pluginwebhookcontrol.ErrStateConflict):
		status, code = 409, "plugin_webhook_state_conflict"
	case errors.Is(err, pluginwebhookcontrol.ErrDeliveryNotReplayable):
		status, code = 409, "plugin_webhook_delivery_not_replayable"
	case errors.Is(err, pluginwebhookcontrol.ErrRotationPending):
		status, code = 409, "plugin_webhook_rotation_pending"
	case errors.Is(err, ErrPreconditionRequired):
		status, code = 428, "precondition_required"
	case errors.Is(err, ErrRevisionConflict), errors.Is(err, pluginwebhookcontrol.ErrRevisionConflict):
		status, code = 412, "revision_conflict"
	case errors.Is(err, pluginwebhookcontrol.ErrTargetForbidden):
		status, code = 422, "plugin_webhook_target_forbidden"
	case errors.Is(err, pluginwebhookcontrol.ErrEntitlementDenied):
		status, code = 422, "plugin_webhook_entitlement_denied"
	case errors.Is(err, pluginwebhookcontrol.ErrQuotaExceeded):
		status, code = 422, "plugin_webhook_quota_exceeded"
	case errors.Is(err, pluginwebhookcontrol.ErrRateLimited):
		status, code = 429, "plugin_webhook_rate_limited"
		var rate pluginwebhookcontrol.RateLimitError
		if errors.As(err, &rate) {
			seconds := int(rate.RetryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			response.Header().Set("Retry-After", strconv.Itoa(seconds))
			params["retry_after_seconds"] = seconds
		}
	case errors.Is(err, pluginwebhookcontrol.ErrSecretUnavailable):
		status, code = 503, "plugin_webhook_secret_unavailable"
	case errors.Is(err, pluginwebhookcontrol.ErrResultUnknown):
		status, code = 503, "plugin_webhook_result_unknown"
	}
	writeError(response, status, code, params)
}

func writeError(response http.ResponseWriter, status int, code string, params map[string]any) {
	if params == nil {
		params = map[string]any{}
	}
	requestID := response.Header().Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
		response.Header().Set("X-Request-ID", requestID)
	}
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(errorEnvelope{Error: apiError{
		Code: code, Message: "request failed", RequestID: requestID, Params: params,
	}})
}

func prepareRequestID(response http.ResponseWriter, request *http.Request) bool {
	values := request.Header.Values("X-Request-ID")
	requestID := uuid.NewString()
	valid := len(values) == 0
	if len(values) == 1 && requestIDPattern.MatchString(values[0]) {
		requestID, valid = values[0], true
	}
	request.Header.Set("X-Request-ID", requestID)
	response.Header().Set("X-Request-ID", requestID)
	return valid
}
