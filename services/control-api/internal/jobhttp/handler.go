package jobhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultQueryTimeout     = 6 * time.Second
	maximumQueryTimeout     = 30 * time.Second
	defaultResponseSize     = 1 << 20
	maximumResponseSize     = 4 << 20
	maximumCommandBodyBytes = 1024
)

type AuthenticateFunc func(*http.Request) (Principal, error)

type HandlerConfig struct {
	QueryTimeout     time.Duration
	MaxResponseBytes int
	Logger           *slog.Logger
}

type Handler struct {
	service          *Service
	authenticate     AuthenticateFunc
	queryTimeout     time.Duration
	maxResponseBytes int
	logger           *slog.Logger
}

type routeOperation string

const (
	operationList        routeOperation = "list"
	operationKinds       routeOperation = "kinds"
	operationDetail      routeOperation = "detail"
	operationAttempts    routeOperation = "attempts"
	operationResults     routeOperation = "results"
	operationReceipts    routeOperation = "receipts"
	operationDeadLetters routeOperation = "dead-letters"
	operationCancel      routeOperation = "cancel"
	operationRetry       routeOperation = "retry"
	operationReplay      routeOperation = "replay"
)

type handlerRoute struct {
	audience  Audience
	operation routeOperation
	taskID    uuid.UUID
}

type requestIDContextKey struct{}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func NewHandler(service *Service, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidRequest
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultResponseSize
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > maximumQueryTimeout ||
		config.MaxResponseBytes < 512 || config.MaxResponseBytes > maximumResponseSize {
		return nil, ErrInvalidRequest
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Handler{
		service: service, authenticate: authenticate, queryTimeout: config.QueryTimeout,
		maxResponseBytes: config.MaxResponseBytes, logger: config.Logger,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := requestIDFromContext(request.Context())
	if requestID == "" && requestIDPattern.MatchString(request.Header.Get("X-Request-ID")) {
		requestID = request.Header.Get("X-Request-ID")
	}
	if requestID == "" {
		requestID = newRequestID()
	}
	request = request.WithContext(withRequestID(request.Context(), requestID))
	writer.Header().Set("X-Request-ID", requestID)
	writer.Header().Set("Cache-Control", "no-store")

	if request.URL.RawPath != "" {
		handler.writeError(writer, request, http.StatusNotFound, "job_route_not_found", "job route was not found")
		return
	}
	route, ok := resolveRoute(request.URL.Path)
	if !ok {
		handler.writeError(writer, request, http.StatusNotFound, "job_route_not_found", "job route was not found")
		return
	}
	requiredMethod := http.MethodGet
	if route.operation == operationCancel || route.operation == operationRetry || route.operation == operationReplay {
		requiredMethod = http.MethodPost
	}
	if request.Method != requiredMethod {
		writer.Header().Set("Allow", requiredMethod)
		handler.writeError(writer, request, http.StatusMethodNotAllowed, "job_method_not_allowed", "job route uses a different method")
		return
	}
	principal, err := handler.authenticate(request)
	if err != nil {
		handler.writeError(writer, request, http.StatusUnauthorized, "job_authentication_required", "authentication is required")
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	switch route.operation {
	case operationKinds:
		if _, err := strictQuery(request, nil); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.Kinds(ctx, principal, route.audience)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		handler.writeResult(writer, request, result)
	case operationList:
		query, err := parseListRequest(request, route.audience)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.List(ctx, principal, query)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		handler.writeResult(writer, request, result)
	case operationDetail:
		if _, err := strictQuery(request, nil); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.Get(ctx, principal, route.audience, route.taskID)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		writer.Header().Set("ETag", `"`+result.Revision+`"`)
		handler.writeResult(writer, request, struct {
			Data Job `json:"data"`
		}{Data: result})
	case operationAttempts, operationResults, operationReceipts, operationDeadLetters:
		query, err := parseChildRequest(request, route)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		if route.operation == operationAttempts {
			result, err := handler.service.Attempts(ctx, principal, query)
			if err != nil {
				handler.writeServiceError(writer, request, err)
				return
			}
			handler.writeResult(writer, request, result)
			return
		}
		if route.operation == operationReceipts {
			result, err := handler.service.Receipts(ctx, principal, query)
			if err != nil {
				handler.writeServiceError(writer, request, err)
				return
			}
			handler.writeResult(writer, request, result)
			return
		}
		if route.operation == operationDeadLetters {
			result, err := handler.service.DeadLetters(ctx, principal, query)
			if err != nil {
				handler.writeServiceError(writer, request, err)
				return
			}
			handler.writeResult(writer, request, result)
			return
		}
		result, err := handler.service.Results(ctx, principal, query)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		handler.writeResult(writer, request, result)
	case operationCancel, operationRetry, operationReplay:
		input, err := parseCommandRequest(writer, request, route)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.Command(ctx, principal, input)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		handler.writeCommandResult(writer, request, result)
	}
}

func resolveRoute(path string) (handlerRoute, bool) {
	for _, candidate := range []struct {
		base     string
		audience Audience
	}{
		{base: "/v1/admin/jobs", audience: AudiencePlatform},
		{base: "/v1/jobs", audience: AudienceTenant},
	} {
		if path == candidate.base {
			return handlerRoute{audience: candidate.audience, operation: operationList}, true
		}
		if path == candidate.base+"/kinds" {
			return handlerRoute{audience: candidate.audience, operation: operationKinds}, true
		}
		suffix, ok := strings.CutPrefix(path, candidate.base+"/")
		if !ok || suffix == "" {
			continue
		}
		segments := strings.Split(suffix, "/")
		if len(segments) < 1 || len(segments) > 2 {
			return handlerRoute{}, false
		}
		taskID, _ := parseCanonicalUUID(segments[0])
		if len(segments) == 1 {
			return handlerRoute{audience: candidate.audience, operation: operationDetail, taskID: taskID}, true
		}
		switch segments[1] {
		case "attempts":
			return handlerRoute{audience: candidate.audience, operation: operationAttempts, taskID: taskID}, true
		case "results":
			return handlerRoute{audience: candidate.audience, operation: operationResults, taskID: taskID}, true
		case "receipts":
			return handlerRoute{audience: candidate.audience, operation: operationReceipts, taskID: taskID}, true
		case "dead-letters":
			return handlerRoute{audience: candidate.audience, operation: operationDeadLetters, taskID: taskID}, true
		case "cancel":
			return handlerRoute{audience: candidate.audience, operation: operationCancel, taskID: taskID}, true
		case "retry":
			return handlerRoute{audience: candidate.audience, operation: operationRetry, taskID: taskID}, true
		case "replay":
			if candidate.audience != AudiencePlatform {
				return handlerRoute{}, false
			}
			return handlerRoute{audience: candidate.audience, operation: operationReplay, taskID: taskID}, true
		default:
			return handlerRoute{}, false
		}
	}
	return handlerRoute{}, false
}

func parseCommandRequest(
	writer http.ResponseWriter,
	request *http.Request,
	route handlerRoute,
) (CommandRequest, error) {
	if request.URL.RawQuery != "" || request.URL.ForceQuery || route.taskID == uuid.Nil {
		return CommandRequest{}, ErrInvalidRequest
	}
	contentTypes := request.Header.Values("Content-Type")
	idempotencyKeys := request.Header.Values("Idempotency-Key")
	revisions := request.Header.Values("If-Match")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json" ||
		len(idempotencyKeys) != 1 || !idempotencyKeyPattern.MatchString(idempotencyKeys[0]) || len(revisions) != 1 {
		return CommandRequest{}, ErrInvalidRequest
	}
	revision, err := parseJobRevision(revisions[0])
	if err != nil {
		return CommandRequest{}, err
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumCommandBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.UseNumber()
	var body map[string]json.RawMessage
	if err := decoder.Decode(&body); err != nil || body == nil || len(body) != 0 {
		return CommandRequest{}, ErrInvalidRequest
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return CommandRequest{}, ErrInvalidRequest
	}
	operation := CommandCancel
	if route.operation == operationRetry {
		operation = CommandRetry
	} else if route.operation == operationReplay {
		operation = CommandReplay
	}
	return CommandRequest{
		Audience: route.audience, TaskID: route.taskID,
		Operation: operation, IdempotencyKey: idempotencyKeys[0], ExpectedRevision: revision,
	}, nil
}

func parseJobRevision(value string) (string, error) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' || strings.HasPrefix(value, "W/") {
		return "", ErrInvalidRequest
	}
	revision := value[1 : len(value)-1]
	if !jobRevisionPattern.MatchString(revision) {
		return "", ErrInvalidRequest
	}
	return revision, nil
}

func parseListRequest(request *http.Request, audience Audience) (ListRequest, error) {
	allowed := map[string]bool{
		"status": true, "kind": true, "resource": true, "tenant_id": true, "task_id": true,
		"from": true, "to": true, "limit": true, "cursor": true, "page": true,
	}
	query, err := strictQuery(request, allowed)
	if err != nil {
		return ListRequest{}, err
	}
	from, err := time.Parse(time.RFC3339, query.Get("from"))
	if err != nil {
		return ListRequest{}, ErrInvalidRequest
	}
	to, err := time.Parse(time.RFC3339, query.Get("to"))
	if err != nil {
		return ListRequest{}, ErrInvalidRequest
	}
	limit, err := parseLimit(query.Get("limit"))
	if err != nil {
		return ListRequest{}, err
	}
	result := ListRequest{
		Audience: audience, Kind: query.Get("kind"), Resource: query.Get("resource"),
		From: from, To: to, Limit: limit, Cursor: query.Get("cursor"),
	}
	if query.Has("page") {
		raw := query.Get("page")
		page, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || page < 1 || page > maximumPageNumber || strconv.FormatUint(page, 10) != raw || query.Has("cursor") {
			return ListRequest{}, ErrInvalidRequest
		}
		result.Page = int(page)
	}
	if raw := query.Get("task_id"); raw != "" {
		taskID, err := parseCanonicalUUID(raw)
		if err != nil {
			return ListRequest{}, ErrInvalidRequest
		}
		result.TaskID = &taskID
	}
	if raw := query.Get("tenant_id"); raw != "" {
		tenantID, err := parseCanonicalUUID(raw)
		if err != nil {
			return ListRequest{}, ErrInvalidRequest
		}
		result.TenantID = &tenantID
	}
	if raw := query.Get("status"); raw != "" {
		parts := strings.Split(raw, ",")
		result.States = make([]State, len(parts))
		for index, part := range parts {
			if part == "" {
				return ListRequest{}, ErrInvalidRequest
			}
			result.States[index] = State(part)
		}
	}
	return result, nil
}

func parseChildRequest(request *http.Request, route handlerRoute) (ChildPageRequest, error) {
	query, err := strictQuery(request, map[string]bool{"limit": true, "cursor": true})
	if err != nil {
		return ChildPageRequest{}, err
	}
	limit, err := parseLimit(query.Get("limit"))
	if err != nil {
		return ChildPageRequest{}, err
	}
	return ChildPageRequest{
		Audience: route.audience, TaskID: route.taskID, Limit: limit, Cursor: query.Get("cursor"),
	}, nil
}

func strictQuery(request *http.Request, allowed map[string]bool) (url.Values, error) {
	if request.URL.ForceQuery || allowed == nil && request.URL.RawQuery != "" {
		return nil, ErrInvalidRequest
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return nil, ErrInvalidRequest
		}
	}
	return query, nil
}

func parseLimit(raw string) (int, error) {
	if raw == "" {
		return defaultPageLimit, nil
	}
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || value < 1 || value > maximumPageLimit {
		return 0, ErrInvalidRequest
	}
	return int(value), nil
}

func parseCanonicalUUID(raw string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidRequest
	}
	return value, nil
}

func (handler *Handler) writeResult(writer http.ResponseWriter, request *http.Request, value any) {
	handler.writeResultWithLimit(writer, request, value, handler.maxResponseBytes)
}

func (handler *Handler) writeCommandResult(writer http.ResponseWriter, request *http.Request, value CommandResult) {
	writer.Header().Set("ETag", `"`+value.Data.Revision+`"`)
	handler.writeResultWithLimit(writer, request, value, maximumResponseSize)
}

func (handler *Handler) writeResultWithLimit(
	writer http.ResponseWriter,
	request *http.Request,
	value any,
	limit int,
) {
	encoded, err := json.Marshal(value)
	if err != nil {
		handler.writeServiceError(writer, request, ErrInvalidStoreResponse)
		return
	}
	if len(encoded)+1 > limit {
		handler.writeServiceError(writer, request, ErrResponseTooLarge)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(append(encoded, '\n'))
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message := publicError(err)
	if status >= 500 {
		handler.logger.ErrorContext(request.Context(), "job query failed",
			"request_id", requestIDFromContext(request.Context()), "code", code, "path", request.URL.Path)
	}
	handler.writeError(writer, request, status, code, message)
}

func (handler *Handler) writeError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	encoded, _ := json.Marshal(errorEnvelope{Error: apiError{
		Code: code, Message: message, RequestID: requestIDFromContext(request.Context()),
	}})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func publicError(err error) (int, string, string) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusBadRequest, "job_invalid_request", "job query parameters are invalid"
	case errors.Is(err, ErrPermissionDenied):
		return http.StatusForbidden, "job_permission_denied", "job read permission is required"
	case errors.Is(err, ErrScopeForbidden):
		return http.StatusForbidden, "job_scope_forbidden", "job scope is not available to this identity"
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "job_not_found", "job was not found"
	case errors.Is(err, ErrIdempotencyConflict):
		return http.StatusConflict, "job_idempotency_conflict", "idempotency key conflicts with another job command"
	case errors.Is(err, ErrInvalidTransition):
		return http.StatusConflict, "job_invalid_transition", "job cannot perform the requested transition"
	case errors.Is(err, ErrRetriesExhausted):
		return http.StatusConflict, "job_retries_exhausted", "job retry attempts are exhausted"
	case errors.Is(err, ErrProducerCommand):
		return http.StatusConflict, "job_producer_command_required", "this job is cancelled or retried from its own page"
	case errors.Is(err, ErrRevisionConflict):
		return http.StatusPreconditionFailed, "job_revision_conflict", "job revision changed; refresh before retrying"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout, "job_request_cancelled", "job query request was cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "job_query_timeout", "job query timed out"
	case errors.Is(err, ErrStoreUnavailable):
		return http.StatusServiceUnavailable, "job_store_unavailable", "job storage is unavailable"
	case errors.Is(err, ErrInvalidStoreResponse):
		return http.StatusBadGateway, "job_store_invalid_response", "job storage returned invalid facts"
	case errors.Is(err, ErrResponseTooLarge):
		return http.StatusBadGateway, "job_response_too_large", "job query response exceeded its limit"
	default:
		return http.StatusInternalServerError, "job_internal_error", "job query could not be completed"
	}
}

func withRequestID(ctx context.Context, requestID string) context.Context {
	if !requestIDPattern.MatchString(requestID) {
		return ctx
	}
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDContextKey{}).(string)
	if !requestIDPattern.MatchString(requestID) {
		return ""
	}
	return requestID
}

func newRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err == nil {
		return hex.EncodeToString(raw)
	}
	return "job-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
}
