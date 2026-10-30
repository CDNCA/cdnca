package rbacmanagerhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
)

const (
	defaultCommandTimeout       = 15 * time.Second
	defaultQueryTimeout         = 6 * time.Second
	maximumHandlerTimeout       = 30 * time.Second
	defaultRequestBytes   int64 = 64 << 10
	defaultResponseBytes        = 1 << 20
	maximumResponseBytes        = 4 << 20
)

var (
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	requestIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	traceparentPattern = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
	stepUpTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

type HandlerConfig struct {
	CommandTimeout   time.Duration
	QueryTimeout     time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int
	Logger           *slog.Logger
}

type Handler struct {
	service          *Service
	authenticate     AuthenticateFunc
	commandTimeout   time.Duration
	queryTimeout     time.Duration
	maxRequestBytes  int64
	maxResponseBytes int
	logger           *slog.Logger
}

type routeOperation string

const (
	operationPermissionCatalog routeOperation = "permission_catalog"
	operationListRoles         routeOperation = "list_roles"
	operationGetRole           routeOperation = "get_role"
	operationCreateRole        routeOperation = "create_role"
	operationRenameRole        routeOperation = "rename_role"
	operationPublishRole       routeOperation = "publish_role"
	operationDeactivateRole    routeOperation = "deactivate_role"
	operationListGrants        routeOperation = "list_grants"
	operationAssignRole        routeOperation = "assign_role"
	operationRevokeGrant       routeOperation = "revoke_grant"
)

type handlerRoute struct {
	operation  routeOperation
	resourceID uuid.UUID
	command    bool
}

type requestFacts struct {
	id       string
	provided bool
}

type requestFactsKey struct{}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type dataEnvelope[T any] struct {
	Data T `json:"data"`
}

type createRoleBody struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type renameRoleBody struct {
	Name string `json:"name"`
}

type publishRoleBody struct {
	Permissions []string `json:"permissions"`
}

type assignRoleBody struct {
	RoleID        string `json:"role_id"`
	SubjectUserID string `json:"subject_user_id"`
}

func NewHandler(service *Service, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidRequest
	}
	if config.CommandTimeout == 0 {
		config.CommandTimeout = defaultCommandTimeout
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultResponseBytes
	}
	if config.CommandTimeout <= 0 || config.CommandTimeout > maximumHandlerTimeout ||
		config.QueryTimeout <= 0 || config.QueryTimeout > maximumHandlerTimeout ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > 1<<20 ||
		config.MaxResponseBytes < 512 || config.MaxResponseBytes > maximumResponseBytes {
		return nil, ErrInvalidRequest
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Handler{service: service, authenticate: authenticate,
		commandTimeout: config.CommandTimeout, queryTimeout: config.QueryTimeout,
		maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes,
		logger: config.Logger}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	facts, validRequestID := requestIdentifier(request)
	request = request.WithContext(context.WithValue(request.Context(), requestFactsKey{}, facts))
	writer.Header().Set("X-Request-ID", facts.id)
	if !validRequestID || request.Header.Get("X-Step-Up-Verified") != "" ||
		len(request.Header.Values("X-Step-Up-Verified")) > 0 {
		handler.writeError(writer, request, http.StatusBadRequest,
			"custom_rbac_validation_error", "request headers are invalid")
		return
	}

	route, matched, allow := resolveRoute(request.URL.Path, request.Method)
	if !matched {
		handler.writeError(writer, request, http.StatusNotFound,
			"custom_rbac_route_not_found", "custom RBAC route was not found")
		return
	}
	if route.operation == "" {
		writer.Header().Set("Allow", allow)
		handler.writeError(writer, request, http.StatusMethodNotAllowed,
			"custom_rbac_method_not_allowed", "request method is not allowed")
		return
	}

	timeout := handler.queryTimeout
	if route.command {
		timeout = handler.commandTimeout
	}
	ctx, cancel := context.WithTimeout(request.Context(), timeout)
	defer cancel()
	request = request.WithContext(ctx)
	session, err := handler.authenticate(request)
	if err != nil {
		handler.writeServiceError(writer, request, ErrUnauthenticated)
		return
	}
	handler.handleAuthenticated(writer, request, route, session)
}

func (handler *Handler) handleAuthenticated(
	writer http.ResponseWriter,
	request *http.Request,
	route handlerRoute,
	session AuthenticatedSession,
) {
	switch route.operation {
	case operationPermissionCatalog:
		if err := requireQueryKeys(request, nil); err != nil || !emptyBody(request) {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.PermissionCatalog(request.Context(), session)
		handler.writeResult(writer, request, http.StatusOK, dataEnvelope[[]PermissionView]{Data: result}, err)
	case operationListRoles:
		input, err := parseRoleList(request)
		if err != nil || !emptyBody(request) {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.ListRoles(request.Context(), session, input)
		handler.writeResult(writer, request, http.StatusOK, result, err)
	case operationGetRole:
		if err := requireQueryKeys(request, nil); err != nil || !emptyBody(request) || route.resourceID == uuid.Nil {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.GetRole(request.Context(), session, route.resourceID)
		handler.writeResult(writer, request, http.StatusOK, dataEnvelope[RoleView]{Data: result}, err)
	case operationCreateRole:
		metadata, ok := handler.writeMetadata(writer, request, false)
		if !ok || !handler.requireNoQuery(writer, request) {
			return
		}
		var body createRoleBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.CreateRole(request.Context(), session,
			body.Name, body.Permissions, metadata)
		handler.writeResult(writer, request, http.StatusCreated, dataEnvelope[RoleView]{Data: result}, err)
	case operationRenameRole:
		metadata, revision, ok := handler.revisionMetadata(writer, request)
		if !ok || !handler.requireNoQuery(writer, request) {
			return
		}
		if route.resourceID == uuid.Nil {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		var body renameRoleBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.RenameRole(request.Context(), session,
			route.resourceID, revision, body.Name, metadata)
		handler.writeResult(writer, request, http.StatusOK, dataEnvelope[RoleView]{Data: result}, err)
	case operationPublishRole:
		metadata, revision, ok := handler.revisionMetadata(writer, request)
		if !ok || !handler.requireNoQuery(writer, request) {
			return
		}
		if route.resourceID == uuid.Nil {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		var body publishRoleBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.PublishRole(request.Context(), session,
			route.resourceID, revision, body.Permissions, metadata)
		handler.writeResult(writer, request, http.StatusOK, dataEnvelope[RoleView]{Data: result}, err)
	case operationDeactivateRole:
		metadata, revision, ok := handler.revisionMetadata(writer, request)
		if !ok || !handler.requireNoQuery(writer, request) {
			return
		}
		if route.resourceID == uuid.Nil || !emptyBody(request) {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.DeactivateRole(request.Context(), session,
			route.resourceID, revision, metadata)
		handler.writeResult(writer, request, http.StatusOK, dataEnvelope[RoleView]{Data: result}, err)
	case operationListGrants:
		input, err := parseGrantList(request)
		if err != nil || !emptyBody(request) {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.ListGrants(request.Context(), session, input)
		handler.writeResult(writer, request, http.StatusOK, result, err)
	case operationAssignRole:
		metadata, revision, ok := handler.revisionMetadata(writer, request)
		if !ok || !handler.requireNoQuery(writer, request) {
			return
		}
		var body assignRoleBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		roleID, roleErr := canonicalUUID(body.RoleID)
		subjectID, subjectErr := canonicalUUID(body.SubjectUserID)
		if roleErr != nil || subjectErr != nil {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.AssignRole(request.Context(), session,
			roleID, revision, subjectID, metadata)
		handler.writeResult(writer, request, http.StatusCreated, dataEnvelope[GrantView]{Data: result}, err)
	case operationRevokeGrant:
		metadata, ok := handler.writeMetadata(writer, request, false)
		if !ok || !handler.requireNoQuery(writer, request) {
			return
		}
		if route.resourceID == uuid.Nil || !emptyBody(request) {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.RevokeGrant(request.Context(), session, route.resourceID, metadata)
		handler.writeResult(writer, request, http.StatusOK, dataEnvelope[RevocationView]{Data: result}, err)
	}
}

func resolveRoute(path, method string) (handlerRoute, bool, string) {
	const base = "/v1/custom-rbac"
	switch path {
	case base + "/permissions":
		if method == http.MethodGet {
			return handlerRoute{operation: operationPermissionCatalog}, true, http.MethodGet
		}
		return handlerRoute{}, true, http.MethodGet
	case base + "/roles":
		switch method {
		case http.MethodGet:
			return handlerRoute{operation: operationListRoles}, true, "GET, POST"
		case http.MethodPost:
			return handlerRoute{operation: operationCreateRole, command: true}, true, "GET, POST"
		default:
			return handlerRoute{}, true, "GET, POST"
		}
	case base + "/grants":
		switch method {
		case http.MethodGet:
			return handlerRoute{operation: operationListGrants}, true, "GET, POST"
		case http.MethodPost:
			return handlerRoute{operation: operationAssignRole, command: true}, true, "GET, POST"
		default:
			return handlerRoute{}, true, "GET, POST"
		}
	}
	if suffix, ok := strings.CutPrefix(path, base+"/roles/"); ok {
		segments := strings.Split(suffix, "/")
		if len(segments) < 1 || len(segments) > 2 || segments[0] == "" {
			return handlerRoute{}, false, ""
		}
		roleID, _ := canonicalUUID(segments[0])
		if len(segments) == 1 {
			if method == http.MethodGet {
				return handlerRoute{operation: operationGetRole, resourceID: roleID}, true, http.MethodGet
			}
			return handlerRoute{}, true, http.MethodGet
		}
		operations := map[string]routeOperation{
			"rename": operationRenameRole, "publish": operationPublishRole,
			"deactivate": operationDeactivateRole,
		}
		operation, ok := operations[segments[1]]
		if !ok {
			return handlerRoute{}, false, ""
		}
		if method != http.MethodPost {
			return handlerRoute{}, true, http.MethodPost
		}
		return handlerRoute{operation: operation, resourceID: roleID, command: true}, true, http.MethodPost
	}
	if suffix, ok := strings.CutPrefix(path, base+"/grants/"); ok {
		segments := strings.Split(suffix, "/")
		if len(segments) != 2 || segments[0] == "" || segments[1] != "revoke" {
			return handlerRoute{}, false, ""
		}
		grantID, _ := canonicalUUID(segments[0])
		if method != http.MethodPost {
			return handlerRoute{}, true, http.MethodPost
		}
		return handlerRoute{operation: operationRevokeGrant, resourceID: grantID, command: true}, true, http.MethodPost
	}
	return handlerRoute{}, false, ""
}

func parseRoleList(request *http.Request) (RoleListInput, error) {
	if err := requireQueryKeys(request, map[string]bool{
		"limit": true, "cursor": true, "include_deactivated": true,
	}); err != nil {
		return RoleListInput{}, err
	}
	limit, err := parseLimit(request.URL.Query().Get("limit"))
	if err != nil {
		return RoleListInput{}, err
	}
	includeDeactivated := false
	if raw := request.URL.Query().Get("include_deactivated"); raw != "" {
		if raw != "true" && raw != "false" {
			return RoleListInput{}, ErrInvalidRequest
		}
		includeDeactivated = raw == "true"
	}
	return RoleListInput{PageInput: PageInput{Limit: limit, Cursor: request.URL.Query().Get("cursor")},
		IncludeDeactivated: includeDeactivated}, nil
}

func parseGrantList(request *http.Request) (GrantListInput, error) {
	if err := requireQueryKeys(request, map[string]bool{
		"limit": true, "cursor": true, "role_id": true, "subject_user_id": true, "state": true,
	}); err != nil {
		return GrantListInput{}, err
	}
	query := request.URL.Query()
	limit, err := parseLimit(query.Get("limit"))
	if err != nil {
		return GrantListInput{}, err
	}
	result := GrantListInput{PageInput: PageInput{Limit: limit, Cursor: query.Get("cursor")}, State: query.Get("state")}
	if result.State == "" {
		result.State = "active"
	}
	if result.State != "all" && result.State != "active" && result.State != "revoked" {
		return GrantListInput{}, ErrInvalidRequest
	}
	if raw := query.Get("role_id"); raw != "" {
		value, err := canonicalUUID(raw)
		if err != nil {
			return GrantListInput{}, err
		}
		result.RoleID = &value
	}
	if raw := query.Get("subject_user_id"); raw != "" {
		value, err := canonicalUUID(raw)
		if err != nil {
			return GrantListInput{}, err
		}
		result.SubjectUserID = &value
	}
	return result, nil
}

func requireQueryKeys(request *http.Request, allowed map[string]bool) error {
	for key, values := range request.URL.Query() {
		if !allowed[key] || len(values) != 1 {
			return ErrInvalidRequest
		}
	}
	return nil
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

func canonicalUUID(raw string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidRequest
	}
	return value, nil
}

func (handler *Handler) revisionMetadata(
	writer http.ResponseWriter,
	request *http.Request,
) (WriteMetadata, int64, bool) {
	metadata, ok := handler.writeMetadata(writer, request, true)
	if !ok {
		return WriteMetadata{}, 0, false
	}
	revision, err := parseIfMatch(request.Header.Get("If-Match"))
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return WriteMetadata{}, 0, false
	}
	return metadata, revision, true
}

func (handler *Handler) writeMetadata(
	writer http.ResponseWriter,
	request *http.Request,
	expectRevision bool,
) (WriteMetadata, bool) {
	facts := requestFactsFromContext(request.Context())
	idempotencyKey, ok := singleHeader(request, "Idempotency-Key")
	if !ok || !idempotencyPattern.MatchString(idempotencyKey) || !facts.provided {
		handler.writeServiceError(writer, request, ErrInvalidRequest)
		return WriteMetadata{}, false
	}
	traceparent, ok := singleHeader(request, "Traceparent")
	match := traceparentPattern.FindStringSubmatch(traceparent)
	if !ok || match == nil || match[1] == strings.Repeat("0", 32) || match[2] == strings.Repeat("0", 16) {
		handler.writeServiceError(writer, request, ErrInvalidRequest)
		return WriteMetadata{}, false
	}
	ifMatchValues := request.Header.Values("If-Match")
	if (expectRevision && len(ifMatchValues) != 1) || (!expectRevision && len(ifMatchValues) != 0) {
		handler.writeServiceError(writer, request, ErrInvalidRequest)
		return WriteMetadata{}, false
	}
	proof := ""
	if values := request.Header.Values("X-Step-Up-Proof"); len(values) > 1 ||
		(len(values) == 1 && !stepUpTokenPattern.MatchString(values[0])) {
		handler.writeServiceError(writer, request, ErrInvalidRequest)
		return WriteMetadata{}, false
	} else if len(values) == 1 {
		proof = values[0]
	}
	return WriteMetadata{IdempotencyKey: idempotencyKey, RequestID: facts.id,
		TraceID: match[1], StepUpToken: proof}, true
}

func parseIfMatch(raw string) (int64, error) {
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, ErrInvalidRequest
	}
	value, err := strconv.ParseInt(raw[1:len(raw)-1], 10, 64)
	if err != nil || value < 1 || strconv.FormatInt(value, 10) != raw[1:len(raw)-1] {
		return 0, ErrInvalidRequest
	}
	return value, nil
}

func singleHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1
}

func (handler *Handler) requireNoQuery(writer http.ResponseWriter, request *http.Request) bool {
	if err := requireQueryKeys(request, nil); err != nil {
		handler.writeServiceError(writer, request, err)
		return false
	}
	return true
}

func (handler *Handler) decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	if request.ContentLength > handler.maxRequestBytes || len(request.Header.Values("Content-Type")) != 1 ||
		len(request.Header.Values("Content-Encoding")) != 0 {
		if request.ContentLength > handler.maxRequestBytes {
			return &http.MaxBytesError{Limit: handler.maxRequestBytes}
		}
		return ErrInvalidRequest
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" ||
		(len(parameters) > 0 && (len(parameters) != 1 || !strings.EqualFold(parameters["charset"], "utf-8"))) {
		return ErrInvalidRequest
	}
	request.Body = http.MaxBytesReader(writer, request.Body, handler.maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return tooLarge
		}
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidRequest
	}
	return nil
}

func emptyBody(request *http.Request) bool {
	if request.ContentLength > 0 || len(request.TransferEncoding) > 0 ||
		len(request.Header.Values("Content-Type")) != 0 || len(request.Header.Values("Content-Encoding")) != 0 {
		return false
	}
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	var buffer [1]byte
	count, err := request.Body.Read(buffer[:])
	return count == 0 && err == io.EOF
}

func requestIdentifier(request *http.Request) (requestFacts, bool) {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 0 {
		return requestFacts{id: newRequestID()}, true
	}
	if len(values) != 1 || !requestIDPattern.MatchString(values[0]) {
		return requestFacts{id: newRequestID()}, false
	}
	return requestFacts{id: values[0], provided: true}, true
}

func requestFactsFromContext(ctx context.Context) requestFacts {
	value, _ := ctx.Value(requestFactsKey{}).(requestFacts)
	return value
}

func newRequestID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "custom-rbac-request-unavailable"
	}
	return "crbac-" + hex.EncodeToString(value)
}

func (handler *Handler) writeResult(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	value any,
	err error,
) {
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		handler.writeServiceError(writer, request, ErrInvalidStoreResponse)
		return
	}
	if len(encoded)+1 > handler.maxResponseBytes {
		handler.writeServiceError(writer, request, ErrResponseTooLarge)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message := publicError(err)
	if status >= 500 {
		handler.logger.ErrorContext(request.Context(), "custom RBAC request failed",
			"request_id", requestFactsFromContext(request.Context()).id,
			"code", code, "path", request.URL.Path)
	}
	handler.writeError(writer, request, status, code, message)
}

func (handler *Handler) writeError(
	writer http.ResponseWriter,
	request *http.Request,
	status int,
	code string,
	message string,
) {
	encoded, _ := json.Marshal(errorEnvelope{Error: apiError{Code: code, Message: message,
		RequestID: requestFactsFromContext(request.Context()).id}})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func publicError(err error) (int, string, string) {
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge, "custom_rbac_payload_too_large", "request body is too large"
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized, "custom_rbac_authentication_required", "authentication is required"
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, rbacmanager.ErrInvalidInput):
		return http.StatusBadRequest, "custom_rbac_validation_error", "request is invalid"
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, rbacmanager.ErrPermissionDenied):
		return http.StatusForbidden, "custom_rbac_permission_denied", "permission is denied"
	case errors.Is(err, rbacmanager.ErrPermissionNotAllowed):
		return http.StatusUnprocessableEntity, "custom_rbac_permission_not_delegable", "permission is not tenant delegable"
	case errors.Is(err, rbacmanager.ErrPermissionEscalation):
		return http.StatusForbidden, "custom_rbac_permission_escalation", "delegation exceeds actor permissions"
	case errors.Is(err, rbacmanager.ErrSelfAssignment):
		return http.StatusForbidden, "custom_rbac_self_assignment_denied", "self assignment is denied"
	case errors.Is(err, ErrNotFound), errors.Is(err, rbacmanager.ErrNotFound),
		errors.Is(err, rbacmanager.ErrTenantBoundary):
		return http.StatusNotFound, "custom_rbac_not_found", "resource was not found"
	case errors.Is(err, rbacmanager.ErrStepUpRequired), errors.Is(err, ErrStepUpUnavailable):
		return http.StatusPreconditionRequired, "custom_rbac_step_up_required", "valid step-up proof is required"
	case errors.Is(err, rbacmanager.ErrSystemRoleImmutable):
		return http.StatusConflict, "custom_rbac_system_role_immutable", "system role is immutable"
	case errors.Is(err, rbacmanager.ErrRoleInactive):
		return http.StatusConflict, "custom_rbac_role_inactive", "custom role is inactive"
	case errors.Is(err, rbacmanager.ErrGrantRevoked):
		return http.StatusConflict, "custom_rbac_grant_revoked", "custom role grant is revoked"
	case errors.Is(err, rbacmanager.ErrRevisionConflict):
		return http.StatusConflict, "custom_rbac_revision_conflict", "custom role revision conflicts"
	case errors.Is(err, rbacmanager.ErrIdempotencyConflict):
		return http.StatusConflict, "custom_rbac_idempotency_conflict", "idempotency key payload conflicts"
	case errors.Is(err, rbacmanager.ErrNameConflict):
		return http.StatusConflict, "custom_rbac_name_conflict", "custom role name conflicts"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout, "custom_rbac_request_cancelled", "request was cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "custom_rbac_request_timeout", "request timed out"
	case errors.Is(err, ErrInvalidStoreResponse):
		return http.StatusBadGateway, "custom_rbac_invalid_store_response", "upstream facts are invalid"
	case errors.Is(err, ErrResponseTooLarge):
		return http.StatusBadGateway, "custom_rbac_response_too_large", "response is too large"
	default:
		return http.StatusServiceUnavailable, "custom_rbac_store_unavailable", "custom RBAC service is unavailable"
	}
}
