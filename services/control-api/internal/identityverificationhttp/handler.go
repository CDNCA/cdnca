package identityverificationhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

const (
	defaultCommandTimeout       = 15 * time.Second
	defaultQueryTimeout         = 6 * time.Second
	maximumHandlerTimeout       = 30 * time.Second
	defaultRequestBytes   int64 = 1 << 20
	defaultResponseBytes        = 1 << 20
	maximumResponseBytes        = 4 << 20
	maximumHeaderBytes          = 16 << 10
	maximumQueryBytes           = 4096
	maximumPathBytes            = 512
	apiPrefix                   = "/v1/identity-verification"
)

type HandlerConfig struct {
	CommandTimeout   time.Duration
	QueryTimeout     time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int
}

type Handler struct {
	service          *Service
	authenticate     AuthenticateFunc
	commandTimeout   time.Duration
	queryTimeout     time.Duration
	maxRequestBytes  int64
	maxResponseBytes int
}

type routeKind string

const (
	routeCreate       routeKind = "create"
	routeGetSelf      routeKind = "get_self"
	routeSelfStatus   routeKind = "self_status"
	routeSubmit       routeKind = "submit"
	routeWithdraw     routeKind = "withdraw"
	routeExpireSelf   routeKind = "expire_self"
	routeListReviewer routeKind = "list_reviewer"
	routeGetReviewer  routeKind = "get_reviewer"
	routeClaim        routeKind = "claim"
	routeDecision     routeKind = "decision"
	routeListAdmin    routeKind = "list_admin"
)

type handlerRoute struct {
	kind    routeKind
	method  string
	caseID  uuid.UUID
	command bool
}

type requestIDKey struct{}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func NewHandler(service *Service, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	return nil, ErrInvalidService
}

// newHandler is a package-local test seam. Production assembly uses NewRuntimeHandler.
func newHandler(service *Service, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidService
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
		return nil, ErrInvalidService
	}
	return &Handler{service: service, authenticate: authenticate,
		commandTimeout: config.CommandTimeout, queryTimeout: config.QueryTimeout,
		maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, validRequestID := requestIdentifier(request)
	request = request.WithContext(context.WithValue(request.Context(), requestIDKey{}, requestID))
	writer.Header().Set("X-Request-ID", requestID)
	if !validRequestID || !validRequestShape(request) {
		handler.writeError(writer, request, http.StatusBadRequest,
			"identity_verification_invalid_request", "request metadata is invalid")
		return
	}
	route, matched := resolveRoute(request.URL.Path)
	if !matched {
		handler.writeError(writer, request, http.StatusNotFound,
			"identity_verification_route_not_found", "identity verification route was not found")
		return
	}
	if request.Method != route.method {
		writer.Header().Set("Allow", route.method)
		handler.writeError(writer, request, http.StatusMethodNotAllowed,
			"identity_verification_method_not_allowed", "request method is not allowed")
		return
	}
	timeout := handler.queryTimeout
	if route.command {
		timeout = handler.commandTimeout
	}
	ctx, cancel := context.WithTimeout(request.Context(), timeout)
	defer cancel()
	request = request.WithContext(ctx)
	rawSession, err := canonicalBearerSession(request)
	if err != nil || hasActorHeaders(request) {
		handler.writeServiceError(writer, request, ErrUnauthenticated)
		return
	}
	session, err := handler.authenticate(request, rawSession)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, ErrUnauthenticated) {
			handler.writeServiceError(writer, request, ErrUnauthenticated)
		} else {
			handler.writeServiceError(writer, request, ErrStoreUnavailable)
		}
		return
	}
	if route.kind == routeListAdmin {
		// 管理端实名审核入口，平台管理员跨租户列表；租户会话 403。
		if session.Principal.ScopeKind != "platform" {
			handler.writeServiceError(writer, request, ErrPermissionDenied)
			return
		}
		admin, err := identityverification.NewPlatformAdmin(session.Principal.UserID, session.Principal.ScopeID,
			session.SessionID, rawSession)
		if err != nil {
			handler.writeServiceError(writer, request, ErrUnauthenticated)
			return
		}
		if !handler.requireNoBody(writer, request) {
			return
		}
		if err := validateQuery(request, map[string]bool{"limit": true, "cursor": true, "kind": true,
			"status": true}); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		input, err := pageInput(request)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.ListAdminCases(request.Context(), admin, input)
		handler.writeJSONResult(writer, request, http.StatusOK, result, err)
		return
	}
	if session.Principal.ScopeKind == "platform" && route.reviewer() {
		// 平台管理员也能代审；以 ?tenant_scope_id= 指定租户，身份仍是管理员本人。
		target, err := reviewTargetTenant(request)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		actor, err := identityverification.NewPlatformReviewActor(session.Principal.UserID,
			session.Principal.ScopeID, session.SessionID, rawSession, target)
		if err != nil {
			handler.writeServiceError(writer, request, ErrUnauthenticated)
			return
		}
		handler.handle(writer, request, route, actor)
		return
	}
	actor, validSession := actorFromSession(session, rawSession)
	if !validSession {
		handler.writeServiceError(writer, request, ErrUnauthenticated)
		return
	}
	handler.handle(writer, request, route, actor)
}

func (route handlerRoute) reviewer() bool {
	switch route.kind {
	case routeListReviewer, routeGetReviewer, routeClaim, routeDecision:
		return true
	default:
		return false
	}
}

func reviewTargetTenant(request *http.Request) (uuid.UUID, error) {
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil || len(values["tenant_scope_id"]) != 1 {
		return uuid.Nil, ErrInvalidRequest
	}
	return canonicalUUID(values.Get("tenant_scope_id"))
}

// reviewerQuery is the extra query a platform reviewer must send; tenant
// sessions may not send it.
func reviewerQuery(actor identityverification.Actor, allowed map[string]bool) map[string]bool {
	if !actor.PlatformReviewer() {
		return allowed
	}
	result := map[string]bool{"tenant_scope_id": true}
	for key := range allowed {
		result[key] = true
	}
	return result
}

func canonicalBearerSession(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", ErrUnauthenticated
	}
	rawSession := strings.TrimPrefix(values[0], "Bearer ")
	if rawSession == "" || len(rawSession) > 8192 || strings.ContainsAny(rawSession, " \t\r\n") ||
		values[0] != "Bearer "+rawSession {
		return "", ErrUnauthenticated
	}
	return rawSession, nil
}

func hasActorHeaders(request *http.Request) bool {
	for _, name := range []string{
		"X-Actor-ID", "X-User-ID", "X-Scope-ID", "X-Scope-Kind", "X-Tenant-ID",
		"X-Principal-ID", "X-Session-ID", "X-Role", "X-Permissions",
	} {
		if len(request.Header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func (handler *Handler) handle(writer http.ResponseWriter, request *http.Request, route handlerRoute,
	actor identityverification.Actor,
) {
	switch route.kind {
	case routeCreate:
		if err := validateQuery(request, nil); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		metadata, err := writeMetadata(request)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		var body createBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.CreateDraft(request.Context(), actor,
			CreateDraftInput{Kind: body.Kind, EvidenceToken: body.EvidenceToken}, metadata)
		status := http.StatusCreated
		if result.Replayed {
			status = http.StatusOK
		}
		handler.writeCase(writer, request, status, result, err)
	case routeGetSelf:
		if err := validateQuery(request, nil); err != nil || !handler.requireNoBody(writer, request) {
			if err != nil {
				handler.writeServiceError(writer, request, err)
			}
			return
		}
		result, err := handler.service.GetSelf(request.Context(), actor, route.caseID)
		handler.writeCase(writer, request, http.StatusOK, result, err)
	case routeSelfStatus:
		if err := validateQuery(request, nil); err != nil || !handler.requireNoBody(writer, request) {
			if err != nil {
				handler.writeServiceError(writer, request, err)
			}
			return
		}
		result, err := handler.service.GetSelfStatus(request.Context(), actor)
		handler.writeJSONResult(writer, request, http.StatusOK, result, err)
	case routeSubmit, routeWithdraw, routeExpireSelf, routeClaim:
		handler.handleMutation(writer, request, route, actor)
	case routeListReviewer:
		if !handler.requireNoBody(writer, request) {
			return
		}
		input, err := parsePage(request, actor)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.ListReviewerCases(request.Context(), actor, input)
		handler.writeJSONResult(writer, request, http.StatusOK, result, err)
	case routeGetReviewer:
		if err := validateQuery(request, reviewerQuery(actor, nil)); err != nil || !handler.requireNoBody(writer, request) {
			if err != nil {
				handler.writeServiceError(writer, request, err)
			}
			return
		}
		result, err := handler.service.GetReviewer(request.Context(), actor, route.caseID)
		handler.writeCase(writer, request, http.StatusOK, result, err)
	case routeDecision:
		if err := validateQuery(request, reviewerQuery(actor, nil)); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		metadata, revision, err := mutationMetadata(request)
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		var body decisionBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.Decide(request.Context(), actor, DecisionInput{
			CaseID: route.caseID, ExpectedRevision: revision, Decision: body.Decision,
			ReasonCode: body.ReasonCode, WriteMetadata: metadata,
		})
		handler.writeCase(writer, request, http.StatusOK, result, err)
	}
}

func (handler *Handler) handleMutation(writer http.ResponseWriter, request *http.Request, route handlerRoute,
	actor identityverification.Actor,
) {
	if err := validateQuery(request, reviewerQuery(actor, nil)); err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	if !handler.requireNoBody(writer, request) {
		return
	}
	metadata, revision, err := mutationMetadata(request)
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	input := MutationInput{CaseID: route.caseID, ExpectedRevision: revision, WriteMetadata: metadata}
	var result CaseView
	switch route.kind {
	case routeSubmit:
		result, err = handler.service.Submit(request.Context(), actor, input)
	case routeWithdraw:
		result, err = handler.service.Withdraw(request.Context(), actor, input)
	case routeExpireSelf:
		result, err = handler.service.ExpireSelf(request.Context(), actor, input)
	case routeClaim:
		result, err = handler.service.Claim(request.Context(), actor, input)
	default:
		err = ErrInvalidRequest
	}
	handler.writeCase(writer, request, http.StatusOK, result, err)
}

type createBody struct {
	Kind          string `json:"kind"`
	EvidenceToken string `json:"evidence_token"`
}

type decisionBody struct {
	Decision   string `json:"decision"`
	ReasonCode string `json:"reason_code"`
}

func (handler *Handler) decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	contentType, err := singleHeader(request, "Content-Type", true)
	if err != nil {
		return ErrInvalidRequest
	}
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return ErrInvalidRequest
	}
	request.Body = http.MaxBytesReader(writer, request.Body, handler.maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func (handler *Handler) requireNoBody(writer http.ResponseWriter, request *http.Request) bool {
	if len(request.Header.Values("Content-Type")) != 0 {
		handler.writeServiceError(writer, request, ErrInvalidRequest)
		return false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1)
	count, err := io.Copy(io.Discard, request.Body)
	if err != nil || count != 0 {
		handler.writeServiceError(writer, request, ErrInvalidRequest)
		return false
	}
	return true
}

func resolveRoute(path string) (handlerRoute, bool) {
	if path == apiPrefix+"/cases" {
		return handlerRoute{kind: routeCreate, method: http.MethodPost, command: true}, true
	}
	if path == apiPrefix+"/admin/cases" {
		return handlerRoute{kind: routeListAdmin, method: http.MethodGet}, true
	}
	if path == apiPrefix+"/reviewer/cases" {
		return handlerRoute{kind: routeListReviewer, method: http.MethodGet}, true
	}
	if path == apiPrefix+"/status" {
		return handlerRoute{kind: routeSelfStatus, method: http.MethodGet}, true
	}
	if !strings.HasPrefix(path, apiPrefix+"/") || strings.HasSuffix(path, "/") {
		return handlerRoute{}, false
	}
	remainder := strings.TrimPrefix(path, apiPrefix+"/")
	segments := strings.Split(remainder, "/")
	var reviewer bool
	if len(segments) >= 2 && segments[0] == "reviewer" && segments[1] == "cases" {
		reviewer = true
		segments = segments[1:]
	}
	if len(segments) < 2 || segments[0] != "cases" {
		return handlerRoute{}, false
	}
	caseID, err := canonicalUUID(segments[1])
	if err != nil {
		return handlerRoute{}, false
	}
	if len(segments) == 2 {
		if reviewer {
			return handlerRoute{kind: routeGetReviewer, method: http.MethodGet, caseID: caseID}, true
		}
		return handlerRoute{kind: routeGetSelf, method: http.MethodGet, caseID: caseID}, true
	}
	if len(segments) != 3 {
		return handlerRoute{}, false
	}
	if reviewer {
		switch segments[2] {
		case "claim":
			return handlerRoute{kind: routeClaim, method: http.MethodPost, caseID: caseID, command: true}, true
		case "decision":
			return handlerRoute{kind: routeDecision, method: http.MethodPost, caseID: caseID, command: true}, true
		default:
			return handlerRoute{}, false
		}
	}
	switch segments[2] {
	case "submit":
		return handlerRoute{kind: routeSubmit, method: http.MethodPost, caseID: caseID, command: true}, true
	case "withdraw":
		return handlerRoute{kind: routeWithdraw, method: http.MethodPost, caseID: caseID, command: true}, true
	case "expire":
		return handlerRoute{kind: routeExpireSelf, method: http.MethodPost, caseID: caseID, command: true}, true
	default:
		return handlerRoute{}, false
	}
}

func parsePage(request *http.Request, actor identityverification.Actor) (PageInput, error) {
	if err := validateQuery(request, reviewerQuery(actor,
		map[string]bool{"limit": true, "cursor": true, "kind": true, "status": true})); err != nil {
		return PageInput{}, err
	}
	return pageInput(request)
}

func pageInput(request *http.Request) (PageInput, error) {
	input := PageInput{Kind: request.URL.Query().Get("kind"), Status: request.URL.Query().Get("status")}
	if raw := request.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 8)
		if err != nil || value < 1 || value > maximumPageLimit || strconv.FormatUint(value, 10) != raw {
			return PageInput{}, ErrInvalidRequest
		}
		input.Limit = int(value)
	}
	input.Cursor = request.URL.Query().Get("cursor")
	if len(input.Cursor) > maxCursorBytes {
		return PageInput{}, ErrInvalidRequest
	}
	return input, nil
}

func mutationMetadata(request *http.Request) (WriteMetadata, int64, error) {
	metadata, err := writeMetadata(request)
	if err != nil {
		return WriteMetadata{}, 0, err
	}
	revision, err := parseIfMatch(request)
	return metadata, revision, err
}

func writeMetadata(request *http.Request) (WriteMetadata, error) {
	key, err := singleHeader(request, "Idempotency-Key", true)
	if err != nil || !metadataPattern.MatchString(key) {
		return WriteMetadata{}, ErrInvalidRequest
	}
	providedRequestID, err := singleHeader(request, "X-Request-ID", true)
	if err != nil || providedRequestID != requestID(request.Context()) {
		return WriteMetadata{}, ErrInvalidRequest
	}
	return WriteMetadata{IdempotencyKey: key, RequestID: providedRequestID}, nil
}

func parseIfMatch(request *http.Request) (int64, error) {
	raw, err := singleHeader(request, "If-Match", true)
	if err != nil || len(raw) < 3 || len(raw) > 22 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, ErrInvalidRequest
	}
	value, err := strconv.ParseInt(raw[1:len(raw)-1], 10, 64)
	if err != nil || value < 1 || strconv.FormatInt(value, 10) != raw[1:len(raw)-1] {
		return 0, ErrInvalidRequest
	}
	return value, nil
}

func validateQuery(request *http.Request, allowed map[string]bool) error {
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return ErrInvalidRequest
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 || entries[0] == "" {
			return ErrInvalidRequest
		}
	}
	return nil
}

func canonicalUUID(raw string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidRequest
	}
	return value, nil
}

func requestIdentifier(request *http.Request) (string, bool) {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 0 {
		return uuid.NewString(), true
	}
	if len(values) != 1 || !metadataPattern.MatchString(values[0]) {
		return uuid.NewString(), false
	}
	return values[0], true
}

func requestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	if !metadataPattern.MatchString(value) {
		return uuid.NewString()
	}
	return value
}

func singleHeader(request *http.Request, name string, required bool) (string, error) {
	values := request.Header.Values(name)
	if len(values) == 0 {
		if required {
			return "", ErrInvalidRequest
		}
		return "", nil
	}
	if len(values) != 1 || values[0] == "" || len(values[0]) > 512 || strings.TrimSpace(values[0]) != values[0] {
		return "", ErrInvalidRequest
	}
	return values[0], nil
}

func validRequestShape(request *http.Request) bool {
	if request.URL.RawPath != "" || len(request.URL.Path) > maximumPathBytes ||
		len(request.URL.RawQuery) > maximumQueryBytes {
		return false
	}
	total := 0
	for name, values := range request.Header {
		total += len(name)
		for _, value := range values {
			total += len(value)
		}
	}
	return total <= maximumHeaderBytes
}

func (handler *Handler) writeCase(writer http.ResponseWriter, request *http.Request, status int, value CaseView, err error) {
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(value.Revision, 10)+`"`)
	handler.writeJSON(writer, request, status, value)
}

func (handler *Handler) writeJSONResult(writer http.ResponseWriter, request *http.Request, status int, value any, err error) {
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	handler.writeJSON(writer, request, status, value)
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, request *http.Request, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		handler.writeServiceError(writer, request, ErrInvalidStoreResponse)
		return
	}
	encoded = append(encoded, '\n')
	if len(encoded) > handler.maxResponseBytes {
		handler.writeServiceError(writer, request, ErrResponseTooLarge)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message := publicError(err)
	handler.writeError(writer, request, status, code, message)
}

func (handler *Handler) writeError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	encoded, _ := json.Marshal(errorEnvelope{Error: apiError{Code: code, Message: message,
		RequestID: requestID(request.Context())}})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func publicError(err error) (int, string, string) {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, identityverification.ErrInvalidInput):
		return http.StatusBadRequest, "identity_verification_invalid_request", "request is invalid"
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized, "identity_verification_unauthenticated", "authentication is required"
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, identityverification.ErrPermissionDenied):
		return http.StatusForbidden, "identity_verification_permission_denied", "permission is denied"
	case errors.Is(err, ErrNotFound), errors.Is(err, identityverification.ErrNotFound):
		return http.StatusNotFound, "identity_verification_not_found", "identity verification case was not found"
	case errors.Is(err, identityverification.ErrRevisionConflict):
		return http.StatusConflict, "identity_verification_revision_conflict", "case revision is stale"
	case errors.Is(err, identityverification.ErrIdempotencyConflict):
		return http.StatusConflict, "identity_verification_idempotency_conflict", "idempotency key payload conflicts"
	case errors.Is(err, identityverification.ErrActiveReview):
		return http.StatusConflict, "identity_verification_active_review", "an active review already exists"
	case errors.Is(err, identityverification.ErrInvalidTransition):
		return http.StatusConflict, "identity_verification_invalid_transition", "case transition is not allowed"
	case errors.Is(err, identityverification.ErrInitialApprovalRequired):
		return http.StatusConflict, "identity_verification_initial_approval_required", "approved initial identity is required"
	case errors.Is(err, identityverification.ErrIdentityMismatch):
		return http.StatusUnprocessableEntity, "identity_verification_identity_mismatch", "trusted identity does not match"
	case errors.Is(err, identityverification.ErrAlreadyVerified):
		return http.StatusConflict, "identity_verification_already_verified", "identity subject is already verified"
	case errors.Is(err, identityverification.ErrSelfReview):
		return http.StatusForbidden, "identity_verification_self_review_forbidden", "self review is forbidden"
	case errors.Is(err, identityverification.ErrReviewAssignment):
		return http.StatusForbidden, "identity_verification_review_assignment_required", "review assignment is required"
	case errors.Is(err, identityverification.ErrExpired):
		return http.StatusConflict, "identity_verification_case_expired", "identity verification case has expired"
	case errors.Is(err, identityverification.ErrNotExpired):
		return http.StatusConflict, "identity_verification_case_not_expired", "identity verification case is not expired"
	case errors.Is(err, identityverification.ErrEvidenceSettlementPending):
		return http.StatusConflict, "identity_verification_evidence_settlement_pending", "trusted evidence settlement is pending"
	case errors.Is(err, ErrInvalidEvidence):
		return http.StatusUnprocessableEntity, "identity_verification_evidence_invalid", "trusted evidence is invalid"
	case errors.Is(err, ErrTrustedEvidenceResolverRequired):
		return http.StatusServiceUnavailable, "identity_verification_trusted_resolver_required", "trusted evidence resolver is required"
	case errors.Is(err, ErrEvidenceUnavailable):
		return http.StatusServiceUnavailable, "identity_verification_evidence_unavailable", "trusted evidence is unavailable"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout, "identity_verification_request_canceled", "request was canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "identity_verification_request_timeout", "request timed out"
	case errors.Is(err, ErrResponseTooLarge):
		return http.StatusServiceUnavailable, "identity_verification_response_too_large", "response could not be returned"
	default:
		return http.StatusServiceUnavailable, "identity_verification_unavailable", "identity verification service is unavailable"
	}
}
