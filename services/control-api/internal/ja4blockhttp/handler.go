package ja4blockhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/ja4block"
	"github.com/google/uuid"
)

const (
	TenantCollectionRoute = "/v1/security/ja4-blocks"
	AdminCollectionRoute  = "/v1/admin/security/ja4-blocks"
	PermissionRead        = "security_policies.read"
	PermissionManage      = "security_policies.manage"
	maximumBodyBytes      = 16 << 10
)

var (
	ErrInvalidDependencies = errors.New("JA4 block HTTP dependencies invalid")
	ErrInvalidRequest      = errors.New("JA4 block HTTP request invalid")
	ErrStepUpRequired      = errors.New("JA4 block step-up required")
	requestIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type Application interface {
	Submit(context.Context, ja4block.Actor, ja4block.SubmitInput) (ja4block.Workflow, error)
	Get(context.Context, ja4block.Actor, uuid.UUID, uuid.UUID) (ja4block.Workflow, error)
}

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

type StepUpCheck struct {
	SessionID           uuid.UUID
	UserID              uuid.UUID
	ScopeID             uuid.UUID
	ScopeKind           string
	TargetTenantScopeID uuid.UUID
	Token               string
	Action              string
	RequestID           string
	RequestSHA256       [sha256.Size]byte
}

type StepUpEvidence struct {
	ID         uuid.UUID
	VerifiedAt time.Time
}

type VerifyStepUpFunc func(context.Context, StepUpCheck) (StepUpEvidence, error)

type Dependencies struct {
	Application         Application
	AuthenticateSession AuthenticateSessionFunc
	VerifyStepUp        VerifyStepUpFunc
}

type Handler struct {
	application  Application
	authenticate AuthenticateSessionFunc
	stepUp       VerifyStepUpFunc
}

func NewHandler(dependencies Dependencies) (*Handler, error) {
	if dependencies.Application == nil || dependencies.AuthenticateSession == nil || dependencies.VerifyStepUp == nil {
		return nil, ErrInvalidDependencies
	}
	return &Handler{application: dependencies.Application, authenticate: dependencies.AuthenticateSession, stepUp: dependencies.VerifyStepUp}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, validID := requestID(request)
	response.Header().Set("X-Request-ID", requestID)
	admin, id, routeOK := route(request.URL.Path)
	if !routeOK {
		writeError(response, http.StatusNotFound, "ja4_block_not_found", requestID)
		return
	}
	if !validID || spoofedActor(request) || len(request.Header.Values("X-API-Key")) != 0 {
		if len(request.Header.Values("X-API-Key")) != 0 {
			writeError(response, http.StatusUnauthorized, "ja4_block_authentication_required", requestID)
		} else {
			writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
		}
		return
	}
	token, ok := bearerToken(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "ja4_block_authentication_required", requestID)
		return
	}
	session, err := handler.authenticate(request.Context(), token)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrAccountDisabled) || errors.Is(err, identity.ErrMembershipDisabled) {
			writeError(response, http.StatusUnauthorized, "ja4_block_authentication_required", requestID)
		} else {
			writeError(response, http.StatusServiceUnavailable, "ja4_block_unavailable", requestID)
		}
		return
	}
	principal := session.Principal
	if session.SessionID == uuid.Nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		writeError(response, http.StatusUnauthorized, "ja4_block_authentication_required", requestID)
		return
	}
	if admin {
		if principal.ScopeKind != "platform" || principal.TenantID != nil || !hasPermission(principal.Permissions, "platform.admin") {
			writeError(response, http.StatusForbidden, "ja4_block_permission_denied", requestID)
			return
		}
	} else if principal.ScopeKind != "tenant" || principal.TenantID == nil {
		writeError(response, http.StatusForbidden, "ja4_block_permission_denied", requestID)
		return
	}
	actor := ja4block.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID,
		ScopeKind: principal.ScopeKind, SessionID: session.SessionID}
	if id == uuid.Nil {
		if request.Method != http.MethodPost {
			response.Header().Set("Allow", http.MethodPost)
			writeError(response, http.StatusMethodNotAllowed, "ja4_block_method_not_allowed", requestID)
			return
		}
		if !hasPermission(principal.Permissions, PermissionManage) {
			writeError(response, http.StatusForbidden, "ja4_block_permission_denied", requestID)
			return
		}
		handler.submit(response, request, requestID, admin, session, actor)
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeError(response, http.StatusMethodNotAllowed, "ja4_block_method_not_allowed", requestID)
		return
	}
	if !hasPermission(principal.Permissions, PermissionRead) {
		writeError(response, http.StatusForbidden, "ja4_block_permission_denied", requestID)
		return
	}
	tenantID := principal.ScopeID
	if admin {
		values := request.URL.Query()
		if len(values) != 1 || len(values["tenant_scope_id"]) != 1 {
			writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
			return
		}
		tenantID, err = uuid.Parse(values.Get("tenant_scope_id"))
		if err != nil || tenantID == uuid.Nil {
			writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
			return
		}
	} else if request.URL.RawQuery != "" {
		writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
		return
	}
	workflow, err := handler.application.Get(request.Context(), actor, tenantID, id)
	if err != nil {
		writeDomainError(response, requestID, err)
		return
	}
	if workflow.ID != id || workflow.TenantScopeID != tenantID {
		writeError(response, http.StatusBadGateway, "ja4_block_dependency_response_invalid", requestID)
		return
	}
	writeJSON(response, http.StatusOK, workflowResponse(workflow))
}

func (handler *Handler) submit(response http.ResponseWriter, request *http.Request, requestID string, admin bool,
	session identity.AuthenticatedSession, actor ja4block.Actor,
) {
	if request.URL.RawQuery != "" || !exactHeader(request, "Content-Type", "application/json") ||
		!exactHeader(request, "If-Match", `"0"`) {
		writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
		return
	}
	idempotency, ok := singleHeader(request, "Idempotency-Key")
	stepToken, stepOK := singleHeader(request, "X-Step-Up-Token")
	if !ok || !stepOK {
		writeError(response, http.StatusPreconditionRequired, "ja4_block_step_up_required", requestID)
		return
	}
	bodyBytes, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maximumBodyBytes))
	if err != nil || len(bodyBytes) == 0 {
		writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
		return
	}
	var body struct {
		TenantScopeID   string `json:"tenant_scope_id"`
		SiteID          string `json:"site_id"`
		JA4             string `json:"ja4"`
		SnapshotAt      string `json:"snapshot_at"`
		DurationSeconds int64  `json:"duration_seconds"`
		Reason          string `json:"reason"`
	}
	decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || ensureEOF(decoder) != nil {
		writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
		return
	}
	tenantID := actor.ScopeID
	if admin {
		tenantID, err = uuid.Parse(body.TenantScopeID)
		if err != nil || tenantID == uuid.Nil {
			writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
			return
		}
	} else if body.TenantScopeID != "" {
		writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
		return
	}
	siteID, siteErr := uuid.Parse(body.SiteID)
	snapshotAt, timeErr := time.Parse(time.RFC3339Nano, body.SnapshotAt)
	if siteErr != nil || siteID == uuid.Nil || timeErr != nil || body.DurationSeconds < 60 || body.DurationSeconds > 2592000 {
		writeError(response, http.StatusBadRequest, "ja4_block_invalid_request", requestID)
		return
	}
	digest := sha256.Sum256(append(append([]byte(nil), bodyBytes...), []byte("\x00"+tenantID.String()+"\x00"+idempotency+"\x00"+requestID)...))
	evidence, err := handler.stepUp(request.Context(), StepUpCheck{SessionID: session.SessionID, UserID: actor.UserID,
		ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind, TargetTenantScopeID: tenantID,
		Token: stepToken, Action: "security.ja4_block.create", RequestID: requestID, RequestSHA256: digest})
	if err != nil || evidence.ID == uuid.Nil || evidence.VerifiedAt.IsZero() {
		writeError(response, http.StatusPreconditionRequired, "ja4_block_step_up_required", requestID)
		return
	}
	workflow, err := handler.application.Submit(request.Context(), actor, ja4block.SubmitInput{
		TenantScopeID: tenantID, SiteID: siteID, JA4: body.JA4, SnapshotAt: snapshotAt,
		Duration: time.Duration(body.DurationSeconds) * time.Second, Reason: body.Reason, ExpectedRevision: 0,
		IdempotencyKey: idempotency, RequestID: requestID, SessionID: session.SessionID,
		StepUpEvidenceID: evidence.ID, StepUpVerifiedAt: evidence.VerifiedAt,
	})
	if err != nil {
		writeDomainError(response, requestID, err)
		return
	}
	if workflow.ID == uuid.Nil || workflow.TenantScopeID != tenantID || workflow.SiteID != siteID || workflow.Revision < 1 {
		writeError(response, http.StatusBadGateway, "ja4_block_dependency_response_invalid", requestID)
		return
	}
	response.Header().Set("ETag", strconv.Quote(strconv.FormatInt(workflow.Revision, 10)))
	writeJSON(response, http.StatusAccepted, workflowResponse(workflow))
}

func route(path string) (bool, uuid.UUID, bool) {
	for _, candidate := range []struct {
		prefix string
		admin  bool
	}{{AdminCollectionRoute, true}, {TenantCollectionRoute, false}} {
		if path == candidate.prefix {
			return candidate.admin, uuid.Nil, true
		}
		suffix, ok := strings.CutPrefix(path, candidate.prefix+"/")
		if !ok || strings.ContainsRune(suffix, '/') {
			continue
		}
		id, err := uuid.Parse(suffix)
		if err == nil && id != uuid.Nil {
			return candidate.admin, id, true
		}
	}
	return false, uuid.Nil, false
}

func bearerToken(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	return token, token != "" && len(token) < 8192 && !strings.ContainsFunc(token, unicode.IsSpace)
}
func requestID(request *http.Request) (string, bool) {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 0 {
		return uuid.NewString(), true
	}
	if len(values) != 1 || !requestIDPattern.MatchString(values[0]) {
		return uuid.NewString(), false
	}
	return values[0], true
}
func singleHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != "" && len(returnValue) <= 8192 && !strings.ContainsAny(returnValue, "\r\n")
}
func exactHeader(request *http.Request, name, want string) bool {
	value, ok := singleHeader(request, name)
	return ok && value == want
}
func hasPermission(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func spoofedActor(request *http.Request) bool {
	for _, name := range []string{"X-Scope-Kind", "X-Tenant-ID", "X-Principal-ID", "X-Session-ID", "X-Role", "X-Permissions"} {
		if len(request.Header.Values(name)) != 0 {
			return true
		}
	}
	return false
}
func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

type workflowView struct {
	ID              uuid.UUID      `json:"id"`
	TenantScopeID   uuid.UUID      `json:"tenant_scope_id"`
	SiteID          uuid.UUID      `json:"site_id"`
	JA4SHA256       string         `json:"ja4_sha256"`
	SnapshotAt      time.Time      `json:"snapshot_at"`
	DurationSeconds int64          `json:"duration_seconds"`
	Reason          string         `json:"reason"`
	Phase           ja4block.Phase `json:"phase"`
	Revision        int64          `json:"revision"`
	PolicyID        *uuid.UUID     `json:"policy_id,omitempty"`
	PolicyRevision  int64          `json:"policy_revision,omitempty"`
	BindingID       *uuid.UUID     `json:"binding_id,omitempty"`
	BindingRevision int64          `json:"binding_revision,omitempty"`
	PublicationID   *uuid.UUID     `json:"edge_publication_id,omitempty"`
	RolloutID       uuid.UUID      `json:"rollout_id"`
	EdgeState       string         `json:"edge_state"`
	AttemptCount    int            `json:"attempt_count"`
	LastErrorCode   string         `json:"last_error_code,omitempty"`
	Replayed        bool           `json:"replayed,omitempty"`
}

func workflowResponse(item ja4block.Workflow) workflowView {
	view := workflowView{ID: item.ID, TenantScopeID: item.TenantScopeID, SiteID: item.SiteID, JA4SHA256: item.JA4SHA256, SnapshotAt: item.SnapshotAt, DurationSeconds: int64(item.Duration / time.Second), Reason: item.Reason, Phase: item.Phase, Revision: item.Revision, PolicyRevision: item.PolicyRevision, BindingRevision: item.BindingRevision, RolloutID: item.RolloutID, EdgeState: item.EdgeState, AttemptCount: item.AttemptCount, LastErrorCode: item.LastErrorCode, Replayed: item.Replayed}
	if item.PolicyID != uuid.Nil {
		view.PolicyID = &item.PolicyID
	}
	if item.BindingID != uuid.Nil {
		view.BindingID = &item.BindingID
	}
	if item.PublicationID != uuid.Nil {
		view.PublicationID = &item.PublicationID
	}
	return view
}

func writeDomainError(response http.ResponseWriter, requestID string, err error) {
	status, code := http.StatusInternalServerError, "ja4_block_internal_error"
	switch {
	case errors.Is(err, ja4block.ErrInvalidInput):
		status, code = http.StatusBadRequest, "ja4_block_invalid_request"
	case errors.Is(err, ja4block.ErrPermissionDenied), errors.Is(err, ja4block.ErrScopeConflict):
		status, code = http.StatusForbidden, "ja4_block_permission_denied"
	case errors.Is(err, ja4block.ErrNotFound):
		status, code = http.StatusNotFound, "ja4_block_not_found"
	case errors.Is(err, ja4block.ErrSnapshotStale), errors.Is(err, ja4block.ErrSnapshotExpired):
		status, code = http.StatusPreconditionFailed, "ja4_block_snapshot_stale"
	case errors.Is(err, ja4block.ErrRevisionConflict), errors.Is(err, ja4block.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "ja4_block_conflict"
	case errors.Is(err, ja4block.ErrStoreUnavailable), errors.Is(err, ja4block.ErrDependencyUnavailable):
		status, code = http.StatusServiceUnavailable, "ja4_block_unavailable"
	}
	writeError(response, status, code, requestID)
}
func writeError(response http.ResponseWriter, status int, code, requestID string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{"code": code, "request_id": requestID}})
}
func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
