package edgepublishhttp

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

const (
	securityActivationReadPermission   = "security_policies.read"
	securityActivationManagePermission = "security_policies.manage"
)

type SecurityActivationDomain interface {
	Status(context.Context, securitypolicy.Actor, uuid.UUID, string) (securityactivation.StatusResult, error)
	Start(context.Context, securitypolicy.Actor, securityactivation.StartInput) (securityactivation.StartResult, error)
	Get(context.Context, securitypolicy.Actor, uuid.UUID) (securityactivation.Candidate, error)
	Reconcile(context.Context, securitypolicy.Actor, securityactivation.ReconcileInput) (securityactivation.ReconcileResult, error)
	Rollback(context.Context, securitypolicy.Actor, securityactivation.RollbackInput) (securityactivation.StartResult, error)
	RebindStatus(context.Context, securitypolicy.Actor, string) (securityactivation.RebindStatus, error)
	// SiteTenantScope is the tenant scope a start for the site runs in (the
	// site's scope for a platform administrator, site-parity3b).
	SiteTenantScope(context.Context, securitypolicy.Actor, uuid.UUID) (uuid.UUID, error)
}

type SecurityActivationHandler struct {
	domain       SecurityActivationDomain
	authenticate AuthenticateSessionFunc
	logger       *slog.Logger
	routes       *http.ServeMux
}

type securityActivationCreateRequest struct {
	SiteID                      uuid.UUID   `json:"site_id"`
	PolicyID                    uuid.UUID   `json:"policy_id"`
	PolicyVersion               int64       `json:"policy_version"`
	ExpectedBindingRevision     int64       `json:"expected_binding_revision"`
	ExpectedActivePolicyVersion int64       `json:"expected_active_policy_version"`
	TargetNodeIDs               []uuid.UUID `json:"target_node_ids"`
	CanarySize                  int         `json:"canary_size"`
	ExpiresAt                   time.Time   `json:"expires_at"`
	// Detach (sec-rebind): withdraw the site's active library of the kind.
	Detach bool `json:"detach,omitempty"`
}

type securityActivationReconcileRequest struct {
	PromotionCAS securityactivation.PromotionCAS `json:"promotion_cas"`
}

type securityActivationRollbackRequest struct {
	SourcePolicyVersion         int64       `json:"source_policy_version"`
	ExpectedBindingRevision     int64       `json:"expected_binding_revision"`
	ExpectedActivePolicyVersion int64       `json:"expected_active_policy_version"`
	TargetNodeIDs               []uuid.UUID `json:"target_node_ids"`
	CanarySize                  int         `json:"canary_size"`
	ExpiresAt                   time.Time   `json:"expires_at"`
}

func NewSecurityActivationHandler(
	domain SecurityActivationDomain,
	authenticate AuthenticateSessionFunc,
	logger *slog.Logger,
) (*SecurityActivationHandler, error) {
	if domain == nil || authenticate == nil {
		return nil, ErrInvalidRuntimeConfig
	}
	if logger == nil {
		logger = slog.Default()
	}
	handler := &SecurityActivationHandler{
		domain: domain, authenticate: authenticate, logger: logger, routes: http.NewServeMux(),
	}
	handler.routes.HandleFunc("GET /v1/site-publications/security-activations", handler.handleStatus)
	handler.routes.HandleFunc("POST /v1/site-publications/security-activations", handler.handleStart)
	handler.routes.HandleFunc("GET /v1/site-publications/security-activations/rebind-status", handler.handleRebindStatus)
	handler.routes.HandleFunc("GET /v1/site-publications/security-activations/{candidate_id}", handler.handleGet)
	handler.routes.HandleFunc("POST /v1/site-publications/security-activations/{candidate_id}/reconcile", handler.handleReconcile)
	handler.routes.HandleFunc("POST /v1/site-publications/security-activations/{candidate_id}/rollback", handler.handleRollback)
	return handler, nil
}

func (handler *SecurityActivationHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Request-ID", responseRequestID(request))
	handler.routes.ServeHTTP(writer, request)
}

func (handler *SecurityActivationHandler) handleStatus(writer http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(writer, request, securityActivationReadPermission)
	if !ok {
		return
	}
	if err := validateQuery(request, map[string]bool{"site_id": true, "policy_kind": true}); err != nil {
		handler.writeError(writer, request, err)
		return
	}
	siteID, err := canonicalUUID(request.URL.Query().Get("site_id"))
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	policyKind := request.URL.Query().Get("policy_kind")
	if policyKind != securitypolicy.KindWAF && policyKind != securitypolicy.KindCC && policyKind != securitypolicy.KindACL {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	result, err := handler.domain.Status(request.Context(), actor, siteID, policyKind)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	if err := writeJSON(writer, http.StatusOK, result); err != nil {
		handler.writeError(writer, request, err)
	}
}

func (handler *SecurityActivationHandler) handleStart(writer http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(writer, request, securityActivationManagePermission)
	if !ok {
		return
	}
	metadata, err := parseWriteMetadata(request)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	var body securityActivationCreateRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	tenantScopeID, err := handler.domain.SiteTenantScope(request.Context(), actor, body.SiteID)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	result, err := handler.domain.Start(request.Context(), actor, securityactivation.StartInput{
		TenantScopeID: tenantScopeID, SiteID: body.SiteID, PolicyID: body.PolicyID,
		PolicyVersion: body.PolicyVersion, ExpectedBindingRevision: body.ExpectedBindingRevision,
		ExpectedActivePolicyVersion: body.ExpectedActivePolicyVersion,
		TargetNodeIDs:               body.TargetNodeIDs, CanarySize: body.CanarySize,
		IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID,
		CorrelationID: metadata.CorrelationID, Traceparent: metadata.Traceparent,
		TaskID: cloneString(metadata.TaskID), ExpiresAt: body.ExpiresAt, Detach: body.Detach,
	})
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	if result.Replayed {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	if err := writeJSON(writer, http.StatusCreated, result); err != nil {
		handler.writeError(writer, request, err)
	}
}

// handleRebindStatus: how many of the tenant's sites bound to a library of
// policy_kind still run an older version, and how many of those its package
// does not entitle (the rules page's "N 个站点因套餐未开通未下发").
func (handler *SecurityActivationHandler) handleRebindStatus(writer http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(writer, request, securityActivationReadPermission)
	if !ok {
		return
	}
	// A tenant-wide summary: a platform session has no tenant of its own.
	if actor.ScopeKind != AudienceTenant {
		handler.writeError(writer, request, ErrPermissionDenied)
		return
	}
	if err := validateQuery(request, map[string]bool{"policy_kind": true}); err != nil {
		handler.writeError(writer, request, err)
		return
	}
	policyKind := request.URL.Query().Get("policy_kind")
	if policyKind != securitypolicy.KindWAF && policyKind != securitypolicy.KindCC {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	result, err := handler.domain.RebindStatus(request.Context(), actor, policyKind)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	if err := writeJSON(writer, http.StatusOK, result); err != nil {
		handler.writeError(writer, request, err)
	}
}

func (handler *SecurityActivationHandler) handleGet(writer http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(writer, request, securityActivationReadPermission)
	if !ok {
		return
	}
	if err := validateQuery(request, map[string]bool{}); err != nil {
		handler.writeError(writer, request, err)
		return
	}
	candidateID, err := canonicalUUID(request.PathValue("candidate_id"))
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	result, err := handler.domain.Get(request.Context(), actor, candidateID)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	if err := writeJSON(writer, http.StatusOK, result); err != nil {
		handler.writeError(writer, request, err)
	}
}

func (handler *SecurityActivationHandler) handleReconcile(writer http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(writer, request, securityActivationManagePermission)
	if !ok {
		return
	}
	metadata, candidateID, ok := handler.writeRequest(writer, request)
	if !ok {
		return
	}
	var body securityActivationReconcileRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	result, err := handler.domain.Reconcile(request.Context(), actor, securityactivation.ReconcileInput{
		CandidateID: candidateID, PromotionCAS: body.PromotionCAS,
		IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID,
		CorrelationID: metadata.CorrelationID, Traceparent: metadata.Traceparent,
		TaskID: cloneString(metadata.TaskID),
	})
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	if result.Replayed {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	if err := writeJSON(writer, http.StatusOK, result); err != nil {
		handler.writeError(writer, request, err)
	}
}

func (handler *SecurityActivationHandler) handleRollback(writer http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(writer, request, securityActivationManagePermission)
	if !ok {
		return
	}
	metadata, candidateID, ok := handler.writeRequest(writer, request)
	if !ok {
		return
	}
	var body securityActivationRollbackRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	result, err := handler.domain.Rollback(request.Context(), actor, securityactivation.RollbackInput{
		CandidateID: candidateID, SourcePolicyVersion: body.SourcePolicyVersion,
		ExpectedBindingRevision:     body.ExpectedBindingRevision,
		ExpectedActivePolicyVersion: body.ExpectedActivePolicyVersion,
		TargetNodeIDs:               body.TargetNodeIDs, CanarySize: body.CanarySize,
		IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID,
		CorrelationID: metadata.CorrelationID, Traceparent: metadata.Traceparent,
		TaskID: cloneString(metadata.TaskID), ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	if result.Replayed {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	if err := writeJSON(writer, http.StatusCreated, result); err != nil {
		handler.writeError(writer, request, err)
	}
}

func (handler *SecurityActivationHandler) actor(
	writer http.ResponseWriter,
	request *http.Request,
	permission string,
) (securitypolicy.Actor, bool) {
	session, err := handler.authenticate(request)
	if err != nil {
		handler.writeError(writer, request, err)
		return securitypolicy.Actor{}, false
	}
	principal := session.Principal
	// site-parity3b: a platform administrator publishes a tenant site's
	// library from the site edit page; the store resolves the site's tenant
	// scope and checks the platform role in the same transaction.
	allowed := slices.Contains(principal.Permissions, permission)
	switch principal.ScopeKind {
	case AudienceTenant:
	case AudiencePlatform:
		allowed = allowed || slices.Contains(principal.Permissions, "platform.admin")
	default:
		allowed = false
	}
	if !allowed {
		handler.writeError(writer, request, ErrPermissionDenied)
		return securitypolicy.Actor{}, false
	}
	return securitypolicy.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}, true
}

func (handler *SecurityActivationHandler) writeRequest(
	writer http.ResponseWriter,
	request *http.Request,
) (WriteMetadata, uuid.UUID, bool) {
	metadata, err := parseWriteMetadata(request)
	if err != nil {
		handler.writeError(writer, request, err)
		return WriteMetadata{}, uuid.Nil, false
	}
	candidateID, err := canonicalUUID(request.PathValue("candidate_id"))
	if err != nil {
		handler.writeError(writer, request, err)
		return WriteMetadata{}, uuid.Nil, false
	}
	return metadata, candidateID, true
}

func (handler *SecurityActivationHandler) writeError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message := classifyError(err)
	if status == http.StatusServiceUnavailable {
		handler.logger.ErrorContext(request.Context(), "security activation request failed",
			"request_id", writer.Header().Get("X-Request-ID"), "method", request.Method,
			"path", request.URL.Path, "error", err)
	}
	_ = writeJSON(writer, status, newErrorEnvelope(code, message, writer.Header().Get("X-Request-ID"), err))
}
