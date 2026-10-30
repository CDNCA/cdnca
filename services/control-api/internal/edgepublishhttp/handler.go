package edgepublishhttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

const (
	maxRequestBytes  = 64 << 10
	maxResponseBytes = 1 << 20
	maxCursorBytes   = 4096
)

var (
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	cursorPattern         = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	taskIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	traceparentPattern    = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
)

type Handler struct {
	service             *Service
	authenticate        AuthenticateFunc
	authenticateSession AuthenticateSessionFunc
	logger              *slog.Logger
	routes              *http.ServeMux
}

func NewHandler(service *Service, authenticate AuthenticateFunc, logger *slog.Logger) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidRequest
	}
	return nil, ErrUnsafeRolloutCommands
}

func newSessionHandler(service *Service, authenticate AuthenticateSessionFunc, logger *slog.Logger) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidRequest
	}
	return newHandler(service, func(request *http.Request) (identity.Principal, error) {
		session, err := authenticate(request)
		if err == nil {
			*request = *request.WithContext(context.WithValue(
				request.Context(), authenticatedCredentialContextKey{}, session,
			))
		}
		return session.Principal, err
	}, authenticate, logger)
}

type authenticatedCredentialContextKey struct{}

func newHandler(
	service *Service,
	authenticate AuthenticateFunc,
	authenticateSession AuthenticateSessionFunc,
	logger *slog.Logger,
) (*Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	handler := &Handler{service: service, authenticate: authenticate, authenticateSession: authenticateSession,
		logger: logger, routes: http.NewServeMux()}
	handler.routes.HandleFunc("POST /v1/admin/site-publications", handler.handlePublish)
	handler.routes.HandleFunc("POST /v1/admin/site-publications/{publication_id}/rollback", handler.handlePublicationRollback)
	handler.routes.HandleFunc("GET /v1/admin/site-publications", handler.handleListPublications(AudiencePlatform))
	handler.routes.HandleFunc("GET /v1/admin/site-publications/{publication_id}", handler.handleGetPublication(AudiencePlatform))
	handler.routes.HandleFunc("GET /v1/admin/site-rollouts", handler.handleListRollouts(AudiencePlatform))
	handler.routes.HandleFunc("POST /v1/admin/site-rollouts/reconciliations", handler.handleNodeConfigReconciliation)
	handler.routes.HandleFunc("GET /v1/admin/site-rollouts/{rollout_id}", handler.handleGetRollout(AudiencePlatform))
	handler.routes.HandleFunc("GET /v1/admin/site-rollouts/{rollout_id}/deployments", handler.handleListDeployments(AudiencePlatform))
	for _, operation := range []string{"start", "pause", "resume", "cancel", "retry-failed"} {
		handler.routes.HandleFunc("POST /v1/admin/site-rollouts/{rollout_id}/"+operation, handler.handleRolloutCommand(operation))
	}

	handler.routes.HandleFunc("GET /v1/site-publications", handler.handleListPublications(AudienceTenant))
	handler.routes.HandleFunc("POST /v1/site-publications", handler.handleTenantPublish)
	handler.routes.HandleFunc("GET /v1/site-publications/{publication_id}", handler.handleGetPublication(AudienceTenant))
	handler.routes.HandleFunc("GET /v1/site-rollouts", handler.handleListRollouts(AudienceTenant))
	handler.routes.HandleFunc("GET /v1/site-rollouts/{rollout_id}", handler.handleGetRollout(AudienceTenant))
	handler.routes.HandleFunc("GET /v1/site-rollouts/{rollout_id}/deployments", handler.handleListDeployments(AudienceTenant))
	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Request-ID", responseRequestID(r))
	h.routes.ServeHTTP(w, r)
}

type publishRequest struct {
	ConfigurationScopeID   string               `json:"configuration_scope_id"`
	ExpectedSourceRevision int64                `json:"expected_source_revision"`
	Target                 publishTarget        `json:"target"`
	HealthCheck            healthCheckRequest   `json:"health_check"`
	MaxAttempts            uint32               `json:"max_attempts"`
	Deadline               string               `json:"deadline"`
	Rollout                rolloutPolicyRequest `json:"rollout"`
}

type publishTarget struct {
	Kind           string   `json:"kind"`
	NodeIDs        []string `json:"node_ids,omitempty"`
	SnapshotID     string   `json:"snapshot_id,omitempty"`
	Revision       int64    `json:"revision,omitempty"`
	ResolverSHA256 string   `json:"resolver_sha256,omitempty"`
}

type rollbackRequest struct {
	ConfigurationScopeID string               `json:"configuration_scope_id"`
	Target               publishTarget        `json:"target"`
	HealthCheck          healthCheckRequest   `json:"health_check"`
	MaxAttempts          uint32               `json:"max_attempts"`
	Deadline             string               `json:"deadline"`
	Rollout              rolloutPolicyRequest `json:"rollout"`
}

type rolloutPolicyRequest struct {
	Strategy         string `json:"strategy"`
	CanarySize       uint32 `json:"canary_size"`
	BatchSize        uint32 `json:"batch_size"`
	FailureThreshold uint32 `json:"failure_threshold"`
	AutoStart        bool   `json:"auto_start"`
}

type healthCheckRequest struct {
	ActivationTimeoutMS          int64  `json:"activation_timeout_ms"`
	ObservationWindowMS          int64  `json:"observation_window_ms"`
	RequiredConsecutiveSuccesses uint32 `json:"required_consecutive_successes"`
}

type rolloutCommandRequest struct {
	ConfigurationScopeID string `json:"configuration_scope_id"`
	ExpectedRevision     int64  `json:"expected_revision"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	// Challenge names, for challenge_policy_unavailable, the node and site
	// whose JS challenge policy is missing (the page shows them).
	Challenge *challengeErrorDetails `json:"challenge,omitempty"`
	// Capability names, for node_capability_unavailable, the refused nodes
	// and the gated capability (the page lists the nodes to upgrade).
	Capability *capabilityErrorDetails `json:"capability,omitempty"`
	// RulePacks names, for rule_pack_unavailable, the refused nodes and the
	// rule packs the first one lacks (published automatically once they arrive).
	RulePacks *rulePackErrorDetails `json:"rule_packs,omitempty"`
	// Modules names, for entitlement_feature_denied, the module codes the
	// lease does not grant.
	Modules []string `json:"modules,omitempty"`
}

type capabilityErrorDetails struct {
	NodeID          string   `json:"node_id"`
	Capability      string   `json:"capability"`
	RequiredVersion uint32   `json:"required_version"`
	OtherNodeIDs    []string `json:"other_node_ids"`
}

type challengeErrorDetails struct {
	NodeID        string   `json:"node_id"`
	SiteID        string   `json:"site_id"`
	Domain        string   `json:"domain"`
	PolicyVersion uint64   `json:"policy_version"`
	OtherNodeIDs  []string `json:"other_node_ids"`
}

func challengeDetails(err error) *challengeErrorDetails {
	var refusal *edgepublish.ChallengePolicyUnavailableError
	if !errors.As(err, &refusal) {
		return nil
	}
	details := &challengeErrorDetails{NodeID: refusal.NodeID.String(), SiteID: refusal.SiteID, Domain: refusal.Domain,
		PolicyVersion: refusal.PolicyVersion, OtherNodeIDs: make([]string, len(refusal.OtherNodeIDs))}
	for index, nodeID := range refusal.OtherNodeIDs {
		details.OtherNodeIDs[index] = nodeID.String()
	}
	return details
}

type rulePackErrorDetails struct {
	NodeID       string   `json:"node_id"`
	SHA256       []string `json:"sha256"`
	OtherNodeIDs []string `json:"other_node_ids"`
	// AutoResume: the refused security activation is recorded and starts by
	// itself once the nodes have the packs (omitted otherwise).
	AutoResume bool `json:"auto_resume,omitempty"`
}

func rulePackDetails(err error) *rulePackErrorDetails {
	var refusal *edgepublish.RulePackUnavailableError
	if !errors.As(err, &refusal) {
		return nil
	}
	details := &rulePackErrorDetails{NodeID: refusal.NodeID.String(), SHA256: refusal.SHA256,
		OtherNodeIDs: make([]string, len(refusal.OtherNodeIDs)), AutoResume: refusal.AutoResume}
	for index, nodeID := range refusal.OtherNodeIDs {
		details.OtherNodeIDs[index] = nodeID.String()
	}
	return details
}

func capabilityDetails(err error) *capabilityErrorDetails {
	var refusal *edgepublish.TargetCapabilityError
	if !errors.As(err, &refusal) {
		return nil
	}
	details := &capabilityErrorDetails{NodeID: refusal.NodeID.String(), Capability: refusal.Capability.String(),
		RequiredVersion: refusal.Required, OtherNodeIDs: make([]string, len(refusal.OtherNodeIDs))}
	for index, nodeID := range refusal.OtherNodeIDs {
		details.OtherNodeIDs[index] = nodeID.String()
	}
	return details
}

func (h *Handler) handlePublish(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	metadata, err := parseWriteMetadata(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	var body publishRequest
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeError(w, r, ErrInvalidRequest)
		return
	}
	input, err := normalizePublish(body)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	result, err := h.service.PublishSession(r.Context(), session, input, metadata)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if result.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if err := writeJSON(w, http.StatusCreated, result); err != nil {
		h.writeError(w, r, err)
	}
}

func (h *Handler) handleTenantPublish(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	metadata, err := parseWriteMetadata(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	var body publishRequest
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeError(w, r, ErrInvalidRequest)
		return
	}
	input, err := normalizePublish(body)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	result, err := h.service.PublishTenantSession(r.Context(), session, input, metadata)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if result.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if err := writeJSON(w, http.StatusCreated, result); err != nil {
		h.writeError(w, r, err)
	}
}

func (h *Handler) handlePublicationRollback(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	metadata, err := parseWriteMetadata(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	publicationID, err := canonicalUUID(r.PathValue("publication_id"))
	if err != nil {
		h.writeError(w, r, ErrInvalidRequest)
		return
	}
	var body rollbackRequest
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeError(w, r, ErrInvalidRequest)
		return
	}
	input, err := normalizeRollback(body, publicationID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	result, err := h.service.RollbackSession(r.Context(), session, input, metadata)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if result.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if err := writeJSON(w, http.StatusCreated, result); err != nil {
		h.writeError(w, r, err)
	}
}

func (h *Handler) handleListPublications(audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := h.principal(w, r, audience)
		if !ok {
			return
		}
		scopeID, page, err := parsePageQuery(r, audience)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		result, err := h.service.ListPublications(r.Context(), principal, audience, scopeID,
			edgepublish.PublicationPageRequest{Limit: page.Limit, Cursor: page.Cursor})
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		if err := writeJSON(w, http.StatusOK, result); err != nil {
			h.writeError(w, r, err)
		}
	}
}

func (h *Handler) handleGetPublication(audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := h.principal(w, r, audience)
		if !ok {
			return
		}
		scopeID, err := parseDetailScope(r, audience)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		publicationID, err := canonicalUUID(r.PathValue("publication_id"))
		if err != nil {
			h.writeError(w, r, ErrInvalidRequest)
			return
		}
		result, err := h.service.GetPublication(r.Context(), principal, audience, scopeID, publicationID)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		if err := writeJSON(w, http.StatusOK, result); err != nil {
			h.writeError(w, r, err)
		}
	}
}

func (h *Handler) handleListRollouts(audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := h.principal(w, r, audience)
		if !ok {
			return
		}
		scopeID, page, err := parsePageQuery(r, audience)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		result, err := h.service.ListRollouts(r.Context(), principal, audience, scopeID,
			edgedeployment.RolloutPageRequest{Limit: page.Limit, Cursor: page.Cursor})
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		if err := writeJSON(w, http.StatusOK, result); err != nil {
			h.writeError(w, r, err)
		}
	}
}

func (h *Handler) handleGetRollout(audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := h.principal(w, r, audience)
		if !ok {
			return
		}
		scopeID, err := parseDetailScope(r, audience)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		rolloutID, err := canonicalUUID(r.PathValue("rollout_id"))
		if err != nil {
			h.writeError(w, r, ErrInvalidRequest)
			return
		}
		result, err := h.service.GetRollout(r.Context(), principal, audience, scopeID, rolloutID)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		w.Header().Set("ETag", quoteRevision(result.Revision))
		if err := writeJSON(w, http.StatusOK, result); err != nil {
			h.writeError(w, r, err)
		}
	}
}

func (h *Handler) handleListDeployments(audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := h.principal(w, r, audience)
		if !ok {
			return
		}
		scopeID, page, err := parsePageQuery(r, audience)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		rolloutID, err := canonicalUUID(r.PathValue("rollout_id"))
		if err != nil {
			h.writeError(w, r, ErrInvalidRequest)
			return
		}
		result, err := h.service.ListDeployments(r.Context(), principal, audience, scopeID, rolloutID,
			edgedeployment.DeploymentPageRequest{Limit: page.Limit, Cursor: page.Cursor})
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		if err := writeJSON(w, http.StatusOK, result); err != nil {
			h.writeError(w, r, err)
		}
	}
}

func (h *Handler) handleRolloutCommand(operation string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := h.session(w, r)
		if !ok {
			return
		}
		metadata, err := parseWriteMetadata(r)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		rolloutID, err := canonicalUUID(r.PathValue("rollout_id"))
		if err != nil {
			h.writeError(w, r, ErrInvalidRequest)
			return
		}
		var body rolloutCommandRequest
		if err := decodeJSON(w, r, &body); err != nil {
			h.writeError(w, r, ErrInvalidRequest)
			return
		}
		scopeID, err := canonicalUUID(body.ConfigurationScopeID)
		if err != nil || body.ExpectedRevision <= 0 {
			h.writeError(w, r, ErrInvalidRequest)
			return
		}
		input := RolloutCommandInput{
			ConfigurationScopeID: scopeID, RolloutID: rolloutID, ExpectedRevision: body.ExpectedRevision,
		}
		var result RolloutView
		switch operation {
		case "start":
			result, err = h.service.StartRollout(r.Context(), session, input, metadata)
		case "pause":
			result, err = h.service.PauseRollout(r.Context(), session, input, metadata)
		case "resume":
			result, err = h.service.ResumeRollout(r.Context(), session, input, metadata)
		case "cancel":
			result, err = h.service.CancelRollout(r.Context(), session, input, metadata)
		case "retry-failed":
			result, err = h.service.RetryFailedRollout(r.Context(), session, input, metadata)
		default:
			err = ErrInvalidRequest
		}
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		if result.Replayed {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		w.Header().Set("ETag", quoteRevision(result.Revision))
		if err := writeJSON(w, http.StatusOK, result); err != nil {
			h.writeError(w, r, err)
		}
	}
}

func (h *Handler) session(w http.ResponseWriter, r *http.Request) (AuthenticatedSession, bool) {
	if hasAPIKeyAuthorization(r) {
		h.writeError(w, r, ErrUnauthenticated)
		return AuthenticatedSession{}, false
	}
	if h.authenticateSession == nil {
		h.writeError(w, r, ErrUnsafeRolloutCommands)
		return AuthenticatedSession{}, false
	}
	session, err := h.authenticateSession(r)
	if err != nil {
		h.writeError(w, r, err)
		return AuthenticatedSession{}, false
	}
	if session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil ||
		session.SessionID == uuid.Nil || session.rawToken() == "" {
		h.writeError(w, r, ErrUnauthenticated)
		return AuthenticatedSession{}, false
	}
	return session, true
}

func (h *Handler) principal(w http.ResponseWriter, r *http.Request, audience string) (identity.Principal, bool) {
	if audience == AudiencePlatform && hasAPIKeyAuthorization(r) {
		h.writeError(w, r, ErrUnauthenticated)
		return identity.Principal{}, false
	}
	principal, err := h.authenticate(r)
	if err != nil {
		h.writeError(w, r, err)
		return identity.Principal{}, false
	}
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		h.writeError(w, r, ErrUnauthenticated)
		return identity.Principal{}, false
	}
	return principal, true
}

func hasAPIKeyAuthorization(request *http.Request) bool {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	scheme, _, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	return found && strings.EqualFold(scheme, "CdncaKey")
}

func normalizePublish(body publishRequest) (PublishInput, error) {
	scopeID, err := canonicalUUID(body.ConfigurationScopeID)
	if err != nil || body.ExpectedSourceRevision <= 0 || body.MaxAttempts == 0 || body.MaxAttempts > 10 {
		return PublishInput{}, ErrInvalidRequest
	}
	deadline, err := time.Parse(time.RFC3339Nano, body.Deadline)
	if err != nil || body.Deadline == "" {
		return PublishInput{}, ErrInvalidRequest
	}
	if body.HealthCheck.ActivationTimeoutMS <= 0 || body.HealthCheck.ActivationTimeoutMS > int64((24*time.Hour)/time.Millisecond) ||
		body.HealthCheck.ObservationWindowMS <= 0 || body.HealthCheck.ObservationWindowMS > int64((24*time.Hour)/time.Millisecond) ||
		body.HealthCheck.RequiredConsecutiveSuccesses == 0 || body.HealthCheck.RequiredConsecutiveSuccesses > 100 {
		return PublishInput{}, ErrInvalidRequest
	}
	result := PublishInput{
		ConfigurationScopeID: scopeID, ExpectedSourceRevision: body.ExpectedSourceRevision,
		TargetKind: body.Target.Kind, MaxAttempts: body.MaxAttempts, Deadline: deadline,
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout:            time.Duration(body.HealthCheck.ActivationTimeoutMS) * time.Millisecond,
			ObservationWindow:            time.Duration(body.HealthCheck.ObservationWindowMS) * time.Millisecond,
			RequiredConsecutiveSuccesses: body.HealthCheck.RequiredConsecutiveSuccesses,
		},
		Rollout: edgedeployment.RolloutPolicy{
			Strategy: body.Rollout.Strategy, CanarySize: body.Rollout.CanarySize,
			BatchSize: body.Rollout.BatchSize, FailureThreshold: body.Rollout.FailureThreshold,
			AutoStart: body.Rollout.AutoStart,
		},
	}
	switch body.Target.Kind {
	case TargetNodes:
		if len(body.Target.NodeIDs) == 0 || len(body.Target.NodeIDs) > 10000 || body.Target.SnapshotID != "" ||
			body.Target.Revision != 0 || body.Target.ResolverSHA256 != "" {
			return PublishInput{}, ErrInvalidRequest
		}
		seen := make(map[uuid.UUID]struct{}, len(body.Target.NodeIDs))
		result.NodeIDs = make([]uuid.UUID, len(body.Target.NodeIDs))
		for index, encoded := range body.Target.NodeIDs {
			result.NodeIDs[index], err = canonicalUUID(encoded)
			if err != nil {
				return PublishInput{}, ErrInvalidRequest
			}
			if _, exists := seen[result.NodeIDs[index]]; exists {
				return PublishInput{}, ErrInvalidRequest
			}
			seen[result.NodeIDs[index]] = struct{}{}
		}
	case TargetLineGroup:
		if len(body.Target.NodeIDs) != 0 || body.Target.Revision <= 0 {
			return PublishInput{}, ErrInvalidRequest
		}
		snapshotID, parseErr := canonicalUUID(body.Target.SnapshotID)
		resolverDigest, digestErr := parseSHA256(body.Target.ResolverSHA256)
		if parseErr != nil || digestErr != nil {
			return PublishInput{}, ErrInvalidRequest
		}
		result.TargetSnapshot = &edgepublish.TargetSnapshotReference{
			ID: snapshotID, Revision: body.Target.Revision, SHA256: resolverDigest,
		}
	default:
		return PublishInput{}, ErrInvalidRequest
	}
	return result, nil
}

func normalizeRollback(body rollbackRequest, publicationID uuid.UUID) (RollbackInput, error) {
	if publicationID == uuid.Nil {
		return RollbackInput{}, ErrInvalidRequest
	}
	base, err := normalizePublish(publishRequest{
		ConfigurationScopeID:   body.ConfigurationScopeID,
		ExpectedSourceRevision: 1,
		Target:                 body.Target, HealthCheck: body.HealthCheck,
		MaxAttempts: body.MaxAttempts, Deadline: body.Deadline,
		Rollout: body.Rollout,
	})
	if err != nil {
		return RollbackInput{}, err
	}
	return RollbackInput{
		ConfigurationScopeID: base.ConfigurationScopeID, PublicationID: publicationID,
		TargetKind: base.TargetKind, NodeIDs: base.NodeIDs, TargetSnapshot: base.TargetSnapshot,
		HealthCheck: base.HealthCheck, MaxAttempts: base.MaxAttempts, Deadline: base.Deadline,
		Rollout: base.Rollout,
	}, nil
}

func parseWriteMetadata(r *http.Request) (WriteMetadata, error) {
	key, err := singleHeader(r, "Idempotency-Key", true)
	if err != nil || !idempotencyKeyPattern.MatchString(key) {
		return WriteMetadata{}, ErrInvalidRequest
	}
	rawRequestID, err := singleHeader(r, "X-Request-ID", true)
	if err != nil {
		return WriteMetadata{}, ErrInvalidRequest
	}
	requestID, err := canonicalUUID(rawRequestID)
	if err != nil {
		return WriteMetadata{}, ErrInvalidRequest
	}
	correlationID := requestID
	encodedCorrelationID, err := singleHeader(r, "X-Correlation-ID", false)
	if err != nil {
		return WriteMetadata{}, ErrInvalidRequest
	}
	if encoded := encodedCorrelationID; encoded != "" {
		correlationID, err = canonicalUUID(encoded)
		if err != nil {
			return WriteMetadata{}, ErrInvalidRequest
		}
	}
	traceparent, err := singleHeader(r, "Traceparent", true)
	if err != nil || !validTraceparent(traceparent) {
		return WriteMetadata{}, ErrInvalidRequest
	}
	var taskID *string
	encodedTaskID, err := singleHeader(r, "X-Task-ID", false)
	if err != nil {
		return WriteMetadata{}, ErrInvalidRequest
	}
	if value := encodedTaskID; value != "" {
		if !taskIDPattern.MatchString(value) {
			return WriteMetadata{}, ErrInvalidRequest
		}
		taskID = &value
	}
	return WriteMetadata{
		IdempotencyKey: key, RequestID: requestID.String(), CorrelationID: correlationID.String(),
		Traceparent: traceparent, TaskID: taskID,
	}, nil
}

func singleHeader(r *http.Request, name string, required bool) (string, error) {
	values := r.Header.Values(name)
	if len(values) > 1 || required && len(values) != 1 {
		return "", ErrInvalidRequest
	}
	if len(values) == 0 {
		return "", nil
	}
	if values[0] == "" {
		return "", ErrInvalidRequest
	}
	return values[0], nil
}

type pageQuery struct {
	Limit  int
	Cursor string
}

func parsePageQuery(r *http.Request, audience string) (*uuid.UUID, pageQuery, error) {
	allowed := map[string]bool{"limit": true, "cursor": true}
	if audience == AudiencePlatform {
		allowed["scope_id"] = true
	} else if _, exists := r.URL.Query()["scope_id"]; exists {
		return nil, pageQuery{}, ErrPermissionDenied
	}
	if err := validateQuery(r, allowed); err != nil {
		return nil, pageQuery{}, err
	}
	scopeID, err := queryScope(r, audience)
	if err != nil {
		return nil, pageQuery{}, err
	}
	var page pageQuery
	if encoded := r.URL.Query().Get("limit"); encoded != "" {
		page.Limit, err = strconv.Atoi(encoded)
		if err != nil || page.Limit < 1 || page.Limit > 100 {
			return nil, pageQuery{}, ErrInvalidRequest
		}
	}
	page.Cursor = r.URL.Query().Get("cursor")
	if page.Cursor != "" && (len(page.Cursor) > maxCursorBytes || !cursorPattern.MatchString(page.Cursor)) {
		return nil, pageQuery{}, ErrInvalidRequest
	}
	return scopeID, page, nil
}

func parseDetailScope(r *http.Request, audience string) (*uuid.UUID, error) {
	allowed := map[string]bool{}
	if audience == AudiencePlatform {
		allowed["scope_id"] = true
	} else if _, exists := r.URL.Query()["scope_id"]; exists {
		return nil, ErrPermissionDenied
	}
	if err := validateQuery(r, allowed); err != nil {
		return nil, err
	}
	return queryScope(r, audience)
}

func queryScope(r *http.Request, audience string) (*uuid.UUID, error) {
	if audience == AudienceTenant {
		return nil, nil
	}
	if audience != AudiencePlatform {
		return nil, ErrInvalidRequest
	}
	scopeID, err := canonicalUUID(r.URL.Query().Get("scope_id"))
	if err != nil {
		return nil, ErrInvalidRequest
	}
	return &scopeID, nil
}

func validateQuery(r *http.Request, allowed map[string]bool) error {
	for key, values := range r.URL.Query() {
		if !allowed[key] || len(values) != 1 {
			return ErrInvalidRequest
		}
	}
	return nil
}

func canonicalUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, ErrInvalidRequest
	}
	return parsed, nil
}

func parseSHA256(value string) ([32]byte, error) {
	var result [32]byte
	if len(value) != hex.EncodedLen(len(result)) || strings.ToLower(value) != value {
		return result, ErrInvalidRequest
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, ErrInvalidRequest
	}
	copy(result[:], decoded)
	if result == ([32]byte{}) {
		return result, ErrInvalidRequest
	}
	return result, nil
}

func validTraceparent(value string) bool {
	matches := traceparentPattern.FindStringSubmatch(value)
	return len(matches) == 4 && matches[1] != strings.Repeat("0", 32) && matches[2] != strings.Repeat("0", 16)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	contentType, err := singleHeader(r, "Content-Type", true)
	if err != nil {
		return ErrInvalidRequest
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return ErrInvalidRequest
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func responseRequestID(r *http.Request) string {
	if parsed, err := canonicalUUID(r.Header.Get("X-Request-ID")); err == nil {
		return parsed.String()
	}
	return uuid.NewString()
}

func quoteRevision(revision int64) string {
	return `"` + strconv.FormatInt(revision, 10) + `"`
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := classifyError(err)
	if status == http.StatusServiceUnavailable {
		h.logger.ErrorContext(r.Context(), "site publication request failed",
			"request_id", w.Header().Get("X-Request-ID"), "method", r.Method, "path", r.URL.Path, "error", err)
	}
	_ = writeJSON(w, status, newErrorEnvelope(code, message, w.Header().Get("X-Request-ID"), err))
}

// newErrorEnvelope is the error body of both handlers of the site publication
// API; the refusal details travel only with their own code (ErrorEnvelope).
func newErrorEnvelope(code, message, requestID string, err error) errorEnvelope {
	body := apiError{Code: code, Message: message, RequestID: requestID}
	switch code {
	case "challenge_policy_unavailable":
		body.Challenge = challengeDetails(err)
	case "node_capability_unavailable":
		body.Capability = capabilityDetails(err)
	case "rule_pack_unavailable":
		body.RulePacks = rulePackDetails(err)
	case "entitlement_feature_denied":
		var refusal *edgepublish.ModuleNotEntitledError
		if errors.As(err, &refusal) {
			body.Modules = append([]string(nil), refusal.Modules...)
		}
	}
	return errorEnvelope{Error: body}
}

func classifyError(err error) (int, string, string) {
	switch {
	case errors.Is(err, edgepublish.ErrCrossScopeConflict):
		// The wrapped reason names the node and the rule, not the other tenant.
		return http.StatusConflict, "node_scope_conflict", strings.TrimPrefix(err.Error(),
			edgepublish.ErrCrossScopeConflict.Error()+": ")
	case errors.As(err, new(*edgepublish.ChallengePolicyUnavailableError)):
		// Names the node and the site whose JS challenge policy it lacks.
		var challenge *edgepublish.ChallengePolicyUnavailableError
		errors.As(err, &challenge)
		return http.StatusUnprocessableEntity, "challenge_policy_unavailable", challenge.Error()
	case errors.As(err, new(*securitypolicy.QuickBlockSiteOverrideError)):
		// A rollback clone the sites' own quick block cannot carry; names them.
		var conflict *securitypolicy.QuickBlockSiteOverrideError
		errors.As(err, &conflict)
		return http.StatusUnprocessableEntity, "quick_block_site_override_conflict", conflict.Error()
	case errors.As(err, new(*edgepublish.RulePackUnavailableError)):
		// Names the nodes whose node artifact set lacks the sites' rule packs.
		var packs *edgepublish.RulePackUnavailableError
		errors.As(err, &packs)
		return http.StatusUnprocessableEntity, "rule_pack_unavailable", packs.Error()
	case errors.As(err, new(*edgepublish.CRSOutOfProfileError)):
		// Names the site and the modsecurity pack outside its CRS profile.
		var profile *edgepublish.CRSOutOfProfileError
		errors.As(err, &profile)
		return http.StatusUnprocessableEntity, "rule_pack_out_of_profile", profile.Error()
	case errors.As(err, new(*edgepublish.TargetCapabilityError)):
		// The message names the node, its agent version and the missing
		// feature so the operator knows which node to upgrade.
		var capability *edgepublish.TargetCapabilityError
		errors.As(err, &capability)
		return http.StatusUnprocessableEntity, "node_capability_unavailable", capability.Error()
	case errors.Is(err, edgepublish.ErrModuleNotEntitled):
		return http.StatusForbidden, "entitlement_feature_denied", "the local entitlement lease does not grant a module this configuration uses"
	case errors.Is(err, packageaddon.ErrQuotaExceeded):
		return http.StatusConflict, "package_resource_quota_exceeded", "package resource quota exceeded"
	case errors.Is(err, packageaddon.ErrFeatureDenied):
		return http.StatusForbidden, "package_feature_denied", "package feature is unavailable"
	case errors.Is(err, packageaddon.ErrSubscriptionInactive):
		return http.StatusConflict, "package_subscription_inactive", "package subscription is not active"
	case errors.Is(err, packageaddon.ErrInUse), errors.Is(err, packageaddon.ErrWAFInUse):
		return http.StatusConflict, "package_addon_in_use", "package resources are still in use"
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, edgepublish.ErrUnauthenticated),
		errors.Is(err, edgedeployment.ErrUnauthenticated), errors.Is(err, identity.ErrInvalidSession):
		return http.StatusUnauthorized, "authentication_required", "authentication is required"
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, edgepublish.ErrPermissionDenied),
		errors.Is(err, edgedeployment.ErrPermissionDenied), errors.Is(err, identity.ErrPermissionDenied),
		errors.Is(err, securityactivation.ErrPermissionDenied):
		return http.StatusForbidden, "permission_denied", "permission is required"
	case errors.Is(err, securityactivation.ErrExpiryTooLate):
		return http.StatusBadRequest, "activation_expiry_too_late", "expires_at must be within 15 minutes"
	case errors.Is(err, securityactivation.ErrNoTargetNodes):
		return http.StatusUnprocessableEntity, "no_target_nodes", "the site's package line groups serve no active node"
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, edgepublish.ErrInvalidInput),
		errors.Is(err, edgedeployment.ErrInvalidInput), errors.Is(err, securityactivation.ErrInvalidInput):
		return http.StatusBadRequest, "validation_error", "request fields are invalid"
	case errors.Is(err, edgepublish.ErrNotFound), errors.Is(err, edgedeployment.ErrNotFound),
		errors.Is(err, edgedeployment.ErrConfigNotFound), errors.Is(err, edgedeployment.ErrNodeNotFound),
		errors.Is(err, securityactivation.ErrNotFound):
		return http.StatusNotFound, "publication_resource_not_found", "publication resource was not found"
	case errors.Is(err, edgepublish.ErrAlreadyPublished):
		// P10: current, but already published (not stale).
		return http.StatusPreconditionFailed, "source_revision_already_published", "the current source revision is already published"
	case errors.Is(err, edgepublish.ErrRevisionConflict), errors.Is(err, edgedeployment.ErrRevisionConflict):
		return http.StatusPreconditionFailed, "revision_conflict", "the expected revision is stale"
	case errors.Is(err, edgepublish.ErrIdempotencyConflict), errors.Is(err, edgedeployment.ErrIdempotencyConflict):
		return http.StatusConflict, "idempotency_conflict", "the idempotency key was used with different input"
	case errors.Is(err, securityactivation.ErrIdempotencyConflict):
		return http.StatusConflict, "idempotency_conflict", "the idempotency key was used with different input"
	case errors.Is(err, securityactivation.ErrSiteLocked):
		return http.StatusConflict, "site_locked", "site is locked by a platform administrator"
	case errors.Is(err, securityactivation.ErrPolicyDeleted):
		return http.StatusConflict, "security_policy_deleted", "a deleted security policy cannot be bound to a site"
	case errors.Is(err, edgepublish.ErrSiteL2Unavailable):
		return http.StatusConflict, "site_l2_unavailable", "a site's custom L2 configuration has no L2 node in the publication target (网站自定义 L2 的节点不在本次发布目标的 L2 中；请改选 L2 配置或改为当前套餐/不配置)"
	case errors.Is(err, edgepublish.ErrTargetSnapshotConflict):
		return http.StatusConflict, "target_snapshot_conflict", "the target snapshot no longer matches"
	case errors.Is(err, edgedeployment.ErrDeadlineExpired):
		return http.StatusConflict, "publication_deadline_expired", "the rollout deadline has expired"
	case errors.Is(err, edgedeployment.ErrNodeDeploymentActive), errors.Is(err, edgedeployment.ErrInvalidTransition),
		errors.Is(err, edgedeployment.ErrRetriesExhausted), errors.Is(err, edgedeployment.ErrNodeReconciliationRequired),
		errors.Is(err, edgedeployment.ErrReconciliationNotRequired), errors.Is(err, edgedeployment.ErrReconciliationSource),
		errors.Is(err, edgedeployment.ErrConfigNotReleasable), errors.Is(err, edgedeployment.ErrConfigurationScopeConflict),
		errors.Is(err, edgedeployment.ErrRollbackStateConflict), errors.Is(err, securityactivation.ErrConflict),
		errors.Is(err, securityactivation.ErrNotHealthy), errors.Is(err, securityactivation.ErrSourceRevisionConflict):
		return http.StatusConflict, "publication_state_conflict", "the publication state does not allow this operation"
	case errors.Is(err, edgepublish.ErrEntitlementDenied):
		return http.StatusUnprocessableEntity, "publication_not_allowed", "the current entitlement does not allow publication"
	case errors.Is(err, edgepublish.ErrNoActiveResources), errors.Is(err, edgepublish.ErrTLSMaterialUnavailable),
		errors.Is(err, edgepublish.ErrTargetIneligible):
		return http.StatusUnprocessableEntity, "publication_not_ready", "the requested configuration cannot be published"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrInvalidResponse), errors.Is(err, edgepublish.ErrSigningFailed),
		errors.Is(err, edgepublish.ErrPersistence), errors.Is(err, ErrUnsafeRolloutCommands),
		errors.Is(err, securityactivation.ErrUnavailable):
		return http.StatusServiceUnavailable, "publication_service_unavailable", "the publication service is unavailable"
	default:
		return http.StatusServiceUnavailable, "publication_service_unavailable", "the publication service is unavailable"
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) error {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("%w: encode response", ErrInvalidResponse)
	}
	if encoded.Len() > maxResponseBytes {
		return fmt.Errorf("%w: response exceeds limit", ErrInvalidResponse)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(encoded.Len()))
	w.WriteHeader(status)
	_, err := w.Write(encoded.Bytes())
	return err
}
