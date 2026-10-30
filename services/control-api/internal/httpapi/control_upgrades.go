package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const controlUpgradeBodyLimit = 1 << 20

var (
	errControlUpgradeUnsupportedMediaType = errors.New("unsupported control upgrade media type")
	errControlUpgradeBodyTooLarge         = errors.New("control upgrade body too large")
)

type controlUpgradeWriteResponse struct {
	Data     controlUpgradeRolloutDetailResponse `json:"data"`
	Replayed bool                                `json:"replayed"`
}

type controlUpgradeDetailResponse struct {
	Data controlUpgradeRolloutDetailResponse `json:"data"`
}

type controlUpgradeRolloutSummaryResponse struct {
	ID                        string                          `json:"id"`
	SchemaVersion             uint16                          `json:"schema_version"`
	InstallationID            string                          `json:"installation_id"`
	Component                 string                          `json:"component"`
	CurrentVersion            string                          `json:"current_version"`
	TargetVersion             string                          `json:"target_version"`
	State                     controlupgrade.PlanState        `json:"state"`
	Completion                controlupgrade.PlanCompletion   `json:"completion"`
	Revision                  string                          `json:"revision"`
	AutomaticRollback         bool                            `json:"automatic_rollback"`
	ParentGrantID             string                          `json:"parent_grant_id"`
	ArtifactID                string                          `json:"artifact_id"`
	ArtifactSHA256            string                          `json:"artifact_sha256"`
	ArtifactSizeBytes         int64                           `json:"artifact_size_bytes"`
	RollbackArtifactID        string                          `json:"rollback_artifact_id"`
	RollbackArtifactSHA256    string                          `json:"rollback_artifact_sha256"`
	RollbackArtifactSizeBytes int64                           `json:"rollback_artifact_size_bytes"`
	ActiveBatch               int                             `json:"active_batch"`
	TotalNodes                int                             `json:"total_nodes"`
	PendingNodes              int                             `json:"pending_nodes"`
	DispatchedNodes           int                             `json:"dispatched_nodes"`
	HealthyNodes              int                             `json:"healthy_nodes"`
	FailedNodes               int                             `json:"failed_nodes"`
	RolledBackNodes           int                             `json:"rolled_back_nodes"`
	Blockers                  []controlupgrade.RolloutBlocker `json:"blockers"`
	CreatedAt                 time.Time                       `json:"created_at"`
	UpdatedAt                 time.Time                       `json:"updated_at"`
}

type controlUpgradeRolloutNodeResponse struct {
	NodeID           string                       `json:"node_id"`
	AgentVersion     string                       `json:"agent_version"`
	ProtocolVersion  uint32                       `json:"protocol_version"`
	State            controlupgrade.PlanNodeState `json:"state"`
	DispatchRevision string                       `json:"dispatch_revision"`
}

type controlUpgradeRolloutEventResponse struct {
	ID       string                   `json:"id"`
	Revision string                   `json:"revision"`
	From     controlupgrade.PlanState `json:"from"`
	To       controlupgrade.PlanState `json:"to"`
	Action   string                   `json:"action"`
	Reason   string                   `json:"reason"`
	BatchID  string                   `json:"batch_id"`
	NodeID   string                   `json:"node_id"`
	// OccurredAt is when the event was committed; omitted on write replies.
	OccurredAt *time.Time `json:"occurred_at,omitempty"`
}

type controlUpgradeStatusReceiptResponse struct {
	Schema           string                              `json:"schema"`
	StatusID         string                              `json:"status_id"`
	StatusRevision   string                              `json:"status_revision"`
	CommandID        string                              `json:"command_id"`
	PlanID           string                              `json:"plan_id"`
	PlanRevision     string                              `json:"plan_revision"`
	BatchID          string                              `json:"batch_id"`
	InstallationID   string                              `json:"installation_id"`
	NodeID           string                              `json:"node_id"`
	Action           string                              `json:"action"`
	CommandSHA256    string                              `json:"command_sha256"`
	StatusSHA256     string                              `json:"status_sha256"`
	State            string                              `json:"state"`
	ObservedAt       time.Time                           `json:"observed_at"`
	DeliveryStream   string                              `json:"delivery_stream"`
	DeliveryConsumer string                              `json:"delivery_consumer"`
	DeliverySequence string                              `json:"delivery_sequence"`
	ActiveEvidence   *controlupgrade.ActiveProbeEvidence `json:"active_evidence,omitempty"`
	ErrorCode        string                              `json:"error_code,omitempty"`
	CurrentVersion   string                              `json:"current_version,omitempty"`
	PreviousVersion  string                              `json:"previous_version,omitempty"`
}

type controlUpgradeRolloutDetailResponse struct {
	controlUpgradeRolloutSummaryResponse
	Batches        []controlupgrade.RolloutBatch         `json:"batches"`
	Nodes          []controlUpgradeRolloutNodeResponse   `json:"nodes"`
	Events         []controlUpgradeRolloutEventResponse  `json:"events"`
	StatusReceipts []controlUpgradeStatusReceiptResponse `json:"status_receipts"`
}

type controlUpgradeListResponse struct {
	Data     []controlUpgradeRolloutSummaryResponse `json:"data"`
	Page     int                                    `json:"page"`
	PageSize int                                    `json:"page_size"`
	Total    int64                                  `json:"total"`
}

type controlUpgradeActionBodyRequest struct {
	ExpectedRevision string `json:"expected_revision"`
	Reason           string `json:"reason"`
}

func (s *Server) handleControlUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireControlUpgradePermission(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		s.writeError(w, r, controlupgrade.ErrInvalidInput)
		return
	}
	var request controlupgrade.CheckRequest
	if err := decodeJSON(w, r, &request); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	request.IdempotencyKey = key
	request.RequestID = requestID(r.Context())
	response, err := s.controlUpgrades.Check(r.Context(), controlUpgradeActor(principal), request)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleCreateControlUpgradeRollout(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireControlUpgradeActor(w, r)
	if !ok {
		return
	}
	key, ok := s.controlUpgradeIdempotencyKey(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		s.writeControlUpgradeError(w, r, controlupgrade.ErrInvalidInput)
		return
	}
	body, err := decodeControlUpgradeCreate(r)
	if err != nil {
		s.writeControlUpgradeBodyError(w, r, err)
		return
	}
	result, err := s.controlUpgrades.CreateRollout(r.Context(), controlUpgradeActor(principal),
		controlupgrade.CreateRolloutRequest{CreateRolloutBody: body, IdempotencyKey: key,
			RequestID: requestID(r.Context())})
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated,
		controlUpgradeWriteResponse{Data: controlUpgradeRolloutDetail(result.Detail), Replayed: result.Replayed})
}

func (s *Server) handleListControlUpgradeRollouts(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireControlUpgradeActor(w, r)
	if !ok {
		return
	}
	request, err := parseControlUpgradeListRawQuery(r.URL.RawQuery)
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	response, err := s.controlUpgrades.ListRollouts(r.Context(), controlUpgradeActor(principal), request)
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, controlUpgradeRolloutList(response))
}

func (s *Server) handleGetControlUpgradeRollout(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireControlUpgradeActor(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		s.writeControlUpgradeError(w, r, controlupgrade.ErrInvalidInput)
		return
	}
	planID, err := parseControlUpgradePlanID(r.PathValue("id"))
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	detail, err := s.controlUpgrades.GetRollout(r.Context(), controlUpgradeActor(principal), planID)
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	receipts, err := s.controlUpgrades.ListRolloutStatusReceipts(r.Context(), controlUpgradeActor(principal), planID)
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	response := controlUpgradeRolloutDetail(detail)
	for _, receipt := range receipts {
		response.StatusReceipts = append(response.StatusReceipts, controlUpgradeStatusReceipt(receipt))
	}
	writeJSON(w, http.StatusOK, controlUpgradeDetailResponse{Data: response})
}

func (s *Server) handleStartControlUpgradeRollout(w http.ResponseWriter, r *http.Request) {
	s.handleControlUpgradeRolloutAction(w, r, string(controlupgrade.PlanStart))
}

func (s *Server) handlePauseControlUpgradeRollout(w http.ResponseWriter, r *http.Request) {
	s.handleControlUpgradeRolloutAction(w, r, string(controlupgrade.PlanPauseAction))
}

func (s *Server) handleResumeControlUpgradeRollout(w http.ResponseWriter, r *http.Request) {
	s.handleControlUpgradeRolloutAction(w, r, string(controlupgrade.PlanResume))
}

func (s *Server) handleRollbackControlUpgradeRollout(w http.ResponseWriter, r *http.Request) {
	s.handleControlUpgradeRolloutAction(w, r, string(controlupgrade.PlanRollback))
}

func (s *Server) handleControlUpgradeRolloutAction(w http.ResponseWriter, r *http.Request, operation string) {
	principal, ok := s.requireControlUpgradeActor(w, r)
	if !ok {
		return
	}
	key, ok := s.controlUpgradeIdempotencyKey(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		s.writeControlUpgradeError(w, r, controlupgrade.ErrInvalidInput)
		return
	}
	planID, err := parseControlUpgradePlanID(r.PathValue("id"))
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	body, err := decodeControlUpgradeAction(r)
	if err != nil {
		s.writeControlUpgradeBodyError(w, r, err)
		return
	}
	if !validControlUpgradeActionBody(body) {
		s.writeControlUpgradeError(w, r, controlupgrade.ErrInvalidInput)
		return
	}
	result, err := s.controlUpgrades.ApplyRolloutAction(r.Context(), controlUpgradeActor(principal),
		controlupgrade.RolloutActionRequest{RolloutActionBody: body, PlanID: planID,
			Operation: operation, IdempotencyKey: key, RequestID: requestID(r.Context())})
	if err != nil {
		s.writeControlUpgradeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK,
		controlUpgradeWriteResponse{Data: controlUpgradeRolloutDetail(result.Detail), Replayed: result.Replayed})
}

func (s *Server) requireControlUpgradeActor(w http.ResponseWriter, r *http.Request) (identity.Principal, bool) {
	principal, err := s.authenticatedPrincipal(r)
	if err == nil && principal.ScopeKind != "platform" {
		err = identity.ErrPermissionDenied
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

func (s *Server) requireControlUpgradePermission(w http.ResponseWriter, r *http.Request) (identity.Principal, bool) {
	principal, err := s.authenticatedPrincipal(r)
	if err == nil && principal.ScopeKind != "platform" {
		err = identity.ErrPermissionDenied
	}
	if err == nil {
		err = identity.Authorize(principal, "control.upgrades.check")
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

func controlUpgradeActor(principal identity.Principal) controlupgrade.Actor {
	return controlupgrade.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}

func decodeControlUpgradeCreate(request *http.Request) (controlupgrade.CreateRolloutBody, error) {
	var body controlupgrade.CreateRolloutBody
	if err := decodeCanonicalControlUpgradeBody(request, &body); err != nil {
		return controlupgrade.CreateRolloutBody{}, err
	}
	return body, nil
}

func decodeControlUpgradeAction(request *http.Request) (controlupgrade.RolloutActionBody, error) {
	var body controlUpgradeActionBodyRequest
	if err := decodeCanonicalControlUpgradeBody(request, &body); err != nil {
		return controlupgrade.RolloutActionBody{}, err
	}
	revision, err := parseControlUpgradeRevision(body.ExpectedRevision, false)
	if err != nil {
		return controlupgrade.RolloutActionBody{}, err
	}
	return controlupgrade.RolloutActionBody{ExpectedRevision: revision, Reason: body.Reason}, nil
}

func decodeCanonicalControlUpgradeBody(request *http.Request, target any) error {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json" {
		return errControlUpgradeUnsupportedMediaType
	}
	encoded, err := io.ReadAll(io.LimitReader(request.Body, controlUpgradeBodyLimit+1))
	if err != nil {
		return controlupgrade.ErrInvalidInput
	}
	if len(encoded) > controlUpgradeBodyLimit {
		return errControlUpgradeBodyTooLarge
	}
	if len(encoded) == 0 {
		return controlupgrade.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return controlupgrade.ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return controlupgrade.ErrInvalidInput
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return controlupgrade.ErrInvalidInput
	}
	return nil
}

func (s *Server) controlUpgradeIdempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 || !requestIDPattern.MatchString(values[0]) {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_idempotency_key",
			"Idempotency-Key must be a single canonical value")
		return "", false
	}
	return values[0], true
}

func parseControlUpgradePlanID(raw string) (string, error) {
	parsed, err := uuid.Parse(raw)
	if err != nil || parsed == uuid.Nil || parsed.String() != raw {
		return "", controlupgrade.ErrInvalidInput
	}
	return raw, nil
}

func validControlUpgradeActionBody(body controlupgrade.RolloutActionBody) bool {
	return body.ExpectedRevision > 0 && body.ExpectedRevision <= uint64(1<<63-1)
}

func parseControlUpgradeRevision(raw string, allowZero bool) (uint64, error) {
	if allowZero && raw == "0" {
		return 0, nil
	}
	if len(raw) < 1 || len(raw) > 19 || raw[0] < '1' || raw[0] > '9' {
		return 0, controlupgrade.ErrInvalidInput
	}
	for index := 1; index < len(raw); index++ {
		if raw[index] < '0' || raw[index] > '9' {
			return 0, controlupgrade.ErrInvalidInput
		}
	}
	parsed, err := strconv.ParseUint(raw, 10, 63)
	if err != nil || strconv.FormatUint(parsed, 10) != raw {
		return 0, controlupgrade.ErrInvalidInput
	}
	return parsed, nil
}

func controlUpgradeRolloutSummary(summary controlupgrade.RolloutSummary) controlUpgradeRolloutSummaryResponse {
	return controlUpgradeRolloutSummaryResponse{
		ID: summary.ID, SchemaVersion: summary.SchemaVersion, InstallationID: summary.InstallationID,
		Component: summary.Component, CurrentVersion: summary.CurrentVersion, TargetVersion: summary.TargetVersion,
		State: summary.State, Completion: summary.Completion, Revision: strconv.FormatUint(summary.Revision, 10),
		AutomaticRollback: summary.AutomaticRollback, ParentGrantID: summary.ParentGrantID,
		ArtifactID: summary.ArtifactID, ArtifactSHA256: summary.ArtifactSHA256,
		ArtifactSizeBytes: summary.ArtifactSizeBytes, RollbackArtifactID: summary.RollbackArtifactID,
		RollbackArtifactSHA256:    summary.RollbackArtifactSHA256,
		RollbackArtifactSizeBytes: summary.RollbackArtifactSizeBytes, ActiveBatch: summary.ActiveBatch,
		TotalNodes: summary.TotalNodes, PendingNodes: summary.PendingNodes,
		DispatchedNodes: summary.DispatchedNodes, HealthyNodes: summary.HealthyNodes,
		FailedNodes: summary.FailedNodes, RolledBackNodes: summary.RolledBackNodes,
		Blockers: summary.Blockers, CreatedAt: summary.CreatedAt, UpdatedAt: summary.UpdatedAt,
	}
}

func controlUpgradeRolloutDetail(detail controlupgrade.RolloutDetail) controlUpgradeRolloutDetailResponse {
	result := controlUpgradeRolloutDetailResponse{
		controlUpgradeRolloutSummaryResponse: controlUpgradeRolloutSummary(detail.RolloutSummary),
		Batches:                              detail.Batches,
		Nodes:                                make([]controlUpgradeRolloutNodeResponse, 0, len(detail.Nodes)),
		Events:                               make([]controlUpgradeRolloutEventResponse, 0, len(detail.Events)),
		StatusReceipts:                       []controlUpgradeStatusReceiptResponse{},
	}
	for _, node := range detail.Nodes {
		result.Nodes = append(result.Nodes, controlUpgradeRolloutNodeResponse{
			NodeID: node.NodeID, AgentVersion: node.AgentVersion, ProtocolVersion: node.ProtocolVersion,
			State: node.State, DispatchRevision: strconv.FormatUint(node.DispatchRevision, 10),
		})
	}
	for _, event := range detail.Events {
		response := controlUpgradeRolloutEventResponse{
			ID: event.ID, Revision: strconv.FormatUint(event.Revision, 10), From: event.From, To: event.To,
			Action: event.Action, Reason: event.Reason, BatchID: event.BatchID, NodeID: event.NodeID,
		}
		if at, ok := detail.EventTimes[event.Revision]; ok {
			response.OccurredAt = &at
		}
		result.Events = append(result.Events, response)
	}
	return result
}

func controlUpgradeStatusReceipt(receipt controlupgrade.RolloutStatusReceipt) controlUpgradeStatusReceiptResponse {
	return controlUpgradeStatusReceiptResponse{
		Schema: receipt.Schema, StatusID: receipt.StatusID, StatusRevision: strconv.FormatUint(receipt.StatusRevision, 10),
		CommandID: receipt.CommandID, PlanID: receipt.PlanID,
		PlanRevision: strconv.FormatUint(receipt.PlanRevision, 10), BatchID: receipt.BatchID,
		InstallationID: receipt.InstallationID, NodeID: receipt.NodeID, Action: receipt.Action,
		CommandSHA256: receipt.CommandSHA256, StatusSHA256: receipt.StatusSHA256, State: receipt.State,
		ObservedAt: receipt.ObservedAt, DeliveryStream: receipt.DeliveryStream,
		DeliveryConsumer: receipt.DeliveryConsumer,
		DeliverySequence: strconv.FormatUint(receipt.DeliverySequence, 10),
		ActiveEvidence:   receipt.ActiveEvidence,
		ErrorCode:        receipt.ErrorCode, CurrentVersion: receipt.CurrentVersion, PreviousVersion: receipt.PreviousVersion,
	}
}

func controlUpgradeRolloutList(response controlupgrade.ListRolloutsResponse) controlUpgradeListResponse {
	result := controlUpgradeListResponse{Data: make([]controlUpgradeRolloutSummaryResponse, 0, len(response.Data)),
		Page: response.Page, PageSize: response.PageSize, Total: response.Total}
	for _, summary := range response.Data {
		result.Data = append(result.Data, controlUpgradeRolloutSummary(summary))
	}
	return result
}

func parseControlUpgradeListQuery(query url.Values) (controlupgrade.ListRolloutsRequest, error) {
	request := controlupgrade.ListRolloutsRequest{Page: 1, PageSize: 20}
	for name, values := range query {
		if len(values) != 1 {
			return controlupgrade.ListRolloutsRequest{}, controlupgrade.ErrInvalidInput
		}
		value := values[0]
		switch name {
		case "page":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 1 {
				return controlupgrade.ListRolloutsRequest{}, controlupgrade.ErrInvalidInput
			}
			request.Page = parsed
		case "page_size":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 1 || parsed > 100 {
				return controlupgrade.ListRolloutsRequest{}, controlupgrade.ErrInvalidInput
			}
			request.PageSize = parsed
		case "state":
			request.State = controlupgrade.PlanState(value)
			if request.State != controlupgrade.PlanQueued && request.State != controlupgrade.PlanCanary &&
				request.State != controlupgrade.PlanRunning && request.State != controlupgrade.PlanPaused &&
				request.State != controlupgrade.PlanRollingBack && request.State != controlupgrade.PlanCompleted &&
				request.State != controlupgrade.PlanFailed {
				return controlupgrade.ListRolloutsRequest{}, controlupgrade.ErrInvalidInput
			}
		case "node_id":
			parsed, err := uuid.Parse(value)
			if err != nil || parsed == uuid.Nil || parsed.String() != value {
				return controlupgrade.ListRolloutsRequest{}, controlupgrade.ErrInvalidInput
			}
			request.NodeID = value
		default:
			return controlupgrade.ListRolloutsRequest{}, controlupgrade.ErrInvalidInput
		}
	}
	return request, nil
}

func parseControlUpgradeListRawQuery(raw string) (controlupgrade.ListRolloutsRequest, error) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return controlupgrade.ListRolloutsRequest{}, controlupgrade.ErrInvalidInput
	}
	return parseControlUpgradeListQuery(query)
}

func (s *Server) writeControlUpgradeBodyError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errControlUpgradeUnsupportedMediaType):
		s.writeAPIError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type",
			"Content-Type must be application/json")
	case errors.Is(err, errControlUpgradeBodyTooLarge):
		s.writeAPIError(w, r, http.StatusRequestEntityTooLarge, "request_too_large",
			"request body exceeds the size limit")
	default:
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
	}
}

func (s *Server) writeControlUpgradeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, controlupgrade.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request fields are invalid")
	case errors.Is(err, controlupgrade.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, controlupgrade.ErrRolloutNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "control_upgrade_rollout_not_found",
			"control upgrade rollout was not found")
	case errors.Is(err, controlupgrade.ErrNodeNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "node_not_found", "node was not found")
	case errors.Is(err, controlupgrade.ErrIdempotencyConflict),
		errors.Is(err, controlupgrade.ErrPlanIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict",
			"idempotency key was already used with different input")
	case errors.Is(err, controlupgrade.ErrStalePlanRevision):
		s.writeAPIError(w, r, http.StatusConflict, "revision_conflict", "rollout revision is stale")
	case errors.Is(err, controlupgrade.ErrInvalidPlanTransition):
		s.writeAPIError(w, r, http.StatusConflict, "control_upgrade_rollout_invalid_transition",
			"control upgrade rollout state does not allow this operation")
	case errors.Is(err, controlupgrade.ErrPlanBlocked):
		s.writeAPIError(w, r, http.StatusConflict, "control_upgrade_rollout_blocked",
			"control upgrade rollout is blocked")
	case errors.Is(err, controlupgrade.ErrPlanNodeNotActive),
		errors.Is(err, controlupgrade.ErrCohortIncompatible):
		s.writeAPIError(w, r, http.StatusConflict, "control_upgrade_cohort_incompatible",
			"control upgrade rollout targets are incompatible")
	case errors.Is(err, controlupgrade.ErrGrantInvalid):
		s.writeAPIError(w, r, http.StatusBadGateway, "control_upgrade_grant_invalid",
			"license service returned an invalid upgrade grant")
	case errors.Is(err, controlupgrade.ErrExecutionInvalid):
		s.writeAPIError(w, r, http.StatusBadGateway, "control_upgrade_execution_invalid",
			"upgrade execution could not be verified")
	case errors.Is(err, controlupgrade.ErrArtifactInvalid):
		s.writeAPIError(w, r, http.StatusBadGateway, "control_upgrade_artifact_invalid",
			"upgrade artifact does not match its signed manifest")
	case errors.Is(err, controlupgrade.ErrArtifactUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "control_upgrade_artifact_unavailable",
			"upgrade artifact could not be cached on the control plane")
	case errors.Is(err, controlupgrade.ErrLicenseOutcomeUnknown):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "control_upgrade_license_outcome_unknown",
			"license service outcome is unknown")
	case errors.Is(err, controlupgrade.ErrLicenseUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "control_upgrade_license_unavailable",
			"license service is unavailable")
	case errors.Is(err, controlupgrade.ErrRuntimeUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "control_upgrade_runtime_unavailable",
			"control upgrade runtime is unavailable")
	case errors.Is(err, controlupgrade.ErrResourceUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "control_upgrade_resource_unavailable",
			"control upgrade resources are unavailable")
	default:
		s.writeError(w, r, err)
	}
}
