package dnsreconcilehttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

type taskView struct {
	ID                  uuid.UUID           `json:"id"`
	TenantID            uuid.UUID           `json:"tenant_id"`
	SiteID              uuid.UUID           `json:"site_id"`
	Revision            int64               `json:"revision"`
	RequiredConsecutive int                 `json:"required_consecutive"`
	Job                 jobView             `json:"job"`
	Request             checkView           `json:"request"`
	Result              reconcileResultView `json:"result"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
	Replayed            bool                `json:"replayed"`
}

type jobView struct {
	ID                uuid.UUID      `json:"id"`
	Kind              string         `json:"kind"`
	Subject           string         `json:"subject"`
	State             jobstate.State `json:"state"`
	Attempt           uint32         `json:"attempt"`
	MaxAttempts       uint32         `json:"max_attempts"`
	CancelRequestedAt *time.Time     `json:"cancel_requested_at,omitempty"`
	Progress          progressView   `json:"progress"`
	LastErrorCode     string         `json:"last_error_code,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	StartedAt         *time.Time     `json:"started_at,omitempty"`
	UpdatedAt         time.Time      `json:"updated_at"`
	CompletedAt       *time.Time     `json:"completed_at,omitempty"`
}

type progressView struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Cancelled int `json:"cancelled"`
	Pending   int `json:"pending"`
}

type checkView struct {
	Name                     string               `json:"name"`
	Expected                 []expectedRecordBody `json:"expected"`
	AuthoritativeNS          []string             `json:"authoritative_ns"`
	TTL                      uint32               `json:"ttl"`
	Line                     string               `json:"line"`
	Weight                   uint32               `json:"weight"`
	PropagationStartedAt     *time.Time           `json:"propagation_started_at,omitempty"`
	PropagationWindowSeconds int64                `json:"propagation_window_seconds"`
	Provider                 providerSnapshotBody `json:"provider"`
}

type reconcileResultView struct {
	TenantID         uuid.UUID                   `json:"tenant_id"`
	SiteID           uuid.UUID                   `json:"site_id"`
	ZoneID           uuid.UUID                   `json:"zone_id"`
	PayloadDigest    string                      `json:"payload_digest"`
	Plan             repairPlanView              `json:"plan"`
	Status           dnscheck.TaskStatus         `json:"status"`
	Replayed         bool                        `json:"replayed"`
	StartedAt        time.Time                   `json:"started_at"`
	UpdatedAt        time.Time                   `json:"updated_at"`
	ReadyAt          *time.Time                  `json:"ready_at,omitempty"`
	InitialRevision  int64                       `json:"initial_revision"`
	ProviderRevision int64                       `json:"provider_revision"`
	Operations       []operationResultView       `json:"operations"`
	DeferredDeletes  []operationResultView       `json:"deferred_deletes"`
	CompensationPlan []providerOperationView     `json:"compensation_plan"`
	Propagation      []propagationAttemptView    `json:"propagation"`
	LastCheck        *checkResultView            `json:"last_check,omitempty"`
	ErrorClass       dnscheck.ProviderErrorClass `json:"error_class"`
	ErrorCode        string                      `json:"error_code"`
}

type repairPlanView struct {
	TenantID             uuid.UUID               `json:"tenant_id"`
	SiteID               uuid.UUID               `json:"site_id"`
	ZoneID               uuid.UUID               `json:"zone_id"`
	PreconditionRevision int64                   `json:"precondition_revision"`
	Digest               string                  `json:"digest"`
	Operations           []providerOperationView `json:"operations"`
}

type providerOperationView struct {
	Sequence       int                     `json:"sequence"`
	Action         dnscheck.ProviderAction `json:"action"`
	RecordID       string                  `json:"record_id,omitempty"`
	Name           string                  `json:"name"`
	Type           string                  `json:"type"`
	Value          string                  `json:"value"`
	TTL            uint32                  `json:"ttl"`
	Line           string                  `json:"line"`
	Weight         uint32                  `json:"weight"`
	PreviousValue  string                  `json:"previous_value,omitempty"`
	PreviousTTL    uint32                  `json:"previous_ttl,omitempty"`
	PreviousLine   string                  `json:"previous_line,omitempty"`
	PreviousWeight uint32                  `json:"previous_weight,omitempty"`
	Reason         string                  `json:"reason"`
}

type operationResultView struct {
	SourceSequence    int                         `json:"source_sequence"`
	Operation         providerOperationView       `json:"operation"`
	ClientRequestID   string                      `json:"client_request_id"`
	ProviderRequestID string                      `json:"provider_request_id,omitempty"`
	ProviderRecordID  string                      `json:"provider_record_id,omitempty"`
	ProviderRevision  int64                       `json:"provider_revision"`
	Status            dnscheck.OperationStatus    `json:"status"`
	Attempts          int                         `json:"attempts"`
	RetryAfterSeconds int64                       `json:"retry_after_seconds,omitempty"`
	ErrorClass        dnscheck.ProviderErrorClass `json:"error_class"`
	ErrorCode         string                      `json:"error_code"`
	ReportSequence    uint64                      `json:"report_sequence"`
}

type propagationAttemptView struct {
	Number                int                     `json:"number"`
	CheckedAt             time.Time               `json:"checked_at"`
	Status                dnscheck.Classification `json:"status"`
	ConsecutiveHealthy    int                     `json:"consecutive_healthy"`
	DependencyUnavailable bool                    `json:"dependency_unavailable"`
}

type checkResultView struct {
	Name         string                  `json:"name"`
	Status       dnscheck.Classification `json:"status"`
	Compliant    bool                    `json:"compliant"`
	CheckedAt    time.Time               `json:"checked_at"`
	Observations []observationView       `json:"observations"`
	RepairPlan   repairPlanView          `json:"repair_plan"`
}

type observationView struct {
	Role       dnscheck.ResolverRole   `json:"role"`
	Resolver   string                  `json:"resolver"`
	RecordType string                  `json:"record_type"`
	Status     dnscheck.Classification `json:"status"`
	Values     []string                `json:"values"`
	CNAMEChain []string                `json:"cname_chain"`
	Attempts   int                     `json:"attempts"`
	MinimumTTL uint32                  `json:"minimum_ttl"`
	ErrorCode  string                  `json:"error_code"`
}

func taskViewOf(task dnsreconcile.Task) taskView {
	return taskView{ID: task.ID, TenantID: task.TenantID, SiteID: task.SiteID, Revision: task.Revision,
		RequiredConsecutive: task.RequiredConsecutive,
		Job:                 jobViewOf(task.Job), Request: checkViewOf(task.Prepared.Request), Result: reconcileResultViewOf(task.Result),
		CreatedAt: task.CreatedAt, UpdatedAt: task.UpdatedAt, Replayed: task.Replayed}
}

func jobViewOf(job jobstate.StoredJob) jobView {
	return jobView{ID: job.ID, Kind: job.Kind, Subject: job.Subject, State: job.State, Attempt: job.Attempt,
		MaxAttempts: job.MaxAttempts, CancelRequestedAt: timePointer(job.CancelRequestedAt), Progress: progressViewOf(job.Progress),
		LastErrorCode: job.LastErrorCode, CreatedAt: job.CreatedAt, StartedAt: timePointer(job.StartedAt),
		UpdatedAt: job.UpdatedAt, CompletedAt: timePointer(job.CompletedAt)}
}

func progressViewOf(progress jobstate.Progress) progressView {
	return progressView{Total: progress.Total, Completed: progress.Completed, Succeeded: progress.Succeeded,
		Failed: progress.Failed, Cancelled: progress.Cancelled, Pending: progress.Pending}
}

func checkViewOf(check dnscheck.CheckRequest) checkView {
	expected := make([]expectedRecordBody, len(check.Expected))
	for index, item := range check.Expected {
		expected[index] = expectedRecordBody{Type: item.Type.String(), Values: append([]string(nil), item.Values...)}
	}
	records := make([]providerRecordBody, len(check.Provider.Records))
	for index, item := range check.Provider.Records {
		records[index] = providerRecordBody{RecordID: item.RecordID, Name: item.Name, Type: item.Type.String(),
			Value: item.Value, TTL: item.TTL, Line: item.Line, Weight: item.Weight}
	}
	return checkView{Name: check.Name, Expected: expected, AuthoritativeNS: append([]string(nil), check.AuthoritativeNS...),
		TTL: check.TTL, Line: check.Line, Weight: check.Weight, PropagationStartedAt: check.PropagationStartedAt,
		PropagationWindowSeconds: int64(check.PropagationWindow / time.Second),
		Provider:                 providerSnapshotBody{ZoneID: check.Provider.ZoneID.String(), Revision: check.Provider.Revision, Records: records}}
}

func reconcileResultViewOf(result dnscheck.ReconcileResult) reconcileResultView {
	view := reconcileResultView{TenantID: result.TenantID, SiteID: result.SiteID, ZoneID: result.ZoneID,
		PayloadDigest: result.PayloadDigest, Plan: repairPlanViewOf(result.Plan), Status: result.Status, Replayed: result.Replayed,
		StartedAt: result.StartedAt, UpdatedAt: result.UpdatedAt, ReadyAt: result.ReadyAt,
		InitialRevision: result.InitialRevision, ProviderRevision: result.ProviderRevision,
		Operations: operationResultsViewOf(result.Operations), DeferredDeletes: operationResultsViewOf(result.DeferredDeletes),
		CompensationPlan: operationsViewOf(result.CompensationPlan), Propagation: propagationViewOf(result.Propagation),
		ErrorClass: result.ErrorClass, ErrorCode: result.ErrorCode}
	if result.LastCheck != nil {
		last := checkResultViewOf(*result.LastCheck)
		view.LastCheck = &last
	}
	return view
}

func repairPlanViewOf(plan dnscheck.RepairPlan) repairPlanView {
	return repairPlanView{TenantID: plan.TenantID, SiteID: plan.SiteID, ZoneID: plan.ZoneID,
		PreconditionRevision: plan.PreconditionRevision, Digest: plan.Digest, Operations: operationsViewOf(plan.Operations)}
}

func operationsViewOf(items []dnscheck.ProviderOperation) []providerOperationView {
	result := make([]providerOperationView, len(items))
	for index, item := range items {
		result[index] = providerOperationView{Sequence: item.Sequence, Action: item.Action, RecordID: item.RecordID,
			Name: item.Name, Type: item.Type.String(), Value: item.Value, TTL: item.TTL,
			Line: item.Line, Weight: item.Weight, PreviousValue: item.PreviousValue, PreviousTTL: item.PreviousTTL,
			PreviousLine: item.PreviousLine, PreviousWeight: item.PreviousWeight, Reason: item.Reason}
	}
	return result
}

func operationResultsViewOf(items []dnscheck.OperationResult) []operationResultView {
	result := make([]operationResultView, len(items))
	for index, item := range items {
		result[index] = operationResultView{SourceSequence: item.SourceSequence,
			Operation:       operationsViewOf([]dnscheck.ProviderOperation{item.Operation})[0],
			ClientRequestID: item.ClientRequestID, ProviderRequestID: item.ProviderRequestID,
			ProviderRecordID: item.ProviderRecordID, ProviderRevision: item.ProviderRevision,
			Status: item.Status, Attempts: item.Attempts, RetryAfterSeconds: int64(item.RetryAfter / time.Second),
			ErrorClass: item.ErrorClass,
			ErrorCode:  item.ErrorCode, ReportSequence: item.ReportSequence}
	}
	return result
}

func propagationViewOf(items []dnscheck.PropagationAttempt) []propagationAttemptView {
	result := make([]propagationAttemptView, len(items))
	for index, item := range items {
		result[index] = propagationAttemptView{Number: item.Number, CheckedAt: item.CheckedAt,
			Status: item.Status, ConsecutiveHealthy: item.ConsecutiveHealthy,
			DependencyUnavailable: item.DependencyUnavailable}
	}
	return result
}

func checkResultViewOf(result dnscheck.CheckResult) checkResultView {
	observations := make([]observationView, len(result.Observations))
	for index, item := range result.Observations {
		observations[index] = observationView{Role: item.Role, Resolver: item.Resolver,
			RecordType: item.RecordType.String(), Status: item.Status, Values: append([]string(nil), item.Values...),
			CNAMEChain: append([]string(nil), item.CNAMEChain...), Attempts: item.Attempts,
			MinimumTTL: item.MinimumTTL, ErrorCode: item.ErrorCode}
	}
	return checkResultView{Name: result.Name, Status: result.Status, Compliant: result.Compliant,
		CheckedAt: result.CheckedAt, Observations: observations, RepairPlan: repairPlanViewOf(result.RepairPlan)}
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func (handler *Handler) writeTask(writer http.ResponseWriter, request *http.Request, status int,
	task dnsreconcile.Task, err error, command bool,
) {
	if err != nil {
		handler.writeError(writer, request, err, command)
		return
	}
	if task.ID == uuid.Nil || task.TenantID == uuid.Nil || task.SiteID == uuid.Nil || task.Revision < 1 {
		handler.writeError(writer, request, ErrUnavailable, command)
		return
	}
	writer.Header().Set("ETag", `"`+strconv.FormatInt(task.Revision, 10)+`"`)
	if task.Replayed {
		writer.Header().Set("X-Idempotent-Replay", "true")
	}
	handler.writeJSON(writer, status, taskViewOf(task))
}

func (handler *Handler) writeError(writer http.ResponseWriter, request *http.Request, err error, command bool) {
	status, code, message := classifyError(err, command)
	handler.writeAPIError(writer, request, status, code, message)
}

func classifyError(err error, command bool) (int, string, string) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized, "authentication_required", "authentication is required"
	case errors.Is(err, ErrWorkloadUnauthenticated):
		return http.StatusUnauthorized, "workload_authentication_required", "workload authentication is required"
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, dnsreconcile.ErrPermissionDenied):
		return http.StatusForbidden, "permission_denied", "permission is required"
	case errors.Is(err, ErrEntitlementDenied), errors.Is(err, dnsreconcile.ErrEntitlementDenied):
		return http.StatusForbidden, "dns_reconcile_entitlement_denied", "DNS reconciliation entitlement is required"
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, dnsreconcile.ErrInvalidInput), errors.Is(err, dnscheck.ErrInvalidInput):
		return http.StatusBadRequest, "dns_reconcile_invalid_request", "request fields are invalid"
	case errors.Is(err, dnsreconcile.ErrNotFound), errors.Is(err, dnscheck.ErrTaskNotFound):
		return http.StatusNotFound, "dns_reconcile_not_found", "DNS reconciliation task was not found"
	case errors.Is(err, dnsreconcile.ErrIdempotencyConflict), errors.Is(err, dnscheck.ErrIdempotencyConflict):
		return http.StatusConflict, "idempotency_conflict", "the idempotency key was used with different input"
	case errors.Is(err, dnsreconcile.ErrRevisionConflict), errors.Is(err, dnscheck.ErrProviderRevisionConflict):
		return http.StatusPreconditionFailed, "revision_conflict", "the expected revision is stale"
	case errors.Is(err, dnsreconcile.ErrCommitNotReady), errors.Is(err, dnscheck.ErrCommitNotReady):
		return http.StatusConflict, "dns_reconcile_commit_not_ready", "the task is not ready to commit"
	case errors.Is(err, dnsreconcile.ErrOperationInFlight):
		return http.StatusConflict, "dns_reconcile_operation_in_flight", "a provider operation is still in flight"
	case errors.Is(err, context.Canceled):
		if command {
			return http.StatusRequestTimeout, "dns_reconcile_result_unknown", "the write result is unknown; retry with the same key and payload"
		}
		return http.StatusRequestTimeout, "dns_reconcile_request_cancelled", "the request was cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		if command {
			return http.StatusGatewayTimeout, "dns_reconcile_result_unknown", "the write result is unknown; retry with the same key and payload"
		}
		return http.StatusGatewayTimeout, "dns_reconcile_request_timeout", "the request timed out"
	default:
		if command {
			return http.StatusServiceUnavailable, "dns_reconcile_result_unknown", "the write result is unknown; retry with the same key and payload"
		}
		return http.StatusServiceUnavailable, "dns_reconcile_unavailable", "DNS reconciliation is unavailable"
	}
}

func (handler *Handler) writeAPIError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	requestID, _ := request.Context().Value(requestIDContextKey{}).(string)
	if requestID == "" {
		requestID = generatedRequestID()
	}
	handler.writeJSON(writer, status, errorEnvelope{Error: apiError{Code: code, Message: message, RequestID: requestID}})
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		encoded, _ = json.Marshal(errorEnvelope{Error: apiError{Code: "dns_reconcile_unavailable",
			Message: "DNS reconciliation is unavailable", RequestID: "request-unavailable"}})
		status = http.StatusServiceUnavailable
	}
	encoded = append(encoded, '\n')
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}
