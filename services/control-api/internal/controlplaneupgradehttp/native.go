package controlplaneupgradehttp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

const (
	nativePlanPath   = "/v1/admin/control-upgrade-plan"
	nativeRunLogPath = nativePlanPath + "/run-log"
)

type NativeDependencies struct {
	AuthenticateSession AuthenticateFunc
	Repository          controlplaneupgrade.SecretRepository
	Trust               *entitlementguard.TrustStore
	InstallationID      string
	CurrentVersion      string
	ProtocolVersion     int
	StatusFile          string
	StateFile           string
	MaintenanceFile     string
	Now                 func() time.Time
	// License 为 nil 时禁用自动取签名计划端点。
	License *controlupgrade.LicenseClient
}

type NativeHandler struct {
	config      NativeDependencies
	core        *Handler
	readStatus  func(string, string, time.Time) (controlplaneupgrade.NativeStandaloneStatus, error)
	readState   func(string) (controlplaneupgrade.State, error)
	readHistory func(string) (controlplaneupgrade.History, error)
	readRunLog  func(string) (controlplaneupgrade.RunLog, error)
}

// NativeRunLogStatus is the master upgrade's script log and service-log tail
// for the current publication. Events are stable codes the console renders.
type NativeRunLogStatus struct {
	Schema     string                      `json:"schema"`
	ObservedAt time.Time                   `json:"observed_at"`
	State      string                      `json:"state"`
	RunLog     *controlplaneupgrade.RunLog `json:"run_log"`
}

type NativeExecutionStatus struct {
	State   string                       `json:"state"`
	Phase   *controlplaneupgrade.Phase   `json:"phase"`
	Receipt *controlplaneupgrade.Receipt `json:"receipt"`
	// History is the runner's checkpoint journal for this execution, oldest
	// first; omitted when the runner did not record one for this plan.
	History []controlplaneupgrade.HistoryEntry `json:"history,omitempty"`
}

type NativePlanStatus struct {
	Schema              string                                  `json:"schema"`
	ObservedAt          time.Time                               `json:"observed_at"`
	Mode                string                                  `json:"mode"`
	PublicationRevision uint64                                  `json:"publication_revision"`
	Publication         *controlplaneupgrade.PublicationReceipt `json:"publication"`
	Execution           NativeExecutionStatus                   `json:"execution"`
	Runtime             controlupgrade.MaintenanceRuntimeState  `json:"runtime"`
}

func NewNative(config NativeDependencies) (*NativeHandler, error) {
	installation, err := uuid.Parse(config.InstallationID)
	if err != nil || installation == uuid.Nil || installation.String() != config.InstallationID ||
		config.AuthenticateSession == nil || config.Repository == nil || config.Trust == nil || config.Now == nil ||
		config.CurrentVersion == "" || config.ProtocolVersion < 1 || config.StateFile != config.StatusFile+".state.json" ||
		config.MaintenanceFile == config.StatusFile || config.MaintenanceFile == config.StateFile {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	for _, path := range []string{config.StatusFile, config.StateFile, config.MaintenanceFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, controlplaneupgrade.ErrInvalidConfig
		}
	}
	if _, err := controlplaneupgrade.NewNativeMaintenanceGate(controlplaneupgrade.NativeMaintenanceGateConfig{
		Enabled: true, File: config.MaintenanceFile, InstallationID: config.InstallationID,
	}, http.NotFoundHandler()); err != nil {
		return nil, err
	}
	return &NativeHandler{config: config,
		core:       &Handler{authenticate: config.AuthenticateSession, maxBodyBytes: 1 << 20},
		readStatus: controlplaneupgrade.ReadNativeStandaloneStatus, readState: controlplaneupgrade.ReadNativeStandaloneState,
		readHistory: controlplaneupgrade.ReadNativeStandaloneHistory,
		readRunLog:  controlplaneupgrade.ReadNativeStandaloneRunLog,
	}, nil
}

func (handler *NativeHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+nativePlanPath, handler.status)
	mux.HandleFunc("POST "+nativePlanPath, handler.publish)
	mux.HandleFunc("POST "+nativePlanPath+"/issue", handler.issue)
	mux.HandleFunc("GET "+nativePlanPath+"/options", handler.options)
	mux.HandleFunc("GET "+nativeRunLogPath, handler.runLog)
	return mux
}

func (handler *NativeHandler) maintenanceGate(next http.Handler) http.Handler {
	gate, err := controlplaneupgrade.NewNativeMaintenanceGate(controlplaneupgrade.NativeMaintenanceGateConfig{
		Enabled: true, File: handler.config.MaintenanceFile, InstallationID: handler.config.InstallationID,
	}, next)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, r, http.StatusServiceUnavailable, "control_upgrade_draining")
		})
	}
	return gate
}

func (handler *NativeHandler) Gate(next http.Handler) http.Handler {
	gate := handler.maintenanceGate(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == nativePlanPath {
			// This route permits only exact, authenticated read-only replay outside
			// the drain lock. Its new-publication path acquires the same gate below.
			handler.publish(w, r)
			return
		}
		gate.ServeHTTP(w, r)
	})
}

func (handler *NativeHandler) current() (controlplaneupgrade.NativeStandaloneStatus, controlupgrade.MaintenanceRuntimeState) {
	status, err := handler.readStatus(handler.config.StatusFile, handler.config.InstallationID, handler.config.Now())
	result := controlupgrade.MaintenanceRuntimeState{Reason: "control_upgrade_runner_unconfirmed"}
	if err != nil {
		return status, result
	}
	if (status.ArtifactFormat != controlplaneupgrade.NativeManifestSchema && status.ArtifactFormat != controlplaneupgrade.NativeManifestSignedSchema) || status.InstallationID != handler.config.InstallationID ||
		status.CurrentVersion != handler.config.CurrentVersion || status.ProtocolVersion != handler.config.ProtocolVersion {
		result.Reason = "execution_unavailable"
	} else if status.Busy || status.Phase == "draining" {
		result.Reason = "control_upgrade_draining"
	} else if status.Ready && status.Phase == "idle" && status.Reason == "ready" {
		result.Ready, result.Reason = true, "ready"
	} else if status.Reason == "execution_unavailable" || status.Reason == "control_upgrade_execution_unavailable" {
		result.Reason = "execution_unavailable"
	}
	return status, result
}

func (handler *NativeHandler) MaintenanceRuntimeStatus(ctx context.Context) controlupgrade.MaintenanceRuntimeState {
	if ctx == nil || ctx.Err() != nil {
		return controlupgrade.MaintenanceRuntimeState{Reason: "control_upgrade_runner_unconfirmed"}
	}
	_, status := handler.current()
	return status
}

func (handler *NativeHandler) replay(ctx context.Context, request controlplaneupgrade.PublishRequest) (controlplaneupgrade.PublicationReceipt, bool, error) {
	document, err := handler.config.Repository.Read(ctx)
	if err != nil {
		return controlplaneupgrade.PublicationReceipt{}, false, err
	}
	current := document.Publication
	if current == nil || current.IdempotencySHA256 != nativeDigest([]byte(request.IdempotencyKey)) {
		return controlplaneupgrade.PublicationReceipt{}, false, nil
	}
	if current.BundleSHA256 != nativeDigest(request.Bundle) || current.ExpectedRevision != request.ExpectedRevision ||
		current.ActorUserID != request.ActorUserID || current.ActorScopeID != request.ActorScopeID ||
		current.InstallationID != handler.config.InstallationID || current.Component != "control-api" {
		return controlplaneupgrade.PublicationReceipt{}, false, controlplaneupgrade.ErrIdempotencyConflict
	}
	receipt := *current
	receipt.Replayed = true
	return receipt, true, nil
}

func (handler *NativeHandler) publish(w http.ResponseWriter, r *http.Request) {
	session, ok := handler.core.manager(w, r)
	if !ok {
		return
	}
	expected, ok := quotedRevision(r.Header.Get("If-Match"), true)
	if !ok || len(r.Header.Values("If-Match")) != 1 || r.Header.Get("If-Match") != `"`+strconv.FormatUint(expected, 10)+`"` ||
		len(r.Header.Values("Idempotency-Key")) != 1 || r.URL.RawQuery != "" || !validMeta(r.Header.Get("Idempotency-Key"), 128) {
		writeError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	bundle, ok := handler.core.rawJSON(w, r)
	if !ok {
		return
	}
	input := controlplaneupgrade.PublishRequest{Bundle: bundle, ExpectedRevision: expected,
		IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: stableRequestID(r),
		ActorUserID: session.Principal.UserID, ActorScopeID: session.Principal.ScopeID}
	receipt, replayed, err := handler.replay(r.Context(), input)
	if err != nil {
		handler.core.writeDomainError(w, r, err)
		return
	}
	respond := func(w http.ResponseWriter, receipt controlplaneupgrade.PublicationReceipt) {
		status := http.StatusCreated
		if receipt.Replayed {
			status = http.StatusOK
		}
		w.Header().Set("ETag", `"`+strconv.FormatUint(receipt.PublicationRevision, 10)+`"`)
		writeJSON(w, status, receipt)
	}
	if replayed {
		respond(w, receipt)
		return
	}
	handler.maintenanceGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receipt, err := handler.Publish(r.Context(), input)
		if err != nil {
			handler.core.writeDomainError(w, r, err)
			return
		}
		respond(w, receipt)
	})).ServeHTTP(w, r)
}

func (handler *NativeHandler) Publish(ctx context.Context, request controlplaneupgrade.PublishRequest) (controlplaneupgrade.PublicationReceipt, error) {
	if receipt, replayed, err := handler.replay(ctx, request); err != nil || replayed {
		return receipt, err
	}
	status, runtime := handler.current()
	if !runtime.Ready {
		return controlplaneupgrade.PublicationReceipt{}, controlplaneupgrade.ErrSecretUnavailable
	}
	publisher, err := controlplaneupgrade.NewPlanPublisher(controlplaneupgrade.PlanPublisherConfig{
		InstallationID: handler.config.InstallationID, Component: "control-api", CurrentVersion: status.CurrentVersion,
		CurrentDigest: status.CurrentArtifactSHA256, ProtocolVersion: status.ProtocolVersion,
		Trust: handler.config.Trust, Now: handler.config.Now,
	}, handler.config.Repository)
	if err != nil {
		return controlplaneupgrade.PublicationReceipt{}, err
	}
	receipt, err := publisher.Publish(ctx, request)
	if err == nil && (receipt.ActorUserID != request.ActorUserID || receipt.ActorScopeID != request.ActorScopeID) {
		// Another actor can win the CAS after our first replay lookup. The shared
		// publisher's legacy replay must not bypass the native actor binding.
		return controlplaneupgrade.PublicationReceipt{}, controlplaneupgrade.ErrIdempotencyConflict
	}
	return receipt, err
}

func (handler *NativeHandler) status(w http.ResponseWriter, r *http.Request) {
	if _, ok := handler.core.manager(w, r); !ok {
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	document, err := handler.config.Repository.Read(r.Context())
	if err != nil {
		handler.core.writeDomainError(w, r, err)
		return
	}
	result := NativePlanStatus{Schema: "cdnca.native-control-upgrade-status/v1", ObservedAt: handler.config.Now().UTC(),
		Mode: "native-standalone", Publication: document.Publication, Execution: NativeExecutionStatus{State: "unavailable"},
		Runtime: handler.MaintenanceRuntimeStatus(r.Context())}
	if document.Publication != nil {
		result.PublicationRevision = document.Publication.PublicationRevision
		if state, err := handler.readState(handler.config.StateFile); err == nil {
			result.Execution = nativeExecution(state, *document.Publication)
			if result.Execution.State != "unavailable" {
				if history, err := handler.readHistory(handler.config.StatusFile + ".history.json"); err == nil &&
					history.PlanID == state.PlanID && history.Sequence == state.Sequence {
					result.Execution.History = history.Entries
				}
			}
		}
	} else if result.Runtime.Ready {
		result.Execution.State = "not_started"
	}
	writeJSON(w, http.StatusOK, result)
}

// runLog projects the runner's published run log only when it belongs to the
// current publication's execution; a stale or foreign log is "unavailable".
func (handler *NativeHandler) runLog(w http.ResponseWriter, r *http.Request) {
	if _, ok := handler.core.manager(w, r); !ok {
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	document, err := handler.config.Repository.Read(r.Context())
	if err != nil {
		handler.core.writeDomainError(w, r, err)
		return
	}
	result := NativeRunLogStatus{Schema: "cdnca.native-control-upgrade-runlog/v1", ObservedAt: handler.config.Now().UTC(), State: "unavailable"}
	if publication := document.Publication; publication != nil {
		if state, err := handler.readState(handler.config.StateFile); err == nil && nativeExecution(state, *publication).State != "unavailable" {
			if log, err := handler.readRunLog(handler.config.StatusFile + ".runlog.json"); err == nil &&
				log.PlanID == state.PlanID && log.Sequence == state.Sequence {
				result.State, result.RunLog = "available", &log
			}
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func nativeExecution(state controlplaneupgrade.State, publication controlplaneupgrade.PublicationReceipt) NativeExecutionStatus {
	result := NativeExecutionStatus{State: "unavailable"}
	if state.PlanID != publication.PlanID || state.BundleSHA256 != publication.BundleSHA256 || state.Sequence != publication.ReleaseSequence {
		return result
	}
	if state.Receipt == nil {
		switch state.Phase {
		case controlplaneupgrade.PhaseVerified, controlplaneupgrade.PhaseExpanded, controlplaneupgrade.PhasePreflighted,
			controlplaneupgrade.PhaseDrained, controlplaneupgrade.PhaseControlStopped, controlplaneupgrade.PhaseDatabaseBackedUp,
			controlplaneupgrade.PhaseDatabaseMigrated, controlplaneupgrade.PhaseActivated, controlplaneupgrade.PhaseHealthy,
			controlplaneupgrade.PhaseContracted, controlplaneupgrade.PhaseRollingBack:
			result.State, result.Phase = "running", &state.Phase
		}
		return result
	}
	receipt := state.Receipt
	if receipt.PlanID != state.PlanID || receipt.BundleSHA256 != state.BundleSHA256 || receipt.Sequence != state.Sequence ||
		receipt.Target != controlplaneupgrade.TargetNativeStandalone || receipt.CurrentVersion != publication.CurrentVersion ||
		receipt.TargetVersion != publication.TargetVersion || receipt.ID == "" || receipt.CompletedAt <= 0 {
		return result
	}
	if state.Phase == controlplaneupgrade.PhaseCompleted && receipt.Result == controlplaneupgrade.ResultApplied ||
		state.Phase == controlplaneupgrade.PhaseRolledBack && receipt.Result == controlplaneupgrade.ResultRolledBack ||
		state.Phase == controlplaneupgrade.PhaseFailed && receipt.Result == controlplaneupgrade.ResultFailed {
		result.State, result.Phase, result.Receipt = "completed", &state.Phase, receipt
	}
	return result
}

func nativeDigest(value []byte) string { return fmt.Sprintf("%x", sha256.Sum256(value)) }

func (handler *NativeHandler) issue(w http.ResponseWriter, r *http.Request) {
	if handler.config.License == nil {
		writeError(w, r, http.StatusServiceUnavailable, "plan_source_unavailable")
		return
	}
	session, ok := handler.core.manager(w, r)
	if !ok {
		return
	}
	if len(r.Header.Values("Idempotency-Key")) != 1 || !validMeta(r.Header.Get("Idempotency-Key"), 128) || r.URL.RawQuery != "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	requestID := stableRequestID(r)
	// Body {} keeps the channel latest (or pin); requested_artifact_id is the customer's choice.
	var choice struct {
		RequestedArtifactID string `json:"requested_artifact_id,omitempty"`
	}
	if !handler.core.decode(w, r, &choice, 4096) {
		return
	}
	if choice.RequestedArtifactID != "" {
		if parsed, err := uuid.Parse(choice.RequestedArtifactID); err != nil || parsed.String() != choice.RequestedArtifactID {
			writeError(w, r, http.StatusBadRequest, "invalid_request")
			return
		}
	}

	parentGrant, err := handler.config.License.IssueParentGrant(r.Context(), controlupgrade.ParentGrantRequest{
		IdempotencyKey:      idempotencyKey,
		RequestID:           requestID,
		Component:           "control-api",
		CurrentVersion:      handler.config.CurrentVersion,
		ProtocolVersion:     handler.config.ProtocolVersion,
		RequestedArtifactID: choice.RequestedArtifactID,
	})
	if err != nil {
		writeIssueError(handler.core, w, r, err)
		return
	}

	bundleResult, err := handler.config.License.IssuePlanArtifactBundle(r.Context(), controlupgrade.PlanArtifactBundleRequest{
		IdempotencyKey:          idempotencyKey,
		RequestID:               requestID,
		PlanID:                  uuid.NewString(),
		InitialPlanRevision:     1,
		ParentUpgradeGrant:      parentGrant.Encoded,
		CommandIssuanceNotAfter: handler.config.Now().Add(2 * time.Hour).Unix(),
	})
	if err != nil {
		writeIssueError(handler.core, w, r, err)
		return
	}

	document, err := handler.config.Repository.Read(r.Context())
	if err != nil {
		handler.core.writeDomainError(w, r, err)
		return
	}
	var expectedRevision uint64
	if document.Publication != nil {
		expectedRevision = document.Publication.PublicationRevision
	}

	input := controlplaneupgrade.PublishRequest{
		Bundle:           bundleResult.Encoded,
		ExpectedRevision: expectedRevision,
		IdempotencyKey:   idempotencyKey,
		RequestID:        requestID,
		ActorUserID:      session.Principal.UserID,
		ActorScopeID:     session.Principal.ScopeID,
	}
	handler.maintenanceGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receipt, err := handler.Publish(r.Context(), input)
		if err != nil {
			handler.core.writeDomainError(w, r, err)
			return
		}
		status := http.StatusCreated
		if receipt.Replayed {
			status = http.StatusOK
		}
		w.Header().Set("ETag", `"`+strconv.FormatUint(receipt.PublicationRevision, 10)+`"`)
		writeJSON(w, status, receipt)
	})).ServeHTTP(w, r)
}

// writeIssueError keeps a License business refusal readable: upgrade_target_blocked
// with its reason_code, or the License code itself (409). Only an unreachable
// License or its 5xx stays the generic 503 of writeDomainError.
func writeIssueError(core *Handler, w http.ResponseWriter, r *http.Request, err error) {
	var blocked *controlupgrade.UpgradeTargetBlockedError
	if errors.As(err, &blocked) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]string{
			"code": "upgrade_target_blocked", "reason_code": blocked.Reason, "request_id": stableRequestID(r)}})
		return
	}
	var refused *controlupgrade.LicenseRefusalError
	if errors.As(err, &refused) {
		writeError(w, r, http.StatusConflict, refused.Code)
		return
	}
	core.writeDomainError(w, r, err)
}

// NativeUpgradeOptions is the version picker for "升级主控". A license
// service that cannot list versions is upgrade_options_unavailable.
type NativeUpgradeOptions struct {
	Schema     string                        `json:"schema"`
	ObservedAt time.Time                     `json:"observed_at"`
	Options    controlupgrade.UpgradeOptions `json:"options"`
}

func (handler *NativeHandler) options(w http.ResponseWriter, r *http.Request) {
	if handler.config.License == nil {
		writeError(w, r, http.StatusServiceUnavailable, "plan_source_unavailable")
		return
	}
	if _, ok := handler.core.manager(w, r); !ok {
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	options, err := handler.config.License.ListUpgradeOptions(r.Context(), controlupgrade.UpgradeOptionsRequest{
		IdempotencyKey: "options-" + uuid.NewString(), Component: "control-api",
		CurrentVersion: handler.config.CurrentVersion, ProtocolVersion: handler.config.ProtocolVersion})
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "upgrade_options_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, NativeUpgradeOptions{Schema: "cdnca.native-control-upgrade-options/v1",
		ObservedAt: handler.config.Now().UTC(), Options: options})
}
