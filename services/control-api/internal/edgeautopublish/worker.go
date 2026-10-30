package edgeautopublish

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
)

type Repository interface {
	ClaimAutomaticPublication(
		context.Context,
		string,
		time.Duration,
	) (edgepublish.AutomaticClaimReference, bool, error)
	RetryAutomaticPublication(context.Context, edgepublish.AutomaticClaimReference, string, time.Duration) error
	FailAutomaticPublication(context.Context, edgepublish.AutomaticClaimReference, string) error
}

type Publisher interface {
	PublishAutomatic(context.Context, edgepublish.AutomaticClaimReference) (edgepublish.PublishResult, error)
}

type WorkerConfig struct {
	WorkerID      string
	LeaseDuration time.Duration
	RetryDelay    time.Duration
}

type Worker struct {
	repository Repository
	publisher  Publisher
	config     WorkerConfig
}

func NewWorker(
	repository Repository,
	publisher Publisher,
	config WorkerConfig,
) (*Worker, error) {
	if nilDependency(repository) || nilDependency(publisher) ||
		strings.TrimSpace(config.WorkerID) == "" || len(config.WorkerID) > 128 ||
		config.LeaseDuration < time.Second || config.LeaseDuration > time.Hour ||
		config.RetryDelay < 0 || config.RetryDelay > time.Hour {
		return nil, ErrInvalidInput
	}
	return &Worker{repository: repository, publisher: publisher, config: config}, nil
}

func (worker *Worker) RunOnce(ctx context.Context) (bool, error) {
	reference, found, err := worker.repository.ClaimAutomaticPublication(
		ctx,
		worker.config.WorkerID,
		worker.config.LeaseDuration,
	)
	if err != nil || !found {
		return false, err
	}
	_, err = worker.publisher.PublishAutomatic(ctx, reference)
	if err != nil {
		if errors.Is(err, ErrStaleClaim) || errors.Is(err, edgepublish.ErrAutomaticRequestExpired) {
			return true, nil
		}
		if reason := permanentFailure(err); reason != "" {
			if failErr := worker.repository.FailAutomaticPublication(ctx, reference, reason); failErr != nil && !errors.Is(failErr, ErrStaleClaim) {
				return true, failErr
			}
			return true, nil
		}
		if retryErr := worker.repository.RetryAutomaticPublication(
			ctx,
			reference,
			FailurePublishUnknown,
			worker.config.RetryDelay,
		); retryErr != nil && !errors.Is(retryErr, ErrStaleClaim) {
			return true, retryErr
		}
		return true, nil
	}
	return true, nil
}

// permanentFailure is the terminal reason of a publication retrying cannot
// fix, or "" for one to retry. A refused node or a line group without nodes
// is republished by its own trigger once that changes, so the request ends
// with a reason the publication page shows instead of retrying until its
// deadline as an unknown outcome.
func permanentFailure(err error) string {
	var capability *edgepublish.TargetCapabilityError
	var challenge *edgepublish.ChallengePolicyUnavailableError
	var packs *edgepublish.RulePackUnavailableError
	var conflict *edgepublish.CrossScopeConflictError
	switch {
	case errors.Is(err, ErrPermissionDenied) || errors.Is(err, edgepublish.ErrPermissionDenied):
		return FailureRBACRevoked
	case errors.Is(err, ErrNoTargetNodes):
		return FailureNoTargetNodes
	case errors.As(err, &packs) || errors.As(err, &capability) && capability.NodeArtifactPending():
		return FailureNodeArtifactsSyncing
	case errors.As(err, &capability) || errors.As(err, &challenge):
		return FailureNodeCapability
	case errors.As(err, &conflict):
		return FailureNodeScopeConflict
	default:
		return ""
	}
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func classifyRollout(action string, states []string) (bool, string, string) {
	if len(states) == 0 || (action != "apply" && action != "rollback") {
		return false, "", ""
	}
	for _, state := range states {
		if !deploymentTerminal(state) {
			return false, "", ""
		}
	}
	for _, state := range states {
		if state == "rollback_failed" {
			return true, StateFailed, FailureRollbackFailed
		}
	}
	for _, state := range states {
		if state == "failed" {
			return true, StateFailed, FailureDeploymentFailed
		}
	}
	for _, state := range states {
		if state == "cancelled" {
			return true, StateFailed, FailureCancelled
		}
	}
	if action == "apply" {
		for _, state := range states {
			if state == "reverted" {
				return true, StateFailed, FailureApplyReverted
			}
		}
		// "superseded": the node ignored this old release, it runs a newer
		// one (edgedeployment.DeploymentSuperseded); not a failure.
		for _, state := range states {
			if state != "healthy" && state != "superseded" {
				return true, StateFailed, FailureDeploymentFailed
			}
		}
		return true, StateSucceeded, SuccessApplyHealthy
	}
	for _, state := range states {
		if state != "reverted" {
			return true, StateFailed, FailureRollbackUnexpected
		}
	}
	return true, StateSucceeded, SuccessRollbackReverted
}

// classifyPersistedRollout decides a reconciling request from its rollout.
// Only contract-v2 rollouts advance rollouts.status past queued (cohort
// facts); a v0/v1 rollout stays queued for good, so its outcome is the
// deployments' own terminal states (as the rollout snapshot derives it),
// unless it was cancelled.
func classifyPersistedRollout(contractVersion int16, action, status string, states []string) (bool, string, string) {
	if contractVersion != 2 {
		if status == "cancelled" {
			return true, StateFailed, FailureCancelled
		}
		return classifyRollout(action, states)
	}
	switch status {
	case "building", "queued", "paused":
		return false, "", ""
	case "cancelled":
		return true, StateFailed, FailureCancelled
	case "failed":
		terminal, outcome, reason := classifyRollout(action, states)
		if terminal && outcome == StateFailed {
			return terminal, outcome, reason
		}
		return true, StateFailed, FailureDeploymentFailed
	case "completed":
		terminal, outcome, reason := classifyRollout(action, states)
		if !terminal {
			return true, StateFailed, FailureDeploymentFailed
		}
		return terminal, outcome, reason
	default:
		return false, "", ""
	}
}

func deploymentTerminal(state string) bool {
	switch state {
	case "healthy", "failed", "reverted", "rollback_failed", "cancelled", "superseded":
		return true
	default:
		return false
	}
}

var _ Publisher = (*edgepublish.Service)(nil)
var _ Repository = (*Store)(nil)
