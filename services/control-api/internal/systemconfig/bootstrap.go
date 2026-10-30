package systemconfig

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrBootstrapNotFresh means the stream already carries operator history or
// the installation already has nodes or published workloads. Activation must
// then go through the console, whose publisher reaches every edge target.
var ErrBootstrapNotFresh = errors.New("system configuration bootstrap requires a fresh installation")

type BootstrapOutcome string

const (
	BootstrapActivated     BootstrapOutcome = "activated"
	BootstrapAlreadyActive BootstrapOutcome = "already_active"

	bootstrapKeyPrefix = "install-bootstrap.system-configuration.v1"
)

type BootstrapResult struct {
	Outcome  BootstrapOutcome
	Revision int64
}

// BootstrapDefaultActivation activates the project default configuration as
// revision 1 on a fresh installation so that default node monitoring (TCP) is
// in force before the first node enrolls. It reuses the audited draft →
// preflight → activate state machine with deterministic idempotency keys, so a
// rerun or an interrupted run converges on the same revision. An existing
// active revision is never replaced, and any other prior state is refused.
func BootstrapDefaultActivation(ctx context.Context, service *Service, actor Actor) (BootstrapResult, error) {
	if service == nil || service.pool == nil {
		return BootstrapResult{}, ErrInvalidStore
	}
	if err := authorizeActorShape(actor); err != nil {
		return BootstrapResult{}, err
	}
	var head int64
	var active *int64
	var workloads bool
	err := service.pool.QueryRow(ctx, `SELECT
			COALESCE((SELECT head_revision FROM system_configuration_streams WHERE platform_scope_id=$1),0),
			(SELECT active_revision FROM system_configuration_streams WHERE platform_scope_id=$1),
			EXISTS(SELECT 1 FROM nodes WHERE admin_state<>'retired') OR
			EXISTS(SELECT 1 FROM sites WHERE deleted_at IS NULL AND enabled) OR
			EXISTS(SELECT 1 FROM l4_forwards WHERE deleted_at IS NULL AND enabled)`, actor.ScopeID).
		Scan(&head, &active, &workloads)
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("inspect system configuration bootstrap state: %w", err)
	}
	if active != nil {
		return BootstrapResult{Outcome: BootstrapAlreadyActive, Revision: *active}, nil
	}
	if head > 1 || workloads {
		return BootstrapResult{}, ErrBootstrapNotFresh
	}

	// With head 1 this only replays our own earlier draft; a foreign draft at
	// revision 1 conflicts with expected head 0 and is reported as not fresh.
	draft, err := service.CreateDraft(ctx, actor, CreateDraftRequest{
		ExpectedHeadRevision: 0, Configuration: ProjectBootstrapConfiguration(),
		IdempotencyKey: bootstrapKeyPrefix + ".draft", RequestID: bootstrapKeyPrefix + ".draft",
	})
	if errors.Is(err, ErrRevisionConflict) || errors.Is(err, ErrIdempotencyConflict) {
		return BootstrapResult{}, ErrBootstrapNotFresh
	}
	if err != nil {
		return BootstrapResult{}, err
	}
	current, err := service.GetRevision(ctx, actor, draft.Revision)
	if err != nil {
		return BootstrapResult{}, err
	}
	manager := &CategoryManager{core: service}
	if current.Status == StatusDraft {
		validated, err := manager.PreflightRevision(ctx, actor, PreflightRevisionRequest{
			Revision: draft.Revision, SnapshotSHA256: draft.SnapshotSHA256,
			IdempotencyKey: bootstrapKeyPrefix + ".preflight", RequestID: bootstrapKeyPrefix + ".preflight",
		})
		if err != nil {
			return BootstrapResult{}, err
		}
		if validated.Status != StatusValidated {
			return BootstrapResult{}, fmt.Errorf("project default system configuration failed preflight: %s", validated.Status)
		}
	} else if current.Status != StatusValidated {
		return BootstrapResult{}, ErrBootstrapNotFresh
	}

	activate := ActivateRequest{
		Revision: draft.Revision, ExpectedActiveRevision: 0,
		IdempotencyKey: bootstrapKeyPrefix + ".activate", RequestID: bootstrapKeyPrefix + ".activate",
	}
	activated, err := service.Activate(ctx, actor, activate)
	if errors.Is(err, ErrPreflightExpired) {
		// A resumed run may find its preflight expired; renew it once.
		renewal := bootstrapKeyPrefix + ".preflight-renew." + uuid.NewString()
		if _, err := service.RecordPreflight(ctx, actor, RecordPreflightRequest{
			Revision: draft.Revision, ExpectedStatus: StatusValidated, SnapshotSHA256: draft.SnapshotSHA256,
			Checks:         configurationPreflightChecks(ProjectBootstrapConfiguration(), draft.SnapshotSHA256, true),
			IdempotencyKey: renewal, RequestID: renewal,
		}); err != nil {
			return BootstrapResult{}, err
		}
		activated, err = service.Activate(ctx, actor, activate)
	}
	if err != nil {
		return BootstrapResult{}, err
	}
	return BootstrapResult{Outcome: BootstrapActivated, Revision: activated.Revision}, nil
}
