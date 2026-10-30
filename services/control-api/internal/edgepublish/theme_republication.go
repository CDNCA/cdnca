package edgepublish

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Theme error page republication: a theme
// activation pins the theme in a new error page publication revision
// (errorpagecontrol.AppendThemePublication); every tenant scope that has
// published error pages then gets that revision through the system
// republication channel (trigger theme_activation), so node default error
// pages follow the theme without a tenant publish.

// SystemTriggerThemeActivation: a theme activation changed the node default
// error pages every tenant scope's published error page snapshot carries.
const SystemTriggerThemeActivation = "theme_activation"

// ThemeErrorPageRepublicationDebounce merges the activations of a quick
// series of theme switches into one error page publication per scope.
const ThemeErrorPageRepublicationDebounce = 5 * time.Second

// Theme republication states (theme_error_page_republications.state).
const (
	ThemeRepublicationPending   = "pending"
	ThemeRepublicationPublished = "published"
	ThemeRepublicationSkipped   = "skipped"
	ThemeRepublicationFailed    = "failed"
)

// ThemeRepublicationAudit is the system event recorded when an activation
// queues the error page republication (BATCH-PLUGIN §10).
const ThemeRepublicationAudit = "site.error_page.republish"

type ThemeErrorPageRepublication struct {
	ActivationRevision int64
	ThemeID            string
	PackageSHA256      string
	PlatformScopeID    uuid.UUID
	RequestID          string
	ActorIP            string
}

// QueueThemeErrorPageRepublicationTx queues the error page republication of
// every tenant scope that has published error pages, for the theme activation
// the caller just recorded in tx (and holds the theme activation lock for).
// It returns the number of scopes queued. It must run before the caller takes
// the error page publication lock (the worker locks a scope's head before it).
func QueueThemeErrorPageRepublicationTx(ctx context.Context, tx pgx.Tx, auditor AuditAppender,
	request ThemeErrorPageRepublication) (int, error) {
	if ctx == nil || tx == nil || auditor == nil || request.ActivationRevision < 1 || request.ThemeID == "" ||
		request.PlatformScopeID == uuid.Nil || request.RequestID == "" {
		return 0, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT rollout.configuration_scope_id
		FROM rollouts rollout
		JOIN configuration_artifacts artifact ON artifact.config_version_id=rollout.config_version_id
		 AND artifact.ordinal=1 AND artifact.kind='configuration' AND artifact.media_type=$1
		JOIN access_scopes scope ON scope.id=rollout.configuration_scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id
		ORDER BY 1`, errorpagecontrol.ProductionSnapshotMediaType)
	if err != nil {
		return 0, fmt.Errorf("%w: read error page scopes", ErrPersistence)
	}
	published, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, fmt.Errorf("%w: scan error page scopes", ErrPersistence)
	}
	scopes := published
	now, err := databaseNow(ctx, tx)
	if err != nil {
		return 0, err
	}
	for _, scopeID := range scopes {
		// Lock order of a publication: configuration scope, then the head.
		if _, err := lockConfigurationScope(ctx, tx, scopeID, now); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO theme_error_page_republications(
			activation_revision,scope_id,state,created_at,updated_at)
			VALUES($1,$2,'pending',clock_timestamp(),clock_timestamp())`, request.ActivationRevision, scopeID); err != nil {
			return 0, fmt.Errorf("%w: record theme republication", ErrPersistence)
		}
		// An earlier activation's pending republication is superseded: the
		// scope gets the latest theme once.
		if _, err := tx.Exec(ctx, `UPDATE theme_error_page_republications SET state='skipped',
			error_class='superseded',updated_at=clock_timestamp()
			WHERE scope_id=$1 AND activation_revision<$2 AND state='pending'`, scopeID, request.ActivationRevision); err != nil {
			return 0, fmt.Errorf("%w: supersede theme republication", ErrPersistence)
		}
		if err := RequestSystemRepublicationTx(ctx, tx, SystemRepublicationRequest{
			ScopeID: scopeID, Trigger: SystemTriggerThemeActivation, Debounce: ThemeErrorPageRepublicationDebounce,
		}); err != nil {
			return 0, err
		}
	}
	scopeIDs := make([]string, 0, len(scopes))
	for _, scopeID := range scopes {
		scopeIDs = append(scopeIDs, scopeID.String())
	}
	if err := auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.PlatformScopeID, Action: ThemeRepublicationAudit,
		ResourceType: "theme_activation", ResourceID: fmt.Sprint(request.ActivationRevision),
		RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{
			"actor_kind": "system", "trigger": SystemTriggerThemeActivation, "scope": "platform",
			"ip": request.ActorIP, "theme_id": request.ThemeID, "package_sha256": request.PackageSHA256,
			"activation_revision": request.ActivationRevision, "scope_count": len(scopes), "scope_ids": scopeIDs,
		},
	}); err != nil {
		return 0, fmt.Errorf("%w: append theme republication audit", ErrPersistence)
	}
	return len(scopes), nil
}

// SlotErrorPageRepublisher queues, for a platform error page slot change
// (errpage-content, user 10-25), the republication of every tenant scope that
// has published error pages and follows the platform theme, through the
// theme_activation channel: the worker publishes the scope's latest error page
// publication, which pins the slots. Like the theme queue it must run before
// the caller takes the error page publication lock.
type SlotErrorPageRepublisher struct{}

func (SlotErrorPageRepublisher) QueueSlotRepublicationTx(ctx context.Context, tx pgx.Tx) (int, error) {
	if ctx == nil || tx == nil {
		return 0, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT rollout.configuration_scope_id
		FROM rollouts rollout
		JOIN configuration_artifacts artifact ON artifact.config_version_id=rollout.config_version_id
		 AND artifact.ordinal=1 AND artifact.kind='configuration' AND artifact.media_type=$1
		JOIN access_scopes scope ON scope.id=rollout.configuration_scope_id AND scope.kind='tenant'
		ORDER BY 1`, errorpagecontrol.ProductionSnapshotMediaType)
	if err != nil {
		return 0, fmt.Errorf("%w: read error page scopes", ErrPersistence)
	}
	published, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, fmt.Errorf("%w: scan error page scopes", ErrPersistence)
	}
	now, err := databaseNow(ctx, tx)
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, scopeID := range published {
		if _, err := lockConfigurationScope(ctx, tx, scopeID, now); err != nil {
			return 0, err
		}
		if err := RequestSystemRepublicationTx(ctx, tx, SystemRepublicationRequest{
			ScopeID: scopeID, Trigger: SystemTriggerThemeActivation, Debounce: ThemeErrorPageRepublicationDebounce,
		}); err != nil {
			return 0, err
		}
		queued++
	}
	return queued, nil
}

// ThemeRepublicationProgress is the latest activation's republication: how
// many scopes it queued and where each stands.
type ThemeRepublicationProgress struct {
	ActivationRevision int64 `json:"activation_revision"`
	Total              int   `json:"total"`
	Pending            int   `json:"pending"`
	Published          int   `json:"published"`
	Skipped            int   `json:"skipped"`
	Failed             int   `json:"failed"`
}

// ThemeRepublicationProgressTx reads the latest activation's progress.
func ThemeRepublicationProgressTx(ctx context.Context, tx pgx.Tx) (ThemeRepublicationProgress, error) {
	var progress ThemeRepublicationProgress
	err := tx.QueryRow(ctx, `SELECT activation.revision,count(item.scope_id),
		count(*) FILTER (WHERE item.state='pending'),count(*) FILTER (WHERE item.state='published'),
		count(*) FILTER (WHERE item.state='skipped'),count(*) FILTER (WHERE item.state='failed')
		FROM (SELECT revision FROM theme_activations WHERE slot IN ('admin','all') ORDER BY revision DESC LIMIT 1) activation
		LEFT JOIN theme_error_page_republications item ON item.activation_revision=activation.revision
		GROUP BY activation.revision`).Scan(&progress.ActivationRevision, &progress.Total, &progress.Pending,
		&progress.Published, &progress.Skipped, &progress.Failed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ThemeRepublicationProgress{}, nil
	}
	return progress, err
}

// WithErrorPagePublisher lets the system republisher deliver theme
// activations (trigger theme_activation). Without it such a trigger fails and
// is retried, never dropped.
func (republisher *SystemRepublisher) WithErrorPagePublisher(publisher *ErrorPagePublisher) error {
	if republisher == nil || publisher == nil || publisher.service == nil || nilErrorPageProductionSource(publisher.source) {
		return ErrInvalidInput
	}
	republisher.errorPages = publisher
	return nil
}

var errThemeRepublisherUnavailable = errors.New("error page publisher is not configured")

// themeAttempt is the error page publication a theme_activation claim made.
type themeAttempt struct {
	rolloutID uuid.UUID
	nodeIDs   []uuid.UUID
	refused   []systemRefusal
	revision  int64
	outcome   string
}

// republishThemeTx publishes the scope's error page snapshot (the latest
// error page publication revision, which pins the active theme) to the nodes
// its last error page rollout went to that can still take it, and settles the
// scope's pending theme republications. Runs in the claim's transaction after
// the scope and head locks.
func (republisher *SystemRepublisher) republishThemeTx(ctx context.Context, tx pgx.Tx, claim systemClaim,
	attemptID uuid.UUID, now time.Time) (themeAttempt, error) {
	if republisher.errorPages == nil {
		return themeAttempt{}, errThemeRepublisherUnavailable
	}
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1 AND kind='tenant'`, claim.scopeID).
		Scan(&tenantID); err != nil {
		return themeAttempt{}, err
	}
	var activation int64
	var accountableUser, platformScope uuid.UUID
	err := tx.QueryRow(ctx, `SELECT activation.revision,activation.activated_by_user_id,activation.platform_scope_id
		FROM theme_activations activation ORDER BY activation.revision DESC LIMIT 1`).
		Scan(&activation, &accountableUser, &platformScope)
	if errors.Is(err, pgx.ErrNoRows) {
		// A tenant theme (PA-26) can change before any platform activation:
		// the accountable platform member is then the first active one.
		err = tx.QueryRow(ctx, `SELECT membership.user_id,membership.scope_id FROM memberships membership
			JOIN access_scopes scope ON scope.id=membership.scope_id AND scope.kind='platform'
			WHERE membership.status='active' ORDER BY membership.created_at,membership.user_id LIMIT 1`).
			Scan(&accountableUser, &platformScope)
		if errors.Is(err, pgx.ErrNoRows) {
			return themeAttempt{outcome: SystemOutcomeNoBaseline}, nil
		}
	}
	if err != nil {
		return themeAttempt{}, err
	}
	var latestRollout uuid.UUID
	err = tx.QueryRow(ctx, `SELECT rollout.id FROM rollouts rollout
		JOIN configuration_artifacts artifact ON artifact.config_version_id=rollout.config_version_id
		 AND artifact.ordinal=1 AND artifact.kind='configuration' AND artifact.media_type=$2
		WHERE rollout.configuration_scope_id=$1 ORDER BY rollout.created_at DESC,rollout.id DESC LIMIT 1`,
		claim.scopeID, errorpagecontrol.ProductionSnapshotMediaType).Scan(&latestRollout)
	if errors.Is(err, pgx.ErrNoRows) {
		return themeAttempt{outcome: SystemOutcomeNoBaseline}, settleThemeTx(ctx, tx, claim.scopeID, activation,
			ThemeRepublicationSkipped, nil, 0, SystemOutcomeNoBaseline)
	}
	if err != nil {
		return themeAttempt{}, err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT node_id FROM node_deployments WHERE rollout_id=$1 ORDER BY node_id`, latestRollout)
	if err != nil {
		return themeAttempt{}, err
	}
	seeds, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return themeAttempt{}, err
	}
	candidates, refused, err := systemTargetNodes(ctx, tx, claim.scopeID, slices.Concat(seeds, claim.excluded), false)
	if err != nil {
		return themeAttempt{}, err
	}
	if len(candidates) == 0 {
		return themeAttempt{outcome: SystemOutcomeNoCapableTarget, refused: refused},
			settleThemeTx(ctx, tx, claim.scopeID, activation, ThemeRepublicationSkipped, nil, 0, SystemOutcomeNoCapableTarget)
	}
	current, err := lockConfigurationScope(ctx, tx, claim.scopeID, now)
	if err != nil {
		return themeAttempt{}, err
	}
	actor := Actor{UserID: accountableUser, ScopeID: platformScope, ScopeKind: ScopeKindPlatform,
		system: &systemActorFacts{attemptID: attemptID, triggers: slices.Clone(claim.triggers)}}
	request := PublishRequest{
		Actor: actor, ConfigurationScopeID: claim.scopeID, ExpectedSourceRevision: current,
		NodeIDs: slices.Clone(candidates), MaxAttempts: 3, Deadline: now.Add(systemRepublicationDeadline),
		IdempotencyKey: "syspub.theme." + attemptID.String(), RequestID: attemptID.String(),
		CorrelationID: attemptID.String(),
	}
	request.HealthCheck.ActivationTimeout = 30 * time.Second
	request.HealthCheck.ObservationWindow = 5 * time.Second
	request.HealthCheck.RequiredConsecutiveSuccesses = 2
	normalized, err := normalizeAutomaticPublishRequest(request, now)
	if err != nil {
		return themeAttempt{}, err
	}
	result, err := republisher.errorPages.publishAuthorizedTx(ctx, tx, normalized, tenantID, now)
	if err != nil {
		return themeAttempt{}, err
	}
	return themeAttempt{outcome: SystemOutcomePublished, rolloutID: result.RolloutID, nodeIDs: candidates,
			refused: refused, revision: int64(result.Binding.PublicationRevision)},
		settleThemeTx(ctx, tx, claim.scopeID, activation, ThemeRepublicationPublished, &result.RolloutID, len(candidates), "")
}

// settleThemeTx settles the scope's pending theme republications up to the
// latest activation: the one publication delivered them all.
func settleThemeTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, activation int64, state string,
	rolloutID *uuid.UUID, nodes int, reason string) error {
	_, err := tx.Exec(ctx, `UPDATE theme_error_page_republications SET state=$3,rollout_id=$4,node_count=$5,
		error_class=NULLIF($6,''),updated_at=clock_timestamp()
		WHERE scope_id=$1 AND activation_revision<=$2 AND state='pending'`, scopeID, activation, state, rolloutID, nodes, reason)
	return err
}

// failThemeTx marks the scope's pending theme republications failed once the
// claim gave up (SystemRepublicationMaxAttempts); the next activation queues
// them again.
func failThemeTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, class string) error {
	_, err := tx.Exec(ctx, `UPDATE theme_error_page_republications SET state='failed',error_class=$2,
		updated_at=clock_timestamp() WHERE scope_id=$1 AND state='pending'`, scopeID, class)
	return err
}
