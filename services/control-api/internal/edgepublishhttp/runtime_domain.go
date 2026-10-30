package edgepublishhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type iamReadDomain struct {
	pool         *pgxpool.Pool
	authorizer   *iamlock.Authorizer
	identity     *identity.Service
	publications PublicationDomain
}

type runtimePublicationCursor struct {
	CreatedAt     time.Time `json:"created_at"`
	PublicationID uuid.UUID `json:"publication_id"`
}

type runtimeRolloutCursor struct {
	CreatedAt time.Time `json:"created_at"`
	RolloutID uuid.UUID `json:"rollout_id"`
}

type runtimeDeploymentCursor struct {
	NodeID       uuid.UUID `json:"node_id"`
	DeploymentID uuid.UUID `json:"deployment_id"`
}

func newIAMReadDomain(
	pool *pgxpool.Pool,
	authorizer *iamlock.Authorizer,
	identityService *identity.Service,
	publications PublicationDomain,
) (*iamReadDomain, error) {
	if !runtimePoolConfigured(pool) || authorizer == nil || !authorizer.Configured() ||
		identityService == nil || !identityService.Configured() || nilPort(publications) {
		return nil, ErrInvalidRuntimeConfig
	}
	return &iamReadDomain{
		pool: pool, authorizer: authorizer, identity: identityService, publications: publications,
	}, nil
}

func (domain *iamReadDomain) Publish(
	ctx context.Context,
	request edgepublish.PublishRequest,
) (edgepublish.PublishResult, error) {
	return domain.publications.Publish(ctx, request)
}

func (domain *iamReadDomain) Rollback(
	ctx context.Context,
	request edgepublish.RollbackRequest,
) (edgepublish.RollbackResult, error) {
	return domain.publications.Rollback(ctx, request)
}

func (domain *iamReadDomain) GetPublication(
	ctx context.Context,
	actor edgepublish.Actor,
	scopeID, publicationID uuid.UUID,
) (edgepublish.PublishResult, error) {
	if ctx == nil || scopeID == uuid.Nil || publicationID == uuid.Nil {
		return edgepublish.PublishResult{}, edgepublish.ErrInvalidInput
	}
	var result edgepublish.PublishResult
	err := pgx.BeginTxFunc(ctx, domain.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := domain.authorizeRead(ctx, tx, actor.UserID, actor.ScopeID, actor.ScopeKind, scopeID); err != nil {
			return err
		}
		var err error
		result, err = scanRuntimePublication(tx.QueryRow(ctx, publicationSelect+`
			WHERE configuration_scope_id=$1 AND id=$2`, scopeID, publicationID), scopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return edgepublish.ErrNotFound
		}
		if err != nil {
			return runtimeReadPersistence(ctx, "get publication", err)
		}
		return nil
	})
	return result, err
}

func (domain *iamReadDomain) ListPublications(
	ctx context.Context,
	actor edgepublish.Actor,
	scopeID uuid.UUID,
	request edgepublish.PublicationPageRequest,
) (edgepublish.PublicationPage, error) {
	if ctx == nil || scopeID == uuid.Nil || request.Limit < 0 || request.Limit > 100 {
		return edgepublish.PublicationPage{}, edgepublish.ErrInvalidInput
	}
	if request.Limit == 0 {
		request.Limit = 20
	}
	cursor, err := decodeRuntimeCursor[runtimePublicationCursor](request.Cursor)
	if err != nil || cursor != nil && (cursor.CreatedAt.IsZero() || cursor.PublicationID == uuid.Nil) {
		return edgepublish.PublicationPage{}, edgepublish.ErrInvalidInput
	}
	var result edgepublish.PublicationPage
	err = pgx.BeginTxFunc(ctx, domain.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := domain.authorizeRead(ctx, tx, actor.UserID, actor.ScopeID, actor.ScopeKind, scopeID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(configuration.source_revision,1)
			FROM access_scopes scope
			LEFT JOIN edge_configuration_scopes configuration ON configuration.scope_id=scope.id
			WHERE scope.id=$1 AND scope.kind='tenant'`, scopeID).Scan(&result.CurrentSourceRevision); errors.Is(err, pgx.ErrNoRows) {
			return edgepublish.ErrInvalidInput
		} else if err != nil || result.CurrentSourceRevision < 1 {
			return runtimeReadPersistence(ctx, "read current source revision", err)
		}
		if result.PendingModules, err = edgepublish.ModulePublicationHoldsTx(ctx, tx, scopeID); err != nil {
			return runtimeReadPersistence(ctx, "read pending modules", err)
		}
		if result.AutomaticFailure, err = edgepublish.LatestAutomaticFailureTx(ctx, tx, scopeID); err != nil {
			return runtimeReadPersistence(ctx, "read automatic publication failure", err)
		}
		var cursorTime *time.Time
		var cursorID *uuid.UUID
		if cursor != nil {
			cursorTime, cursorID = &cursor.CreatedAt, &cursor.PublicationID
		}
		rows, err := tx.Query(ctx, publicationSelect+`
			WHERE configuration_scope_id=$1
			  AND ($2::timestamptz IS NULL OR (created_at,id) < ($2,$3))
			ORDER BY created_at DESC,id DESC LIMIT $4`, scopeID, cursorTime, cursorID, request.Limit+1)
		if err != nil {
			return runtimeReadPersistence(ctx, "list publications", err)
		}
		defer rows.Close()
		items := make([]edgepublish.PublishResult, 0, request.Limit+1)
		for rows.Next() {
			item, err := scanRuntimePublication(rows, scopeID)
			if err != nil {
				return runtimeReadPersistence(ctx, "scan publication", err)
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return runtimeReadPersistence(ctx, "iterate publications", err)
		}
		if len(items) > request.Limit {
			last := items[request.Limit-1]
			result.NextCursor, err = encodeRuntimeCursor(runtimePublicationCursor{
				CreatedAt: last.CreatedAt, PublicationID: last.PublicationID,
			})
			if err != nil {
				return runtimeReadPersistence(ctx, "encode publication cursor", err)
			}
			items = items[:request.Limit]
		}
		result.Items = items
		return nil
	})
	return result, err
}

const publicationSelect = `
	SELECT id,source_revision,canonical_snapshot_sha256,artifact_sha256,
	       config_version_id,rollout_id,node_count,created_at,target_kind,
	       target_snapshot_id,target_snapshot_revision,target_resolver_sha256,target_snapshot_sha256
	FROM edge_config_publications `

func scanRuntimePublication(row interface{ Scan(...any) error }, scopeID uuid.UUID) (edgepublish.PublishResult, error) {
	var result edgepublish.PublishResult
	var snapshotDigest, artifactDigest, resolverDigest, targetDigest []byte
	var targetID *uuid.UUID
	var targetRevision *int64
	if err := row.Scan(
		&result.PublicationID, &result.SourceRevision, &snapshotDigest, &artifactDigest,
		&result.ConfigVersionID, &result.RolloutID, &result.NodeCount, &result.CreatedAt, &result.TargetKind,
		&targetID, &targetRevision, &resolverDigest, &targetDigest,
	); err != nil {
		return edgepublish.PublishResult{}, err
	}
	if len(snapshotDigest) != 32 || len(artifactDigest) != 32 || len(targetDigest) != 32 {
		return edgepublish.PublishResult{}, errors.New("invalid publication digest")
	}
	result.ConfigurationScopeID = scopeID
	copy(result.CanonicalSnapshotSHA256[:], snapshotDigest)
	copy(result.ArtifactSHA256[:], artifactDigest)
	copy(result.TargetSnapshotSHA256[:], targetDigest)
	if targetID != nil || targetRevision != nil || len(resolverDigest) != 0 {
		if targetID == nil || targetRevision == nil || len(resolverDigest) != 32 {
			return edgepublish.PublishResult{}, errors.New("invalid publication target")
		}
		result.TargetSnapshot = &edgepublish.TargetSnapshotReference{ID: *targetID, Revision: *targetRevision}
		copy(result.TargetSnapshot.SHA256[:], resolverDigest)
	}
	return result, nil
}

func (domain *iamReadDomain) GetRollout(
	ctx context.Context,
	actor edgedeployment.Actor,
	scopeID, rolloutID uuid.UUID,
) (edgedeployment.RolloutSnapshot, error) {
	if ctx == nil || scopeID == uuid.Nil || rolloutID == uuid.Nil {
		return edgedeployment.RolloutSnapshot{}, edgedeployment.ErrInvalidInput
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	var result edgedeployment.RolloutSnapshot
	err := pgx.BeginTxFunc(ctx, domain.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := domain.authorizeRead(ctx, tx, actor.UserID, actor.ScopeID, actor.ScopeKind, scopeID); err != nil {
			return err
		}
		var err error
		result, err = loadRuntimeRollout(ctx, tx, scopeID, rolloutID, now)
		return err
	})
	return result, err
}

func (domain *iamReadDomain) ListRollouts(
	ctx context.Context,
	actor edgedeployment.Actor,
	scopeID uuid.UUID,
	request edgedeployment.RolloutPageRequest,
) (edgedeployment.RolloutPage, error) {
	if ctx == nil || scopeID == uuid.Nil || request.Limit < 0 || request.Limit > 100 {
		return edgedeployment.RolloutPage{}, edgedeployment.ErrInvalidInput
	}
	if request.Limit == 0 {
		request.Limit = 20
	}
	cursor, err := decodeRuntimeCursor[runtimeRolloutCursor](request.Cursor)
	if err != nil || cursor != nil && (cursor.CreatedAt.IsZero() || cursor.RolloutID == uuid.Nil) {
		return edgedeployment.RolloutPage{}, edgedeployment.ErrInvalidInput
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	var result edgedeployment.RolloutPage
	err = pgx.BeginTxFunc(ctx, domain.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := domain.authorizeRead(ctx, tx, actor.UserID, actor.ScopeID, actor.ScopeKind, scopeID); err != nil {
			return err
		}
		var cursorTime *time.Time
		var cursorID *uuid.UUID
		if cursor != nil {
			cursorTime, cursorID = &cursor.CreatedAt, &cursor.RolloutID
		}
		rows, err := tx.Query(ctx, `SELECT id,created_at FROM rollouts
			WHERE configuration_scope_id=$1
			  AND ($2::timestamptz IS NULL OR (created_at,id) < ($2,$3))
			ORDER BY created_at DESC,id DESC LIMIT $4`, scopeID, cursorTime, cursorID, request.Limit+1)
		if err != nil {
			return runtimeReadPersistence(ctx, "list rollouts", err)
		}
		keys := make([]runtimeRolloutCursor, 0, request.Limit+1)
		for rows.Next() {
			var key runtimeRolloutCursor
			if err := rows.Scan(&key.RolloutID, &key.CreatedAt); err != nil {
				rows.Close()
				return runtimeReadPersistence(ctx, "scan rollout key", err)
			}
			keys = append(keys, key)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return runtimeReadPersistence(ctx, "iterate rollout keys", err)
		}
		rows.Close()
		if len(keys) > request.Limit {
			result.NextCursor, err = encodeRuntimeCursor(keys[request.Limit-1])
			if err != nil {
				return runtimeReadPersistence(ctx, "encode rollout cursor", err)
			}
			keys = keys[:request.Limit]
		}
		result.Items = make([]edgedeployment.RolloutSnapshot, 0, len(keys))
		for _, key := range keys {
			item, err := loadRuntimeRollout(ctx, tx, scopeID, key.RolloutID, now)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, item)
		}
		return nil
	})
	return result, err
}

func (domain *iamReadDomain) ListDeployments(
	ctx context.Context,
	actor edgedeployment.Actor,
	scopeID, rolloutID uuid.UUID,
	request edgedeployment.DeploymentPageRequest,
) (edgedeployment.DeploymentPage, error) {
	if ctx == nil || scopeID == uuid.Nil || rolloutID == uuid.Nil || request.Limit < 0 || request.Limit > 100 {
		return edgedeployment.DeploymentPage{}, edgedeployment.ErrInvalidInput
	}
	if request.Limit == 0 {
		request.Limit = 20
	}
	cursor, err := decodeRuntimeCursor[runtimeDeploymentCursor](request.Cursor)
	if err != nil || cursor != nil && (cursor.NodeID == uuid.Nil || cursor.DeploymentID == uuid.Nil) {
		return edgedeployment.DeploymentPage{}, edgedeployment.ErrInvalidInput
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	var result edgedeployment.DeploymentPage
	err = pgx.BeginTxFunc(ctx, domain.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		if err := domain.authorizeRead(ctx, tx, actor.UserID, actor.ScopeID, actor.ScopeKind, scopeID); err != nil {
			return err
		}
		var maxAttempts int
		var deadline time.Time
		if err := tx.QueryRow(ctx, `SELECT max_attempts,deadline_at FROM rollouts
			WHERE configuration_scope_id=$1 AND id=$2`, scopeID, rolloutID).Scan(
			&maxAttempts, &deadline,
		); errors.Is(err, pgx.ErrNoRows) {
			return edgedeployment.ErrNotFound
		} else if err != nil {
			return runtimeReadPersistence(ctx, "read rollout deployment limit", err)
		}
		items, err := loadRuntimeDeployments(
			ctx, tx, scopeID, rolloutID, uint32(maxAttempts), deadline.After(now), cursor, request.Limit+1,
		)
		if err != nil {
			return err
		}
		if len(items) > request.Limit {
			last := items[request.Limit-1]
			result.NextCursor, err = encodeRuntimeCursor(runtimeDeploymentCursor{
				NodeID: last.NodeID, DeploymentID: last.ID,
			})
			if err != nil {
				return runtimeReadPersistence(ctx, "encode deployment cursor", err)
			}
			items = items[:request.Limit]
		}
		result.Items = items
		return nil
	})
	return result, err
}

func loadRuntimeRollout(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, rolloutID uuid.UUID,
	now time.Time,
) (edgedeployment.RolloutSnapshot, error) {
	var result edgedeployment.RolloutSnapshot
	var persistedState string
	var maxAttempts int
	var contractVersion int16
	var strategy string
	var canarySize, batchSize, failureThreshold int
	var pauseReason *string
	var deadline time.Time
	if err := tx.QueryRow(ctx, `SELECT id,configuration_scope_id,config_version_id,action,status,revision,
		max_attempts,created_at,updated_at,contract_version,strategy,canary_size,batch_size,failure_threshold,
		released_cohort,pause_reason,deadline_at FROM rollouts WHERE configuration_scope_id=$1 AND id=$2`,
		scopeID, rolloutID).Scan(
		&result.ID, &result.ConfigurationScopeID, &result.ConfigVersionID, &result.Action,
		&persistedState, &result.Revision, &maxAttempts, &result.CreatedAt, &result.UpdatedAt,
		&contractVersion, &strategy, &canarySize, &batchSize, &failureThreshold,
		&result.ReleasedCohort, &pauseReason, &deadline,
	); errors.Is(err, pgx.ErrNoRows) {
		return edgedeployment.RolloutSnapshot{}, edgedeployment.ErrNotFound
	} else if err != nil {
		return edgedeployment.RolloutSnapshot{}, runtimeReadPersistence(ctx, "read rollout", err)
	}
	result.MaxAttempts = uint32(maxAttempts)
	if pauseReason != nil {
		result.PauseReason = *pauseReason
	}
	deployments, err := loadRuntimeDeployments(
		ctx, tx, scopeID, rolloutID, result.MaxAttempts, deadline.After(now), nil, 10001,
	)
	if err != nil {
		return edgedeployment.RolloutSnapshot{}, err
	}
	if len(deployments) == 0 || len(deployments) > 10000 {
		return edgedeployment.RolloutSnapshot{}, edgepublish.ErrPersistence
	}
	if contractVersion == 2 {
		result.Policy = edgedeployment.RolloutPolicy{Strategy: strategy, CanarySize: uint32(canarySize),
			BatchSize: uint32(batchSize), FailureThreshold: uint32(failureThreshold),
			CohortCount: deployments[len(deployments)-1].Cohort + 1}
	}
	applyRuntimeRolloutAggregate(&result, persistedState, deployments)
	return result, nil
}

func loadRuntimeDeployments(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, rolloutID uuid.UUID,
	maxAttempts uint32,
	retryAllowed bool,
	cursor *runtimeDeploymentCursor,
	limit int,
) ([]edgedeployment.DeploymentSnapshot, error) {
	var cursorNodeID, cursorDeploymentID *uuid.UUID
	if cursor != nil {
		cursorNodeID, cursorDeploymentID = &cursor.NodeID, &cursor.DeploymentID
	}
	rows, err := tx.Query(ctx, `WITH latest AS (
			SELECT DISTINCT ON (deployment.id)
			       deployment.id,deployment.node_id,deployment.attempt,deployment.state,deployment.cohort,
			       deployment.created_at,deployment.updated_at
			FROM node_deployments deployment
			JOIN rollouts rollout ON rollout.id=deployment.rollout_id
			WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2
			ORDER BY deployment.id,deployment.attempt DESC
		)
		SELECT latest.id,latest.node_id,latest.attempt,latest.state,latest.cohort,
		       latest.created_at,latest.updated_at,event.payload,outbox.status,`+edgedeployment.FrozenMarkSQL+`
		FROM latest
		JOIN edge_command_outbox outbox ON outbox.deployment_id=latest.id AND outbox.deployment_attempt=latest.attempt
		LEFT JOIN LATERAL (
			SELECT payload FROM deployment_status_events
			WHERE deployment_id=latest.id AND attempt=latest.attempt
			ORDER BY transition_sequence DESC LIMIT 1
		) event ON true
		WHERE ($3::uuid IS NULL OR (latest.node_id,latest.id) > ($3,$4))
		ORDER BY latest.node_id,latest.id LIMIT $5`,
		scopeID, rolloutID, cursorNodeID, cursorDeploymentID, limit)
	if err != nil {
		return nil, runtimeReadPersistence(ctx, "list rollout deployments", err)
	}
	defer rows.Close()
	result := make([]edgedeployment.DeploymentSnapshot, 0, limit)
	for rows.Next() {
		var item edgedeployment.DeploymentSnapshot
		var attempt int
		var payload []byte
		var outboxStatus, frozenMark string
		if err := rows.Scan(&item.ID, &item.NodeID, &attempt, &item.State, &item.Cohort,
			&item.CreatedAt, &item.UpdatedAt, &payload, &outboxStatus, &frozenMark); err != nil {
			return nil, runtimeReadPersistence(ctx, "scan rollout deployment", err)
		}
		item.Attempt, item.MaxAttempts = uint32(attempt), maxAttempts
		item.Released = outboxStatus != "held"
		code, unchanged := edgedeployment.DeploymentStatusError(payload)
		item.ErrorCode = code
		item.Superseded = edgedeployment.DeploymentSuperseded(item.State, code, unchanged)
		item.CanRetry = retryAllowed && runtimeDeploymentFailed(item.State) && !item.Superseded && item.Attempt < maxAttempts
		item.Warnings = edgedeployment.DeploymentWarnings(payload)
		edgedeployment.ApplyFrozenMark(&item, frozenMark)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, runtimeReadPersistence(ctx, "iterate rollout deployments", err)
	}
	return result, nil
}

func applyRuntimeRolloutAggregate(
	result *edgedeployment.RolloutSnapshot,
	persistedState string,
	deployments []edgedeployment.DeploymentSnapshot,
) {
	for _, deployment := range deployments {
		switch {
		case deployment.State == "queued":
			result.Progress.Pending++
		case result.Action == "apply" && deployment.State == "healthy" ||
			result.Action == "rollback" && deployment.State == "reverted":
			result.Progress.Succeeded++
		case deployment.Frozen:
			result.Progress.Frozen++
		case deployment.Superseded:
			result.Progress.Superseded++
		case runtimeDeploymentFailed(deployment.State):
			result.Progress.Failed++
		case deployment.State == "cancelled":
			result.Progress.Cancelled++
		default:
			result.Progress.Running++
		}
	}
	result.Progress.Total = len(deployments)
	if result.Policy.Strategy == edgedeployment.RolloutStrategyCanary {
		switch persistedState {
		case "queued":
			result.State = edgedeployment.RolloutStateQueued
		case "running":
			result.State = edgedeployment.RolloutStateRunning
		case "paused":
			result.State = edgedeployment.RolloutStatePaused
		case "cancelled":
			result.State = edgedeployment.RolloutStateCancelled
		case "failed":
			result.State = edgedeployment.RolloutStateFailed
		case "completed":
			if result.Progress.Succeeded+result.Progress.Superseded+result.Progress.Frozen == result.Progress.Total {
				result.State = edgedeployment.RolloutStateSucceeded
			} else {
				result.State = edgedeployment.RolloutStatePartialFailed
			}
		}
		result.CanStart = persistedState == "queued" && result.ReleasedCohort == -1
		result.CanPause = persistedState == "running"
		result.CanResume = persistedState == "paused"
		result.CanCancel = persistedState == "queued" || persistedState == "running" || persistedState == "paused"
		result.CanRetry = persistedState == "paused" &&
			runtimeHasRetryableCohortDeployment(deployments, result.ReleasedCohort)
		return
	}
	// A frozen refusal is no failure: the redelivery is a new publication.
	terminal := result.Progress.Succeeded + result.Progress.Superseded + result.Progress.Frozen + result.Progress.Failed + result.Progress.Cancelled
	switch {
	case result.Progress.Cancelled == result.Progress.Total && persistedState == "cancelled":
		result.State = edgedeployment.RolloutStateCancelled
	case result.Progress.Succeeded+result.Progress.Superseded+result.Progress.Frozen == result.Progress.Total:
		result.State = edgedeployment.RolloutStateSucceeded
	case terminal == result.Progress.Total && result.Progress.Failed > 0 && result.Progress.Succeeded == 0:
		result.State = edgedeployment.RolloutStateFailed
	case terminal == result.Progress.Total && (result.Progress.Failed > 0 || result.Progress.Cancelled > 0):
		result.State = edgedeployment.RolloutStatePartialFailed
	case result.Progress.Pending == result.Progress.Total:
		result.State = edgedeployment.RolloutStateQueued
	default:
		result.State = edgedeployment.RolloutStateRunning
	}
	result.CanCancel = persistedState == "queued" && result.Progress.Pending == result.Progress.Total
	result.CanRetry = (result.State == edgedeployment.RolloutStateFailed ||
		result.State == edgedeployment.RolloutStatePartialFailed) && runtimeHasRetryableDeployment(deployments)
}

func runtimeHasRetryableCohortDeployment(
	deployments []edgedeployment.DeploymentSnapshot,
	cohort int,
) bool {
	for _, deployment := range deployments {
		if deployment.Cohort == cohort && deployment.CanRetry {
			return true
		}
	}
	return false
}

func runtimeHasRetryableDeployment(deployments []edgedeployment.DeploymentSnapshot) bool {
	for _, deployment := range deployments {
		if deployment.CanRetry {
			return true
		}
	}
	return false
}

func runtimeDeploymentFailed(state string) bool {
	return state == "failed" || state == "rollback_failed"
}

func (domain *iamReadDomain) authorizeRead(
	ctx context.Context,
	tx pgx.Tx,
	userID, authenticationScopeID uuid.UUID,
	scopeKind string,
	targetScopeID uuid.UUID,
) error {
	credential, ok := ctx.Value(authenticatedCredentialContextKey{}).(AuthenticatedSession)
	rawToken := credential.rawToken()
	if !ok || rawToken == "" || credential.Principal.UserID != userID ||
		credential.Principal.ScopeID != authenticationScopeID || credential.Principal.ScopeKind != scopeKind {
		return ErrUnauthenticated
	}
	permission := edgepublish.PermissionRead
	if scopeKind == AudienceTenant {
		permission = tenantReadPermission
		if targetScopeID != authenticationScopeID || credential.Principal.TenantID == nil ||
			*credential.Principal.TenantID == uuid.Nil {
			return ErrPermissionDenied
		}
	} else if scopeKind != AudiencePlatform {
		return ErrPermissionDenied
	}
	if (credential.kind != credentialSession && credential.kind != credentialAPIKey) ||
		(credential.kind == credentialSession && credential.SessionID == uuid.Nil) {
		return ErrUnauthenticated
	}

	var authorization iamlock.Authorization
	var err error
	if credential.kind == credentialAPIKey {
		authorization, err = domain.authorizer.AuthorizeAPIKey(ctx, tx, rawToken, targetScopeID, permission)
	} else {
		authorization, err = domain.authorizer.AuthorizeSession(ctx, tx, rawToken, targetScopeID, permission)
	}
	if err != nil {
		return domain.authorizationError(ctx, credential, err)
	}
	if !authorization.Valid() || authorization.UserID() != userID ||
		authorization.AuthenticationScopeID() != authenticationScopeID ||
		authorization.TargetScopeID() != targetScopeID || authorization.CredentialKind() != credential.kind {
		return ErrPermissionDenied
	}
	sealedTenantID, hasTenant := authorization.TenantID()
	if !hasTenant {
		return ErrPermissionDenied
	}
	if scopeKind == AudienceTenant && sealedTenantID != *credential.Principal.TenantID {
		return ErrPermissionDenied
	}
	if credential.kind == credentialSession && authorization.CredentialID() != credential.SessionID {
		return ErrPermissionDenied
	}
	return nil
}

func (domain *iamReadDomain) authorizationError(
	ctx context.Context,
	credential AuthenticatedSession,
	err error,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, iamlock.ErrInvalidCredential) {
		return ErrUnauthenticated
	}
	if !errors.Is(err, iamlock.ErrPermissionDenied) {
		return runtimeReadPersistence(ctx, "authorize read", err)
	}
	if credential.kind == credentialAPIKey {
		return ErrPermissionDenied
	}
	if credential.kind != credentialSession {
		return ErrUnauthenticated
	}
	session, authenticateErr := domain.identity.AuthenticateSession(ctx, credential.rawToken())
	if authenticateErr != nil {
		if errors.Is(authenticateErr, identity.ErrInvalidSession) {
			return ErrUnauthenticated
		}
		return runtimeReadPersistence(ctx, "re-authenticate read", authenticateErr)
	}
	current := session.Principal
	if session.SessionID != credential.SessionID || current.UserID != credential.Principal.UserID ||
		current.ScopeID != credential.Principal.ScopeID || current.ScopeKind != credential.Principal.ScopeKind ||
		!sameTenant(current.TenantID, credential.Principal.TenantID) {
		return ErrUnauthenticated
	}
	return ErrPermissionDenied
}

func sameTenant(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func decodeRuntimeCursor[T any](encoded string) (*T, error) {
	if encoded == "" {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var cursor T
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return nil, err
	}
	return &cursor, nil
}

func encodeRuntimeCursor(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func runtimeReadPersistence(ctx context.Context, operation string, _ error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%w: %s", edgepublish.ErrPersistence, operation)
}

var _ PublicationDomain = (*iamReadDomain)(nil)
var _ RolloutDomain = (*iamReadDomain)(nil)
