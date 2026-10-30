package site

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const statusRecoveryKind = "site.status_recovery"

type statusRecoverySubject struct {
	SiteID             uuid.UUID
	Trigger            RecoveryTrigger
	SiteRevision       int64
	EdgeSourceRevision int64
}

type statusProjectionQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type StatusRecoveryStartRequest struct {
	TenantID      uuid.UUID
	TaskID        uuid.UUID
	WorkerID      string
	LeaseDuration time.Duration
}

type StatusRecoveryReportRequest struct {
	TenantID uuid.UUID
	TaskID   uuid.UUID
	WorkerID string
	LeaseID  uuid.UUID
	State    jobstate.ItemState
	Code     string
	Attempt  uint32
	Sequence uint64
}

func projectOperationalStatus(stored string, locked bool) OperationalStatus {
	if locked {
		return OperationalStatusLocked
	}
	switch stored {
	case StatusPackageExpired:
		return OperationalStatusPackageExpired
	case StatusTrafficExceeded:
		return OperationalStatusTrafficExceeded
	default:
		return OperationalStatusNormal
	}
}

func OperationalStatusOf(stored string, locked bool) OperationalStatus {
	return projectOperationalStatus(stored, locked)
}

func validRecoveryTrigger(trigger RecoveryTrigger) bool {
	return trigger == RecoveryTriggerRenewal || trigger == RecoveryTriggerTrafficTopUp ||
		trigger == RecoveryTriggerUnlock
}

func newStatusRecoverySubject(siteID uuid.UUID, trigger RecoveryTrigger, siteRevision, edgeSourceRevision int64) (string, error) {
	if siteID == uuid.Nil || !validRecoveryTrigger(trigger) || siteRevision < 1 || edgeSourceRevision < 1 {
		return "", ErrInvalidInput
	}
	return fmt.Sprintf("site/status-recovery/%s/%s/%d/%d", siteID, trigger, siteRevision, edgeSourceRevision), nil
}

func parseStatusRecoverySubject(subject string) (statusRecoverySubject, error) {
	parts := strings.Split(subject, "/")
	if len(parts) != 6 || parts[0] != "site" || parts[1] != "status-recovery" {
		return statusRecoverySubject{}, ErrInvalidInput
	}
	siteID, err := uuid.Parse(parts[2])
	if err != nil || siteID == uuid.Nil {
		return statusRecoverySubject{}, ErrInvalidInput
	}
	trigger := RecoveryTrigger(parts[3])
	if !validRecoveryTrigger(trigger) {
		return statusRecoverySubject{}, ErrInvalidInput
	}
	siteRevision, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil || siteRevision < 1 {
		return statusRecoverySubject{}, ErrInvalidInput
	}
	edgeRevision, err := strconv.ParseInt(parts[5], 10, 64)
	if err != nil || edgeRevision < 1 {
		return statusRecoverySubject{}, ErrInvalidInput
	}
	return statusRecoverySubject{SiteID: siteID, Trigger: trigger, SiteRevision: siteRevision, EdgeSourceRevision: edgeRevision}, nil
}

func validateRecoveryReport(current, report RecoveryReportCursor, desired, active uuid.UUID, healthy bool) error {
	if report.Attempt < current.Attempt || report.Attempt == current.Attempt && report.Sequence < current.Sequence {
		return ErrRecoveryReportStale
	}
	if report == current {
		return ErrRecoveryReportDuplicate
	}
	if desired == uuid.Nil || active != desired {
		return ErrRecoveryVersionMismatch
	}
	if !healthy {
		return ErrRecoveryUnhealthy
	}
	return nil
}

func recoveryIdempotencyKey(actor Actor, clientKey string) string {
	digest := sha256.Sum256([]byte(actor.ScopeID.String() + "\x00" + actor.UserID.String() + "\x00" + clientKey))
	return "site-recovery-" + hex.EncodeToString(digest[:])
}

func (s *Store) requestStatusRecovery(
	ctx context.Context,
	actor Actor,
	request StatusRecoveryRequest,
	digest [32]byte,
) (WriteResult, error) {
	operation := statusRecoveryKind + "." + string(request.Trigger)
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// The IAM global lock (taken by authorization) must be the first
		// effective lock of the transaction (069), so authorize before the
		// site row lock, as Update does.
		targetScopeID, err := mutationTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if err := authorizeAutomaticMutation(ctx, tx, actor, targetScopeID); err != nil {
			return err
		}
		var scopeID, tenantID uuid.UUID
		var storedStatus string
		var lockedAt *time.Time
		var deletedAt *time.Time
		var currentRevision int64
		query := `SELECT site.scope_id,scope.tenant_id,site.status,site.locked_at,site.deleted_at,site.revision
			FROM sites site JOIN access_scopes scope ON scope.id=site.scope_id WHERE site.id=$1`
		args := []any{request.ID}
		if actor.ScopeKind == "tenant" {
			query += ` AND site.scope_id=$2`
			args = append(args, actor.ScopeID)
		}
		query += ` FOR UPDATE OF site`
		if err := tx.QueryRow(ctx, query, args...).Scan(&scopeID, &tenantID, &storedStatus, &lockedAt, &deletedAt, &currentRevision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if deletedAt != nil || scopeID != targetScopeID {
			return ErrNotFound
		}
		if currentRevision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if request.Trigger == RecoveryTriggerUnlock && lockedAt == nil ||
			request.Trigger == RecoveryTriggerRenewal && storedStatus != StatusPackageExpired ||
			request.Trigger == RecoveryTriggerTrafficTopUp && storedStatus != StatusTrafficExceeded {
			return ErrLockStateConflict
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := decodeStoredSite(write.ResponseBody, &result.Site); err != nil {
				return err
			}
			if err := s.projectStatusRecovery(ctx, tx, &result.Site); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, scopeID, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := decodeStoredSite(write.ResponseBody, &result.Site); err != nil {
				return err
			}
			if err := s.projectStatusRecovery(ctx, tx, &result.Site); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}

		if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID); err != nil {
			return err
		}
		var edgeSourceRevision int64
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID).
			Scan(&edgeSourceRevision); err != nil {
			return err
		}
		subject, err := newStatusRecoverySubject(request.ID, request.Trigger, currentRevision, edgeSourceRevision)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(map[string]any{
			"site_id": request.ID, "trigger": request.Trigger, "site_revision": currentRevision,
			"edge_source_revision": edgeSourceRevision,
		})
		if err != nil {
			return err
		}
		created, err := jobstate.CreateTx(ctx, tx, jobstate.CreateInput{
			TenantID: tenantID, Kind: statusRecoveryKind, Subject: subject,
			IdempotencyKey: recoveryIdempotencyKey(actor, request.IdempotencyKey), Payload: payload,
			Items: []jobstate.CreateItem{{ItemID: request.ID.String()}}, MaxAttempts: 20,
			RequestID: request.RequestID, TraceID: request.RequestID,
		}, s.now().UTC())
		if err != nil {
			if errors.Is(err, jobstate.ErrIdempotencyConflict) {
				return ErrIdempotencyConflict
			}
			return err
		}
		if err := enqueueAutomaticMutation(ctx, tx, actor, scopeID, request.ID, "site.update", request.RequestID); err != nil {
			return err
		}
		item, err := selectSite(ctx, tx, request.ID)
		if err != nil {
			return err
		}
		item.OperationalStatus = projectOperationalStatus(item.Status, item.Lock.Locked)
		item.StatusRecovery = &StatusRecovery{
			TaskID: created.Job.ID, TaskState: string(created.Job.State), Trigger: request.Trigger,
			SiteRevision: currentRevision, EdgeSourceRevision: edgeSourceRevision,
			Attempt: created.Job.Attempt,
		}
		result.Site = item
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: operation,
			ResourceType: "site", ResourceID: request.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{
				"task_id": created.Job.ID, "trigger": request.Trigger, "site_revision": currentRevision,
				"edge_source_revision": edgeSourceRevision,
			},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, operation, request.IdempotencyKey, request.ID, 202, item)
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("request site status recovery: %w", err)
	}
	return result, nil
}

const trafficRecoveredDisplayWindow = 7 * 24 * time.Hour

// projectTrafficEnforcement reads the latest package traffic suspension of the
// site (migration 299; absent on older schemas).
func (s *Store) projectTrafficEnforcement(ctx context.Context, database statusProjectionQueryer, item *Site) error {
	item.TrafficEnforcement = nil
	var installed bool
	if err := database.QueryRow(ctx, `SELECT to_regclass('package_traffic_site_suspensions') IS NOT NULL`).
		Scan(&installed); err != nil || !installed {
		return err
	}
	var value TrafficEnforcement
	var recoveredSiteStatus *string
	err := database.QueryRow(ctx, `SELECT subscription_id,suspended_at,recovered_at,recovered_reason,recovered_site_status
		FROM package_traffic_site_suspensions WHERE site_id=$1
		ORDER BY suspended_at DESC,suspension_id DESC LIMIT 1`, item.ID).
		Scan(&value.SubscriptionID, &value.SuspendedAt, &value.RecoveredAt, &value.RecoveredReason, &recoveredSiteStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	item.TrafficEnforcement = s.trafficEnforcementState(value, recoveredSiteStatus, item.Status)
	return nil
}

// trafficEnforcementState is the displayed state of the latest suspension, or
// nil when there is nothing to show.
func (s *Store) trafficEnforcementState(value TrafficEnforcement, recoveredSiteStatus *string, siteStatus string) *TrafficEnforcement {
	switch {
	case value.RecoveredAt == nil && siteStatus == StatusTrafficExceeded:
		value.State = "suspended"
	case value.RecoveredAt != nil && recoveredSiteStatus != nil && *recoveredSiteStatus == StatusActive &&
		s.now().Sub(*value.RecoveredAt) < trafficRecoveredDisplayWindow:
		value.State = "recovered"
	default:
		return nil
	}
	return &value
}

// projectListStatus is projectStatusRecovery for a whole list page (PJ-C04):
// one suspension query and one recovery-task query for all rows; only rows with
// a recovery task read its publication health. scopes[i] is items[i]'s scope.
func (s *Store) projectListStatus(ctx context.Context, tx pgx.Tx, items []ListItem, scopes []uuid.UUID) error {
	if len(items) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(items))
	index := make(map[uuid.UUID]int, len(items))
	for i := range items {
		ids[i], index[items[i].ID] = items[i].ID, i
		items[i].OperationalStatus = projectOperationalStatus(items[i].Status, items[i].Lock.Locked)
		items[i].StatusRecovery, items[i].TrafficEnforcement = nil, nil
	}
	certificateRows, err := tx.Query(ctx, `SELECT site_id FROM (
			SELECT DISTINCT ON (site_id) site_id,action FROM certificate_site_binding_facts
			WHERE site_id=ANY($1) ORDER BY site_id,sequence DESC
		) current_binding WHERE action='bind'`, ids)
	if err != nil {
		return err
	}
	for certificateRows.Next() {
		var siteID uuid.UUID
		if err := certificateRows.Scan(&siteID); err != nil {
			certificateRows.Close()
			return err
		}
		if i, ok := index[siteID]; ok {
			items[i].HTTPSCertificateBound = true
		}
	}
	certificateRows.Close()
	if err := certificateRows.Err(); err != nil {
		return err
	}
	var installed bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('package_traffic_site_suspensions') IS NOT NULL`).Scan(&installed); err != nil {
		return err
	}
	if installed {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (site_id) site_id,subscription_id,suspended_at,recovered_at,
			recovered_reason,recovered_site_status
			FROM package_traffic_site_suspensions WHERE site_id=ANY($1)
			ORDER BY site_id,suspended_at DESC,suspension_id DESC`, ids)
		if err != nil {
			return err
		}
		for rows.Next() {
			var siteID uuid.UUID
			var value TrafficEnforcement
			var recoveredSiteStatus *string
			if err := rows.Scan(&siteID, &value.SubscriptionID, &value.SuspendedAt, &value.RecoveredAt,
				&value.RecoveredReason, &recoveredSiteStatus); err != nil {
				rows.Close()
				return err
			}
			if i, ok := index[siteID]; ok {
				items[i].TrafficEnforcement = s.trafficEnforcementState(value, recoveredSiteStatus, items[i].Status)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (site.id) site.id,job.id,job.state,job.subject,job.attempt,item.sequence
		FROM sites site
		JOIN access_scopes scope ON scope.id=site.scope_id
		JOIN background_jobs job ON job.tenant_id=scope.tenant_id AND job.kind=$2
		  AND job.subject LIKE 'site/status-recovery/'||site.id::text||'/%'
		JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id AND item.item_id=site.id::text
		WHERE site.id=ANY($1)
		ORDER BY site.id,job.created_at DESC,job.id DESC`, ids, statusRecoveryKind)
	if err != nil {
		return err
	}
	type found struct {
		at       int
		recovery StatusRecovery
	}
	recoveries := make([]found, 0)
	for rows.Next() {
		var siteID uuid.UUID
		var recovery StatusRecovery
		var state, subject string
		var attempt int
		var sequence int64
		if err := rows.Scan(&siteID, &recovery.TaskID, &state, &subject, &attempt, &sequence); err != nil {
			rows.Close()
			return err
		}
		parsed, err := parseStatusRecoverySubject(subject)
		if err != nil || parsed.SiteID != siteID {
			rows.Close()
			return ErrInvalidInput
		}
		recovery.TaskState, recovery.Trigger = state, parsed.Trigger
		recovery.SiteRevision, recovery.EdgeSourceRevision = parsed.SiteRevision, parsed.EdgeSourceRevision
		recovery.Attempt, recovery.Sequence = uint32(attempt), uint64(sequence)
		if i, ok := index[siteID]; ok {
			recoveries = append(recoveries, found{at: i, recovery: recovery})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, entry := range recoveries {
		recovery := entry.recovery
		if err := projectRecoveryHealth(ctx, tx, scopes[entry.at], &recovery); err != nil {
			return err
		}
		items[entry.at].StatusRecovery = &recovery
	}
	return nil
}

func (s *Store) projectStatusRecovery(ctx context.Context, database statusProjectionQueryer, item *Site) error {
	item.OperationalStatus = projectOperationalStatus(item.Status, item.Lock.Locked)
	bound, err := siteCertificateBound(ctx, database, item.ID)
	if err != nil {
		return err
	}
	item.HTTPSCertificateBound = bound
	if err := s.projectTrafficEnforcement(ctx, database, item); err != nil {
		return err
	}
	prefix := "site/status-recovery/" + item.ID.String() + "/%"
	var recovery StatusRecovery
	var subject, state string
	var attempt int
	var sequence int64
	err = database.QueryRow(ctx, `SELECT job.id,job.state,job.subject,job.attempt,item.sequence
		FROM access_scopes scope JOIN background_jobs job ON job.tenant_id=scope.tenant_id
		JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id AND item.item_id=$2
		WHERE scope.id=$1 AND job.kind=$3 AND job.subject LIKE $4
		ORDER BY job.created_at DESC,job.id DESC LIMIT 1`, item.ScopeID, item.ID.String(), statusRecoveryKind, prefix).
		Scan(&recovery.TaskID, &state, &subject, &attempt, &sequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	parsed, err := parseStatusRecoverySubject(subject)
	if err != nil || parsed.SiteID != item.ID {
		return ErrInvalidInput
	}
	recovery.TaskState = state
	recovery.Trigger = parsed.Trigger
	recovery.SiteRevision = parsed.SiteRevision
	recovery.EdgeSourceRevision = parsed.EdgeSourceRevision
	recovery.Attempt = uint32(attempt)
	recovery.Sequence = uint64(sequence)
	if err := projectRecoveryHealth(ctx, database, item.ScopeID, &recovery); err != nil {
		return err
	}
	item.StatusRecovery = &recovery
	return nil
}

// projectRecoveryHealth fills the desired/active edge version of a status
// recovery from the publication of its edge source revision.
func projectRecoveryHealth(ctx context.Context, database statusProjectionQueryer, scopeID uuid.UUID, recovery *StatusRecovery) error {
	var desired uuid.UUID
	var healthy bool
	err := database.QueryRow(ctx, `WITH latest AS (
			SELECT DISTINCT ON (deployment.node_id) deployment.node_id,deployment.state
			FROM node_deployments deployment JOIN edge_config_publications publication ON publication.rollout_id=deployment.rollout_id
			WHERE publication.configuration_scope_id=$1 AND publication.source_revision=$2
			ORDER BY deployment.node_id,deployment.attempt DESC
		)
		SELECT publication.config_version_id,
			rollout.status='completed' AND count(latest.node_id)=publication.node_count AND
			COALESCE(bool_and(latest.state='healthy' AND node_state.current_config_version_id=publication.config_version_id),false)
		FROM edge_config_publications publication
		JOIN rollouts rollout ON rollout.id=publication.rollout_id
		LEFT JOIN latest ON true
		LEFT JOIN node_config_state node_state ON node_state.node_id=latest.node_id
		  AND node_state.configuration_scope_id=publication.configuration_scope_id
		WHERE publication.configuration_scope_id=$1 AND publication.source_revision=$2
		GROUP BY publication.config_version_id,publication.node_count,rollout.status`, scopeID, recovery.EdgeSourceRevision).
		Scan(&desired, &healthy)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil {
		recovery.DesiredEdgeVersionID = &desired
		recovery.Healthy = healthy
		if healthy {
			active := desired
			recovery.ActiveEdgeVersionID = &active
		}
	}
	return nil
}

func (s *Store) StartStatusRecovery(ctx context.Context, request StatusRecoveryStartRequest) (jobstate.Claim, error) {
	var claim jobstate.Claim
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		claim, err = jobstate.StartTx(ctx, tx, jobstate.StartInput{
			TenantID: request.TenantID, JobID: request.TaskID, Kind: statusRecoveryKind,
			WorkerID: request.WorkerID, LeaseDuration: request.LeaseDuration,
		}, s.now().UTC())
		return err
	})
	return claim, err
}

func (s *Store) ReportStatusRecovery(ctx context.Context, request StatusRecoveryReportRequest) (jobstate.ReportResult, error) {
	var result jobstate.ReportResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var subject string
		if err := tx.QueryRow(ctx, `SELECT subject FROM background_jobs WHERE tenant_id=$1 AND id=$2 AND kind=$3`,
			request.TenantID, request.TaskID, statusRecoveryKind).Scan(&subject); err != nil {
			return err
		}
		parsed, err := parseStatusRecoverySubject(subject)
		if err != nil {
			return err
		}
		var currentAttempt int
		var currentSequence int64
		if err := tx.QueryRow(ctx, `SELECT attempt,sequence FROM background_job_items
			WHERE tenant_id=$1 AND job_id=$2 AND item_id=$3`, request.TenantID, request.TaskID, parsed.SiteID.String()).
			Scan(&currentAttempt, &currentSequence); err != nil {
			return err
		}
		if request.Attempt < uint32(currentAttempt) ||
			request.Attempt == uint32(currentAttempt) && request.Sequence < uint64(currentSequence) {
			return ErrRecoveryReportStale
		}
		if request.Attempt == uint32(currentAttempt) && request.Sequence == uint64(currentSequence) && currentSequence > 0 {
			return ErrRecoveryReportDuplicate
		}
		if request.State == jobstate.ItemSucceeded {
			var desired, active uuid.UUID
			var healthy bool
			err := tx.QueryRow(ctx, `WITH latest AS (
					SELECT DISTINCT ON (deployment.node_id) deployment.node_id,deployment.state
					FROM node_deployments deployment JOIN edge_config_publications publication ON publication.rollout_id=deployment.rollout_id
					WHERE publication.configuration_scope_id=(SELECT site.scope_id FROM sites site
					  JOIN access_scopes scope ON scope.id=site.scope_id AND scope.tenant_id=$3 WHERE site.id=$2)
					  AND publication.source_revision=$1 ORDER BY deployment.node_id,deployment.attempt DESC
				)
				SELECT publication.config_version_id,
					publication.config_version_id,
					rollout.status='completed' AND count(latest.node_id)=publication.node_count AND
					COALESCE(bool_and(latest.state='healthy' AND node_state.current_config_version_id=publication.config_version_id),false)
				FROM edge_config_publications publication JOIN rollouts rollout ON rollout.id=publication.rollout_id
				LEFT JOIN latest ON true LEFT JOIN node_config_state node_state ON node_state.node_id=latest.node_id
				  AND node_state.configuration_scope_id=publication.configuration_scope_id
				WHERE publication.configuration_scope_id=(SELECT site.scope_id FROM sites site
				  JOIN access_scopes scope ON scope.id=site.scope_id AND scope.tenant_id=$3 WHERE site.id=$2)
				  AND publication.source_revision=$1
				GROUP BY publication.config_version_id,publication.node_count,rollout.status`,
				parsed.EdgeSourceRevision, parsed.SiteID, request.TenantID).Scan(&desired, &active, &healthy)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrRecoveryUnhealthy
			}
			if err != nil {
				return err
			}
			if err := validateRecoveryReport(RecoveryReportCursor{Attempt: uint32(currentAttempt), Sequence: uint64(currentSequence)},
				RecoveryReportCursor{Attempt: request.Attempt, Sequence: request.Sequence}, desired, active, healthy); err != nil {
				return err
			}
		}
		result, err = jobstate.ReportTx(ctx, tx, jobstate.ReportInput{
			TenantID: request.TenantID, JobID: request.TaskID, WorkerID: request.WorkerID, LeaseID: request.LeaseID,
			Report: jobstate.Report{ItemID: parsed.SiteID.String(), State: request.State, Code: request.Code,
				Attempt: request.Attempt, Sequence: request.Sequence},
		}, s.now().UTC())
		if err != nil || !result.Applied || request.State != jobstate.ItemSucceeded {
			return err
		}
		var command pgconnCommandTag
		now := s.now().UTC()
		switch parsed.Trigger {
		case RecoveryTriggerUnlock:
			command, err = tx.Exec(ctx, `UPDATE sites SET lock_reason=NULL,locked_at=NULL,locked_by_user_id=NULL,
				revision=revision+1,updated_at=$3 WHERE id=$1 AND revision=$2 AND locked_at IS NOT NULL
				AND EXISTS(SELECT 1 FROM access_scopes scope WHERE scope.id=sites.scope_id AND scope.tenant_id=$4)`,
				parsed.SiteID, parsed.SiteRevision, now, request.TenantID)
		case RecoveryTriggerRenewal:
			command, err = tx.Exec(ctx, `UPDATE sites SET status=$3,revision=revision+1,updated_at=$4
				WHERE id=$1 AND revision=$2 AND status=$5
				AND EXISTS(SELECT 1 FROM access_scopes scope WHERE scope.id=sites.scope_id AND scope.tenant_id=$6)`,
				parsed.SiteID, parsed.SiteRevision, StatusActive, now, StatusPackageExpired, request.TenantID)
		case RecoveryTriggerTrafficTopUp:
			command, err = tx.Exec(ctx, `UPDATE sites SET status=$3,revision=revision+1,updated_at=$4
				WHERE id=$1 AND revision=$2 AND status=$5
				AND EXISTS(SELECT 1 FROM access_scopes scope WHERE scope.id=sites.scope_id AND scope.tenant_id=$6)`,
				parsed.SiteID, parsed.SiteRevision, StatusActive, now, StatusTrafficExceeded, request.TenantID)
		}
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		var scopeID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT site.scope_id FROM sites site JOIN access_scopes scope
			ON scope.id=site.scope_id AND scope.tenant_id=$2 WHERE site.id=$1`, parsed.SiteID, request.TenantID).
			Scan(&scopeID); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: statusRecoveryKind + ".applied", ResourceType: "site",
			ResourceID: parsed.SiteID.String(), RequestID: result.Job.RequestID, Result: "success",
			Payload: map[string]any{"task_id": request.TaskID, "trigger": parsed.Trigger,
				"site_revision": parsed.SiteRevision, "edge_source_revision": parsed.EdgeSourceRevision},
		})
	})
	return result, err
}

type pgconnCommandTag interface {
	RowsAffected() int64
}
