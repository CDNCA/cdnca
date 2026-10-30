package certificateasset

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PublicationStatus struct {
	TenantScopeID       uuid.UUID  `json:"tenant_scope_id"`
	SiteID              uuid.UUID  `json:"site_id"`
	AssetID             uuid.UUID  `json:"asset_id"`
	VersionID           uuid.UUID  `json:"version_id"`
	BindingRevision     int64      `json:"binding_revision"`
	Operation           string     `json:"operation"`
	Default             bool       `json:"default"`
	StateSequence       int64      `json:"state_sequence"`
	State               string     `json:"state"`
	Attempt             int        `json:"attempt"`
	NextAttemptAt       *time.Time `json:"next_attempt_at,omitempty"`
	OccurredAt          time.Time  `json:"occurred_at"`
	FailureCode         string     `json:"failure_code,omitempty"`
	PublicationID       *uuid.UUID `json:"publication_id,omitempty"`
	PublicationRevision int64      `json:"publication_revision,omitempty"`
	ConfigVersionID     *uuid.UUID `json:"config_version_id,omitempty"`
	RolloutID           *uuid.UUID `json:"rollout_id,omitempty"`
	RolloutRevision     int64      `json:"rollout_revision,omitempty"`
}

type PublicationStatusEvent struct {
	Sequence      int64      `json:"sequence"`
	State         string     `json:"state"`
	Attempt       int        `json:"attempt"`
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	OccurredAt    time.Time  `json:"occurred_at"`
	FailureCode   string     `json:"failure_code,omitempty"`
}

type PublicationStatusDetail struct {
	Current PublicationStatus        `json:"current"`
	History []PublicationStatusEvent `json:"history"`
}

type PublicationStatusFilter struct {
	State     string
	Operation string
	SiteID    uuid.UUID
}

type PublicationStatusCursor struct {
	SnapshotAt          time.Time
	LastOccurredAt      time.Time
	LastSiteID          uuid.UUID
	LastBindingRevision int64
}

type PublicationStatusPage struct {
	Items      []PublicationStatus      `json:"items"`
	SnapshotAt time.Time                `json:"snapshot_at"`
	NextCursor *PublicationStatusCursor `json:"next_cursor,omitempty"`
}

type PublicationStatusStore struct{ pool *pgxpool.Pool }

func NewPublicationStatusStore(pool *pgxpool.Pool) (*PublicationStatusStore, error) {
	if pool == nil {
		return nil, ErrInvalidInput
	}
	return &PublicationStatusStore{pool: pool}, nil
}

func (store *PublicationStatusStore) List(
	ctx context.Context,
	actor Actor,
	tenantScopeID uuid.UUID,
	filter PublicationStatusFilter,
	cursor PublicationStatusCursor,
	limit int,
) (PublicationStatusPage, error) {
	if store == nil || store.pool == nil || ctx == nil || limit < 1 || limit > 200 ||
		!validPublicationStatusFilter(filter) || !validPublicationStatusCursor(cursor) {
		return PublicationStatusPage{}, ErrInvalidInput
	}
	if err := validateActor(actor, tenantScopeID); err != nil {
		return PublicationStatusPage{}, err
	}

	var page PublicationStatusPage
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := authorizeActor(ctx, tx, actor, tenantScopeID, false); err != nil {
			return err
		}
		var databaseNow time.Time
		if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&databaseNow); err != nil {
			return err
		}
		snapshotAt := cursor.SnapshotAt
		if snapshotAt.IsZero() {
			snapshotAt = databaseNow
		} else if snapshotAt.After(databaseNow) {
			return ErrInvalidInput
		}

		var siteFilter *uuid.UUID
		if filter.SiteID != uuid.Nil {
			siteFilter = &filter.SiteID
		}
		var lastOccurredAt *time.Time
		var lastSiteID *uuid.UUID
		var lastRevision *int64
		if !cursor.SnapshotAt.IsZero() {
			lastOccurredAt, lastSiteID, lastRevision =
				&cursor.LastOccurredAt, &cursor.LastSiteID, &cursor.LastBindingRevision
		}
		rows, err := tx.Query(ctx, `SELECT intent.tenant_scope_id,intent.site_id,
			intent.asset_id,intent.version_id,intent.binding_revision,intent.operation,intent.is_default,
			latest.sequence,latest.state,latest.attempt,latest.next_attempt_at,
			latest.failure_code,latest.occurred_at,latest.publication_id,
			latest.publication_revision,latest.config_version_id,latest.rollout_id,latest.rollout_revision
		FROM certificate_publication_intents intent
		JOIN LATERAL (
			SELECT state.sequence,state.state,state.attempt,state.next_attempt_at,
				state.failure_code,state.occurred_at,state.publication_id,
				state.publication_revision,state.config_version_id,state.rollout_id,state.rollout_revision
			FROM certificate_publication_intent_state_facts state
			WHERE state.tenant_scope_id=intent.tenant_scope_id AND state.site_id=intent.site_id
			  AND state.binding_revision=intent.binding_revision AND state.occurred_at<=$2
			ORDER BY state.sequence DESC LIMIT 1
		) latest ON true
		WHERE intent.tenant_scope_id=$1 AND intent.created_at<=$2
		  AND ($3::text='' OR latest.state=$3)
		  AND ($4::text='' OR intent.operation=$4)
		  AND ($5::uuid IS NULL OR intent.site_id=$5)
		  AND ($6::timestamptz IS NULL OR latest.occurred_at<$6 OR
		       (latest.occurred_at=$6 AND intent.site_id>$7) OR
		       (latest.occurred_at=$6 AND intent.site_id=$7 AND intent.binding_revision<$8))
		ORDER BY latest.occurred_at DESC,intent.site_id,intent.binding_revision DESC
		LIMIT $9`, tenantScopeID, snapshotAt, filter.State, filter.Operation, siteFilter,
			lastOccurredAt, lastSiteID, lastRevision, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		items := make([]PublicationStatus, 0, limit+1)
		for rows.Next() {
			status, err := scanPublicationStatus(rows)
			if err != nil {
				return err
			}
			items = append(items, status)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		page = publicationStatusPage(items, limit, snapshotAt)
		return nil
	})
	if err != nil {
		return PublicationStatusPage{}, fmt.Errorf("list certificate publication statuses: %w", err)
	}
	return page, nil
}

func (store *PublicationStatusStore) Get(
	ctx context.Context,
	actor Actor,
	tenantScopeID, siteID uuid.UUID,
	bindingRevision int64,
) (PublicationStatusDetail, error) {
	if store == nil || store.pool == nil || ctx == nil || siteID == uuid.Nil || bindingRevision < 1 {
		return PublicationStatusDetail{}, ErrInvalidInput
	}
	if err := validateActor(actor, tenantScopeID); err != nil {
		return PublicationStatusDetail{}, err
	}

	var detail PublicationStatusDetail
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := authorizeActor(ctx, tx, actor, tenantScopeID, false); err != nil {
			return err
		}
		row := tx.QueryRow(ctx, `SELECT intent.tenant_scope_id,intent.site_id,
			intent.asset_id,intent.version_id,intent.binding_revision,intent.operation,intent.is_default,
			latest.sequence,latest.state,latest.attempt,latest.next_attempt_at,
			latest.failure_code,latest.occurred_at,latest.publication_id,
			latest.publication_revision,latest.config_version_id,latest.rollout_id,latest.rollout_revision
		FROM certificate_publication_intents intent
		JOIN LATERAL (
			SELECT sequence,state,attempt,next_attempt_at,failure_code,occurred_at,
				publication_id,publication_revision,config_version_id,rollout_id,rollout_revision
			FROM certificate_publication_intent_state_facts state
			WHERE state.tenant_scope_id=intent.tenant_scope_id AND state.site_id=intent.site_id
			  AND state.binding_revision=intent.binding_revision
			ORDER BY state.sequence DESC LIMIT 1
		) latest ON true
		WHERE intent.tenant_scope_id=$1 AND intent.site_id=$2 AND intent.binding_revision=$3`,
			tenantScopeID, siteID, bindingRevision)
		current, err := scanPublicationStatus(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}

		rows, err := tx.Query(ctx, `SELECT sequence,state,attempt,next_attempt_at,failure_code,occurred_at
		FROM certificate_publication_intent_state_facts
		WHERE tenant_scope_id=$1 AND site_id=$2 AND binding_revision=$3
		ORDER BY sequence`, tenantScopeID, siteID, bindingRevision)
		if err != nil {
			return err
		}
		defer rows.Close()
		history := make([]PublicationStatusEvent, 0, current.StateSequence)
		for rows.Next() {
			event, err := scanPublicationStatusEvent(rows)
			if err != nil {
				return err
			}
			history = append(history, event)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(history) == 0 || history[len(history)-1].Sequence != current.StateSequence {
			return ErrInvalidStore
		}
		detail = PublicationStatusDetail{Current: current, History: history}
		return nil
	})
	if err != nil {
		return PublicationStatusDetail{}, fmt.Errorf("get certificate publication status: %w", err)
	}
	return detail, nil
}

type publicationStatusScanner interface{ Scan(...any) error }

func scanPublicationStatus(scanner publicationStatusScanner) (PublicationStatus, error) {
	var status PublicationStatus
	var nextAttempt sql.NullTime
	var failureCode sql.NullString
	var publicationID, configVersionID, rolloutID uuid.NullUUID
	var publicationRevision, rolloutRevision sql.NullInt64
	err := scanner.Scan(
		&status.TenantScopeID, &status.SiteID, &status.AssetID, &status.VersionID,
		&status.BindingRevision, &status.Operation, &status.Default, &status.StateSequence,
		&status.State, &status.Attempt, &nextAttempt, &failureCode, &status.OccurredAt,
		&publicationID, &publicationRevision, &configVersionID, &rolloutID, &rolloutRevision,
	)
	if err != nil {
		return PublicationStatus{}, err
	}
	if nextAttempt.Valid {
		status.NextAttemptAt = &nextAttempt.Time
	}
	if failureCode.Valid {
		status.FailureCode = failureCode.String
	}
	if publicationID.Valid {
		status.PublicationID = &publicationID.UUID
	}
	if publicationRevision.Valid {
		status.PublicationRevision = publicationRevision.Int64
	}
	if configVersionID.Valid {
		status.ConfigVersionID = &configVersionID.UUID
	}
	if rolloutID.Valid {
		status.RolloutID = &rolloutID.UUID
	}
	if rolloutRevision.Valid {
		status.RolloutRevision = rolloutRevision.Int64
	}
	if !validPublicationStatus(status) {
		return PublicationStatus{}, ErrInvalidStore
	}
	return status, nil
}

func scanPublicationStatusEvent(scanner publicationStatusScanner) (PublicationStatusEvent, error) {
	var event PublicationStatusEvent
	var nextAttempt sql.NullTime
	var failureCode sql.NullString
	if err := scanner.Scan(&event.Sequence, &event.State, &event.Attempt, &nextAttempt,
		&failureCode, &event.OccurredAt); err != nil {
		return PublicationStatusEvent{}, err
	}
	if nextAttempt.Valid {
		event.NextAttemptAt = &nextAttempt.Time
	}
	if failureCode.Valid {
		event.FailureCode = failureCode.String
	}
	if !validPublicationStatusState(event.Sequence, event.State, event.Attempt,
		event.NextAttemptAt, event.OccurredAt, event.FailureCode) {
		return PublicationStatusEvent{}, ErrInvalidStore
	}
	return event, nil
}

func validPublicationStatus(status PublicationStatus) bool {
	base := status.TenantScopeID != uuid.Nil && status.SiteID != uuid.Nil && status.AssetID != uuid.Nil &&
		status.VersionID != uuid.Nil && status.BindingRevision > 0 &&
		(status.Operation == "publish" || status.Operation == "unpublish") &&
		validPublicationStatusState(status.StateSequence, status.State, status.Attempt,
			status.NextAttemptAt, status.OccurredAt, status.FailureCode)
	if !base {
		return false
	}
	completeResult := status.PublicationID != nil && *status.PublicationID != uuid.Nil &&
		status.PublicationRevision > 0 && status.ConfigVersionID != nil && *status.ConfigVersionID != uuid.Nil &&
		status.RolloutID != nil && *status.RolloutID != uuid.Nil && status.RolloutRevision > 0
	emptyResult := status.PublicationID == nil && status.PublicationRevision == 0 &&
		status.ConfigVersionID == nil && status.RolloutID == nil && status.RolloutRevision == 0
	return (status.State == "succeeded" && completeResult) || (status.State != "succeeded" && emptyResult)
}

func validPublicationStatusState(
	sequence int64,
	state string,
	attempt int,
	nextAttemptAt *time.Time,
	occurredAt time.Time,
	failureCode string,
) bool {
	if sequence < 1 || occurredAt.IsZero() || attempt < 0 {
		return false
	}
	switch state {
	case "pending":
		return sequence == 1 && attempt == 0 && nextAttemptAt != nil &&
			!nextAttemptAt.Before(occurredAt) && failureCode == ""
	case "leased":
		return attempt > 0 && nextAttemptAt == nil && failureCode == ""
	case "retry_wait":
		return attempt > 0 && nextAttemptAt != nil && nextAttemptAt.After(occurredAt) &&
			validPublicationFailureCode(failureCode)
	case "succeeded":
		return attempt > 0 && nextAttemptAt == nil && failureCode == ""
	case "permanent_failed":
		return attempt > 0 && nextAttemptAt == nil && validPublicationFailureCode(failureCode)
	default:
		return false
	}
}

func validPublicationStatusFilter(filter PublicationStatusFilter) bool {
	if filter.Operation != "" && filter.Operation != "publish" && filter.Operation != "unpublish" {
		return false
	}
	if filter.State == "" {
		return true
	}
	switch filter.State {
	case "pending", "leased", "retry_wait", "succeeded", "permanent_failed":
		return true
	default:
		return false
	}
}

func validPublicationStatusCursor(cursor PublicationStatusCursor) bool {
	empty := cursor.SnapshotAt.IsZero() && cursor.LastOccurredAt.IsZero() &&
		cursor.LastSiteID == uuid.Nil && cursor.LastBindingRevision == 0
	if empty {
		return true
	}
	return !cursor.SnapshotAt.IsZero() && !cursor.LastOccurredAt.IsZero() &&
		cursor.LastSiteID != uuid.Nil && cursor.LastBindingRevision > 0 &&
		!cursor.LastOccurredAt.After(cursor.SnapshotAt)
}

func publicationStatusPage(
	items []PublicationStatus,
	limit int,
	snapshotAt time.Time,
) PublicationStatusPage {
	visible := items
	if len(visible) > limit {
		visible = visible[:limit]
	}
	page := PublicationStatusPage{
		Items: append([]PublicationStatus(nil), visible...), SnapshotAt: snapshotAt,
	}
	if len(items) > limit {
		last := visible[len(visible)-1]
		page.NextCursor = &PublicationStatusCursor{
			SnapshotAt: snapshotAt, LastOccurredAt: last.OccurredAt,
			LastSiteID: last.SiteID, LastBindingRevision: last.BindingRevision,
		}
	}
	return page
}
