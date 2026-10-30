// Package packageautopublish writes the automatic publication policy a
// package implies (user decision 10-22: opening a package turns on automatic
// publication). It has no internal imports so the package stores, which
// edgeautopublish depends on, can call it in their own transactions.
package packageautopublish

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrInvalidInput = errors.New("invalid package automatic publication input")

const (
	modeManual    = "manual"
	modeAutomatic = "automatic"
)

// Package policy parameters: one automatic publication waits up to a minute
// for activation, observes 30 seconds and needs 3 healthy reports, as the
// market supply policy does (marketsupply/delivery.go).
const (
	packagePolicyActivationTimeoutMS = 60_000
	packagePolicyObservationWindowMS = 30_000
	packagePolicySuccesses           = 3
	packagePolicyMaxAttempts         = 3
	packagePolicyDeadlineSeconds     = 1800

	ReasonOpened = "package_opened"
	ReasonEnded  = "package_ended"
)

// EnsureTx turns on automatic publication for a tenant scope
// whose package was opened, renewed or changed (user decision 10-22). The
// policy names no nodes (migration 457): each publication targets the nodes
// of the line groups the scope's sites use, their own or their package's
// primary/backup group, as they are when it is published (edgeautopublish.publicationNodeIDs).
// An automatic policy already in force (a market supply one names its pool's
// nodes) is kept. actorScopeID/actorUserID publish the scope's changes: the
// package owner (a member of the tenant scope) or a platform operator.
func EnsureTx(ctx context.Context, tx pgx.Tx, scopeID, actorScopeID, actorUserID uuid.UUID) (bool, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || actorScopeID == uuid.Nil || actorUserID == uuid.Nil {
		return false, ErrInvalidInput
	}
	if err := lockPolicyScope(ctx, tx, scopeID); err != nil {
		return false, err
	}
	mode, found, err := latestPolicyMode(ctx, tx, scopeID)
	if err != nil || found && mode == modeAutomatic {
		return false, err
	}
	return true, insertPackagePolicy(ctx, tx, scopeID, modeAutomatic, actorScopeID, actorUserID, ReasonOpened)
}

// StopTx returns a tenant scope to manual publication when a
// package was cancelled, disabled or deleted and the scope has no other live
// package at at. What the nodes run is left as it is; later changes wait for a
// manual publication. A market supply policy is a pool delivery, not a
// package one, and is kept.
func StopTx(ctx context.Context, tx pgx.Tx, scopeID, actorScopeID, actorUserID uuid.UUID, at time.Time) (bool, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || actorScopeID == uuid.Nil || actorUserID == uuid.Nil || at.IsZero() {
		return false, ErrInvalidInput
	}
	if err := lockPolicyScope(ctx, tx, scopeID); err != nil {
		return false, err
	}
	var live bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM package_subscriptions
		WHERE tenant_scope_id=$1 AND lifecycle_status='active' AND admin_enabled AND deleted_at IS NULL
		  AND starts_at<=$2 AND ends_at>$2)`, scopeID, at).Scan(&live); err != nil || live {
		return false, err
	}
	var mode, reason string
	err := tx.QueryRow(ctx, `SELECT mode,reason FROM edge_automatic_publication_policy_facts
		WHERE target_scope_id=$1 ORDER BY revision DESC LIMIT 1`, scopeID).Scan(&mode, &reason)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (mode != modeAutomatic || reason != ReasonOpened) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, insertPackagePolicy(ctx, tx, scopeID, modeManual, actorScopeID, actorUserID, ReasonEnded)
}

// lockPolicyScope takes the lock 086's policy trigger takes, so the revision
// read below is still the latest when the fact is inserted.
func lockPolicyScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'edge-automatic-publication-policy:' || $1::text, 0))`, scopeID)
	return err
}

func latestPolicyMode(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (string, bool, error) {
	var mode string
	err := tx.QueryRow(ctx, `SELECT mode FROM edge_automatic_publication_policy_facts
		WHERE target_scope_id=$1 ORDER BY revision DESC LIMIT 1`, scopeID).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return mode, err == nil, err
}

func insertPackagePolicy(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, mode string,
	actorScopeID, actorUserID uuid.UUID, reason string) error {
	_, err := tx.Exec(ctx, `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at)
		SELECT $1,COALESCE(max(revision),0)+1,$2,'{}',$3,$4,$5,$6,$7,$8,$9,$10,clock_timestamp()
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1`,
		scopeID, mode, packagePolicyActivationTimeoutMS, packagePolicyObservationWindowMS, packagePolicySuccesses,
		packagePolicyMaxAttempts, packagePolicyDeadlineSeconds, actorScopeID, actorUserID, reason)
	return err
}
