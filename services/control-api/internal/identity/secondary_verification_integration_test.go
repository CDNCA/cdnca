//go:build integration

package identity_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type secondaryVerificationNotifierStub struct {
	notices []identity.SecondaryVerificationNotice
}

func (stub *secondaryVerificationNotifierStub) NotifySecondaryVerificationTx(_ context.Context, _ pgx.Tx, notice identity.SecondaryVerificationNotice) error {
	stub.notices = append(stub.notices, notice)
	return nil
}

func TestSecondaryVerificationRequestNotifiesOnceAndLocksSitesAtDeadline(t *testing.T) {
	fixture := seedManagedUserAuthorityFixture(t, "identity.users.manage")
	ctx := t.Context()
	sessionID := uuid.New()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), fixture.actor.UserID, fixture.actor.ScopeID,
		bytes.Repeat([]byte{0x5a}, 32), time.Now().Add(-time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	fixture.actor.SessionID = sessionID
	notifier := &secondaryVerificationNotifierStub{}
	fixture.service.SetSecondaryVerificationNotifier(notifier)
	siteID := insertSecondaryVerificationSite(t, fixture.pool, fixture.targetScopeID, fixture.targetUserID, "secver.example.com", true, "", uuid.Nil)
	// Sites stopped or locked for other reasons: only the missing half is held, and only that half is undone.
	adminLocked := insertSecondaryVerificationSite(t, fixture.pool, fixture.targetScopeID, fixture.targetUserID, "secver-locked.example.com", true, "管理员锁定", fixture.actor.UserID)
	adminDisabled := insertSecondaryVerificationSite(t, fixture.pool, fixture.targetScopeID, fixture.targetUserID, "secver-off.example.com", false, "", uuid.Nil)
	untouched := insertSecondaryVerificationSite(t, fixture.pool, fixture.targetScopeID, fixture.targetUserID, "secver-off-locked.example.com", false, "管理员锁定", fixture.actor.UserID)

	initial, err := fixture.service.GetManagedUserSecondaryVerification(ctx, fixture.actor, fixture.targetUserID, fixture.targetScopeID)
	if err != nil || initial.Revision != 0 || initial.Enabled || initial.ExpiryAction != identity.SecondaryExpiryNone {
		t.Fatalf("initial=(%#v,%v)", initial, err)
	}
	deadline := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	input := identity.UpdateManagedUserSecondaryVerificationInput{
		UserID: fixture.targetUserID, TenantScopeID: fixture.targetScopeID, ExpectedRevision: 0, Enabled: true,
		Deadline: &deadline, ExpiryAction: identity.SecondaryExpiryLockSites, IdempotencyKey: "secver-enable", RequestID: "secver-enable",
	}
	enabled, err := fixture.service.UpdateManagedUserSecondaryVerification(ctx, fixture.actor, input)
	if err != nil || enabled.Revision != 1 || !enabled.Enabled || enabled.Completed || enabled.RequestedAt == nil ||
		enabled.Deadline == nil || !enabled.Deadline.Equal(deadline) {
		t.Fatalf("enabled=(%#v,%v)", enabled, err)
	}
	if len(notifier.notices) != 1 || notifier.notices[0].UserID != fixture.targetUserID || notifier.notices[0].Username == "" {
		t.Fatalf("notices=%#v", notifier.notices)
	}
	if replayed, err := fixture.service.UpdateManagedUserSecondaryVerification(ctx, fixture.actor, input); err != nil ||
		replayed.Revision != 1 || len(notifier.notices) != 1 {
		t.Fatalf("replay=(%#v,%v) notices=%d", replayed, err, len(notifier.notices))
	}
	stale := input
	stale.IdempotencyKey, stale.RequestID = "secver-stale", "secver-stale"
	if _, err := fixture.service.UpdateManagedUserSecondaryVerification(ctx, fixture.actor, stale); !errors.Is(err, identity.ErrRevisionConflict) {
		t.Fatalf("stale revision error=%v", err)
	}
	later := deadline.Add(24 * time.Hour)
	edit := input
	edit.ExpectedRevision, edit.Deadline, edit.IdempotencyKey, edit.RequestID = 1, &later, "secver-edit", "secver-edit"
	edited, err := fixture.service.UpdateManagedUserSecondaryVerification(ctx, fixture.actor, edit)
	if err != nil || edited.Revision != 2 || !edited.RequestedAt.Equal(*enabled.RequestedAt) || len(notifier.notices) != 1 {
		t.Fatalf("edit=(%#v,%v) notices=%d", edited, err, len(notifier.notices))
	}
	noDeadline := edit
	noDeadline.ExpectedRevision, noDeadline.Deadline, noDeadline.IdempotencyKey = 2, nil, "secver-nodeadline"
	if _, err := fixture.service.UpdateManagedUserSecondaryVerification(ctx, fixture.actor, noDeadline); !errors.Is(err, identity.ErrInvalidUserInput) {
		t.Fatalf("lock_sites without deadline error=%v", err)
	}

	store := identity.NewStore(fixture.pool)
	republisher := &secondaryVerificationRepublisherStub{}
	if pass, err := store.EnforceSecondaryVerificationDeadlines(ctx, republisher, 100); err != nil || pass.Held != 0 || len(republisher.calls) != 0 {
		t.Fatalf("enforcement before deadline=(%#v,%v) calls=%d", pass, err, len(republisher.calls))
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE identity_user_secondary_verification SET deadline=now()-interval '1 minute'
		WHERE scope_id=$1 AND user_id=$2`, fixture.targetScopeID, fixture.targetUserID); err != nil {
		t.Fatal(err)
	}
	var revisionBefore int64
	if err := fixture.pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, fixture.targetScopeID).Scan(&revisionBefore); err != nil {
		t.Fatal(err)
	}
	if pass, err := store.EnforceSecondaryVerificationDeadlines(ctx, republisher, 100); err != nil || pass.Held != 1 {
		t.Fatalf("enforcement after deadline=(%#v,%v)", pass, err)
	}
	if len(republisher.calls) != 1 || republisher.calls[0].ScopeID != fixture.targetScopeID || republisher.calls[0].UserID != fixture.targetUserID ||
		republisher.calls[0].Operation != identity.SecondaryVerificationOperationDisable || republisher.calls[0].FromRevision != revisionBefore ||
		!republisher.sawCommittedChange {
		t.Fatalf("republish after stopping sites=%#v saw=%v", republisher.calls, republisher.sawCommittedChange)
	}
	expectSite := func(id uuid.UUID, enabled bool, reason string) {
		t.Helper()
		var gotEnabled bool
		var gotReason *string
		if err := fixture.pool.QueryRow(ctx, `SELECT enabled,lock_reason FROM sites WHERE id=$1`, id).Scan(&gotEnabled, &gotReason); err != nil {
			t.Fatal(err)
		}
		if gotEnabled != enabled || (gotReason == nil) != (reason == "") || gotReason != nil && *gotReason != reason {
			t.Fatalf("site %s enabled=%v reason=%v, want %v %q", id, gotEnabled, gotReason, enabled, reason)
		}
	}
	expectSite(siteID, false, identity.SecondaryVerificationLockReason)
	expectSite(adminLocked, false, "管理员锁定")
	expectSite(adminDisabled, false, identity.SecondaryVerificationLockReason)
	expectSite(untouched, false, "管理员锁定")
	var holds int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM identity_secondary_verification_site_holds WHERE released_at IS NULL`).Scan(&holds); err != nil || holds != 3 {
		t.Fatalf("open holds=(%d,%v)", holds, err)
	}
	if pass, err := store.EnforceSecondaryVerificationDeadlines(ctx, republisher, 100); err != nil || pass != (identity.SecondaryVerificationEnforcement{}) || len(republisher.calls) != 1 {
		t.Fatalf("second enforcement=(%#v,%v) calls=%d", pass, err, len(republisher.calls))
	}
	enforced, err := fixture.service.GetManagedUserSecondaryVerification(ctx, fixture.actor, fixture.targetUserID, fixture.targetScopeID)
	if err != nil || enforced.EnforcedAt == nil || enforced.Completed {
		t.Fatalf("enforced=(%#v,%v)", enforced, err)
	}

	// The user completes the reverification: sites come back without an administrator.
	seedApprovedReverification(t, fixture.pool, fixture.targetScopeID, fixture.targetUserID)
	if pass, err := store.EnforceSecondaryVerificationDeadlines(ctx, republisher, 100); err != nil || pass.Released != 1 || pass.Held != 0 {
		t.Fatalf("release after reverification=(%#v,%v)", pass, err)
	}
	if len(republisher.calls) != 2 || republisher.calls[1].Operation != identity.SecondaryVerificationOperationEnable {
		t.Fatalf("republish after restoring sites=%#v", republisher.calls)
	}
	expectSite(siteID, true, "")
	expectSite(adminLocked, true, "管理员锁定")
	expectSite(adminDisabled, false, "")
	expectSite(untouched, false, "管理员锁定")
	completed, err := fixture.service.GetManagedUserSecondaryVerification(ctx, fixture.actor, fixture.targetUserID, fixture.targetScopeID)
	if err != nil || !completed.Completed || completed.EnforcedAt != nil {
		t.Fatalf("completed=(%#v,%v)", completed, err)
	}
	if pass, err := store.EnforceSecondaryVerificationDeadlines(ctx, republisher, 100); err != nil || pass != (identity.SecondaryVerificationEnforcement{}) || len(republisher.calls) != 2 {
		t.Fatalf("idle pass=(%#v,%v) calls=%d", pass, err, len(republisher.calls))
	}

	disable := identity.UpdateManagedUserSecondaryVerificationInput{UserID: fixture.targetUserID, TenantScopeID: fixture.targetScopeID,
		ExpectedRevision: 2, Enabled: false, ExpiryAction: identity.SecondaryExpiryNone, IdempotencyKey: "secver-disable", RequestID: "secver-disable"}
	disabled, err := fixture.service.UpdateManagedUserSecondaryVerification(ctx, fixture.actor, disable)
	if err != nil || disabled.Enabled || disabled.RequestedAt != nil || disabled.EnforcedAt != nil || disabled.Revision != 3 {
		t.Fatalf("disabled=(%#v,%v)", disabled, err)
	}
	for action, want := range map[string]int{
		"identity.user.secondary_verification.update": 3, "identity.user.secondary_verification.enforce": 1,
		"identity.user.secondary_verification.release": 1, "site.lock": 3, "site.unlock": 3,
	} {
		var got int
		if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1`, action).Scan(&got); err != nil || got != want {
			t.Fatalf("audit %s=(%d,%v), want %d", action, got, err, want)
		}
	}
}

type secondaryVerificationRepublisherStub struct {
	calls              []identity.SecondaryVerificationRepublish
	sawCommittedChange bool
}

// RepublishNowTx runs inside the enforcement transaction: the site change it
// republishes must already be visible there.
func (stub *secondaryVerificationRepublisherStub) RepublishNowTx(ctx context.Context, tx pgx.Tx, request identity.SecondaryVerificationRepublish) error {
	stub.calls = append(stub.calls, request)
	var current int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, request.ScopeID).Scan(&current); err != nil {
		return err
	}
	stub.sawCommittedChange = current > request.FromRevision
	return nil
}

func insertSecondaryVerificationSite(t *testing.T, pool *pgxpool.Pool, scopeID, ownerID uuid.UUID, domain string, enabled bool,
	lockReason string, lockedBy uuid.UUID) uuid.UUID {
	t.Helper()
	siteID := uuid.New()
	var reason, locker any
	var lockedAt any
	status := "active"
	if !enabled {
		status = "disabled"
	}
	if lockReason != "" {
		reason, locker, lockedAt = lockReason, lockedBy, time.Now().UTC()
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
			https_enabled,enabled,status,created_by_user_id,updated_by_user_id,display_id,lock_reason,locked_at,locked_by_user_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,$7,true,$8,$12,$3,$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2),$9,$10,$11)`, siteID, scopeID, ownerID, domain,
			[]string{"80"}, []string{"443"}, []string{"192.0.2.1"}, enabled, reason, lockedAt, locker, status); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled) VALUES($1,1,'192.0.2.1',80,1,true)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return siteID
}

// seedApprovedReverification writes an approved, evidence-settled personal
// reverification created now (after the request), as the review flow would.
func seedApprovedReverification(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) {
	t.Helper()
	caseID, writeID := uuid.New(), uuid.New()
	fingerprint, digest := bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x52}, 32)
	now := time.Now().UTC()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			return err
		}
		var reviewer uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT user_id FROM memberships WHERE scope_id=$1 AND user_id<>$2 ORDER BY user_id LIMIT 1`,
			scopeID, userID).Scan(&reviewer); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO identity_verification_cases(
			id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,reviewer_user_id,revision,
			created_at,state_changed_at,submitted_at,expires_at,terminal_at,retention_until,evidence_settlement_required)
			VALUES($1,$2,$3,'personal_reverification','approved',$4,$8,4,$5,$5,$5,$6,$5,$7,true)`,
			caseID, scopeID, userID, fingerprint, now, now.Add(time.Hour), now.Add(365*24*time.Hour), reviewer); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO identity_verification_write_requests(
			id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at,response_body,completed_at)
			VALUES($1,$2,$3,'identity_verification.create_draft',$4,$5,$6,'{}'::jsonb,$6)`,
			writeID, scopeID, userID, "secver-reverification-"+caseID.String(), digest, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO identity_verification_evidence_settlements(
			id,tenant_scope_id,actor_user_id,case_id,write_request_id,operation,idempotency_key,
			request_digest,evidence_claim_digest,resolver_name,resolver_reference,state,revision,
			attempt_count,available_at,created_at,updated_at,settled_at)
			VALUES($1,$2,$3,$4,$5,'identity_verification.create_draft',$6,$7,$8,
			'secver-test','secver-test-' || $4::uuid::text,'commit_pending',1,0,$9,$9,$9,NULL)`, uuid.New(), scopeID, userID, caseID, writeID,
			"secver-reverification-"+caseID.String(), digest, fingerprint, now); err != nil {
			return err
		}
		lease := uuid.New()
		if _, err := tx.Exec(t.Context(), `UPDATE identity_verification_evidence_settlements
			SET state='leased',revision=revision+1,attempt_count=attempt_count+1,lease_token=$2,lease_expires_at=$3,updated_at=$4
			WHERE case_id=$1 AND state='commit_pending'`, caseID, lease, now.Add(time.Minute), now); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE identity_verification_evidence_settlements
			SET state='settled',revision=revision+1,lease_token=NULL,lease_expires_at=NULL,updated_at=$2,settled_at=$2
			WHERE case_id=$1 AND state='leased' AND lease_token=$3`, caseID, now, lease)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
