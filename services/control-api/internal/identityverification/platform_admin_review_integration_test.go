//go:build integration

package identityverification

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// "实名审核：现在审核人必须是该租户的成员，平台管理员也能代审，还是那个管理员是最高权限，
// 租户审核可做的管理都可一个人做"。平台管理员（tenantaccess 规则）以本人身份领取/读取/裁决任意租户的
// 实名单，审计记管理员；不能以申请人身份操作（self.manage），无 platform.admin 的平台成员仍拒。
func TestPlatformAdministratorReviewsTenantIdentityVerification(t *testing.T) {
	fixture := newVerificationFixture(t)
	ctx := t.Context()
	tenantScope := fixture.applicant.ScopeID
	platformScope := ensurePlatformScope(t, fixture.pool)
	admin := insertPlatformReviewActor(t, fixture.pool, platformScope, tenantScope, "platform.admin")
	viewer := insertPlatformReviewActor(t, fixture.pool, platformScope, tenantScope, "sites.manage")

	draft, err := fixture.service.CreateDraft(ctx, fixture.applicant.Actor,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xd1), "platform-review"))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	settleDraft(t, fixture.pool, draft.ID, fixture.clock.now())
	submitted, err := fixture.service.Submit(ctx, fixture.applicant.Actor, mutation(draft, "platform-review-submit"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	// 无 platform.admin 的平台成员：读、领取都拒，且不落任何事实。
	before := counts(t, fixture.pool, verificationWriteFactTables...)
	if _, err := fixture.service.StartReview(ctx, viewer, mutation(submitted, "viewer-start")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("non-admin platform StartReview err=%v, want permission denied", err)
	}
	if _, err := fixture.service.GetForReview(ctx, viewer, submitted.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("non-admin platform GetForReview err=%v, want permission denied", err)
	}
	assertFactCountsEqual(t, before, counts(t, fixture.pool, verificationWriteFactTables...))

	// 平台管理员不能以申请人身份操作（self.manage 只认本人成员）。
	if _, err := fixture.service.CreateDraft(ctx, admin,
		validPersonalDraft(KindPersonalInitial, bytesOf(32, 0xd2), "admin-self")); !errors.Is(err, ErrPermissionDenied) &&
		!errors.Is(err, ErrInvalidInput) {
		t.Fatalf("platform admin CreateDraft err=%v, want rejection", err)
	}
	if _, err := fixture.service.Get(ctx, admin, submitted.ID); !errors.Is(err, ErrPermissionDenied) &&
		!errors.Is(err, ErrInvalidInput) {
		t.Fatalf("platform admin Get(self) err=%v, want rejection", err)
	}
	if _, err := fixture.service.Withdraw(ctx, admin, mutation(submitted, "admin-withdraw")); !errors.Is(err, ErrPermissionDenied) &&
		!errors.Is(err, ErrInvalidInput) {
		t.Fatalf("platform admin Withdraw err=%v, want rejection", err)
	}

	// 目标租户与案件租户不一致：拒。
	wrongTarget := admin
	wrongTarget.reviewTargetScopeID = fixture.otherScope
	if _, err := fixture.service.StartReview(ctx, wrongTarget, mutation(submitted, "admin-wrong-target")); !errors.Is(err, ErrPermissionDenied) &&
		!errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant StartReview err=%v, want rejection", err)
	}

	if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		return fixture.service.AuthorizeReviewerList(ctx, tx, admin)
	}); err != nil {
		t.Fatalf("platform admin AuthorizeReviewerList: %v", err)
	}
	read, err := fixture.service.GetForReview(ctx, admin, submitted.ID)
	if err != nil || read.ID != submitted.ID {
		t.Fatalf("platform admin GetForReview=%#v err=%v", read, err)
	}
	reviewing, err := fixture.service.StartReview(ctx, admin, mutation(submitted, "admin-start"))
	if err != nil {
		t.Fatalf("platform admin StartReview: %v", err)
	}
	if reviewing.ReviewerUserID == nil || *reviewing.ReviewerUserID != admin.UserID ||
		reviewing.TenantScopeID != tenantScope {
		t.Fatalf("reviewing=%#v", reviewing)
	}
	replay, err := fixture.service.StartReview(ctx, admin, mutation(submitted, "admin-start"))
	if err != nil || !replay.Replayed || replay.Revision != reviewing.Revision {
		t.Fatalf("StartReview replay=%#v err=%v", replay, err)
	}
	approved, err := fixture.service.Review(ctx, admin, ReviewRequest{CaseID: reviewing.ID,
		ExpectedRevision: reviewing.Revision, Decision: DecisionApprove, ReasonCode: ReasonEvidenceVerified,
		IdempotencyKey: "admin-approve", RequestID: "admin-approve-request"})
	if err != nil {
		t.Fatalf("platform admin Review: %v", err)
	}
	if approved.Status != StatusApproved {
		t.Fatalf("approved=%#v", approved)
	}
	for _, action := range []string{operationStartReview, operationReview} {
		assertPlatformReviewAudit(t, fixture.pool, tenantScope, admin.UserID, platformScope, action)
	}
	var reviewer uuid.UUID
	if err := fixture.pool.QueryRow(ctx, `SELECT reviewer_user_id FROM identity_verification_reviews
		WHERE tenant_scope_id=$1 AND case_id=$2`, tenantScope, approved.ID).Scan(&reviewer); err != nil ||
		reviewer != admin.UserID {
		t.Fatalf("review row reviewer=%s err=%v", reviewer, err)
	}
	assertVerifiedPerson(t, fixture.pool, fixture.applicant.Actor, bytesOf(32, 0xd1))
}

func ensurePlatformScope(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var scopeID uuid.UUID
	err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY created_at LIMIT 1`).
		Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		scopeID = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	return scopeID
}

// insertPlatformReviewActor creates a platform member holding permission and
// returns its session actor aimed at targetTenantScope for review.
func insertPlatformReviewActor(t *testing.T, pool *pgxpool.Pool, platformScope, targetTenantScope uuid.UUID,
	permission string,
) Actor {
	t.Helper()
	ctx := context.Background()
	userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New()
	must := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	must(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'test-password-hash')`,
		userID, "idreview-platform-"+strings.ReplaceAll(uuid.NewString(), "-", "")[:8])
	must(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScope, userID)
	must(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'idreview platform role',true)`,
		roleID, platformScope, "idreview-"+strings.ReplaceAll(roleID.String(), "-", "")[:12])
	must(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
	must(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platformScope, userID, roleID)
	sessionHash := sessionRefreshTokenHash(sessionID)
	must(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$1,$2,$3,$4,$5,$6)`, sessionID, userID, platformScope, sessionHash[:],
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
	tokens, err := identity.NewTokenManager(identityVerificationTestSessionSecret, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rawSession, _, err := tokens.Mint(userID, platformScope, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := NewPlatformReviewActor(userID, platformScope, sessionID, rawSession, targetTenantScope)
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func assertPlatformReviewAudit(t *testing.T, pool *pgxpool.Pool, tenantScope, admin, platformScope uuid.UUID,
	action string,
) {
	t.Helper()
	var actorScope, actorKind string
	if err := pool.QueryRow(t.Context(), `SELECT payload->>'actor_scope_id',payload->>'actor_scope_kind'
		FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3 AND result='success'
		ORDER BY stream_position DESC LIMIT 1`, tenantScope, admin, action).Scan(&actorScope, &actorKind); err != nil {
		t.Fatalf("%s audit: %v", action, err)
	}
	if actorScope != platformScope.String() || actorKind != "platform" {
		t.Fatalf("%s audit actor scope=%s kind=%s", action, actorScope, actorKind)
	}
}
