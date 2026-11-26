//go:build integration

package plugininstallation

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ledgerResolver answers lifecycle reports like the license service: failWith refuses (only failFor's reports when
// set), otherwise it signs for the receipt (license revision = control to_revision + 100).
type ledgerResolver struct {
	failWith error
	failFor  uuid.UUID
	reported []Receipt
}

func (*ledgerResolver) Resolve(context.Context, ActivationResolveRequest) (ActivationResult, error) {
	return ActivationResult{}, ErrFactDenied
}

func (*ledgerResolver) Discover(context.Context, CandidateDiscoveryRequest) (Page, error) {
	return Page{}, nil
}

func (resolver *ledgerResolver) ReportLifecycle(_ context.Context, request LifecycleReportRequest) (LifecycleReportResult, error) {
	resolver.reported = append(resolver.reported, request.Receipt)
	if resolver.failWith != nil && (resolver.failFor == uuid.Nil || resolver.failFor == request.Receipt.AuthorizationID) {
		return LifecycleReportResult{}, resolver.failWith
	}
	return LifecycleReportResult{AuthorizationID: request.Receipt.AuthorizationID,
		LifecycleRevision: request.Receipt.ToRevision + 100, Status: request.Receipt.Snapshot.Status}, nil
}

// 真实 PG（迁移 684）：暂停在本机提交后上报授权端超时——接口成功、状态已暂停、license_sync=pending，
// 回执只有一条；同 key 重复点暂停只回放；新 key 再暂停按状态拒绝、不产生回执；后台补报成功后列表与详情为 synced，
// 详情不再调用授权端。覆盖首次安装后直接暂停（安装回执已签收、身份代际 1）与恢复过一次后再暂停（身份代际 3）。
func TestPauseCommittedThenLicenseReportReplayed(t *testing.T) {
	for _, name := range []string{"fresh_install", "after_resume"} {
		t.Run(name, func(t *testing.T) {
			pool := databasetest.MigratedPool(t, nil)
			ctx := t.Context()
			now := time.Now().UTC().Truncate(time.Second)
			scope, user, session, role := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(ctx, query, args...); err != nil {
					t.Fatalf("%v\n%s", err, query)
				}
			}
			count := func(query string, args ...any) int {
				t.Helper()
				var value int
				if err := pool.QueryRow(ctx, query, args...).Scan(&value); err != nil {
					t.Fatalf("%v\n%s", err, query)
				}
				return value
			}
			exec(`INSERT INTO tenants(id,display_name) VALUES($1,'暂停补报')`, scope)
			exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, scope)
			exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'暂停补报','unused')`, user, "p-"+user.String())
			exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, user)
			exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'pause fixture',true)`, role, scope, "p-"+role.String())
			exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2),($1,$3)`, role, PermissionRead, PermissionManage)
			exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scope, user, role)
			refresh := sha256.Sum256(session[:])
			exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
				VALUES($1,$2,$3,$4,$5,$6,$7)`, session, uuid.New(), user, scope, refresh[:], now.Add(-time.Minute), now.Add(time.Hour))
			actor := Actor{UserID: user, SessionID: session, TenantID: scope, RequestID: "pause-ledger-request"}
			clock := now
			repository, err := NewPostgresRepository(pool, func() time.Time { return clock })
			if err != nil {
				t.Fatal(err)
			}
			install := testCommand(scope, uuid.New(), uuid.New(), uuid.New())
			install.Action, install.NewPermissionsConfirmed = ActionConfirm, true
			install.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "pause-install-fact"}}
			head, err := repository.Apply(ctx, actor, install, &recordingVerifier{})
			if err != nil {
				t.Fatalf("install: %v", err)
			}
			if name == "after_resume" {
				paused, err := repository.Apply(ctx, actor, protectiveCommand(head.Installation, ActionDisable, "", "earlier-pause"), nil)
				if err != nil {
					t.Fatal(err)
				}
				resumed := protectiveCommand(paused.Installation, ActionResume, "", "earlier-resume")
				if head, err = repository.Apply(ctx, actor, resumed, nil); err != nil {
					t.Fatal(err)
				}
			}
			// Everything before this pause reached the license service.
			earlier, err := repository.UnreportedReceipts(ctx, install.InstallationID, uuid.Nil, 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, receipt := range earlier {
				if err := repository.MarkReported(ctx, receipt.ID, receipt.ToRevision+100); err != nil {
					t.Fatal(err)
				}
			}
			resolver := &ledgerResolver{failWith: licenseCallError{cause: "timeout", err: ErrFactUnavailable}}
			domain, err := NewProductionDomain(repository, resolver)
			if err != nil {
				t.Fatal(err)
			}
			domain.installationID = install.InstallationID
			authorization := install.AuthorizationID
			pause := MutationRequest{TenantID: scope, AuthorizationID: authorization, Action: ActionDisable,
				ExpectedRevision: head.Installation.Revision, IdempotencyKey: "pause-ledger-key", RequestID: actor.RequestID}
			pauseReceipts := `SELECT count(*) FROM plugin_installation_receipts WHERE authorization_id=$1 AND action='disable'`
			acknowledged := `SELECT count(*) FROM plugin_installation_license_reports report JOIN plugin_installation_receipts
				receipt ON receipt.id=report.receipt_id WHERE receipt.authorization_id=$1 AND receipt.idempotency_key=$2`
			before := count(pauseReceipts, authorization)

			paused, err := domain.Mutate(ctx, actor, pause)
			if err != nil || paused.Installation.Status != StatusDisabled || paused.LicenseSync != LicenseSyncPending ||
				paused.Installation.IdentityGeneration != head.Installation.IdentityGeneration+1 {
				t.Fatalf("pause=%+v sync=%s err=%v", paused.Installation, paused.LicenseSync, err)
			}
			if count(pauseReceipts, authorization) != before+1 || count(acknowledged, authorization, pause.IdempotencyKey) != 0 ||
				LicenseReportCause(resolver.failWith) != "timeout" {
				t.Fatal("pause did not leave exactly one unacknowledged receipt")
			}
			// 重复点暂停（同 key 原样重试）：回放，不产生第二条回执；授权端仍不可达，仍 pending。
			again, err := domain.Mutate(ctx, actor, pause)
			if err != nil || again.Installation.Revision != paused.Installation.Revision || again.LicenseSync != LicenseSyncPending ||
				count(pauseReceipts, authorization) != before+1 {
				t.Fatalf("repeated pause=%+v sync=%s err=%v", again.Installation, again.LicenseSync, err)
			}
			// 新 key 再点暂停：已暂停，按状态拒绝，不写回执。
			fresh := pause
			fresh.IdempotencyKey, fresh.ExpectedRevision = "pause-ledger-key-2", paused.Installation.Revision
			if _, err := domain.Mutate(ctx, actor, fresh); !errors.Is(err, ErrTransitionInvalid) ||
				count(pauseReceipts, authorization) != before+1 {
				t.Fatalf("second pause err=%v", err)
			}
			page, err := domain.List(ctx, actor, ListRequest{TenantID: scope, Limit: 50})
			if err != nil || len(page.Items) != 1 || page.Items[0].LicenseSync != LicenseSyncPending ||
				page.Items[0].Installation.Status != StatusDisabled {
				t.Fatalf("list while pending=%+v err=%v", page.Items, err)
			}

			// 授权端恢复：失败回执的退避到期后，后台一轮补报原回执（同一 ID），签收后列表与详情 synced，详情不再上报。
			resolver.failWith, resolver.reported = nil, nil
			if _, err := domain.deliverAll(ctx, repository); err != nil || len(resolver.reported) != 0 {
				t.Fatalf("round while backing off reports=%d err=%v", len(resolver.reported), err)
			}
			clock = clock.Add(licenseReportMaxBackoff + time.Second)
			if _, err := domain.deliverAll(ctx, repository); err != nil {
				t.Fatal(err)
			}
			if len(resolver.reported) != 1 || resolver.reported[0].IdempotencyKey != pause.IdempotencyKey ||
				resolver.reported[0].Result != ReceiptDisabled || count(acknowledged, authorization, pause.IdempotencyKey) != 1 {
				t.Fatalf("background replay reports=%+v", resolver.reported)
			}
			if revision := count(`SELECT report.lifecycle_revision FROM plugin_installation_license_reports report
				JOIN plugin_installation_receipts receipt ON receipt.id=report.receipt_id WHERE receipt.idempotency_key=$1`,
				pause.IdempotencyKey); uint64(revision) != paused.Installation.Revision+100 {
				t.Fatalf("stored license revision=%d", revision)
			}
			resolver.reported = nil
			detail, err := domain.Get(ctx, actor, authorization)
			if err != nil || detail.LicenseSync != LicenseSyncSynced || detail.Installation.Status != StatusDisabled ||
				len(resolver.reported) != 0 {
				t.Fatalf("detail after replay=%+v sync=%s reports=%d err=%v", detail.Installation, detail.LicenseSync,
					len(resolver.reported), err)
			}
			if replay, err := domain.Mutate(ctx, actor, pause); err != nil || replay.LicenseSync != LicenseSyncSynced ||
				len(resolver.reported) != 0 || count(pauseReceipts, authorization) != before+1 {
				t.Fatalf("retry after sync=%+v reports=%d err=%v", replay.LicenseSync, len(resolver.reported), err)
			}
			// 只追加：签收记录不能改写。
			if _, err := pool.Exec(ctx, `UPDATE plugin_installation_license_reports SET lifecycle_revision=1`); err == nil {
				t.Fatal("license report acknowledgement rewritten")
			}
		})
	}
}

// 详情读取即补报（页面打开 / 重试）：授权端恢复后打开详情，未送达的回执送达，状态 synced。
func TestDetailsDeliverPendingLicenseReport(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	f := platformTargetsFixture{t: t, pool: pool, now: now}
	tenant := f.tenant("详情补报")
	actor := f.member(tenant, ScopeTenant, PermissionRead, PermissionManage)
	actor.RequestID = "details-ledger-request"
	repository, err := NewPostgresRepository(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	install := testCommand(tenant, uuid.New(), uuid.New(), uuid.New())
	install.Action, install.NewPermissionsConfirmed = ActionConfirm, true
	install.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "details-install-fact"}}
	if _, err := repository.Apply(ctx, actor, install, &recordingVerifier{}); err != nil {
		t.Fatal(err)
	}
	resolver := &ledgerResolver{failWith: licenseCallError{cause: "refused:signer_unavailable", err: ErrFactUnavailable}}
	domain, err := NewProductionDomain(repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if view, err := domain.Get(ctx, actor, install.AuthorizationID); err != nil || view.LicenseSync != LicenseSyncPending {
		t.Fatalf("details while refused sync=%s err=%v", view.LicenseSync, err)
	}
	resolver.failWith = nil
	view, err := domain.Get(ctx, actor, install.AuthorizationID)
	if err != nil || view.LicenseSync != LicenseSyncSynced || len(resolver.reported) != 2 ||
		resolver.reported[1].Result != ReceiptInstalled {
		t.Fatalf("details after recovery sync=%s reports=%d err=%v", view.LicenseSync, len(resolver.reported), err)
	}
}

// ledgerFixture installs plugins of one tenant and control installation into a migrated database (694), with a
// repository clock the test moves.
type ledgerFixture struct {
	t              *testing.T
	pool           *pgxpool.Pool
	actor          Actor
	installationID uuid.UUID
	clock          *time.Time
	repository     *PostgresRepository
}

func newLedgerFixture(t *testing.T, name string) ledgerFixture {
	pool := databasetest.MigratedPool(t, nil)
	now := time.Now().UTC().Truncate(time.Second)
	f := platformTargetsFixture{t: t, pool: pool, now: now}
	tenant := f.tenant(name)
	actor := f.member(tenant, ScopeTenant, PermissionRead, PermissionManage)
	actor.RequestID = "ledger-request"
	clock := &now
	repository, err := NewPostgresRepository(pool, func() time.Time { return *clock })
	if err != nil {
		t.Fatal(err)
	}
	return ledgerFixture{t: t, pool: pool, actor: actor, installationID: uuid.New(), clock: clock, repository: repository}
}

// install confirms a plugin under authorizationID and then pauses and resumes it cycles times; it returns the
// head installation (1 + 2*cycles receipts).
func (f ledgerFixture) install(authorizationID uuid.UUID, cycles int) Installation {
	f.t.Helper()
	command := testCommand(f.actor.TenantID, f.installationID, authorizationID, uuid.New())
	command.Action, command.NewPermissionsConfirmed = ActionConfirm, true
	command.IdempotencyKey, command.RequestID = "install-"+authorizationID.String(), "install-request-"+authorizationID.String()
	command.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "fact-" + authorizationID.String()}}
	head, err := f.repository.Apply(f.t.Context(), f.actor, command, &recordingVerifier{})
	if err != nil {
		f.t.Fatalf("install %s: %v", authorizationID, err)
	}
	for cycle := range cycles {
		head = f.apply(head.Installation, ActionDisable, fmt.Sprintf("pause-%d", cycle))
		head = f.apply(head.Installation, ActionResume, fmt.Sprintf("resume-%d", cycle))
	}
	return head.Installation
}

func (f ledgerFixture) apply(current Installation, action, key string) MutationResult {
	f.t.Helper()
	result, err := f.repository.Apply(f.t.Context(), f.actor,
		protectiveCommand(current, action, "", key+"-"+current.AuthorizationID.String()[:8]), nil)
	if err != nil {
		f.t.Fatalf("%s %s: %v", action, current.AuthorizationID, err)
	}
	return result
}

// acknowledgeAll marks every receipt of authorizationID reported.
func (f ledgerFixture) acknowledgeAll(authorizationID uuid.UUID) {
	f.t.Helper()
	receipts, err := f.repository.UnreportedReceipts(f.t.Context(), f.installationID, authorizationID, 1000)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, receipt := range receipts {
		if err := f.repository.MarkReported(f.t.Context(), receipt.ID, receipt.ToRevision+100); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f ledgerFixture) unacknowledged(authorizationID uuid.UUID) int {
	f.t.Helper()
	receipts, err := f.repository.UnreportedReceipts(f.t.Context(), f.installationID, authorizationID, 1000)
	if err != nil {
		f.t.Fatal(err)
	}
	return len(receipts)
}

// 真实 PG：排序在前的授权积压 500 条以上未签收回执时，与它不相邻的授权只差一条未签收
// 暂停回执，列表照样标 pending；列表与详情三项一致（授权端不可达，详情只补报失败、不改变状态）。
func TestListLicenseSyncMatchesDetailsBehindLargeBacklog(t *testing.T) {
	f := newLedgerFixture(t, "列表同步状态")
	backlog := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	synced := uuid.MustParse("7fffffff-ffff-4fff-bfff-ffffffffffff")
	behind := uuid.MustParse("ffffffff-ffff-4fff-bfff-ffffffffffff")
	f.install(backlog, 251)
	f.install(synced, 0)
	f.acknowledgeAll(synced)
	head := f.install(behind, 0)
	f.acknowledgeAll(behind)
	f.apply(head, ActionDisable, "behind-pause")
	if n := f.unacknowledged(backlog); n <= 500 {
		t.Fatalf("backlog=%d, want more than 500", n)
	}
	resolver := &ledgerResolver{failWith: licenseCallError{cause: "timeout", err: ErrFactUnavailable}}
	domain, err := NewProductionDomain(f.repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	domain.installationID = f.installationID
	page, err := domain.List(t.Context(), f.actor, ListRequest{TenantID: f.actor.TenantID, Limit: 50})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("list=%d err=%v", len(page.Items), err)
	}
	want := map[uuid.UUID]string{backlog: LicenseSyncPending, synced: LicenseSyncSynced, behind: LicenseSyncPending}
	for _, item := range page.Items {
		id := item.Installation.AuthorizationID
		detail, err := domain.Get(t.Context(), f.actor, id)
		if err != nil || item.LicenseSync != want[id] || detail.LicenseSync != item.LicenseSync {
			t.Fatalf("%s list=%s detail=%s want=%s err=%v", id, item.LicenseSync, detail.LicenseSync, want[id], err)
		}
	}
}

// 真实 PG：队首授权的第一条回执持续被拒时，后台只给它退避，另一个授权每轮照常签收；
// 退避未到期不重试、到期后再试一次并加倍退避；授权端恢复后原授权按修订顺序补齐，签收记录只有一份。
func TestBackgroundReportsBackOffFailingAuthorizationOnly(t *testing.T) {
	f := newLedgerFixture(t, "补报公平")
	stuck := uuid.MustParse("00000000-0000-4000-8000-000000000002")
	healthy := uuid.MustParse("ffffffff-ffff-4fff-bfff-fffffffffffe")
	f.install(stuck, 1)
	healthyHead := f.install(healthy, 0)
	healthyHead = f.apply(healthyHead, ActionDisable, "healthy-pause").Installation
	resolver := &ledgerResolver{failWith: licenseCallError{cause: "refused:invalid_request", err: ErrFactDenied},
		failFor: stuck}
	domain, err := NewProductionDomain(f.repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	domain.installationID = f.installationID
	ctx := t.Context()
	attempt := func() (int, time.Duration) {
		t.Helper()
		var failures int
		var seconds int64
		if err := f.pool.QueryRow(ctx, `SELECT attempt.failures,
				extract(epoch FROM attempt.next_attempt_at-attempt.last_attempted_at)::bigint
			FROM plugin_installation_license_report_attempts attempt
			JOIN plugin_installation_receipts receipt ON receipt.id=attempt.receipt_id
			WHERE receipt.authorization_id=$1 ORDER BY receipt.to_revision LIMIT 1`, stuck).Scan(&failures, &seconds); err != nil {
			t.Fatal(err)
		}
		return failures, time.Duration(seconds) * time.Second
	}
	round := func() []Receipt {
		t.Helper()
		resolver.reported = nil
		_, _ = domain.deliverAll(ctx, f.repository)
		return resolver.reported
	}

	if reported := round(); len(reported) != 3 || f.unacknowledged(healthy) != 0 || f.unacknowledged(stuck) != 3 {
		t.Fatalf("first round reports=%d healthy pending=%d stuck pending=%d", len(reported),
			f.unacknowledged(healthy), f.unacknowledged(stuck))
	}
	if failures, wait := attempt(); failures != 1 || wait != 2*licenseReportRetryBase {
		t.Fatalf("first backoff failures=%d wait=%s", failures, wait)
	}
	// Backing off: the stuck authorization is not tried, the other still signs at once.
	f.apply(healthyHead, ActionResume, "healthy-resume")
	if reported := round(); len(reported) != 1 || reported[0].AuthorizationID != healthy || f.unacknowledged(healthy) != 0 {
		t.Fatalf("round while backing off reports=%+v", reported)
	}
	*f.clock = f.clock.Add(2*licenseReportRetryBase + time.Second)
	if reported := round(); len(reported) != 1 || reported[0].AuthorizationID != stuck {
		t.Fatalf("due retry reports=%+v", reported)
	}
	if failures, wait := attempt(); failures != 2 || wait != 4*licenseReportRetryBase {
		t.Fatalf("second backoff failures=%d wait=%s", failures, wait)
	}
	resolver.failWith = nil
	*f.clock = f.clock.Add(4*licenseReportRetryBase + time.Second)
	reported := round()
	if len(reported) != 3 || f.unacknowledged(stuck) != 0 {
		t.Fatalf("recovered round reports=%d pending=%d", len(reported), f.unacknowledged(stuck))
	}
	for index, receipt := range reported {
		if receipt.AuthorizationID != stuck || receipt.ToRevision != uint64(1+index) {
			t.Fatalf("recovered report %d to_revision=%d authorization=%s", index, receipt.ToRevision, receipt.AuthorizationID)
		}
	}
	if due, err := f.repository.DueReports(ctx, f.installationID, 100); err != nil || len(due) != 0 {
		t.Fatalf("due after recovery=%d err=%v", len(due), err)
	}
	if pending, err := f.repository.PendingAuthorizations(ctx, f.installationID, []uuid.UUID{stuck, healthy}); err != nil ||
		len(pending) != 0 {
		t.Fatalf("pending after recovery=%v err=%v", pending, err)
	}
	if reported := round(); len(reported) != 0 {
		t.Fatalf("idle round reports=%d", len(reported))
	}
}

// 真实 PG：运营端先暂停，主控再暂停（授权端 already_disabled 签收）。运营暂停未解除时
// 详情显示运营暂停、主控恢复 409、不写回执；运营端恢复后授权端 enabled、本机仍是自己的暂停：详情显示本主控暂停，
// 恢复写本机并上报签收（授权端 already_enabled），原样重试只回放一条回执；新 key 再恢复按状态拒绝。
func TestResumeOwnPauseAfterOperatorLiftsItsPause(t *testing.T) {
	f := newLedgerFixture(t, "运营恢复后本机恢复")
	ctx := t.Context()
	authorization := uuid.New()
	head := f.install(authorization, 0)
	f.acknowledgeAll(authorization)
	paused := f.apply(head, ActionDisable, "own-pause")
	if err := f.repository.MarkReported(ctx, paused.Receipt.ID, 9); err != nil { // already_disabled
		t.Fatal(err)
	}
	remote := installationView(paused.Installation)
	remote.AuthorizationStatus, remote.PausedBy = StatusDisabled, PausedByOperator
	resolver := &flakyResumeResolver{resumeResolver: resumeResolver{remote: []InstallationView{remote}}}
	domain, err := NewProductionDomain(f.repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	domain.installationID = f.installationID
	resumes := func() int {
		t.Helper()
		var n int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM plugin_installation_receipts WHERE action='resume' AND
			authorization_id=$1`, authorization).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	request := MutationRequest{TenantID: f.actor.TenantID, AuthorizationID: authorization, Action: ActionResume,
		ExpectedRevision: paused.Installation.Revision, IdempotencyKey: "resume-after-operator", RequestID: f.actor.RequestID}

	detail, err := domain.Get(ctx, f.actor, authorization)
	if err != nil || detail.PausedBy != PausedByOperator || detail.LicenseSync != LicenseSyncSynced {
		t.Fatalf("operator pause detail paused_by=%s sync=%s err=%v", detail.PausedBy, detail.LicenseSync, err)
	}
	if _, err := domain.Mutate(ctx, f.actor, request); !errors.Is(err, ErrPlatformPaused) || resumes() != 0 {
		t.Fatalf("resume under the operator pause err=%v receipts=%d", err, resumes())
	}

	resolver.remote[0].AuthorizationStatus, resolver.remote[0].PausedBy = StatusEnabled, ""
	detail, err = domain.Get(ctx, f.actor, authorization)
	if err != nil || detail.Installation.Status != StatusDisabled || detail.AuthorizationStatus != StatusDisabled ||
		detail.PausedBy != PausedByInstallation {
		t.Fatalf("after the operator resumed detail=%s/%s paused_by=%s err=%v", detail.Installation.Status,
			detail.AuthorizationStatus, detail.PausedBy, err)
	}
	resumed, err := domain.Mutate(ctx, f.actor, request)
	if err != nil || resumed.Installation.Status != StatusEnabled || resumed.LicenseSync != LicenseSyncSynced ||
		resumes() != 1 || len(resolver.reported) != 1 {
		t.Fatalf("resume=%s sync=%s receipts=%d reports=%d err=%v", resumed.Installation.Status, resumed.LicenseSync,
			resumes(), len(resolver.reported), err)
	}
	again, err := domain.Mutate(ctx, f.actor, request)
	if err != nil || again.Installation.Revision != resumed.Installation.Revision || resumes() != 1 ||
		len(resolver.reported) != 1 {
		t.Fatalf("exact retry revision=%d receipts=%d reports=%d err=%v", again.Installation.Revision, resumes(),
			len(resolver.reported), err)
	}
	fresh := request
	fresh.IdempotencyKey = "resume-after-operator-2"
	if _, err := domain.Mutate(ctx, f.actor, fresh); !errors.Is(err, ErrTransitionInvalid) || resumes() != 1 {
		t.Fatalf("fresh resume of an enabled head err=%v", err)
	}
}

// 真实 PG：一次打开详情最多补报 10 批 × 20 条。199、200 条在这一次补完并返回 synced；
// 201 条补到 200、返回 pending，下一次补完最后一条。
func TestDetailsExactBatchBoundary(t *testing.T) {
	f := newLedgerFixture(t, "整批补报")
	resolver := &ledgerResolver{}
	domain, err := NewProductionDomain(f.repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	domain.installationID = f.installationID
	for _, total := range []int{199, 200, 201} {
		authorization := uuid.New()
		head := f.install(authorization, (total-1)/2)
		if total%2 == 0 {
			f.apply(head, ActionDisable, "extra-pause")
		}
		if n := f.unacknowledged(authorization); n != total {
			t.Fatalf("fixture receipts=%d want %d", n, total)
		}
		resolver.reported = nil
		want, wantReported := LicenseSyncSynced, total
		if total > licenseReportBatch*licenseReportRounds {
			want, wantReported = LicenseSyncPending, licenseReportBatch*licenseReportRounds
		}
		detail, err := domain.Get(t.Context(), f.actor, authorization)
		if err != nil || detail.LicenseSync != want || len(resolver.reported) != wantReported ||
			f.unacknowledged(authorization) != total-wantReported {
			t.Fatalf("total=%d sync=%s reports=%d remaining=%d err=%v", total, detail.LicenseSync, len(resolver.reported),
				f.unacknowledged(authorization), err)
		}
		for index, receipt := range resolver.reported {
			if receipt.ToRevision != uint64(index+1) {
				t.Fatalf("total=%d report %d to_revision=%d", total, index, receipt.ToRevision)
			}
		}
		if want == LicenseSyncPending {
			if detail, err := domain.Get(t.Context(), f.actor, authorization); err != nil ||
				detail.LicenseSync != LicenseSyncSynced || f.unacknowledged(authorization) != 0 {
				t.Fatalf("total=%d second read sync=%s err=%v", total, detail.LicenseSync, err)
			}
		}
	}
}
