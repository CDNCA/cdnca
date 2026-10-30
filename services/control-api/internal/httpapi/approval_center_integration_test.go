package httpapi

// 平台审批中心 PG 用例。待出包前全量跑：需要 TEST_DATABASE_URL；迁移
// 522（分支占位 530，merge-p9 改号）。
// 受管操作用全局防火墙策略 PUT /v1/firewall/policy：本测试不挂防火墙运行时，重放到达业务
// 处理器时得到 404（未挂载），以此证明"批准即用审批人会话重放到原路由"。

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/approvalcenter"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type approvalCenterFixture struct {
	pool                         *pgxpool.Pool
	server                       *httptest.Server
	clock                        *time.Time
	owner, requester, approver   string // access tokens
	ownerID, requesterID, apprID uuid.UUID
	platformScope                uuid.UUID
	stepUp                       *approvalStepUpRecorder
}

// approvalStepUpRecorder accepts the token "valid" and records the binding.
type approvalStepUpRecorder struct {
	bindings [][]byte
}

func (r *approvalStepUpRecorder) ConsumeStepUpTxWithScopes(_ context.Context, _ pgx.Tx, actor mfa.Actor, _ []uuid.UUID,
	request mfa.ConsumeStepUpRequest) (mfa.Evidence, error) {
	if request.Token != "valid" || !request.PlatformScope || request.Audience != approvalcenter.StepUpAudience ||
		request.Action != approvalcenter.StepUpAction {
		return mfa.Evidence{}, mfa.ErrInvalidInput
	}
	r.bindings = append(r.bindings, request.ResourceBindingDigest)
	return mfa.Evidence{ProofID: uuid.New(), ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID, SessionID: actor.SessionID,
		PlatformScope: true, Audience: request.Audience, Action: request.Action, UseOrdinal: 1,
		ResourceBindingDigest: request.ResourceBindingDigest}, nil
}

func newApprovalCenterFixture(t *testing.T) *approvalCenterFixture {
	t.Helper()
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "ac-owner", "AC Owner", passwordHash, "bootstrap-ac-owner")
	if err != nil {
		t.Fatal(err)
	}
	// requester and approver: platform_admin members holding the approval codes but not platform.admin.
	requesterID := insertApprovalPlatformUser(t, pool, owner.ScopeID, "ac-requester", passwordHash, "firewall.manage", "approvals.read")
	approverID := insertApprovalPlatformUser(t, pool, owner.ScopeID, "ac-approver", passwordHash, "approvals.read", "approvals.approve")
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	tokens, err := identity.NewTokenManager("approval-center-http-secret-at-least-thirty-two-bytes", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &approvalCenterFixture{pool: pool, clock: &now, platformScope: owner.ScopeID, ownerID: owner.UserID,
		requesterID: requesterID, apprID: approverID, stepUp: &approvalStepUpRecorder{}}
	fixture.server = httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		Now: func() time.Time { return *fixture.clock }, ApprovalStepUpConsumer: fixture.stepUp}).Handler())
	t.Cleanup(fixture.server.Close)
	client := fixture.server.Client()
	ownerAuth, _ := loginOK(t, client, fixture.server.URL, "ac-owner")
	requesterAuth, _ := loginOK(t, client, fixture.server.URL, "ac-requester")
	approverAuth, _ := loginOK(t, client, fixture.server.URL, "ac-approver")
	fixture.owner, fixture.requester, fixture.approver = ownerAuth.AccessToken, requesterAuth.AccessToken, approverAuth.AccessToken
	return fixture
}

// insertApprovalPlatformUser adds a platform_admin member (the billing fixture's
// system role) and grants that role the approval codes; it has no platform.admin.
func insertApprovalPlatformUser(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, username, passwordHash string, permissions ...string) uuid.UUID {
	t.Helper()
	userID := insertBillingPlatformUser(t, pool, scopeID, username, username, passwordHash, true)
	runBillingAuthorityMutation(t, pool, []uuid.UUID{scopeID}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
			SELECT role.id,permission.name FROM roles role, permissions permission
			WHERE role.scope_id=$1 AND role.name='platform_admin' AND role.system_role AND permission.name=ANY($2::text[])
			ON CONFLICT DO NOTHING`, scopeID, permissions)
		return err
	})
	return userID
}

func (f *approvalCenterFixture) call(t *testing.T, method, path, authorization string, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(method, f.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := f.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	decoded := map[string]any{}
	_ = json.Unmarshal(raw, &decoded)
	return response.StatusCode, decoded
}

func (f *approvalCenterFixture) enable(t *testing.T, rules ...string) {
	t.Helper()
	var revision float64
	status, body := f.call(t, http.MethodGet, "/v1/admin/approval-center/settings", "Bearer "+f.owner, "", nil)
	if status != http.StatusOK {
		t.Fatalf("get settings = %d %v", status, body)
	}
	revision, _ = body["revision"].(float64)
	encoded, _ := json.Marshal(map[string]any{"enabled": true, "rules": rules, "revision": int64(revision)})
	if status, body := f.call(t, http.MethodPut, "/v1/admin/approval-center/settings", "Bearer "+f.owner, string(encoded), nil); status != http.StatusOK {
		t.Fatalf("enable = %d %v", status, body)
	}
}

func (f *approvalCenterFixture) submitFirewall(t *testing.T, token string) map[string]any {
	t.Helper()
	status, body := f.call(t, http.MethodPut, "/v1/firewall/policy", "Bearer "+token, `{"rules":[]}`, map[string]string{
		"Idempotency-Key": "fw-" + uuid.NewString(), "X-Approval-Reason": url.QueryEscape("修复误封"),
	})
	if status != http.StatusAccepted || body["code"] != "approval_submitted" {
		t.Fatalf("submit = %d %v", status, body)
	}
	return body["approval"].(map[string]any)
}

func (f *approvalCenterFixture) decide(t *testing.T, token, id, decision string, revision float64, stepUp string) (int, map[string]any) {
	t.Helper()
	encoded, _ := json.Marshal(map[string]any{"expected_revision": int64(revision), "step_up_token": stepUp})
	if stepUp == "" {
		encoded, _ = json.Marshal(map[string]any{"expected_revision": int64(revision)})
	}
	return f.call(t, http.MethodPost, "/v1/admin/approval-requests/"+id+"/"+decision, "Bearer "+token, string(encoded), nil)
}

func activateApprovalMFA(t *testing.T, pool *pgxpool.Pool, userID, scopeID uuid.UUID, now time.Time) {
	t.Helper()
	recorder := &httpBillingApprovalStepUpConsumer{now: now}
	// 041 validates the seeded proof against a live auth session of the user.
	var sessionID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM auth_sessions WHERE user_id=$1 AND scope_id=$2
		AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`, userID, scopeID).Scan(&sessionID); err != nil {
		t.Fatalf("approver session: %v", err)
	}
	runBillingAuthorityMutation(t, pool, []uuid.UUID{scopeID}, func(ctx context.Context, tx pgx.Tx) error {
		// The billing test consumer inserts an activated credential as a side effect.
		_, err := recorder.ConsumeStepUpTxWithScopes(ctx, tx, mfa.Actor{UserID: userID, ScopeID: scopeID, SessionID: sessionID}, nil,
			mfa.ConsumeStepUpRequest{Token: "seed", PlatformScope: true, Audience: "seed", Action: "seed",
				Context: mfa.RequestContext{RequestID: "seed-" + uuid.NewString(), TraceID: "seed"}})
		return err
	})
}

func TestApprovalCenterOffPassesThrough(t *testing.T) {
	f := newApprovalCenterFixture(t)
	// Off by default: no 428, the business route answers as before (firewall runtime not mounted: 404).
	status, body := f.call(t, http.MethodPut, "/v1/firewall/policy", "Bearer "+f.requester, `{"rules":[]}`, map[string]string{"Idempotency-Key": "k"})
	if status == http.StatusPreconditionRequired || status == http.StatusAccepted {
		t.Fatalf("center off: status=%d %v", status, body)
	}
	if status, body := f.call(t, http.MethodGet, "/v1/runtime-features", "Bearer "+f.requester, "", nil); status != http.StatusOK ||
		body["features"].(map[string]any)["approval_center"] != false {
		t.Fatalf("runtime features = %d %v", status, body)
	}
}

func TestApprovalCenterRequireReasonSubmitApproveExecute(t *testing.T) {
	f := newApprovalCenterFixture(t)
	f.enable(t, approvalcenter.DefaultRules()...)
	status, body := f.call(t, http.MethodPut, "/v1/firewall/policy", "Bearer "+f.requester, `{"rules":[]}`, map[string]string{"Idempotency-Key": "k"})
	if status != http.StatusPreconditionRequired || body["error"].(map[string]any)["code"] != "approval_required" {
		t.Fatalf("no reason = %d %v", status, body)
	}
	approval := f.submitFirewall(t, f.requester)
	id, revision := approval["id"].(string), approval["revision"].(float64)
	// Q2: the approver's approval runs the stored request at once with the approver's session.
	status, body = f.decide(t, f.approver, id, "approve", revision, "")
	if status != http.StatusOK {
		t.Fatalf("approve = %d %v", status, body)
	}
	result := body["approval"].(map[string]any)
	results := result["results"].([]any)
	if result["step_up"] != "none" || len(results) != 1 || results[0].(map[string]any)["status"].(float64) != http.StatusNotFound ||
		result["state"] != approvalcenter.StateFailed {
		t.Fatalf("approved = %v", result)
	}
	var stepUpNote, actor string
	if err := f.pool.QueryRow(t.Context(), `SELECT payload->>'step_up_note',actor_user_id::text FROM audit_events
		WHERE action='approval_center.request.approve' AND resource_id=$1`, id).Scan(&stepUpNote, &actor); err != nil ||
		stepUpNote != "未二次验证" || actor != f.apprID.String() {
		t.Fatalf("approve audit note=%q actor=%s err=%v", stepUpNote, actor, err)
	}
	// Approving again is a conflict: the request is single use.
	if status, _ := f.decide(t, f.approver, id, "approve", revision, ""); status != http.StatusConflict {
		t.Fatalf("second approve = %d", status)
	}
}

func TestApprovalCenterRejectAndExpire(t *testing.T) {
	f := newApprovalCenterFixture(t)
	f.enable(t, approvalcenter.RuleFirewallPolicy)
	rejected := f.submitFirewall(t, f.requester)
	if status, body := f.decide(t, f.approver, rejected["id"].(string), "reject", rejected["revision"].(float64), ""); status != http.StatusOK ||
		body["approval"].(map[string]any)["state"] != approvalcenter.StateRejected {
		t.Fatalf("reject = %d %v", status, body)
	}
	expiring := f.submitFirewall(t, f.requester)
	*f.clock = f.clock.Add(approvalcenter.PendingTTL)
	status, body := f.call(t, http.MethodGet, "/v1/admin/approval-requests/"+expiring["id"].(string), "Bearer "+f.approver, "", nil)
	if status != http.StatusOK || body["approval"].(map[string]any)["state"] != approvalcenter.StateExpired {
		t.Fatalf("expired read = %d %v", status, body)
	}
	if status, body := f.decide(t, f.approver, expiring["id"].(string), "approve", expiring["revision"].(float64), ""); status != http.StatusConflict ||
		body["error"].(map[string]any)["code"] != "approval_expired" {
		t.Fatalf("approve expired = %d %v", status, body)
	}
}

func TestApprovalCenterSelfApprovalOnlyForPlatformAdmin(t *testing.T) {
	f := newApprovalCenterFixture(t)
	f.enable(t, approvalcenter.RuleFirewallPolicy)
	// The approver holds approvals.approve but not platform.admin: it cannot approve its own request.
	own := f.submitFirewall(t, f.approver)
	if status, body := f.decide(t, f.approver, own["id"].(string), "approve", own["revision"].(float64), ""); status != http.StatusForbidden ||
		body["error"].(map[string]any)["code"] != "approval_same_operator" {
		t.Fatalf("self approve = %d %v", status, body)
	}
	// platform_owner holds platform.admin: self approval allowed, recorded as self_approved.
	ownerOwn := f.submitFirewall(t, f.owner)
	status, body := f.decide(t, f.owner, ownerOwn["id"].(string), "approve", ownerOwn["revision"].(float64), "")
	if status != http.StatusOK || body["approval"].(map[string]any)["self_approved"] != true {
		t.Fatalf("platform admin self approve = %d %v", status, body)
	}
}

func TestApprovalCenterMFAApproverMustStepUp(t *testing.T) {
	f := newApprovalCenterFixture(t)
	f.enable(t, approvalcenter.RuleFirewallPolicy)
	activateApprovalMFA(t, f.pool, f.apprID, f.platformScope, *f.clock)
	approval := f.submitFirewall(t, f.requester)
	id, revision := approval["id"].(string), approval["revision"].(float64)
	if status, body := f.call(t, http.MethodGet, "/v1/admin/approval-requests/"+id, "Bearer "+f.approver, "", nil); status != http.StatusOK ||
		body["step_up_required"] != true {
		t.Fatalf("detail = %d %v", status, body)
	}
	if status, body := f.decide(t, f.approver, id, "approve", revision, ""); status != http.StatusPreconditionRequired ||
		body["error"].(map[string]any)["code"] != "mfa_step_up_required" {
		t.Fatalf("approve without proof = %d %v", status, body)
	}
	if status, body := f.decide(t, f.approver, id, "approve", revision, "valid"); status != http.StatusOK ||
		body["approval"].(map[string]any)["step_up"] != approvalcenter.StepUpMFA || len(f.stepUp.bindings) != 1 {
		t.Fatalf("approve with proof = %d %v", status, body)
	}
}

func TestApprovalCenterAPIKeyPasses(t *testing.T) {
	f := newApprovalCenterFixture(t)
	f.enable(t, approvalcenter.DefaultRules()...)
	// Q4: an API key call is never held; the business route authenticates it (an unknown key: 401).
	status, body := f.call(t, http.MethodPut, "/v1/firewall/policy", "CdncaKey not-a-real-key", `{"rules":[]}`, map[string]string{"Idempotency-Key": "k"})
	if status == http.StatusPreconditionRequired || status == http.StatusAccepted {
		t.Fatalf("api key = %d %v", status, body)
	}
	var stored int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM approval_requests`).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("stored requests = %d err=%v", stored, err)
	}
}

// 遗留 5：executing 超过 10 分钟的单子由恢复器标记为 unknown（系统审计），不重放；原进程迟到的
// Finish 仍以真实结果覆盖 unknown。
func TestApprovalCenterRecoveryMarksStaleExecutingUnknown(t *testing.T) {
	f := newApprovalCenterFixture(t)
	f.enable(t, approvalcenter.RuleFirewallPolicy)
	stale, fresh := f.submitFirewall(t, f.requester), f.submitFirewall(t, f.requester)
	decidedAt := map[string]time.Time{stale["id"].(string): f.clock.Add(-approvalcenter.StaleExecuting),
		fresh["id"].(string): f.clock.Add(-approvalcenter.StaleExecuting + time.Second)}
	for id, at := range decidedAt {
		// The state a crash mid-replay leaves behind.
		if _, err := f.pool.Exec(t.Context(), `UPDATE approval_requests SET state='executing',decided_by_user_id=$2,
			decided_at=$3,step_up='none' WHERE id=$1`, id, f.apprID, at); err != nil {
			t.Fatal(err)
		}
	}
	store := approvalcenter.NewStore(f.pool, nil, func() time.Time { return *f.clock })
	if marked, err := store.MarkStaleExecuting(t.Context()); err != nil || marked != 1 {
		t.Fatalf("marked = %d err=%v", marked, err)
	}
	if marked, err := store.MarkStaleExecuting(t.Context()); err != nil || marked != 0 {
		t.Fatalf("second pass marked = %d err=%v", marked, err)
	}
	states := map[string]string{}
	rows, err := f.pool.Query(t.Context(), `SELECT id::text,state FROM approval_requests`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, state string
		if err := rows.Scan(&id, &state); err != nil {
			t.Fatal(err)
		}
		states[id] = state
	}
	rows.Close()
	if states[stale["id"].(string)] != approvalcenter.StateUnknown || states[fresh["id"].(string)] != approvalcenter.StateExecuting {
		t.Fatalf("states = %v", states)
	}
	var actorKind, result string
	if err := f.pool.QueryRow(t.Context(), `SELECT actor_kind,result FROM audit_events
		WHERE action='approval_center.request.outcome_unknown' AND resource_id=$1`, stale["id"]).Scan(&actorKind, &result); err != nil ||
		actorKind != "system" || result != "failure" {
		t.Fatalf("unknown audit kind=%q result=%q err=%v", actorKind, result, err)
	}
	status, body := f.call(t, http.MethodGet, "/v1/admin/approval-requests?state=unknown&limit=10", "Bearer "+f.approver, "", nil)
	if items, _ := body["items"].([]any); status != http.StatusOK || len(items) != 1 {
		t.Fatalf("list unknown = %d %v", status, body)
	}
	id := uuid.MustParse(stale["id"].(string))
	done, err := store.Finish(t.Context(), approvalcenter.Session{UserID: f.apprID, ScopeID: f.platformScope}, id,
		[]approvalcenter.StepResult{{Status: http.StatusOK}}, "late-finish")
	if err != nil || done.State != approvalcenter.StateExecuted {
		t.Fatalf("late finish = %v err=%v", done.State, err)
	}
}
