//go:build integration

package rbacmanagerhttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type integrationFixture struct {
	pool           *pgxpool.Pool
	verifier       transactionStepUpVerifier
	handler        *Handler
	service        *Service
	tenantAID      uuid.UUID
	tenantAScope   uuid.UUID
	tenantAActor   AuthenticatedSession
	tenantASubject uuid.UUID
	tenantARole    uuid.UUID
	tenantBID      uuid.UUID
	tenantBScope   uuid.UUID
	tenantBActor   AuthenticatedSession
	tenantBSubject uuid.UUID
}

type transactionStepUpVerifier struct{}

type capturingStepUpConsumer struct {
	mu       sync.Mutex
	actors   []mfa.Actor
	requests []mfa.ConsumeStepUpRequest
}

type integrationMFACipher struct{}

var integrationMFACipherPrefix = []byte("rbac-mfa-test-v1:")

func (integrationMFACipher) Encrypt(plaintext []byte) (string, []byte, error) {
	ciphertext := append([]byte(nil), integrationMFACipherPrefix...)
	ciphertext = append(ciphertext, plaintext...)
	return "rbac-mfa-test-key", ciphertext, nil
}

func (integrationMFACipher) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	if keyID != "rbac-mfa-test-key" || !bytes.HasPrefix(ciphertext, integrationMFACipherPrefix) {
		return nil, errors.New("test MFA ciphertext rejected")
	}
	return append([]byte(nil), ciphertext[len(integrationMFACipherPrefix):]...), nil
}

func (consumer *capturingStepUpConsumer) ConsumeStepUpTxWithScopes(
	ctx context.Context,
	tx pgx.Tx,
	actor mfa.Actor,
	scopes []uuid.UUID,
	request mfa.ConsumeStepUpRequest,
) (mfa.Evidence, error) {
	if tx == nil {
		return mfa.Evidence{}, errors.New("transaction is required")
	}
	if err := iamstage2b.AssertAuthorityMutation(ctx, tx, iamstage2b.OperationMFAConsumeStepUp, scopes); err != nil {
		return mfa.Evidence{}, err
	}
	consumer.mu.Lock()
	consumer.actors = append(consumer.actors, actor)
	request.ResourceBindingDigest = append([]byte(nil), request.ResourceBindingDigest...)
	consumer.requests = append(consumer.requests, request)
	consumer.mu.Unlock()
	return mfa.Evidence{ProofID: uuid.New(), ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID,
		SessionID: actor.SessionID, TenantID: request.TenantID, Method: "totp",
		Audience: request.Audience, Action: request.Action, VerifiedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(time.Minute), UseOrdinal: 1,
		ResourceBindingDigest: append([]byte(nil), request.ResourceBindingDigest...)}, nil
}

func (transactionStepUpVerifier) VerifyAndConsume(
	ctx context.Context,
	tx pgx.Tx,
	proof rbacmanager.StepUpProof,
	check rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	var proofID, actorUserID, actorScopeID, sessionID, tenantID uuid.UUID
	var audience, action, requestID, method string
	var permissions []string
	var verifiedAt time.Time
	var consumed bool
	err := tx.QueryRow(ctx, `SELECT proof_id,actor_user_id,actor_scope_id,session_id,tenant_id,
		audience,action,request_id,permissions,method,verified_at,consumed
		FROM custom_rbac_http_test_proofs WHERE token=$1 FOR UPDATE`, proof.Token).
		Scan(&proofID, &actorUserID, &actorScopeID, &sessionID, &tenantID,
			&audience, &action, &requestID, &permissions, &method, &verifiedAt, &consumed)
	if err != nil || consumed || actorUserID != check.Actor.UserID || actorScopeID != check.Actor.ScopeID ||
		sessionID != check.Actor.SessionID || tenantID != check.TenantID || audience != check.Audience ||
		action != check.Action || requestID != check.RequestID || check.RoleID == uuid.Nil ||
		check.TraceID == "" || len(check.MutationDigest) != sha256.Size ||
		!validStepUpAction(check) || !slices.Equal(permissions, check.Permissions) {
		return rbacmanager.StepUpEvidence{}, errors.New("test proof binding or replay rejected")
	}
	command, err := tx.Exec(ctx, `UPDATE custom_rbac_http_test_proofs SET consumed=true,
		bound_role_id=$2,bound_subject_user_id=$3,bound_trace_id=$4
		WHERE token=$1 AND consumed=false`, proof.Token, check.RoleID, check.SubjectUserID, check.TraceID)
	if err != nil || command.RowsAffected() != 1 {
		return rbacmanager.StepUpEvidence{}, errors.New("test proof consumption lost compare-and-swap")
	}
	return rbacmanager.StepUpEvidence{ProofID: proofID, Method: method, VerifiedAt: verifiedAt}, nil
}

type failingAuditor struct{}

func (failingAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("injected HTTP audit failure")
}

func TestPG17MigrationChainAndEmpty042RoundTrip(t *testing.T) {
	// The whole chain through the real migrator (085 on reads the migrator's
	// ledger columns; the hand-made version ledger below only serves the
	// pre-085 round trips).
	pool := databasetest.FreshSchemaPool(t, "custom_rbac_http_head", nil, func(ctx context.Context, pool *pgxpool.Pool) error {
		return database.Migrate(ctx, pool, "up")
	})
	head := migrationHead(t)
	if head < 65 {
		t.Fatalf("migration head=%d, want at least 65", head)
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != head {
		t.Fatalf("migration ledger count=%d head=%d", count, head)
	}

	roundTrip := isolatedHTTPPool(t)
	migrateHTTPTo(t, roundTrip, 42)
	applyHTTPMigration(t, roundTrip, "042_custom_rbac.down.sql", 42, false)
	assertHTTPTable(t, roundTrip, "custom_roles", false)
	applyHTTPMigration(t, roundTrip, "042_custom_rbac.up.sql", 42, true)
	assertHTTPTable(t, roundTrip, "custom_roles", true)

	watermarkRoundTrip := isolatedHTTPPool(t)
	migrateHTTPTo(t, watermarkRoundTrip, 65)
	applyHTTPMigration(t, watermarkRoundTrip, "065_custom_rbac_state_watermark.down.sql", 65, false)
	assertHTTPTable(t, watermarkRoundTrip, "custom_rbac_state_watermark", false)
	applyHTTPMigration(t, watermarkRoundTrip, "065_custom_rbac_state_watermark.up.sql", 65, true)
	assertHTTPTable(t, watermarkRoundTrip, "custom_rbac_state_watermark", true)

	legacy042 := isolatedHTTPPool(t)
	migrateHTTPTo(t, legacy042, 64)
	if _, err := legacy042.Exec(t.Context(), `ALTER TABLE mfa_step_up_uses
		DROP COLUMN resource_binding_sha256`); err != nil {
		t.Fatal(err)
	}
	applyHTTPMigration(t, legacy042, "065_custom_rbac_state_watermark.up.sql", 65, true)
	var bindingColumn bool
	if err := legacy042.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='mfa_step_up_uses' AND
		      column_name='resource_binding_sha256')`).Scan(&bindingColumn); err != nil {
		t.Fatal(err)
	}
	if !bindingColumn {
		t.Fatal("migration 065 did not restore legacy 042 MFA resource binding column")
	}
}

func TestPG17CustomRBACWatermarkFollowsCommitOrderAndRollback(t *testing.T) {
	pool := isolatedHTTPPool(t)
	migrateHTTPTo(t, pool, 65)

	firstTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var firstVersion int64
	if err := firstTx.QueryRow(t.Context(), `SELECT allocate_custom_rbac_state_version()`).
		Scan(&firstVersion); err != nil {
		_ = firstTx.Rollback(t.Context())
		t.Fatal(err)
	}

	type allocationResult struct {
		version int64
		err     error
	}
	started := make(chan struct{})
	secondResult := make(chan allocationResult, 1)
	allocationContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		secondTx, err := pool.Begin(allocationContext)
		if err != nil {
			secondResult <- allocationResult{err: err}
			return
		}
		defer func() { _ = secondTx.Rollback(context.Background()) }()
		close(started)
		var version int64
		err = secondTx.QueryRow(allocationContext, `SELECT allocate_custom_rbac_state_version()`).
			Scan(&version)
		if err == nil {
			err = secondTx.Commit(allocationContext)
		}
		secondResult <- allocationResult{version: version, err: err}
	}()
	<-started
	select {
	case result := <-secondResult:
		_ = firstTx.Rollback(t.Context())
		t.Fatalf("second watermark allocation did not wait for first transaction: %+v", result)
	case <-time.After(100 * time.Millisecond):
	}
	if err := firstTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-secondResult:
		if result.err != nil || result.version != firstVersion+1 {
			t.Fatalf("second watermark allocation = %+v, first=%d", result, firstVersion)
		}
	case <-allocationContext.Done():
		t.Fatalf("second watermark allocation remained blocked: %v", allocationContext.Err())
	}

	rolledBackTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var rolledBackVersion int64
	if err := rolledBackTx.QueryRow(t.Context(), `SELECT allocate_custom_rbac_state_version()`).
		Scan(&rolledBackVersion); err != nil {
		_ = rolledBackTx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := rolledBackTx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	committedTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var committedVersion int64
	if err := committedTx.QueryRow(t.Context(), `SELECT allocate_custom_rbac_state_version()`).
		Scan(&committedVersion); err != nil {
		_ = committedTx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := committedTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if committedVersion != rolledBackVersion {
		t.Fatalf("rollback consumed watermark version: rolled back=%d committed=%d",
			rolledBackVersion, committedVersion)
	}
}

func TestPG17FactBearing042And065DownFailClosed(t *testing.T) {
	for _, target := range []int{42, 65} {
		t.Run(strconv.Itoa(target), func(t *testing.T) {
			// The facts come from today's rbacmanager, which needs the release
			// head (069's IAM lock protocol among others), and the migrator
			// cannot roll that head back to 042/065 (268's one-way gate). The
			// fact guard is the first statement of each down script, so run
			// the script itself at the head: it must refuse.
			pool := databasetest.MigratedPool(t, nil)
			fixture := seedHTTPIdentityFixture(t, pool)
			core, err := rbacmanager.NewService(pool, transactionStepUpVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			role, err := core.CreateRole(t.Context(), sessionActor(fixture.tenantAActor),
				rbacmanager.CreateRoleRequest{Name: "rollback-guard", Permissions: []string{"sites.read"},
					Mutation: rbacmanager.MutationContext{IdempotencyKey: "rollback-guard",
						RequestID: "rollback-guard-request", TraceID: strings.Repeat("d", 32)}})
			if err != nil {
				t.Fatal(err)
			}
			before := captureRBACRollbackFacts(t, pool, fixture.tenantARole, role.ID)
			name := fmt.Sprintf("%03d_custom_rbac", target)
			if target == 65 {
				name = "065_custom_rbac_state_watermark"
			}
			err = runHTTPMigration(t.Context(), pool, name+".down.sql", target, false)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("business facts prevent migration %03d rollback", target)) {
				t.Fatalf("migration %d fact-bearing down error=%v", target, err)
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
				t.Fatalf("migration %d fact-bearing down SQLSTATE=%v error=%v", target, pgErr, err)
			}
			after := captureRBACRollbackFacts(t, pool, fixture.tenantARole, role.ID)
			if before != after {
				t.Fatalf("migration %d changed facts after rejected down: before=%+v after=%+v", target, before, after)
			}
			assertHTTPMigrationApplied(t, pool, target, true)
			assertHTTPTable(t, pool, "custom_roles", true)
			if target == 65 {
				assertHTTPTable(t, pool, "custom_rbac_state_watermark", true)
			}
		})
	}
}

func TestHTTPRBACBoundariesLiveRevocationAndGrantWorkflow(t *testing.T) {
	fixture := newIntegrationFixture(t)

	response := fixture.get("tenant-a", "/v1/custom-rbac/permissions")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"name":"identity.roles.manage"`) ||
		!strings.Contains(response.Body.String(), `"step_up_required":true`) {
		t.Fatalf("permission catalog status=%d body=%s", response.Code, response.Body.String())
	}

	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles",
		`{"name":"platform-escalation","permissions":["platform.admin"]}`, "not-delegable", "not-delegable-request", "", "")
	assertAPIError(t, response, http.StatusUnprocessableEntity, "custom_rbac_permission_not_delegable")
	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles",
		`{"name":"actor-escalation","permissions":["dns.manage"]}`, "permission-escalation", "permission-escalation-request", "", "")
	assertAPIError(t, response, http.StatusForbidden, "custom_rbac_permission_escalation")

	response = fixture.command("tenant-a", http.MethodPost,
		"/v1/custom-rbac/roles/"+fixture.tenantARole.String()+"/rename",
		`{"name":"cannot-rename-owner"}`, "system-role", "system-role-request", `"1"`, "")
	assertAPIError(t, response, http.StatusConflict, "custom_rbac_system_role_immutable")

	lifecycle := fixture.createRole(t, "tenant-a", "lifecycle-reader", []string{"sites.read"}, "lifecycle-create")
	response = fixture.command("tenant-a", http.MethodPost,
		"/v1/custom-rbac/roles/"+lifecycle.ID.String()+"/rename",
		`{"name":"lifecycle-manager"}`, "lifecycle-rename", "lifecycle-rename-request", `"1"`, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"current_revision":2`) ||
		!strings.Contains(response.Body.String(), `"name":"lifecycle-manager"`) {
		t.Fatalf("rename status=%d body=%s", response.Code, response.Body.String())
	}
	response = fixture.command("tenant-a", http.MethodPost,
		"/v1/custom-rbac/roles/"+lifecycle.ID.String()+"/publish",
		`{"permissions":["sites.manage"]}`, "lifecycle-publish", "lifecycle-publish-request", `"2"`, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"current_revision":3`) ||
		!strings.Contains(response.Body.String(), `"permissions":["sites.manage"]`) {
		t.Fatalf("publish status=%d body=%s", response.Code, response.Body.String())
	}
	response = fixture.get("tenant-a", "/v1/custom-rbac/roles/"+lifecycle.ID.String())
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"current_revision":3`) {
		t.Fatalf("detail status=%d body=%s", response.Code, response.Body.String())
	}
	response = fixture.command("tenant-a", http.MethodPost,
		"/v1/custom-rbac/roles/"+lifecycle.ID.String()+"/deactivate", "",
		"lifecycle-deactivate", "lifecycle-deactivate-request", `"3"`, "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"deactivated_at"`) {
		t.Fatalf("deactivate status=%d body=%s", response.Code, response.Body.String())
	}
	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/grants",
		fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, lifecycle.ID, fixture.tenantASubject),
		"assign-inactive", "assign-inactive-request", `"3"`, "")
	assertAPIError(t, response, http.StatusConflict, "custom_rbac_role_inactive")

	roleA := fixture.createRole(t, "tenant-a", "site-manager", []string{"sites.manage"}, "create-a")
	roleB := fixture.createRole(t, "tenant-b", "other-reader", []string{"sites.read"}, "create-b")
	response = fixture.get("tenant-a", "/v1/custom-rbac/roles/"+roleB.ID.String())
	assertAPIError(t, response, http.StatusNotFound, "custom_rbac_not_found")

	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/grants",
		fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, roleA.ID, fixture.tenantAActor.UserID),
		"assign-self", "assign-self-request", `"1"`, "")
	assertAPIError(t, response, http.StatusForbidden, "custom_rbac_self_assignment_denied")
	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/grants",
		fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, roleA.ID, fixture.tenantBSubject),
		"assign-cross", "assign-cross-request", `"1"`, "")
	assertAPIError(t, response, http.StatusNotFound, "custom_rbac_not_found")

	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/grants",
		fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, roleA.ID, fixture.tenantASubject),
		"assign-subject", "assign-subject-request", `"1"`, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("assign status=%d body=%s", response.Code, response.Body.String())
	}
	var grantEnvelope dataEnvelope[GrantView]
	decodeResponse(t, response, &grantEnvelope)
	assertEffectivePermission(t, fixture.pool, fixture.tenantAScope, fixture.tenantASubject, "sites.manage", true)

	response = fixture.command("tenant-a", http.MethodPost,
		"/v1/custom-rbac/grants/"+grantEnvelope.Data.ID.String()+"/revoke", "",
		"revoke-subject", "revoke-subject-request", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", response.Code, response.Body.String())
	}
	assertEffectivePermission(t, fixture.pool, fixture.tenantAScope, fixture.tenantASubject, "sites.manage", false)
	response = fixture.get("tenant-a", "/v1/custom-rbac/grants?state=revoked")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), grantEnvelope.Data.ID.String()) {
		t.Fatalf("revoked grants status=%d body=%s", response.Code, response.Body.String())
	}

	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.tenantAScope,
		fixture.tenantAActor.UserID, fixture.tenantARole); err != nil {
		t.Fatal(err)
	}
	response = fixture.get("tenant-a", "/v1/custom-rbac/roles")
	assertAPIError(t, response, http.StatusForbidden, "custom_rbac_permission_denied")
}

func TestHTTPCommittedPrincipalRevocationWinsAuthorizationRaces(t *testing.T) {
	fixture := newIntegrationFixture(t)
	role := fixture.createRole(t, "tenant-a", "principal-race-role", []string{"sites.read"}, "principal-race-role")
	revokeSubject := fixture.seedSubject(t, "principal-race-revoke")
	response := fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/grants",
		fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, role.ID, revokeSubject),
		"principal-race-grant", "principal-race-grant-request", `"1"`, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("seed race grant status=%d body=%s", response.Code, response.Body.String())
	}
	var seededGrant dataEnvelope[GrantView]
	decodeResponse(t, response, &seededGrant)

	fixture.assertRevocationWins(t,
		`UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP,revocation_reason='race test'
		 WHERE id=$1`, []any{fixture.tenantAActor.SessionID},
		func() *httptest.ResponseRecorder {
			return fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles",
				`{"name":"session-race","permissions":["sites.read"]}`,
				"session-race", "session-race-request", "", "")
		}, http.StatusForbidden, "custom_rbac_permission_denied")
	fixture.replaceActorSession(t)

	fixture.assertRevocationWins(t,
		`UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`,
		[]any{fixture.tenantAScope, fixture.tenantAActor.UserID},
		func() *httptest.ResponseRecorder {
			return fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles",
				`{"name":"membership-race","permissions":["sites.read"]}`,
				"membership-race", "membership-race-request", "", "")
		}, http.StatusForbidden, "custom_rbac_permission_denied")
	fixture.exec(t, `UPDATE memberships SET status='active' WHERE scope_id=$1 AND user_id=$2`,
		fixture.tenantAScope, fixture.tenantAActor.UserID)

	assignSubject := fixture.seedSubject(t, "principal-race-assign")
	fixture.assertRevocationWins(t,
		`UPDATE users SET status='disabled',revision=revision+1 WHERE id=$1`,
		[]any{fixture.tenantAActor.UserID},
		func() *httptest.ResponseRecorder {
			return fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/grants",
				fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, role.ID, assignSubject),
				"actor-user-race", "actor-user-race-request", `"1"`, "")
		}, http.StatusForbidden, "custom_rbac_permission_denied")
	fixture.exec(t, `UPDATE users SET status='active',revision=revision+1 WHERE id=$1`, fixture.tenantAActor.UserID)

	fixture.assertRevocationWins(t,
		`UPDATE tenants SET status='suspended' WHERE id=$1`, []any{fixture.tenantAID},
		func() *httptest.ResponseRecorder {
			return fixture.command("tenant-a", http.MethodPost,
				"/v1/custom-rbac/grants/"+seededGrant.Data.ID.String()+"/revoke", "",
				"tenant-race", "tenant-race-request", "", "")
		}, http.StatusForbidden, "custom_rbac_permission_denied")
	fixture.exec(t, `UPDATE tenants SET status='active' WHERE id=$1`, fixture.tenantAID)

	for index, mutation := range []struct {
		statement string
		args      []any
		restore   string
	}{
		{`UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, nil,
			`UPDATE memberships SET status='active' WHERE scope_id=$1 AND user_id=$2`},
		{`UPDATE users SET status='disabled',revision=revision+1 WHERE id=$1`, nil,
			`UPDATE users SET status='active',revision=revision+1 WHERE id=$1`},
	} {
		subject := fixture.seedSubject(t, fmt.Sprintf("subject-race-%d", index))
		mutation.args = []any{subject}
		if index == 0 {
			mutation.args = []any{fixture.tenantAScope, subject}
		}
		fixture.assertRevocationWins(t, mutation.statement, mutation.args,
			func() *httptest.ResponseRecorder {
				return fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/grants",
					fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, role.ID, subject),
					fmt.Sprintf("subject-race-%d", index), fmt.Sprintf("subject-race-request-%d", index), `"1"`, "")
			}, http.StatusNotFound, "custom_rbac_not_found")
		fixture.exec(t, mutation.restore, mutation.args...)
	}
}

func TestHTTPCriticalStepUpBindingReplayIdempotencyAndAuditRollback(t *testing.T) {
	fixture := newIntegrationFixture(t)
	body := `{"name":"user-manager","permissions":["identity.users.manage"]}`
	response := fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles", body,
		"missing-proof", "missing-proof-request", "", "")
	assertAPIError(t, response, http.StatusPreconditionRequired, "custom_rbac_step_up_required")

	wrongToken := strings.Repeat("B", 43)
	fixture.seedProof(t, wrongToken, fixture.tenantAActor, fixture.tenantAID,
		"identity.custom_role.publish", "wrong-binding-request", []string{"identity.users.manage"})
	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles", body,
		"wrong-binding", "wrong-binding-request", "", wrongToken)
	assertAPIError(t, response, http.StatusPreconditionRequired, "custom_rbac_step_up_required")
	fixture.assertProofUsed(t, wrongToken, false)

	rollbackToken := strings.Repeat("C", 43)
	fixture.seedProof(t, rollbackToken, fixture.tenantAActor, fixture.tenantAID,
		"identity.custom_role.create", "audit-rollback-request", []string{"identity.users.manage"})
	failingCore, err := rbacmanager.NewServiceWithDependencies(fixture.pool, failingAuditor{}, fixture.verifier, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	failingService, err := newService(failingCore, newPostgresReadStore(fixture.pool),
		ServiceConfig{CursorKey: bytes.Repeat([]byte{8}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	failingHandler := fixture.handlerForService(t, failingService)
	request := integrationCommand(http.MethodPost, "/v1/custom-rbac/roles", body,
		"audit-rollback", "audit-rollback-request", "", rollbackToken)
	request.Header.Set("Authorization", "tenant-a")
	response = perform(failingHandler, request)
	assertAPIError(t, response, http.StatusServiceUnavailable, "custom_rbac_store_unavailable")
	fixture.assertProofUsed(t, rollbackToken, false)
	assertCountByName(t, fixture.pool, "user-manager", 0)

	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles", body,
		"audit-rollback", "audit-rollback-request", "", rollbackToken)
	if response.Code != http.StatusCreated {
		t.Fatalf("post-rollback retry status=%d body=%s", response.Code, response.Body.String())
	}
	var criticalRole dataEnvelope[RoleView]
	decodeResponse(t, response, &criticalRole)
	fixture.assertProofUsed(t, rollbackToken, true)
	fixture.assertProofBinding(t, rollbackToken, criticalRole.Data.ID, uuid.Nil, strings.Repeat("a", 32))
	assertCountByName(t, fixture.pool, "user-manager", 1)
	if strings.Contains(response.Body.String(), rollbackToken) ||
		strings.Contains(response.Body.String(), "step_up_proof_id") ||
		strings.Contains(response.Body.String(), "permissions_digest") {
		t.Fatalf("critical response leaked proof material: %s", response.Body.String())
	}

	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles", body,
		"audit-rollback", "audit-rollback-request", "", rollbackToken)
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"replayed":true`) {
		t.Fatalf("idempotent replay status=%d body=%s", response.Code, response.Body.String())
	}
	fixture.assertProofUsed(t, rollbackToken, true)

	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles",
		`{"name":"different-name","permissions":["identity.users.manage"]}`,
		"audit-rollback", "different-payload-request", "", rollbackToken)
	assertAPIError(t, response, http.StatusConflict, "custom_rbac_idempotency_conflict")
	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles",
		`{"name":"proof-reuse","permissions":["identity.users.manage"]}`,
		"proof-reuse", "proof-reuse-request", "", rollbackToken)
	assertAPIError(t, response, http.StatusPreconditionRequired, "custom_rbac_step_up_required")
}

func TestHTTPMFAStepUpAdapterBindsRoleSubjectAndTraceInRBACTransaction(t *testing.T) {
	fixture := newIntegrationFixture(t)
	consumer := &capturingStepUpConsumer{}
	adapter, err := newMFAStepUpVerifier(consumer)
	if err != nil {
		t.Fatal(err)
	}
	core, err := rbacmanager.NewService(fixture.pool, adapter)
	if err != nil {
		t.Fatal(err)
	}
	service, err := newService(core, newPostgresReadStore(fixture.pool),
		ServiceConfig{CursorKey: bytes.Repeat([]byte{8}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	handler := fixture.handlerForService(t, service)
	createRequestID := "adapter-create-request"
	request := integrationCommand(http.MethodPost, "/v1/custom-rbac/roles",
		`{"name":"adapter-critical","permissions":["identity.users.manage"]}`,
		"adapter-create", createRequestID, "", strings.Repeat("D", 43))
	request.Header.Set("Authorization", "tenant-a")
	response := perform(handler, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("adapter create status=%d body=%s", response.Code, response.Body.String())
	}
	var role dataEnvelope[RoleView]
	decodeResponse(t, response, &role)

	assignRequestID := "adapter-assign-request"
	request = integrationCommand(http.MethodPost, "/v1/custom-rbac/grants",
		fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, role.Data.ID, fixture.tenantASubject),
		"adapter-assign", assignRequestID, `"1"`, strings.Repeat("E", 43))
	request.Header.Set("Authorization", "tenant-a")
	response = perform(handler, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("adapter assign status=%d body=%s", response.Code, response.Body.String())
	}

	consumer.mu.Lock()
	actors := append([]mfa.Actor(nil), consumer.actors...)
	requests := append([]mfa.ConsumeStepUpRequest(nil), consumer.requests...)
	consumer.mu.Unlock()
	if len(requests) != 2 || len(actors) != 2 {
		t.Fatalf("adapter calls=%d actors=%d", len(requests), len(actors))
	}
	traceID := strings.Repeat("a", 32)
	checks := []rbacmanager.StepUpCheck{
		{Actor: sessionActor(fixture.tenantAActor), TenantID: fixture.tenantAID,
			Audience: "custom-rbac", Action: "identity.custom_role.create", RoleID: role.Data.ID,
			Permissions: []string{"identity.users.manage"},
			MutationDigest: expectedRBACMutationDigest("identity.custom_role.create", "adapter-create", struct {
				Name        string   `json:"name"`
				Permissions []string `json:"permissions"`
			}{"adapter-critical", []string{"identity.users.manage"}}),
			RequestID: createRequestID, TraceID: traceID},
		{Actor: sessionActor(fixture.tenantAActor), TenantID: fixture.tenantAID,
			Audience: "custom-rbac", Action: "identity.custom_role.assign", RoleID: role.Data.ID,
			SubjectUserID: fixture.tenantASubject, ExpectedRevision: 1,
			Permissions: []string{"identity.users.manage"},
			MutationDigest: expectedRBACMutationDigest("identity.custom_role.assign", "adapter-assign", struct {
				RoleID    uuid.UUID `json:"role_id"`
				Revision  int64     `json:"role_revision"`
				SubjectID uuid.UUID `json:"subject_user_id"`
			}{role.Data.ID, 1, fixture.tenantASubject}),
			RequestID: assignRequestID, TraceID: traceID},
	}
	for index, check := range checks {
		want, err := stepUpBindingDigest(check)
		if err != nil {
			t.Fatal(err)
		}
		if actors[index].UserID != check.Actor.UserID || actors[index].ScopeID != check.Actor.ScopeID ||
			actors[index].SessionID != check.Actor.SessionID || requests[index].TenantID != check.TenantID ||
			requests[index].Action != check.Action || requests[index].Context.RequestID != check.RequestID ||
			requests[index].Context.TraceID != check.TraceID ||
			!bytes.Equal(requests[index].ResourceBindingDigest, want[:]) {
			t.Fatalf("adapter call %d lost binding: actor=%+v request=%+v", index, actors[index], requests[index])
		}
	}
}

func TestHTTPRealMFAAdapterRejectsLogicalMutationProofReuse(t *testing.T) {
	fixture := newIntegrationFixture(t)
	seedCriticalRole := func(name, key, requestID, token string) RoleView {
		fixture.seedProof(t, token, fixture.tenantAActor, fixture.tenantAID,
			"identity.custom_role.create", requestID, []string{"identity.users.manage"})
		response := fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/roles",
			fmt.Sprintf(`{"name":%q,"permissions":["identity.users.manage"]}`, name),
			key, requestID, "", token)
		if response.Code != http.StatusCreated {
			t.Fatalf("seed critical role status=%d body=%s", response.Code, response.Body.String())
		}
		var envelope dataEnvelope[RoleView]
		decodeResponse(t, response, &envelope)
		return envelope.Data
	}
	role := seedCriticalRole("real-mfa-critical", "real-mfa-seed", "real-mfa-seed-request", strings.Repeat("G", 43))
	deactivateTarget := seedCriticalRole("real-mfa-deactivate-target", "real-mfa-seed-two",
		"real-mfa-seed-two-request", strings.Repeat("H", 43))

	mfaService, recoveryCodes := activateHTTPRealMFA(t, fixture)
	adapter, err := NewMFAStepUpVerifier(mfaService)
	if err != nil {
		t.Fatal(err)
	}
	core, err := rbacmanager.NewService(fixture.pool, adapter)
	if err != nil {
		t.Fatal(err)
	}
	service, err := newService(core, newPostgresReadStore(fixture.pool),
		ServiceConfig{CursorKey: bytes.Repeat([]byte{8}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	handler := fixture.handlerForService(t, service)
	command := func(target, body, key, requestID, ifMatch, proof string) *httptest.ResponseRecorder {
		request := integrationCommand(http.MethodPost, target, body, key, requestID, ifMatch, proof)
		request.Header.Set("Authorization", "tenant-a")
		return perform(handler, request)
	}
	issue := func(index int, action, key string) mfa.StepUpResult {
		return issueHTTPRealMFAProof(t, mfaService, fixture, recoveryCodes[index], action, key)
	}

	publishProof := issue(0, "identity.custom_role.publish", "real-publish-proof")
	publishPath := "/v1/custom-rbac/roles/" + role.ID.String() + "/publish"
	publishBody := `{"permissions":["identity.users.manage"]}`
	response := command(publishPath, publishBody, "real-publish-a", "real-publish-shared-request", `"1"`, publishProof.Token)
	if response.Code != http.StatusOK {
		t.Fatalf("first publish status=%d body=%s", response.Code, response.Body.String())
	}
	var published dataEnvelope[RoleView]
	decodeResponse(t, response, &published)
	if published.Data.CurrentRevision != 2 {
		t.Fatalf("first publish revision=%d", published.Data.CurrentRevision)
	}
	response = command(publishPath, publishBody, "real-publish-a", "real-publish-shared-request", `"1"`, publishProof.Token)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"replayed":true`) {
		t.Fatalf("exact publish replay status=%d body=%s", response.Code, response.Body.String())
	}
	response = command(publishPath, publishBody, "real-publish-b", "real-publish-shared-request", `"2"`, publishProof.Token)
	assertAPIError(t, response, http.StatusPreconditionRequired, "custom_rbac_step_up_required")
	assertHTTPRealMFAUses(t, fixture.pool, publishProof.ProofID, 1)

	concurrentProof := issue(1, "identity.custom_role.publish", "real-concurrent-proof")
	responses := make(chan *httptest.ResponseRecorder, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- command(publishPath, publishBody, "real-concurrent-publish",
				"real-concurrent-publish-request", `"2"`, concurrentProof.Token)
		}()
	}
	wait.Wait()
	close(responses)
	replays := 0
	for response := range responses {
		if response.Code != http.StatusOK {
			t.Fatalf("concurrent exact publish status=%d body=%s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), `"replayed":true`) {
			replays++
		}
	}
	if replays != 1 {
		t.Fatalf("concurrent exact publish replays=%d, want 1", replays)
	}
	assertHTTPRealMFAUses(t, fixture.pool, concurrentProof.ProofID, 1)

	auditProof := issue(2, "identity.custom_role.publish", "real-audit-proof")
	failingCore, err := rbacmanager.NewServiceWithDependencies(fixture.pool, failingAuditor{}, adapter, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	failingService, err := newService(failingCore, newPostgresReadStore(fixture.pool),
		ServiceConfig{CursorKey: bytes.Repeat([]byte{8}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	failingHandler := fixture.handlerForService(t, failingService)
	failingRequest := integrationCommand(http.MethodPost, publishPath, publishBody,
		"real-audit-publish", "real-audit-publish-request", `"3"`, auditProof.Token)
	failingRequest.Header.Set("Authorization", "tenant-a")
	response = perform(failingHandler, failingRequest)
	assertAPIError(t, response, http.StatusServiceUnavailable, "custom_rbac_store_unavailable")
	assertHTTPRealMFAUses(t, fixture.pool, auditProof.ProofID, 0)
	assertHTTPWriteCount(t, fixture.pool, "real-audit-publish", 0)
	assertHTTPAuditCount(t, fixture.pool, "real-audit-publish-request", 0)
	response = command(publishPath, publishBody, "real-audit-publish", "real-audit-publish-request", `"3"`, auditProof.Token)
	if response.Code != http.StatusOK {
		t.Fatalf("publish after audit rollback status=%d body=%s", response.Code, response.Body.String())
	}
	assertHTTPRealMFAUses(t, fixture.pool, auditProof.ProofID, 1)
	assertHTTPWriteCount(t, fixture.pool, "real-audit-publish", 1)
	assertHTTPAuditCount(t, fixture.pool, "real-audit-publish-request", 2)

	assignProof := issue(3, "identity.custom_role.assign", "real-assign-proof")
	assignBody := fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, role.ID, fixture.tenantASubject)
	response = command("/v1/custom-rbac/grants", assignBody, "real-assign-a", "real-assign-shared-request", `"4"`, assignProof.Token)
	if response.Code != http.StatusCreated {
		t.Fatalf("first assign status=%d body=%s", response.Code, response.Body.String())
	}
	var firstGrant dataEnvelope[GrantView]
	decodeResponse(t, response, &firstGrant)
	response = command("/v1/custom-rbac/grants", assignBody, "real-assign-a", "real-assign-shared-request", `"4"`, assignProof.Token)
	if response.Code != http.StatusCreated {
		t.Fatalf("exact assign replay status=%d body=%s", response.Code, response.Body.String())
	}
	var replayedGrant dataEnvelope[GrantView]
	decodeResponse(t, response, &replayedGrant)
	if !replayedGrant.Data.Replayed || replayedGrant.Data.ID != firstGrant.Data.ID {
		t.Fatalf("exact assign replay changed grant: first=%+v replay=%+v", firstGrant.Data, replayedGrant.Data)
	}
	assertHTTPRealMFAUses(t, fixture.pool, assignProof.ProofID, 1)

	revokeProof := issue(4, "identity.custom_role.revoke", "real-revoke-proof")
	firstRevokePath := "/v1/custom-rbac/grants/" + firstGrant.Data.ID.String() + "/revoke"
	response = command(firstRevokePath, "", "real-revoke-a", "real-revoke-shared-request", "", revokeProof.Token)
	if response.Code != http.StatusOK {
		t.Fatalf("first revoke status=%d body=%s", response.Code, response.Body.String())
	}
	var firstRevocation dataEnvelope[RevocationView]
	decodeResponse(t, response, &firstRevocation)
	response = command(firstRevokePath, "", "real-revoke-a", "real-revoke-shared-request", "", revokeProof.Token)
	if response.Code != http.StatusOK {
		t.Fatalf("exact revoke replay status=%d body=%s", response.Code, response.Body.String())
	}
	var replayedRevocation dataEnvelope[RevocationView]
	decodeResponse(t, response, &replayedRevocation)
	if !replayedRevocation.Data.Replayed || replayedRevocation.Data.ID != firstRevocation.Data.ID {
		t.Fatalf("exact revoke replay changed result: first=%+v replay=%+v", firstRevocation.Data, replayedRevocation.Data)
	}
	response = command("/v1/custom-rbac/grants", assignBody, "real-assign-b", "real-assign-shared-request", `"4"`, assignProof.Token)
	assertAPIError(t, response, http.StatusPreconditionRequired, "custom_rbac_step_up_required")

	secondAssignProof := issue(5, "identity.custom_role.assign", "real-second-assign-proof")
	response = command("/v1/custom-rbac/grants", assignBody, "real-assign-c", "real-assign-c-request", `"4"`, secondAssignProof.Token)
	if response.Code != http.StatusCreated {
		t.Fatalf("second logical assign status=%d body=%s", response.Code, response.Body.String())
	}
	var secondGrant dataEnvelope[GrantView]
	decodeResponse(t, response, &secondGrant)
	if secondGrant.Data.ID == firstGrant.Data.ID {
		t.Fatal("second logical assign reused server-generated grant ID")
	}
	response = command("/v1/custom-rbac/grants/"+secondGrant.Data.ID.String()+"/revoke", "",
		"real-revoke-b", "real-revoke-shared-request", "", revokeProof.Token)
	assertAPIError(t, response, http.StatusPreconditionRequired, "custom_rbac_step_up_required")
	assertHTTPRealMFAUses(t, fixture.pool, revokeProof.ProofID, 1)

	deactivateProof := issue(6, "identity.custom_role.deactivate", "real-deactivate-proof")
	deactivatePath := "/v1/custom-rbac/roles/" + role.ID.String() + "/deactivate"
	response = command(deactivatePath, "", "real-deactivate-a", "real-deactivate-shared-request", `"4"`, deactivateProof.Token)
	if response.Code != http.StatusOK {
		t.Fatalf("first deactivate status=%d body=%s", response.Code, response.Body.String())
	}
	response = command(deactivatePath, "", "real-deactivate-a", "real-deactivate-shared-request", `"4"`, deactivateProof.Token)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"replayed":true`) {
		t.Fatalf("exact deactivate replay status=%d body=%s", response.Code, response.Body.String())
	}
	response = command("/v1/custom-rbac/roles/"+deactivateTarget.ID.String()+"/deactivate", "",
		"real-deactivate-b", "real-deactivate-shared-request", `"1"`, deactivateProof.Token)
	assertAPIError(t, response, http.StatusPreconditionRequired, "custom_rbac_step_up_required")
	assertHTTPRealMFAUses(t, fixture.pool, deactivateProof.ProofID, 1)
}

func realMFAHandler(t *testing.T, fixture *integrationFixture) (*Handler, *MFAStepUpVerifier, *mfa.Service, []string) {
	t.Helper()
	mfaService, recoveryCodes := activateHTTPRealMFA(t, fixture)
	adapter, err := NewMFAStepUpVerifier(mfaService)
	if err != nil {
		t.Fatal(err)
	}
	core, err := rbacmanager.NewService(fixture.pool, adapter)
	if err != nil {
		t.Fatal(err)
	}
	service, err := newService(core, newPostgresReadStore(fixture.pool),
		ServiceConfig{CursorKey: bytes.Repeat([]byte{8}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return fixture.handlerForService(t, service), adapter, mfaService, recoveryCodes
}

func realMFACommand(handler *Handler, target, body, key, requestID, ifMatch, proof string) *httptest.ResponseRecorder {
	request := integrationCommand(http.MethodPost, target, body, key, requestID, ifMatch, proof)
	request.Header.Set("Authorization", "tenant-a")
	return perform(handler, request)
}

func TestHTTPRealMFACriticalCreateRequiresStepUp(t *testing.T) {
	fixture := newIntegrationFixture(t)
	handler, _, mfaService, recoveryCodes := realMFAHandler(t, fixture)
	body := `{"name":"real-mfa-create","permissions":["identity.users.manage"]}`
	response := realMFACommand(handler, "/v1/custom-rbac/roles", body,
		"real-create-noproof", "real-create-noproof-request", "", "")
	assertAPIError(t, response, http.StatusPreconditionRequired, "custom_rbac_step_up_required")
	assertHTTPWriteCount(t, fixture.pool, "real-create-noproof", 0)

	proof := issueHTTPRealMFAProof(t, mfaService, fixture, recoveryCodes[0],
		"identity.custom_role.create", "real-create-proof")
	response = realMFACommand(handler, "/v1/custom-rbac/roles", body,
		"real-create", "real-create-request", "", proof.Token)
	if response.Code != http.StatusCreated {
		t.Fatalf("real MFA create status=%d body=%s", response.Code, response.Body.String())
	}
	assertHTTPRealMFAUses(t, fixture.pool, proof.ProofID, 1)
	assertHTTPWriteCount(t, fixture.pool, "real-create", 1)
}

func TestHTTPRealMFAAdapterRejectsCrossTenantAuthorityScope(t *testing.T) {
	fixture := newIntegrationFixture(t)
	_, adapter, mfaService, recoveryCodes := realMFAHandler(t, fixture)
	proof := issueHTTPRealMFAProof(t, mfaService, fixture, recoveryCodes[0],
		"identity.custom_role.publish", "cross-tenant-proof")
	check := rbacmanager.StepUpCheck{
		Actor: sessionActor(fixture.tenantAActor), Audience: "custom-rbac",
		Action: "identity.custom_role.publish", RoleID: uuid.New(), ExpectedRevision: 1,
		Permissions: []string{"identity.users.manage"}, MutationDigest: bytes.Repeat([]byte{7}, sha256.Size),
		RequestID: "cross-tenant-request", TraceID: "cross-tenant-trace",
	}
	consume := func(tenantID uuid.UUID) error {
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		// Same v1 entry lock as rbacmanager.runMutation.
		if _, err := protocol.BeginAuthorityMutation(t.Context(), tx,
			protocol.Operation(check.Action), []uuid.UUID{fixture.tenantAScope}); err != nil {
			t.Fatal(err)
		}
		next := check
		next.TenantID = tenantID
		_, err = adapter.VerifyAndConsume(t.Context(), tx, rbacmanager.StepUpProof{Token: proof.Token}, next)
		return err
	}
	if err := consume(fixture.tenantBID); !errors.Is(err, ErrStepUpUnavailable) {
		t.Fatalf("cross-tenant consume error=%v, want unavailable", err)
	}
	if err := consume(fixture.tenantAID); err != nil {
		t.Fatalf("same-tenant consume error=%v", err)
	}
	// Both transactions rolled back: the proof stays unused.
	assertHTTPRealMFAUses(t, fixture.pool, proof.ProofID, 0)
}

func TestHTTPRealMFAInterleavedStepUpTransactionsDoNotDeadlock(t *testing.T) {
	fixture := newIntegrationFixture(t)
	handler, _, mfaService, recoveryCodes := realMFAHandler(t, fixture)
	createProofs := make([]mfa.StepUpResult, 2)
	roles := make([]RoleView, 2)
	for index := range roles {
		key := fmt.Sprintf("interleave-create-%d", index)
		createProofs[index] = issueHTTPRealMFAProof(t, mfaService, fixture, recoveryCodes[index],
			"identity.custom_role.create", key+"-proof")
		response := realMFACommand(handler, "/v1/custom-rbac/roles",
			fmt.Sprintf(`{"name":"interleave-%d","permissions":["identity.users.manage"]}`, index),
			key, key+"-request", "", createProofs[index].Token)
		if response.Code != http.StatusCreated {
			t.Fatalf("seed role %d status=%d body=%s", index, response.Code, response.Body.String())
		}
		var envelope dataEnvelope[RoleView]
		decodeResponse(t, response, &envelope)
		roles[index] = envelope.Data
	}
	publishProofs := []mfa.StepUpResult{
		issueHTTPRealMFAProof(t, mfaService, fixture, recoveryCodes[2], "identity.custom_role.publish", "interleave-publish-proof"),
		issueHTTPRealMFAProof(t, mfaService, fixture, recoveryCodes[3], "identity.custom_role.deactivate", "interleave-deactivate-proof"),
	}
	directProof := issueHTTPRealMFAProof(t, mfaService, fixture, recoveryCodes[4],
		"identity.custom_role.publish", "interleave-direct-proof")

	// A Stage2B holder takes the tenant scope first; the RBAC (v1 then Stage2B)
	// and standalone MFA (Stage2B only) transactions queue behind it and then
	// interleave with each other.
	holder, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iamstage2b.BeginAuthorityMutation(t.Context(), holder, iamstage2b.OperationMFAConsumeStepUp,
		[]uuid.UUID{fixture.tenantAScope}); err != nil {
		_ = holder.Rollback(t.Context())
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 3)
	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		<-start
		response := realMFACommand(handler, "/v1/custom-rbac/roles/"+roles[0].ID.String()+"/publish",
			`{"permissions":["identity.users.manage"]}`, "interleave-publish", "interleave-publish-request",
			`"1"`, publishProofs[0].Token)
		if response.Code != http.StatusOK {
			errs <- fmt.Errorf("publish status=%d body=%s", response.Code, response.Body.String())
		}
	}()
	go func() {
		defer wait.Done()
		<-start
		response := realMFACommand(handler, "/v1/custom-rbac/roles/"+roles[1].ID.String()+"/deactivate",
			"", "interleave-deactivate", "interleave-deactivate-request", `"1"`, publishProofs[1].Token)
		if response.Code != http.StatusOK {
			errs <- fmt.Errorf("deactivate status=%d body=%s", response.Code, response.Body.String())
		}
	}()
	go func() {
		defer wait.Done()
		<-start
		if _, err := mfaService.ConsumeStepUp(t.Context(), mfa.Actor{UserID: fixture.tenantAActor.UserID,
			ScopeID: fixture.tenantAScope, SessionID: fixture.tenantAActor.SessionID}, mfa.ConsumeStepUpRequest{
			Token: directProof.Token, TenantID: fixture.tenantAID, Audience: "custom-rbac",
			Action: "identity.custom_role.publish",
			Context: mfa.RequestContext{RequestID: "interleave-direct", TraceID: "interleave-direct-trace"},
		}); err != nil {
			errs <- fmt.Errorf("direct consume: %w", err)
		}
	}()
	close(start)
	time.Sleep(150 * time.Millisecond)
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for _, proof := range append(publishProofs, directProof) {
		assertHTTPRealMFAUses(t, fixture.pool, proof.ProofID, 1)
	}
}

func TestHTTPConcurrentRevisionCASHasOneWinnerAndRoleCursorExcludesLaterInsert(t *testing.T) {
	fixture := newIntegrationFixture(t)
	role := fixture.createRole(t, "tenant-a", "cas-role", []string{"sites.read"}, "cas-create")

	responses := make(chan int, 2)
	var wait sync.WaitGroup
	for index, permission := range []string{"sites.read", "sites.manage"} {
		wait.Add(1)
		go func(index int, permission string) {
			defer wait.Done()
			response := fixture.command("tenant-a", http.MethodPost,
				"/v1/custom-rbac/roles/"+role.ID.String()+"/publish",
				fmt.Sprintf(`{"permissions":[%q]}`, permission),
				fmt.Sprintf("cas-publish-%d", index), fmt.Sprintf("cas-publish-request-%d", index), `"1"`, "")
			responses <- response.Code
		}(index, permission)
	}
	wait.Wait()
	close(responses)
	statuses := []int{}
	for status := range responses {
		statuses = append(statuses, status)
	}
	sort.Ints(statuses)
	if !slices.Equal(statuses, []int{http.StatusOK, http.StatusConflict}) {
		t.Fatalf("concurrent publish statuses=%v", statuses)
	}

	fixture.createRole(t, "tenant-a", "cursor-a", []string{"sites.read"}, "cursor-a")
	fixture.createRole(t, "tenant-a", "cursor-b", []string{"sites.read"}, "cursor-b")
	first := fixture.get("tenant-a", "/v1/custom-rbac/roles?limit=2")
	if first.Code != http.StatusOK {
		t.Fatalf("first page status=%d body=%s", first.Code, first.Body.String())
	}
	var firstPage RolePageView
	decodeResponse(t, first, &firstPage)
	if firstPage.Page.NextCursor == "" {
		t.Fatalf("first page missing cursor: %s", first.Body.String())
	}
	response := fixture.command("tenant-a", http.MethodPost,
		"/v1/custom-rbac/roles/"+role.ID.String()+"/deactivate", "",
		"cursor-deactivate", "cursor-deactivate-request", `"2"`, "")
	if response.Code != http.StatusOK {
		t.Fatalf("cursor deactivation status=%d body=%s", response.Code, response.Body.String())
	}
	later := fixture.createRole(t, "tenant-a", "cursor-later", []string{"sites.read"}, "cursor-later")
	second := fixture.get("tenant-a", "/v1/custom-rbac/roles?limit=2&cursor="+firstPage.Page.NextCursor)
	if second.Code != http.StatusOK {
		t.Fatalf("second page status=%d body=%s", second.Code, second.Body.String())
	}
	var secondPage RolePageView
	decodeResponse(t, second, &secondPage)
	for _, item := range append(firstPage.Data, secondPage.Data...) {
		if item.ID == later.ID {
			t.Fatalf("later role entered frozen pagination snapshot: %#v", item)
		}
		if item.ID == role.ID && item.DeactivatedAt != nil {
			t.Fatalf("post-snapshot deactivation changed cursor state: %#v", item)
		}
	}
	freshRoles := fixture.get("tenant-a", "/v1/custom-rbac/roles?include_deactivated=true")
	if freshRoles.Code != http.StatusOK || !strings.Contains(freshRoles.Body.String(), role.ID.String()) ||
		!strings.Contains(freshRoles.Body.String(), `"deactivated_at"`) {
		t.Fatalf("fresh role list missed deactivation status=%d body=%s", freshRoles.Code, freshRoles.Body.String())
	}
	tampered := tamperCursor(firstPage.Page.NextCursor)
	response = fixture.get("tenant-a", "/v1/custom-rbac/roles?limit=2&cursor="+tampered)
	assertAPIError(t, response, http.StatusBadRequest, "custom_rbac_validation_error")

	grantRole := fixture.createRole(t, "tenant-a", "grant-cursor-role", []string{"sites.read"}, "grant-cursor-role")
	subjects := []uuid.UUID{fixture.tenantASubject, fixture.seedSubject(t, "grant-cursor-two"),
		fixture.seedSubject(t, "grant-cursor-three")}
	grants := make([]GrantView, 0, len(subjects))
	for index, subject := range subjects {
		response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/grants",
			fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, grantRole.ID, subject),
			fmt.Sprintf("grant-cursor-%d", index), fmt.Sprintf("grant-cursor-request-%d", index), `"1"`, "")
		if response.Code != http.StatusCreated {
			t.Fatalf("grant cursor assign status=%d body=%s", response.Code, response.Body.String())
		}
		var envelope dataEnvelope[GrantView]
		decodeResponse(t, response, &envelope)
		grants = append(grants, envelope.Data)
	}
	firstGrants := fixture.get("tenant-a", "/v1/custom-rbac/grants?limit=2&state=active")
	if firstGrants.Code != http.StatusOK {
		t.Fatalf("first grant page status=%d body=%s", firstGrants.Code, firstGrants.Body.String())
	}
	var firstGrantPage GrantPageView
	decodeResponse(t, firstGrants, &firstGrantPage)
	if firstGrantPage.Page.NextCursor == "" {
		t.Fatalf("first grant page missing cursor: %s", firstGrants.Body.String())
	}
	response = fixture.command("tenant-a", http.MethodPost,
		"/v1/custom-rbac/grants/"+grants[0].ID.String()+"/revoke", "",
		"grant-cursor-revoke", "grant-cursor-revoke-request", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("grant cursor revoke status=%d body=%s", response.Code, response.Body.String())
	}
	laterSubject := fixture.seedSubject(t, "grant-cursor-later")
	response = fixture.command("tenant-a", http.MethodPost, "/v1/custom-rbac/grants",
		fmt.Sprintf(`{"role_id":%q,"subject_user_id":%q}`, grantRole.ID, laterSubject),
		"grant-cursor-later", "grant-cursor-later-request", `"1"`, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("later grant status=%d body=%s", response.Code, response.Body.String())
	}
	var laterGrant dataEnvelope[GrantView]
	decodeResponse(t, response, &laterGrant)
	secondGrants := fixture.get("tenant-a", "/v1/custom-rbac/grants?limit=2&state=active&cursor="+
		firstGrantPage.Page.NextCursor)
	if secondGrants.Code != http.StatusOK {
		t.Fatalf("second grant page status=%d body=%s", secondGrants.Code, secondGrants.Body.String())
	}
	var secondGrantPage GrantPageView
	decodeResponse(t, secondGrants, &secondGrantPage)
	seenRevokedAtSnapshot := false
	for _, item := range append(firstGrantPage.Data, secondGrantPage.Data...) {
		if item.ID == laterGrant.Data.ID {
			t.Fatalf("later grant entered frozen pagination snapshot: %#v", item)
		}
		if item.ID == grants[0].ID {
			seenRevokedAtSnapshot = true
			if item.RevokedAt != nil {
				t.Fatalf("post-snapshot revocation changed cursor state: %#v", item)
			}
		}
	}
	if !seenRevokedAtSnapshot {
		t.Fatal("cursor snapshot lost grant revoked after first page")
	}
	freshActive := fixture.get("tenant-a", "/v1/custom-rbac/grants?state=active")
	if strings.Contains(freshActive.Body.String(), grants[0].ID.String()) ||
		!strings.Contains(freshActive.Body.String(), laterGrant.Data.ID.String()) {
		t.Fatalf("fresh active grants did not reflect latest state: %s", freshActive.Body.String())
	}
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	// The handlers and services under test run against the release head.
	fixture := &integrationFixture{pool: databasetest.MigratedPool(t, nil), verifier: transactionStepUpVerifier{},
		tenantAID: uuid.New(), tenantAScope: uuid.New(), tenantASubject: uuid.New(), tenantARole: uuid.New(),
		tenantBID: uuid.New(), tenantBScope: uuid.New(), tenantBSubject: uuid.New()}
	fixture.tenantAActor = AuthenticatedSession{UserID: uuid.New(), ScopeID: fixture.tenantAScope,
		SessionID: uuid.New(), ScopeKind: "tenant", IdentityDomain: rbacmanager.CustomerControlIdentityDomain}
	fixture.tenantBActor = AuthenticatedSession{UserID: uuid.New(), ScopeID: fixture.tenantBScope,
		SessionID: uuid.New(), ScopeKind: "tenant", IdentityDomain: rbacmanager.CustomerControlIdentityDomain}
	fixture.seedIdentity(t)
	if _, err := fixture.pool.Exec(t.Context(), `CREATE TABLE custom_rbac_http_test_proofs(
		token text PRIMARY KEY,proof_id uuid NOT NULL,actor_user_id uuid NOT NULL,
		actor_scope_id uuid NOT NULL,session_id uuid NOT NULL,tenant_id uuid NOT NULL,
		audience text NOT NULL,action text NOT NULL,request_id text NOT NULL,
		permissions text[] NOT NULL,method text NOT NULL,verified_at timestamptz NOT NULL,
		consumed boolean NOT NULL DEFAULT false,bound_role_id uuid,bound_subject_user_id uuid,
		bound_trace_id text)`); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(fixture.pool, fixture.verifier,
		ServiceConfig{CursorKey: bytes.Repeat([]byte{8}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
	fixture.handler = fixture.handlerForService(t, service)
	return fixture
}

func seedHTTPIdentityFixture(t *testing.T, pool *pgxpool.Pool) *integrationFixture {
	t.Helper()
	fixture := &integrationFixture{pool: pool, verifier: transactionStepUpVerifier{},
		tenantAID: uuid.New(), tenantAScope: uuid.New(), tenantASubject: uuid.New(), tenantARole: uuid.New(),
		tenantBID: uuid.New(), tenantBScope: uuid.New(), tenantBSubject: uuid.New()}
	fixture.tenantAActor = AuthenticatedSession{UserID: uuid.New(), ScopeID: fixture.tenantAScope,
		SessionID: uuid.New(), ScopeKind: "tenant", IdentityDomain: rbacmanager.CustomerControlIdentityDomain}
	fixture.tenantBActor = AuthenticatedSession{UserID: uuid.New(), ScopeID: fixture.tenantBScope,
		SessionID: uuid.New(), ScopeKind: "tenant", IdentityDomain: rbacmanager.CustomerControlIdentityDomain}
	fixture.seedIdentity(t)
	return fixture
}

func sessionActor(session AuthenticatedSession) rbacmanager.Actor {
	return rbacmanager.Actor{UserID: session.UserID, ScopeID: session.ScopeID,
		SessionID: session.SessionID, ScopeKind: session.ScopeKind, IdentityDomain: session.IdentityDomain}
}

type rollbackFacts struct {
	Roles              int
	Revisions          int
	WriteRequests      int
	ProjectedRoles     int
	ProjectedGrants    int
	OwnerManage        int
	AuditEvents        int
	Watermark          int64
	WatermarkAvailable bool
}

func captureRBACRollbackFacts(
	t *testing.T,
	pool *pgxpool.Pool,
	ownerRoleID, customRoleID uuid.UUID,
) rollbackFacts {
	t.Helper()
	result := rollbackFacts{}
	queries := []struct {
		query string
		args  []any
		value *int
	}{
		{`SELECT count(*) FROM custom_roles WHERE id=$1`, []any{customRoleID}, &result.Roles},
		{`SELECT count(*) FROM custom_role_revisions WHERE role_id=$1`, []any{customRoleID}, &result.Revisions},
		{`SELECT count(*) FROM custom_rbac_write_requests WHERE response_body->>'id'=$1`, []any{customRoleID.String()}, &result.WriteRequests},
		{`SELECT count(*) FROM roles WHERE id=$1`, []any{customRoleID}, &result.ProjectedRoles},
		{`SELECT count(*) FROM role_permissions WHERE role_id=$1`, []any{customRoleID}, &result.ProjectedGrants},
		{`SELECT count(*) FROM role_permissions WHERE role_id=$1 AND permission_name='identity.roles.manage'`, []any{ownerRoleID}, &result.OwnerManage},
		{`SELECT count(*) FROM audit_events WHERE action LIKE 'identity.custom_role.%'`, nil, &result.AuditEvents},
	}
	for _, query := range queries {
		if err := pool.QueryRow(t.Context(), query.query, query.args...).Scan(query.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('custom_rbac_state_watermark') IS NOT NULL`).
		Scan(&result.WatermarkAvailable); err != nil {
		t.Fatal(err)
	}
	if result.WatermarkAvailable {
		if err := pool.QueryRow(t.Context(), `SELECT current_version FROM custom_rbac_state_watermark
			WHERE singleton`).Scan(&result.Watermark); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func (fixture *integrationFixture) seedIdentity(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	for _, tenant := range []struct {
		id, scopeID uuid.UUID
		name        string
	}{{fixture.tenantAID, fixture.tenantAScope, "HTTP Tenant A"},
		{fixture.tenantBID, fixture.tenantBScope, "HTTP Tenant B"}} {
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenant.id, tenant.name); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id)
			VALUES($1,'tenant',$2)`, tenant.scopeID, tenant.id); err != nil {
			t.Fatal(err)
		}
	}
	users := []struct {
		id, scopeID uuid.UUID
		username    string
	}{{fixture.tenantAActor.UserID, fixture.tenantAScope, "http-actor-a"},
		{fixture.tenantASubject, fixture.tenantAScope, "http-subject-a"},
		{fixture.tenantBActor.UserID, fixture.tenantBScope, "http-actor-b"},
		{fixture.tenantBSubject, fixture.tenantBScope, "http-subject-b"}}
	for _, user := range users {
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,$2,'hash')`, user.id, user.username); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
			user.scopeID, user.id); err != nil {
			t.Fatal(err)
		}
	}
	for index, actor := range []AuthenticatedSession{fixture.tenantAActor, fixture.tenantBActor} {
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, actor.SessionID, uuid.New(), actor.UserID,
			actor.ScopeID, bytes.Repeat([]byte{byte(40 + index)}, 32), time.Now().Add(-time.Hour), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	ownerB := uuid.New()
	for _, owner := range []struct {
		roleID uuid.UUID
		actor  AuthenticatedSession
	}{{fixture.tenantARole, fixture.tenantAActor}, {ownerB, fixture.tenantBActor}} {
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($1,$2,'tenant_owner','HTTP integration owner',true)`, owner.roleID, owner.actor.ScopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
			SELECT $1,unnest($2::text[]) ON CONFLICT DO NOTHING`, owner.roleID,
			[]string{"identity.users.manage", "sites.manage", "sites.read"}); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, owner.actor.ScopeID, owner.actor.UserID, owner.roleID); err != nil {
			t.Fatal(err)
		}
	}
	viewer := uuid.New()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'tenant_viewer','HTTP integration viewer',true)`, viewer, fixture.tenantAScope); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'identity.self.read')`, viewer); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.tenantAScope, fixture.tenantASubject, viewer); err != nil {
		t.Fatal(err)
	}
}

func (fixture *integrationFixture) seedSubject(t *testing.T, username string) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,$2,'hash')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id)
		VALUES($1,$2)`, fixture.tenantAScope, userID); err != nil {
		t.Fatal(err)
	}
	return userID
}

func (fixture *integrationFixture) exec(t *testing.T, statement string, arguments ...any) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), statement, arguments...); err != nil {
		t.Fatal(err)
	}
}

func (fixture *integrationFixture) replaceActorSession(t *testing.T) {
	t.Helper()
	sessionID := uuid.New()
	randomID := uuid.New()
	refreshHash := append(append([]byte(nil), randomID[:]...), randomID[:]...)
	fixture.exec(t, `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), fixture.tenantAActor.UserID,
		fixture.tenantAScope, refreshHash, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	fixture.tenantAActor.SessionID = sessionID
}

func (fixture *integrationFixture) assertRevocationWins(
	t *testing.T,
	statement string,
	arguments []any,
	command func() *httptest.ResponseRecorder,
	wantStatus int,
	wantCode string,
) {
	t.Helper()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), statement, arguments...); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		close(started)
		response <- command()
	}()
	<-started
	select {
	case early := <-response:
		t.Fatalf("authorization command escaped uncommitted principal lock: status=%d body=%s",
			early.Code, early.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case completed := <-response:
		assertAPIError(t, completed, wantStatus, wantCode)
	case <-time.After(5 * time.Second):
		t.Fatal("authorization command did not resume after revocation commit")
	}
}

func (fixture *integrationFixture) handlerForService(t *testing.T, service *Service) *Handler {
	t.Helper()
	handler, err := NewHandler(service, func(request *http.Request) (AuthenticatedSession, error) {
		switch request.Header.Get("Authorization") {
		case "tenant-a":
			return fixture.tenantAActor, nil
		case "tenant-b":
			return fixture.tenantBActor, nil
		default:
			return AuthenticatedSession{}, errors.New("not authenticated")
		}
	}, HandlerConfig{CommandTimeout: 5 * time.Second, QueryTimeout: 5 * time.Second,
		MaxRequestBytes: 64 << 10, MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func (fixture *integrationFixture) seedProof(
	t *testing.T,
	token string,
	actor AuthenticatedSession,
	tenantID uuid.UUID,
	action string,
	requestID string,
	permissions []string,
) {
	t.Helper()
	values := append([]string(nil), permissions...)
	sort.Strings(values)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO custom_rbac_http_test_proofs(
		token,proof_id,actor_user_id,actor_scope_id,session_id,tenant_id,audience,
		action,request_id,permissions,method,verified_at)
		VALUES($1,$2,$3,$4,$5,$6,'custom-rbac',$7,$8,$9,'totp',$10)`, token, uuid.New(),
		actor.UserID, actor.ScopeID, actor.SessionID, tenantID, action, requestID, values, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func (fixture *integrationFixture) assertProofUsed(t *testing.T, token string, want bool) {
	t.Helper()
	var got bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT consumed FROM custom_rbac_http_test_proofs
		WHERE token=$1`, token).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("proof used=%t want=%t", got, want)
	}
}

func (fixture *integrationFixture) assertProofBinding(
	t *testing.T,
	token string,
	roleID, subjectUserID uuid.UUID,
	traceID string,
) {
	t.Helper()
	var gotRoleID, gotSubjectUserID uuid.UUID
	var gotTraceID string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT bound_role_id,bound_subject_user_id,bound_trace_id
		FROM custom_rbac_http_test_proofs WHERE token=$1`, token).
		Scan(&gotRoleID, &gotSubjectUserID, &gotTraceID); err != nil {
		t.Fatal(err)
	}
	if gotRoleID != roleID || gotSubjectUserID != subjectUserID || gotTraceID != traceID {
		t.Fatalf("proof binding=(%v,%v,%v) want=(%s,%s,%s)", gotRoleID, gotSubjectUserID,
			gotTraceID, roleID, subjectUserID, traceID)
	}
}

func (fixture *integrationFixture) createRole(
	t *testing.T,
	auth string,
	name string,
	permissions []string,
	key string,
) RoleView {
	t.Helper()
	encodedPermissions := make([]string, len(permissions))
	for index, permission := range permissions {
		encodedPermissions[index] = strconv.Quote(permission)
	}
	response := fixture.command(auth, http.MethodPost, "/v1/custom-rbac/roles",
		fmt.Sprintf(`{"name":%q,"permissions":[%s]}`, name, strings.Join(encodedPermissions, ",")),
		key, key+"-request", "", "")
	if response.Code != http.StatusCreated {
		t.Fatalf("create role %s status=%d body=%s", name, response.Code, response.Body.String())
	}
	var envelope dataEnvelope[RoleView]
	decodeResponse(t, response, &envelope)
	return envelope.Data
}

func (fixture *integrationFixture) command(
	auth, method, target, body, key, requestID, ifMatch, proof string,
) *httptest.ResponseRecorder {
	request := integrationCommand(method, target, body, key, requestID, ifMatch, proof)
	request.Header.Set("Authorization", auth)
	return perform(fixture.handler, request)
}

func (fixture *integrationFixture) get(auth, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Authorization", auth)
	return perform(fixture.handler, request)
}

func integrationCommand(method, target, body, key, requestID, ifMatch, proof string) *http.Request {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	request := httptest.NewRequest(method, target, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	} else {
		request.Body = http.NoBody
		request.ContentLength = 0
	}
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("X-Request-ID", requestID)
	request.Header.Set("Traceparent", "00-"+strings.Repeat("a", 32)+"-"+strings.Repeat("b", 16)+"-01")
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	if proof != "" {
		request.Header.Set("X-Step-Up-Proof", proof)
	}
	return request
}

func expectedRBACMutationDigest(operation, idempotencyKey string, payload any) []byte {
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		panic("encode expected RBAC mutation payload: " + err.Error())
	}
	payloadDigest := sha256.Sum256(encodedPayload)
	encodedMutation, err := json.Marshal(struct {
		Version        int    `json:"version"`
		Operation      string `json:"operation"`
		IdempotencyKey string `json:"idempotency_key"`
		PayloadSHA256  string `json:"payload_sha256"`
	}{1, operation, idempotencyKey, hex.EncodeToString(payloadDigest[:])})
	if err != nil {
		panic("encode expected RBAC mutation binding: " + err.Error())
	}
	digest := sha256.Sum256(encodedMutation)
	return append([]byte(nil), digest[:]...)
}

func activateHTTPRealMFA(t *testing.T, fixture *integrationFixture) (*mfa.Service, []string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	service, err := mfa.NewServiceWithDependencies(
		fixture.pool,
		integrationMFACipher{},
		audit.New(fixture.pool),
		mfa.Config{Clock: func() time.Time { return now }, Issuer: "CDNCA RBAC Integration"},
	)
	if err != nil {
		t.Fatal(err)
	}
	actor := mfa.Actor{UserID: fixture.tenantAActor.UserID, ScopeID: fixture.tenantAActor.ScopeID,
		SessionID: fixture.tenantAActor.SessionID}
	enrollment, err := service.BeginEnrollment(t.Context(), actor, mfa.EnrollmentRequest{
		AccountLabel: "rbac-integration@example.invalid", IdempotencyKey: "real-mfa-enrollment",
		Context: mfa.RequestContext{RequestID: "real-mfa-enrollment-request", TraceID: "real-mfa-enrollment-trace"},
	})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := service.Activate(t.Context(), actor, mfa.ActivationRequest{
		CredentialID:   enrollment.CredentialID,
		Code:           httpRealMFATOTP(secret, now),
		IdempotencyKey: "real-mfa-activation",
		Context:        mfa.RequestContext{RequestID: "real-mfa-activation-request", TraceID: "real-mfa-activation-trace"},
	})
	clear(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(activation.RecoveryCodes) != mfa.RecoveryCodeCount {
		t.Fatalf("real MFA recovery code count=%d want=%d", len(activation.RecoveryCodes), mfa.RecoveryCodeCount)
	}
	return service, activation.RecoveryCodes
}

func httpRealMFATOTP(secret []byte, now time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/int64(mfa.TOTPPeriod/time.Second)))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

func issueHTTPRealMFAProof(
	t *testing.T,
	service *mfa.Service,
	fixture *integrationFixture,
	recoveryCode, action, key string,
) mfa.StepUpResult {
	t.Helper()
	result, err := service.CreateStepUp(t.Context(), mfa.Actor{
		UserID: fixture.tenantAActor.UserID, ScopeID: fixture.tenantAActor.ScopeID,
		SessionID: fixture.tenantAActor.SessionID,
	}, mfa.StepUpRequest{
		TenantID: fixture.tenantAID, Audience: "custom-rbac", Action: action,
		Authentication: mfa.Authentication{Method: mfa.MethodRecoveryCode, Code: recoveryCode},
		TTL:            mfa.MaxStepUpTTL, MaxUses: 1, IdempotencyKey: key,
		Context: mfa.RequestContext{RequestID: "request-" + key, TraceID: "trace-" + key},
	})
	if err != nil {
		t.Fatalf("issue real MFA proof %s: %v", key, err)
	}
	return result
}

func assertHTTPRealMFAUses(t *testing.T, pool *pgxpool.Pool, proofID uuid.UUID, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM mfa_step_up_uses WHERE proof_id=$1`, proofID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("real MFA proof %s use count=%d want=%d", proofID, got, want)
	}
}

func assertHTTPWriteCount(t *testing.T, pool *pgxpool.Pool, idempotencyKey string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM custom_rbac_write_requests
		WHERE idempotency_key=$1`, idempotencyKey).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("RBAC write count for %q=%d want=%d", idempotencyKey, got, want)
	}
}

func assertHTTPAuditCount(t *testing.T, pool *pgxpool.Pool, requestID string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE request_id=$1`, requestID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("audit count for request %q=%d want=%d", requestID, got, want)
	}
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), destination); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
}

func assertEffectivePermission(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, userID uuid.UUID,
	permission string,
	want bool,
) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1
		FROM custom_rbac_effective_permissions($1,$2) WHERE permission_name=$3)`,
		scopeID, userID, permission).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("effective permission %s=%t want=%t", permission, got, want)
	}
}

func assertCountByName(t *testing.T, pool *pgxpool.Pool, name string, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM custom_roles WHERE current_name=$1`, name).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("role count for %q=%d want=%d", name, count, want)
	}
}

func isolatedHTTPPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	var rawVersion string
	if err := admin.QueryRow(ctx, `SHOW server_version_num`).Scan(&rawVersion); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	version, err := strconv.Atoi(rawVersion)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if version/10000 != 17 {
		admin.Close()
		t.Fatalf("PostgreSQL major=%d, want 17", version/10000)
	}
	schema := "custom_rbac_http_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^custom_rbac_http_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations(
		version bigint PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		pool.Close()
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

// migrationHead is the newest embedded migration version.
func migrationHead(t *testing.T) int {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	head := 0
	for _, entry := range entries {
		prefix, _, found := strings.Cut(entry.Name(), "_")
		if version, err := strconv.Atoi(prefix); found && err == nil && strings.HasSuffix(entry.Name(), ".up.sql") && version > head {
			head = version
		}
	}
	return head
}

func migrateHTTPTo(t *testing.T, pool *pgxpool.Pool, target int) int {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	upByVersion := map[int]string{}
	head := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		prefix, _, found := strings.Cut(entry.Name(), "_")
		version, err := strconv.Atoi(prefix)
		if !found || err != nil || version < 1 {
			continue
		}
		if _, duplicate := upByVersion[version]; duplicate {
			t.Fatalf("duplicate up migration version %d", version)
		}
		upByVersion[version] = entry.Name()
		if version > head {
			head = version
		}
	}
	if target == 0 {
		target = head
	}
	for version := 1; version <= target; version++ {
		name, ok := upByVersion[version]
		if !ok {
			t.Fatalf("migration %03d missing from continuous chain", version)
		}
		applyHTTPMigration(t, pool, name, version, true)
	}
	return head
}

func applyHTTPMigration(t *testing.T, pool *pgxpool.Pool, name string, version int, up bool) {
	t.Helper()
	if err := runHTTPMigration(t.Context(), pool, name, version, up); err != nil {
		t.Fatalf("apply migration %s: %v", name, err)
	}
}

func runHTTPMigration(
	ctx context.Context,
	pool *pgxpool.Pool,
	name string,
	version int,
	up bool,
) error {
	script, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		if up {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, version)
		} else {
			_, err = tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=$1`, version)
		}
		return err
	})
}

func assertHTTPMigrationApplied(t *testing.T, pool *pgxpool.Pool, version int, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration %d applied=%t want=%t", version, got, want)
	}
}

func assertHTTPTable(t *testing.T, pool *pgxpool.Pool, table string, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("table %s exists=%t want=%t", table, got, want)
	}
}
