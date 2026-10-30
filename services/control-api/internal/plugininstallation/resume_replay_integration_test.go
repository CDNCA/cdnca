//go:build integration

package plugininstallation

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

// fix-plugverify B-补1（DEV-PLUG-01/F5）真实 PG：主动暂停 → 恢复本地成功，首次上报成功或结果未知，
// 同 key 同请求重试回放唯一回执、身份代际只增一次，并再投一次上报。
func TestResumeExactRetryReplaysPersistedReceipt(t *testing.T) {
	for _, failReport := range []bool{false, true} {
		name := "report_succeeded"
		if failReport {
			name = "report_unknown"
		}
		t.Run(name, func(t *testing.T) {
			pool := databasetest.ClonedMigratedPool(t, nil)
			now := time.Now().UTC().Truncate(time.Second)
			scope, user, session, role := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(t.Context(), query, args...); err != nil {
					t.Fatalf("%v\n%s", err, query)
				}
			}
			exec(`INSERT INTO tenants(id,display_name) VALUES($1,'恢复重试')`, scope)
			exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, scope)
			exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'恢复重试','unused')`, user, "r-"+user.String())
			exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, user)
			exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'resume fixture',true)`, role, scope, "r-"+role.String())
			exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2),($1,$3)`, role, PermissionRead, PermissionManage)
			exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scope, user, role)
			refresh := sha256.Sum256(session[:])
			exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
				VALUES($1,$2,$3,$4,$5,$6,$7)`, session, uuid.New(), user, scope, refresh[:], now.Add(-time.Minute), now.Add(time.Hour))
			actor := Actor{UserID: user, SessionID: session, TenantID: scope, RequestID: "resume-replay-request"}
			repository, err := NewPostgresRepository(pool, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			install := testCommand(scope, uuid.New(), uuid.New(), uuid.New())
			install.Action, install.NewPermissionsConfirmed = ActionConfirm, true
			install.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "resume-install-fact"}}
			installed, err := repository.Apply(t.Context(), actor, install, &recordingVerifier{})
			if err != nil {
				t.Fatalf("install: %v", err)
			}
			paused, err := repository.Apply(t.Context(), actor, protectiveCommand(installed.Installation, ActionDisable, "主动暂停", "resume-pause"), nil)
			if err != nil {
				t.Fatalf("pause: %v", err)
			}
			remote := installationView(paused.Installation)
			remote.AuthorizationStatus, remote.PausedBy = StatusDisabled, PausedByInstallation
			resolver := &flakyResumeResolver{resumeResolver: resumeResolver{remote: []InstallationView{remote}}, failReport: failReport}
			domain, err := NewProductionDomain(repository, resolver)
			if err != nil {
				t.Fatal(err)
			}
			request := resumeRequest(actor, remote)
			first, firstErr := domain.Mutate(t.Context(), actor, request)
			if failReport != errors.Is(firstErr, ErrResultUnknown) || !failReport && (firstErr != nil || first.Installation.Status != StatusEnabled) {
				t.Fatalf("first status=%s err=%v", first.Installation.Status, firstErr)
			}
			if !failReport {
				resolver.remote[0].AuthorizationStatus, resolver.remote[0].PausedBy = StatusEnabled, ""
			}
			resolver.failReport = false
			second, err := domain.Mutate(t.Context(), actor, request)
			if err != nil || second.Installation.Status != StatusEnabled {
				t.Fatalf("exact retry status=%s err=%v", second.Installation.Status, err)
			}
			var receipts int
			var generation uint64
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_installation_receipts WHERE action='resume' AND authorization_id=$1`,
				request.AuthorizationID).Scan(&receipts); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(t.Context(), `SELECT identity_generation FROM plugin_installation_heads WHERE authorization_id=$1`,
				request.AuthorizationID).Scan(&generation); err != nil {
				t.Fatal(err)
			}
			if receipts != 1 || generation != paused.Installation.IdentityGeneration+1 || len(resolver.reported) != 2 ||
				resolver.reported[0].ID != resolver.reported[1].ID {
				t.Fatalf("receipts=%d generation=%d (paused %d) reports=%d", receipts, generation,
					paused.Installation.IdentityGeneration, len(resolver.reported))
			}
			// 新 key 对已启用的恢复仍被拒绝。
			fresh := request
			fresh.IdempotencyKey = "resume-key-fresh"
			if _, err := domain.Mutate(t.Context(), actor, fresh); !errors.Is(err, ErrTransitionInvalid) {
				t.Fatalf("fresh resume of enabled err=%v", err)
			}
			// 运营在恢复后暂停：原请求重试不能回放绕过。
			resolver.remote[0].AuthorizationStatus, resolver.remote[0].PausedBy = StatusDisabled, PausedByOperator
			if _, err := domain.Mutate(context.Background(), actor, request); !errors.Is(err, ErrPlatformPaused) {
				t.Fatalf("retry after operator pause err=%v", err)
			}
		})
	}
}
