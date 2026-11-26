//go:build integration

package plugininstallation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

type confirmReplayResolver struct {
	candidate  Candidate
	resolveErr error
	resolves   int
	reported   []Receipt
}

func (resolver *confirmReplayResolver) Resolve(context.Context, ActivationResolveRequest) (ActivationResult, error) {
	resolver.resolves++
	if resolver.resolveErr != nil {
		return ActivationResult{}, resolver.resolveErr
	}
	return ActivationResult{Candidate: resolver.candidate, verified: true}, nil
}

func (*confirmReplayResolver) Discover(context.Context, CandidateDiscoveryRequest) (Page, error) {
	return Page{}, nil
}

func (resolver *confirmReplayResolver) ReportLifecycle(_ context.Context,
	request LifecycleReportRequest) (LifecycleReportResult, error) {
	resolver.reported = append(resolver.reported, request.Receipt)
	return LifecycleReportResult{AuthorizationID: request.Receipt.AuthorizationID, LifecycleRevision: 1}, nil
}

// 真实 PG：平台管理员确认租户插件（选租户）。(b) 授权端已签发激活事实但首个响应丢失、本地未落库：
// 同 key 重试走授权端重放并完成本地落库；(a) 本地回执已存在：同 key 同内容重试不再调授权端（首个激活事实一分钟后过期），
// 直接回放唯一回执（授权端已签收，不再补投： 迁移 684）；同 key 改权限集合、目标租户、预期修订或
// 请求 ID 仍冲突。
func TestPlatformConfirmRetryReplaysLocalReceiptBeforeLicense(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	f := platformTargetsFixture{t: t, pool: pool, now: time.Now().UTC().Truncate(time.Second)}
	var platformScope uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		f.exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	}
	tenantA, tenantB := f.tenant("确认重放甲"), f.tenant("确认重放乙")
	actor := f.member(platformScope, ScopePlatform, PermissionPlatformRead, PermissionPlatformManage)
	actor.RequestID = "confirm-replay-request"
	repository, err := NewPostgresRepository(pool, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	candidate := Candidate{TenantID: platformScope, InstallationID: uuid.New(), AuthorizationID: uuid.New(),
		VerificationID: uuid.New(), PluginID: "com.example.reinstall", Version: "1.0.0", ResourceScope: ResourceScopeTenant,
		EntrypointType: EntrypointExternalHTTPS, ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("1"),
		ManifestScopes: []string{"plugin.read", "plugin.write"}, ApprovedScopes: []string{"plugin.read"},
		SensitiveScopes: []string{}}
	resolver := &confirmReplayResolver{candidate: candidate, resolveErr: ErrFactUnavailable}
	domain, err := NewProductionDomain(repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	request := MutationRequest{TenantID: platformScope, AuthorizationID: candidate.AuthorizationID,
		VerificationID: candidate.VerificationID, Action: ActionConfirm, ExpectedRevision: 3,
		IdempotencyKey: "confirm-replay-key", RequestID: actor.RequestID, ApprovedScopes: []string{"plugin.read"},
		NewPermissionsConfirmed: true, Targets: &Targets{TenantScopeIDs: []uuid.UUID{tenantA}}}
	count := func(query string) int {
		t.Helper()
		var value int
		if err := pool.QueryRow(t.Context(), query, candidate.AuthorizationID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	heads := `SELECT count(*) FROM plugin_installation_heads WHERE authorization_id=$1`
	receipts := `SELECT count(*) FROM plugin_installation_receipts WHERE authorization_id=$1`

	// (b) The license service issued the fact but its answer was lost: nothing is stored locally.
	if _, err := domain.Mutate(t.Context(), actor, request); !errors.Is(err, ErrFactUnavailable) {
		t.Fatalf("lost activation answer err=%v", err)
	}
	if count(heads) != 0 || count(receipts) != 0 {
		t.Fatal("a lost activation answer stored a head")
	}
	resolver.resolveErr = nil
	first, err := domain.Mutate(t.Context(), actor, request)
	if err != nil || first.Installation.Status != StatusEnabled || first.Installation.Revision != 1 {
		t.Fatalf("retry after the lost answer=%+v err=%v", first.Installation, err)
	}
	if resolver.resolves != 2 || count(heads) != 1 || count(receipts) != 1 || len(resolver.reported) != 1 {
		t.Fatalf("after (b) resolves=%d heads=%d receipts=%d reports=%d", resolver.resolves, count(heads),
			count(receipts), len(resolver.reported))
	}

	// (a) The local receipt exists; the first fact has expired upstream. The retry never reaches the license service.
	resolver.resolveErr = ErrActivationInvalid
	replay, err := domain.Mutate(t.Context(), actor, request)
	if err != nil || replay.Installation.Revision != first.Installation.Revision ||
		replay.Installation.Status != first.Installation.Status ||
		replay.Installation.IdentityGeneration != first.Installation.IdentityGeneration || replay.Targets == nil ||
		len(replay.Targets.Tenants) != 1 || replay.Targets.Tenants[0].ScopeID != tenantA {
		t.Fatalf("local replay=%+v err=%v", replay, err)
	}
	if resolver.resolves != 2 || count(heads) != 1 || count(receipts) != 1 || len(resolver.reported) != 1 ||
		replay.LicenseSync != LicenseSyncSynced {
		t.Fatalf("after (a) resolves=%d heads=%d receipts=%d reports=%d", resolver.resolves, count(heads),
			count(receipts), len(resolver.reported))
	}

	for name, mutate := range map[string]func(*MutationRequest, *Actor){
		"scopes": func(request *MutationRequest, _ *Actor) {
			request.ApprovedScopes = []string{"plugin.read", "plugin.write"}
		},
		"targets": func(request *MutationRequest, _ *Actor) {
			request.Targets = &Targets{TenantScopeIDs: []uuid.UUID{tenantB}}
		},
		"revision":     func(request *MutationRequest, _ *Actor) { request.ExpectedRevision++ },
		"verification": func(request *MutationRequest, _ *Actor) { request.VerificationID = uuid.New() },
		"request id": func(request *MutationRequest, actor *Actor) {
			request.RequestID, actor.RequestID = "confirm-replay-other", "confirm-replay-other"
		},
	} {
		changed, changedActor := request, actor
		mutate(&changed, &changedActor)
		if _, err := domain.Mutate(t.Context(), changedActor, changed); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("same key, changed %s err=%v", name, err)
		}
	}
	if resolver.resolves != 2 || count(heads) != 1 || count(receipts) != 1 {
		t.Fatalf("conflicts reached the license service or stored rows: resolves=%d", resolver.resolves)
	}
}
