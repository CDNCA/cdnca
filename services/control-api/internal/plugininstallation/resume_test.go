package plugininstallation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// 报告 B（DEV-PLUG-01/F5）：enabled → 主动暂停 → 恢复使用；不拿 confirm/upgrade 冒充恢复。
func resumeFixture(t *testing.T) (Service, *memoryStore, Installation) {
	t.Helper()
	now := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	store := newMemoryStore()
	service := Service{Store: store, Verifier: &recordingVerifier{}, Now: func() time.Time { return now }}
	tenantID, installationID, authorizationID := uuid.New(), uuid.New(), uuid.New()
	install := testCommand(tenantID, installationID, authorizationID, uuid.New())
	install.Action = ActionConfirm
	install.NewPermissionsConfirmed = true
	install.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "fact-install"}}
	installed, err := service.Apply(context.Background(), install)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	paused, err := service.Apply(context.Background(), protectiveCommand(installed.Installation, ActionDisable, "租户主动暂停", "pause-1"))
	if err != nil || paused.Installation.Status != StatusDisabled {
		t.Fatalf("pause=%+v err=%v", paused, err)
	}
	return service, store, paused.Installation
}

func resumeCommand(current Installation, key string) Command {
	command := protectiveCommand(current, ActionResume, "", key)
	command.Reason = ""
	return command
}

func TestServiceResumesOwnPauseSymmetrically(t *testing.T) {
	service, store, paused := resumeFixture(t)
	command := resumeCommand(paused, "resume-1")
	result, err := service.Apply(context.Background(), command)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if result.Installation.Status != StatusEnabled || result.Installation.Revision != paused.Revision+1 ||
		result.Installation.IdentityGeneration != paused.IdentityGeneration+1 ||
		result.Installation.VerificationID != paused.VerificationID || result.Installation.LKGVersion != paused.LKGVersion ||
		result.Receipt.Action != ActionResume || result.Receipt.Result != ReceiptResumed || result.Receipt.Reason != "" {
		t.Fatalf("resume result=%+v", result)
	}
	// 双击/原 key 重放：同一结果，不再写收据。
	receipts := len(store.receipts)
	replayed, err := service.Apply(context.Background(), command)
	if err != nil || replayed.Receipt.ID != result.Receipt.ID || len(store.receipts) != receipts {
		t.Fatalf("replay=%+v err=%v receipts=%d", replayed, err, len(store.receipts))
	}
	// 已启用不能再恢复；旧 revision 拒绝。
	again := resumeCommand(result.Installation, "resume-2")
	if _, err := service.Apply(context.Background(), again); !errors.Is(err, ErrTransitionInvalid) {
		t.Fatalf("resume enabled err=%v", err)
	}
	stale := resumeCommand(paused, "resume-stale")
	if _, err := service.Apply(context.Background(), stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale resume err=%v", err)
	}
	// 恢复后可以再次暂停（对称）。
	if _, err := service.Apply(context.Background(), protectiveCommand(result.Installation, ActionDisable, "再次暂停", "pause-2")); err != nil {
		t.Fatalf("pause after resume: %v", err)
	}
}

func TestServiceResumeRejectsReasonFactsAndDriftedCandidate(t *testing.T) {
	service, store, paused := resumeFixture(t)
	withReason := resumeCommand(paused, "resume-reason")
	withReason.Reason = "恢复"
	withFacts := resumeCommand(paused, "resume-facts")
	withFacts.Facts = []SignedRuntimeFact{{Scope: "plugin.read", RequestID: "fact"}}
	drifted := resumeCommand(paused, "resume-drift")
	drifted.Candidate.ApprovedScopes = []string{}
	otherTenant := resumeCommand(paused, "resume-tenant")
	otherTenant.TenantID, otherTenant.Candidate.TenantID = uuid.New(), uuid.New()
	for name, command := range map[string]Command{"reason": withReason, "facts": withFacts} {
		if _, err := service.Apply(context.Background(), command); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s err=%v", name, err)
		}
	}
	if _, err := service.Apply(context.Background(), drifted); !errors.Is(err, ErrTransitionInvalid) {
		t.Errorf("drifted candidate err=%v", err)
	}
	if _, err := service.Apply(context.Background(), otherTenant); err == nil {
		t.Errorf("cross tenant err=%v", err)
	}
	if store.current(paused.TenantID, paused.AuthorizationID).Status != StatusDisabled {
		t.Fatal("rejected resume changed state")
	}
}

// 生产域：恢复前读签名快照，只有本主控自停、授权未变时才写；平台暂停与授权端不可达都保持原状态。
type resumeRepository struct {
	head    InstallationView
	applied []Command
}

func (repository *resumeRepository) List(context.Context, Actor, ListRequest) (Page, error) {
	return Page{Items: []InstallationView{repository.head}}, nil
}

func (repository *resumeRepository) Get(context.Context, Actor, uuid.UUID) (InstallationView, error) {
	return repository.head, nil
}

func (*resumeRepository) HasReceipt(context.Context, Actor, uuid.UUID, string) (bool, error) {
	return false, nil
}

func (repository *resumeRepository) Apply(_ context.Context, _ Actor, command Command, _ CandidateVerifier) (MutationResult, error) {
	repository.applied = append(repository.applied, command)
	next := cloneInstallation(repository.head.Installation)
	next.Status, next.Revision, next.IdentityGeneration = StatusEnabled, next.Revision+1, next.IdentityGeneration+1
	return MutationResult{Installation: next, Receipt: Receipt{ID: uuid.New(), Action: command.Action,
		Result: ReceiptResumed, Snapshot: next}}, nil
}

type resumeResolver struct {
	remote   []InstallationView
	fail     bool
	reported []Receipt
}

func (resolver *resumeResolver) Resolve(context.Context, ActivationResolveRequest) (ActivationResult, error) {
	return ActivationResult{}, ErrFactDenied
}

func (resolver *resumeResolver) Discover(context.Context, CandidateDiscoveryRequest) (Page, error) {
	if resolver.fail {
		return Page{}, ErrFactUnavailable
	}
	return Page{Items: resolver.remote}, nil
}

func (resolver *resumeResolver) ReportLifecycle(_ context.Context, request LifecycleReportRequest) (LifecycleReportResult, error) {
	resolver.reported = append(resolver.reported, request.Receipt)
	return LifecycleReportResult{}, nil
}

func productionResumeFixture(remoteStatus, pausedBy string) (*ProductionDomain, *resumeRepository, *resumeResolver, Actor) {
	tenantID := uuid.New()
	local := mergeView(tenantID, "acme.cache", "1.2.0", StatusDisabled, "")
	local.Installation.IdentityGeneration = 2
	remote := local
	remote.Installation = cloneInstallation(local.Installation)
	remote.Installation.Status = remoteStatus
	remote.AuthorizationStatus = remoteStatus
	remote.PausedBy = pausedBy
	repository := &resumeRepository{head: local}
	resolver := &resumeResolver{remote: []InstallationView{remote}}
	domain, _ := NewProductionDomain(repository, resolver)
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "resume-request"}
	return domain, repository, resolver, actor
}

func resumeRequest(actor Actor, head InstallationView) MutationRequest {
	return MutationRequest{TenantID: actor.TenantID, AuthorizationID: head.Installation.AuthorizationID,
		Action: ActionResume, ExpectedRevision: head.Installation.Revision, IdempotencyKey: "resume-key",
		RequestID: actor.RequestID}
}

func TestProductionResumeOnlyOwnPauseAndReportsLifecycle(t *testing.T) {
	domain, repository, resolver, actor := productionResumeFixture(StatusDisabled, PausedByInstallation)
	view, err := domain.Mutate(context.Background(), actor, resumeRequest(actor, repository.head))
	if err != nil || view.Installation.Status != StatusEnabled {
		t.Fatalf("resume view=%+v err=%v", view, err)
	}
	if len(repository.applied) != 1 || repository.applied[0].Action != ActionResume ||
		repository.applied[0].Candidate.VerificationID != repository.head.Installation.VerificationID ||
		len(resolver.reported) != 1 || resolver.reported[0].Result != ReceiptResumed {
		t.Fatalf("applied=%+v reported=%+v", repository.applied, resolver.reported)
	}
}

func TestProductionResumeKeepsStateWhenPlatformPausedOrUnreachable(t *testing.T) {
	for name, setup := range map[string]struct {
		remoteStatus, pausedBy string
		fail                   bool
		want                   error
	}{
		"operator pause":       {StatusDisabled, PausedByOperator, false, ErrPlatformPaused},
		"market delist":        {StatusDisabled, PausedByService, false, ErrPlatformPaused},
		"pause without owner":  {StatusDisabled, "", false, ErrPlatformPaused},
		"license unreachable":  {StatusDisabled, PausedByInstallation, true, ErrFactUnavailable},
		"remote already moved": {StatusEnabled, "", false, ErrFactDenied},
	} {
		t.Run(name, func(t *testing.T) {
			domain, repository, resolver, actor := productionResumeFixture(setup.remoteStatus, setup.pausedBy)
			resolver.fail = setup.fail
			if _, err := domain.Mutate(context.Background(), actor, resumeRequest(actor, repository.head)); !errors.Is(err, setup.want) {
				t.Fatalf("err=%v want %v", err, setup.want)
			}
			if len(repository.applied) != 0 || len(resolver.reported) != 0 {
				t.Fatalf("rejected resume wrote state applied=%d reported=%d", len(repository.applied), len(resolver.reported))
			}
		})
	}
	// 授权端已换版本/权限（如运营批准了新版本但未升级）：恢复只能针对原授权，否则拒绝。
	domain, repository, resolver, actor := productionResumeFixture(StatusDisabled, PausedByInstallation)
	resolver.remote[0].Installation.VerificationID = uuid.New()
	if _, err := domain.Mutate(context.Background(), actor, resumeRequest(actor, repository.head)); !errors.Is(err, ErrFactDenied) {
		t.Fatalf("drifted authorization err=%v", err)
	}
	if len(repository.applied) != 0 {
		t.Fatal("drifted authorization resumed")
	}
}

func TestHandlerResumeRouteRequiresManageIfMatchAndEmptyBody(t *testing.T) {
	tenantID, authorizationID := uuid.New(), uuid.New()
	view := handlerTestView(tenantID, authorizationID)
	view.PausedBy, view.PausedReason = PausedByOperator, "合规复核"
	view.Installation.Status = StatusDisabled
	domain := &handlerTestDomain{mutationResult: view, getResult: view}
	handler := newHandlerForTest(t, tenantID, domain)
	path := "/v1/tenant-scopes/" + tenantID.String() + "/plugin-installations/" + authorizationID.String()
	send := func(body, ifMatch, key string) *httptest.ResponseRecorder {
		request := authenticatedHandlerRequest(http.MethodPost, path+"/resume", bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
		if ifMatch != "" {
			request.Header.Set("If-Match", ifMatch)
		}
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := send(`{}`, `"7"`, "plugin-resume-1")
	if response.Code != http.StatusOK || domain.lastMutation.Action != ActionResume ||
		domain.lastMutation.ExpectedRevision != 7 || domain.lastMutation.IdempotencyKey != "plugin-resume-1" ||
		domain.lastMutation.Reason != "" {
		t.Fatalf("resume status=%d body=%s mutation=%+v", response.Code, response.Body.String(), domain.lastMutation)
	}
	for name, body := range map[string]string{"reason": `{"reason":"x"}`, "array": `[]`, "empty": ``} {
		assertHandlerError(t, send(body, `"7"`, "plugin-resume-"+name), http.StatusBadRequest, "invalid_request")
	}
	assertHandlerError(t, send(`{}`, "", "plugin-resume-noetag"), http.StatusBadRequest, "invalid_request")
	domain.err = ErrPlatformPaused
	assertHandlerError(t, send(`{}`, `"7"`, "plugin-resume-platform"), http.StatusConflict, "plugin_installation_platform_paused")

	// 读模型带出平台暂停的处理者与原因，页面据此说明"平台已暂停"。
	domain.err = nil
	read := authenticatedHandlerRequest(http.MethodGet, path, nil)
	readResponse := httptest.NewRecorder()
	handler.ServeHTTP(readResponse, read)
	var wire map[string]any
	if err := json.Unmarshal(readResponse.Body.Bytes(), &wire); err != nil || wire["paused_by"] != PausedByOperator ||
		wire["paused_reason"] != "合规复核" {
		t.Fatalf("read wire=%v err=%v", wire, err)
	}
}

// fix-plugverify B：持久回执的仓库替身——Apply 按幂等键回放（摘要不同即冲突），首次恢复后本地 head 变 enabled。
type replayResumeRepository struct {
	resumeRepository
	receipts map[string]MutationResult
	digests  map[string][32]byte
}

func (repository *replayResumeRepository) Apply(ctx context.Context, actor Actor, command Command,
	verifier CandidateVerifier) (MutationResult, error) {
	digest, err := commandDigest(command)
	if err != nil {
		return MutationResult{}, err
	}
	if stored, found := repository.receipts[command.IdempotencyKey]; found {
		if repository.digests[command.IdempotencyKey] != digest {
			return MutationResult{}, ErrIdempotencyConflict
		}
		return stored, nil
	}
	result, err := repository.resumeRepository.Apply(ctx, actor, command, verifier)
	if err != nil {
		return result, err
	}
	repository.head.Installation = cloneInstallation(result.Installation)
	repository.receipts[command.IdempotencyKey], repository.digests[command.IdempotencyKey] = result, digest
	return result, nil
}

func (repository *replayResumeRepository) HasReceipt(_ context.Context, _ Actor, _ uuid.UUID, key string) (bool, error) {
	_, found := repository.receipts[key]
	return found, nil
}

type flakyResumeResolver struct {
	resumeResolver
	failReport bool
}

func (resolver *flakyResumeResolver) ReportLifecycle(_ context.Context, request LifecycleReportRequest) (LifecycleReportResult, error) {
	resolver.reported = append(resolver.reported, request.Receipt)
	if resolver.failReport {
		return LifecycleReportResult{}, ErrFactUnavailable
	}
	return LifecycleReportResult{}, nil
}

func replayResumeFixture(t *testing.T) (*ProductionDomain, *replayResumeRepository, *flakyResumeResolver, Actor) {
	t.Helper()
	_, base, resolver, actor := productionResumeFixture(StatusDisabled, PausedByInstallation)
	repository := &replayResumeRepository{resumeRepository: *base, receipts: map[string]MutationResult{},
		digests: map[string][32]byte{}}
	flaky := &flakyResumeResolver{resumeResolver: *resolver}
	domain, err := NewProductionDomain(repository, flaky)
	if err != nil {
		t.Fatal(err)
	}
	return domain, repository, flaky, actor
}

// 报告 B-补1：恢复成功（或上报结果未知）后，同 key 同请求重试回放原回执并补投上报，不再新建回执、不再换身份代际。
func TestProductionResumeExactRetryReplaysPersistedReceipt(t *testing.T) {
	for _, failReport := range []bool{false, true} {
		domain, repository, resolver, actor := replayResumeFixture(t)
		resolver.failReport = failReport
		request := resumeRequest(actor, repository.head)
		first, err := domain.Mutate(context.Background(), actor, request)
		if failReport != errors.Is(err, ErrResultUnknown) || !failReport && (err != nil || first.Installation.Status != StatusEnabled) {
			t.Fatalf("failReport=%v first=%+v err=%v", failReport, first.Installation.Status, err)
		}
		generation := repository.head.Installation.IdentityGeneration
		// 授权端快照此时已是 enabled（上报成功）或仍 disabled（上报未达），回放都不依赖它。
		if !failReport {
			resolver.remote[0].AuthorizationStatus, resolver.remote[0].PausedBy = StatusEnabled, ""
		}
		resolver.failReport = false
		second, err := domain.Mutate(context.Background(), actor, request)
		if err != nil || second.Installation.Status != StatusEnabled {
			t.Fatalf("failReport=%v exact retry status=%s err=%v", failReport, second.Installation.Status, err)
		}
		if len(repository.applied) != 1 || len(repository.receipts) != 1 ||
			repository.head.Installation.IdentityGeneration != generation || len(resolver.reported) != 2 ||
			resolver.reported[1].ID != resolver.reported[0].ID {
			t.Fatalf("failReport=%v applied=%d receipts=%d generation=%d/%d reported=%d", failReport,
				len(repository.applied), len(repository.receipts), repository.head.Installation.IdentityGeneration,
				generation, len(resolver.reported))
		}
		// 新 key 的恢复仍走状态门禁：已启用不能再恢复。
		fresh := request
		fresh.IdempotencyKey = "resume-key-2"
		if _, err := domain.Mutate(context.Background(), actor, fresh); !errors.Is(err, ErrTransitionInvalid) {
			t.Fatalf("failReport=%v fresh resume of enabled err=%v", failReport, err)
		}
		// 同 key 不同请求：换 revision 不是这次恢复的下一版，按状态拒绝；换 request_id 摘要冲突。都不回放、不补投。
		changed := request
		changed.ExpectedRevision++
		if _, err := domain.Mutate(context.Background(), actor, changed); !errors.Is(err, ErrTransitionInvalid) {
			t.Fatalf("failReport=%v changed revision err=%v", failReport, err)
		}
		otherActor := actor
		otherActor.RequestID = "resume-request-other"
		other := request
		other.RequestID = otherActor.RequestID
		if _, err := domain.Mutate(context.Background(), otherActor, other); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("failReport=%v changed request err=%v", failReport, err)
		}
		if len(resolver.reported) != 2 {
			t.Fatalf("failReport=%v refused retries reported=%d", failReport, len(resolver.reported))
		}
	}
}

// B-补1 反控：已有原回执的重试仍拒绝运营/安全暂停、撤销、结束、本地卸载/再暂停与权限漂移，不补投。
func TestProductionResumeRetryKeepsSafetyGuards(t *testing.T) {
	for name, setup := range map[string]struct {
		remoteStatus, pausedBy, local string
		drift                         bool
		want                          error
	}{
		"operator pause":     {StatusDisabled, PausedByOperator, StatusEnabled, false, ErrPlatformPaused},
		"service pause":      {StatusDisabled, PausedByService, StatusEnabled, false, ErrPlatformPaused},
		"revoked":            {"revoked", "", StatusEnabled, false, ErrFactDenied},
		"ended":              {"ended", "", StatusEnabled, false, ErrFactDenied},
		"uninstalled":        {StatusEnabled, "", StatusUninstalled, false, ErrTransitionInvalid},
		"paused again":       {StatusDisabled, PausedByInstallation, StatusDisabled, false, ErrTransitionInvalid},
		"permission drifted": {StatusEnabled, "", StatusEnabled, true, ErrFactDenied},
	} {
		t.Run(name, func(t *testing.T) {
			domain, repository, resolver, actor := replayResumeFixture(t)
			request := resumeRequest(actor, repository.head)
			if _, err := domain.Mutate(context.Background(), actor, request); err != nil {
				t.Fatalf("first resume: %v", err)
			}
			resolver.remote[0].AuthorizationStatus, resolver.remote[0].PausedBy = setup.remoteStatus, setup.pausedBy
			if setup.drift {
				resolver.remote[0].Installation.ApprovedScopes = append(resolver.remote[0].Installation.ApprovedScopes, "zz.extra")
			}
			repository.head.Installation.Status = setup.local
			if setup.local != StatusEnabled {
				repository.head.Installation.Revision++
			}
			if _, err := domain.Mutate(context.Background(), actor, request); !errors.Is(err, setup.want) {
				t.Fatalf("retry err=%v want %v", err, setup.want)
			}
			if len(repository.applied) != 1 || len(resolver.reported) != 1 {
				t.Fatalf("refused retry wrote applied=%d reported=%d", len(repository.applied), len(resolver.reported))
			}
		})
	}
}
