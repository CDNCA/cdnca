package plugininstallation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

// memoryLedgerRepository is resumeRepository plus the migration 684 ledger: receipts in commit order, acknowledged
// ones by ID, failed ones (backing off until the test clears failures) by ID. marked, when set, receives every
// acknowledged receipt ID; pendingErr fails PendingAuthorizations.
type memoryLedgerRepository struct {
	resumeRepository
	receipts   []Receipt
	reported   map[uuid.UUID]uint64
	failures   map[uuid.UUID]int
	marked     chan uuid.UUID
	pendingErr error
}

func (repository *memoryLedgerRepository) Apply(ctx context.Context, actor Actor, command Command,
	verifier CandidateVerifier) (MutationResult, error) {
	result, err := repository.resumeRepository.Apply(ctx, actor, command, verifier)
	if err != nil {
		return result, err
	}
	if command.Action == ActionDisable {
		result.Installation.Status, result.Receipt.Result = StatusDisabled, ReceiptDisabled
		result.Receipt.Snapshot = cloneInstallation(result.Installation)
	}
	result.Receipt.AuthorizationID = command.AuthorizationID
	result.Receipt.ToRevision = result.Installation.Revision
	repository.receipts = append(repository.receipts, result.Receipt)
	repository.head.Installation = cloneInstallation(result.Installation)
	return result, nil
}

func (repository *memoryLedgerRepository) UnreportedReceipts(_ context.Context, _, authorizationID uuid.UUID,
	limit int) ([]Receipt, error) {
	out := []Receipt{}
	for _, receipt := range repository.receipts {
		if _, done := repository.reported[receipt.ID]; !done && len(out) < limit &&
			(authorizationID == uuid.Nil || receipt.AuthorizationID == authorizationID) {
			out = append(out, receipt)
		}
	}
	return out, nil
}

func (repository *memoryLedgerRepository) PendingAuthorizations(_ context.Context, _ uuid.UUID,
	authorizationIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	if repository.pendingErr != nil {
		return nil, repository.pendingErr
	}
	pending := map[uuid.UUID]bool{}
	for _, receipt := range repository.receipts {
		if _, done := repository.reported[receipt.ID]; !done && slices.Contains(authorizationIDs, receipt.AuthorizationID) {
			pending[receipt.AuthorizationID] = true
		}
	}
	return pending, nil
}

func (repository *memoryLedgerRepository) DueReports(_ context.Context, _ uuid.UUID, limit int) ([]Receipt, error) {
	seen := map[uuid.UUID]bool{}
	due := []Receipt{}
	for _, receipt := range repository.receipts {
		if _, done := repository.reported[receipt.ID]; done || seen[receipt.AuthorizationID] {
			continue
		}
		seen[receipt.AuthorizationID] = true
		if repository.failures[receipt.ID] == 0 && len(due) < limit {
			due = append(due, receipt)
		}
	}
	return due, nil
}

func (repository *memoryLedgerRepository) MarkReported(_ context.Context, receiptID uuid.UUID, revision uint64) error {
	if revision == 0 {
		return ErrInvalidInput
	}
	repository.reported[receiptID] = revision
	if repository.marked != nil {
		repository.marked <- receiptID
	}
	return nil
}

func (repository *memoryLedgerRepository) RecordReportFailure(_ context.Context, receiptID uuid.UUID,
	base, maxWait time.Duration) (int, time.Duration, error) {
	if repository.failures == nil {
		repository.failures = map[uuid.UUID]int{}
	}
	repository.failures[receiptID]++
	return repository.failures[receiptID], min(maxWait, base<<min(repository.failures[receiptID], 5)), nil
}

// orderedReportResolver answers reports in order; failWith refuses every call, or only those of failFor when set.
type orderedReportResolver struct {
	resumeResolver
	failWith error
	failFor  uuid.UUID
}

func (resolver *orderedReportResolver) ReportLifecycle(_ context.Context, request LifecycleReportRequest) (LifecycleReportResult, error) {
	resolver.reported = append(resolver.reported, request.Receipt)
	if resolver.failWith != nil && (resolver.failFor == uuid.Nil || resolver.failFor == request.Receipt.AuthorizationID) {
		return LifecycleReportResult{}, resolver.failWith
	}
	return LifecycleReportResult{AuthorizationID: request.Receipt.AuthorizationID,
		LifecycleRevision: request.Receipt.ToRevision + 10}, nil
}

// 账本里同一授权的未送达回执按修订顺序补报，遇到失败即停（后面的只会被判过期）；
// 其他授权照常补报；全部送达后详情为 synced，不再调用授权端。
func TestLicenseReportsReplayInRevisionOrderAndStopAtFailure(t *testing.T) {
	first, second, other := uuid.New(), uuid.New(), uuid.New()
	authorization, otherAuthorization := uuid.New(), uuid.New()
	repository := &memoryLedgerRepository{reported: map[uuid.UUID]uint64{}, receipts: []Receipt{
		{ID: first, AuthorizationID: authorization, ToRevision: 2},
		{ID: second, AuthorizationID: authorization, ToRevision: 3},
		{ID: other, AuthorizationID: otherAuthorization, ToRevision: 2},
	}}
	resolver := &orderedReportResolver{failWith: licenseCallError{cause: "timeout", err: ErrFactUnavailable}}
	domain, err := NewProductionDomain(repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	failedID, err := domain.deliverAll(context.Background(), repository)
	if !errors.Is(err, ErrFactUnavailable) || LicenseReportCause(err) != "timeout" || failedID != authorization {
		t.Fatalf("unreachable license: authorization=%s err=%v cause=%s", failedID, err, LicenseReportCause(err))
	}
	// One attempt per authorization: the second receipt of the failed one is not sent this round; each failed
	// head backs off on its own.
	if len(resolver.reported) != 2 || resolver.reported[0].ID != first || resolver.reported[1].ID != other ||
		len(repository.reported) != 0 || repository.failures[first] != 1 || repository.failures[other] != 1 ||
		repository.failures[second] != 0 {
		t.Fatalf("attempts=%v reported=%v failures=%v", resolver.reported, repository.reported, repository.failures)
	}
	// While they back off a round sends nothing.
	resolver.failWith, resolver.reported = nil, nil
	if _, err := domain.deliverAll(context.Background(), repository); err != nil || len(resolver.reported) != 0 {
		t.Fatalf("round while backing off sent %d err=%v", len(resolver.reported), err)
	}
	repository.failures = nil // the backoff ran out
	if _, err := domain.deliverAll(context.Background(), repository); err != nil {
		t.Fatal(err)
	}
	if got := []uuid.UUID{resolver.reported[0].ID, resolver.reported[1].ID, resolver.reported[2].ID}; !slices.Equal(got,
		[]uuid.UUID{first, second, other}) || repository.reported[first] != 12 || repository.reported[second] != 13 {
		t.Fatalf("replay order=%v reported=%v", got, repository.reported)
	}
	resolver.reported = nil
	if state := domain.syncLicense(context.Background(), "get-request", "get", authorization); state != LicenseSyncSynced ||
		len(resolver.reported) != 0 {
		t.Fatalf("synced details state=%s reports=%d", state, len(resolver.reported))
	}
}

// 排在前面的授权持续失败时只退避它自己，后面的授权每轮照常签收；
// 它恢复后按修订顺序补齐。
func TestLicenseReportsFailingAuthorizationDoesNotStarveOthers(t *testing.T) {
	stuck, healthy := uuid.MustParse("00000000-0000-7000-8000-000000000001"), uuid.MustParse("ffffffff-ffff-7fff-bfff-ffffffffffff")
	repository := &memoryLedgerRepository{reported: map[uuid.UUID]uint64{}}
	for revision := uint64(2); revision < 2+150; revision++ {
		repository.receipts = append(repository.receipts, Receipt{ID: uuid.New(), AuthorizationID: stuck, ToRevision: revision})
	}
	late := Receipt{ID: uuid.New(), AuthorizationID: healthy, ToRevision: 2}
	repository.receipts = append(repository.receipts, late)
	resolver := &orderedReportResolver{failWith: licenseCallError{cause: "refused:invalid_request", err: ErrFactDenied},
		failFor: stuck}
	domain, err := NewProductionDomain(repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	failedID, err := domain.deliverAll(context.Background(), repository)
	if failedID != stuck || err == nil || repository.reported[late.ID] != 12 || len(resolver.reported) != 2 ||
		repository.failures[repository.receipts[0].ID] != 1 {
		t.Fatalf("first round failed=%s err=%v reports=%d reported=%v", failedID, err, len(resolver.reported), repository.reported)
	}
	healthyNext := Receipt{ID: uuid.New(), AuthorizationID: healthy, ToRevision: 3}
	repository.receipts = append(repository.receipts, healthyNext)
	resolver.reported = nil
	if _, err := domain.deliverAll(context.Background(), repository); err != nil || len(resolver.reported) != 1 ||
		repository.reported[healthyNext.ID] != 13 {
		t.Fatalf("second round reports=%d err=%v", len(resolver.reported), err)
	}
	resolver.failWith, resolver.reported, repository.failures = nil, nil, nil
	if _, err := domain.deliverAll(context.Background(), repository); err != nil || len(resolver.reported) != 150 {
		t.Fatalf("recovered round reports=%d err=%v", len(resolver.reported), err)
	}
	for index, receipt := range resolver.reported {
		if receipt.AuthorizationID != stuck || receipt.ToRevision != uint64(2+index) || repository.reported[receipt.ID] == 0 {
			t.Fatalf("recovered report %d=%+v", index, receipt)
		}
	}
}

// 打开详情补报，每批 20、最多 10 批；199/200 条在这一次就补完、返回 synced，
// 201 条剩 1 条、返回 pending；顺序按修订号。耗完十轮后的复查读失败时保持 pending。
func TestDetailsReportExactBatchBoundary(t *testing.T) {
	for _, total := range []int{199, 200, 201} {
		authorization := uuid.New()
		repository := &memoryLedgerRepository{reported: map[uuid.UUID]uint64{}}
		for revision := range total {
			repository.receipts = append(repository.receipts, Receipt{ID: uuid.New(), AuthorizationID: authorization,
				ToRevision: uint64(revision + 1)})
		}
		resolver := &orderedReportResolver{}
		domain, err := NewProductionDomain(repository, resolver)
		if err != nil {
			t.Fatal(err)
		}
		want, wantReported := LicenseSyncSynced, total
		if total > licenseReportBatch*licenseReportRounds {
			want, wantReported = LicenseSyncPending, licenseReportBatch*licenseReportRounds
		}
		if state := domain.syncLicense(context.Background(), "get-request", "get", authorization); state != want ||
			len(resolver.reported) != wantReported || len(repository.reported) != wantReported {
			t.Fatalf("total=%d state=%s reports=%d acknowledged=%d", total, state, len(resolver.reported),
				len(repository.reported))
		}
		for index, receipt := range resolver.reported {
			if receipt.ToRevision != uint64(index+1) {
				t.Fatalf("total=%d report %d to_revision=%d", total, index, receipt.ToRevision)
			}
		}
	}
	authorization := uuid.New()
	repository := &unreadableAfterRoundsLedger{memoryLedgerRepository: memoryLedgerRepository{reported: map[uuid.UUID]uint64{}}}
	for revision := range licenseReportBatch * licenseReportRounds {
		repository.receipts = append(repository.receipts, Receipt{ID: uuid.New(), AuthorizationID: authorization,
			ToRevision: uint64(revision + 1)})
	}
	domain, err := NewProductionDomain(repository, &orderedReportResolver{})
	if err != nil {
		t.Fatal(err)
	}
	if state := domain.syncLicense(context.Background(), "get-request", "get", authorization); state != LicenseSyncPending {
		t.Fatalf("unreadable recheck state=%s", state)
	}
}

// unreadableAfterRoundsLedger fails the read that follows the last delivery round.
type unreadableAfterRoundsLedger struct {
	memoryLedgerRepository
	reads int
}

func (repository *unreadableAfterRoundsLedger) UnreportedReceipts(ctx context.Context, installationID,
	authorizationID uuid.UUID, limit int) ([]Receipt, error) {
	repository.reads++
	if repository.reads > licenseReportRounds {
		return nil, ErrStorageUnavailable
	}
	return repository.memoryLedgerRepository.UnreportedReceipts(ctx, installationID, authorizationID, limit)
}

// 列表按本页授权查未签收回执；账本读失败时显示待确认（pending），不显示已同步。
func TestListLicenseSyncPendingWhenLedgerUnreadable(t *testing.T) {
	tenantID := uuid.New()
	local := mergeView(tenantID, "acme.cache", "1.2.0", StatusEnabled, "")
	repository := &memoryLedgerRepository{resumeRepository: resumeRepository{head: local}, reported: map[uuid.UUID]uint64{},
		pendingErr: ErrStorageUnavailable}
	domain, err := NewProductionDomain(repository, &orderedReportResolver{})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "list-request"}
	page, err := domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50})
	if err != nil || len(page.Items) != 1 || page.Items[0].LicenseSync != LicenseSyncPending {
		t.Fatalf("list with an unreadable ledger=%+v err=%v", page.Items, err)
	}
	repository.pendingErr = nil
	page, err = domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50})
	if err != nil || len(page.Items) != 1 || page.Items[0].LicenseSync != LicenseSyncSynced {
		t.Fatalf("list with nothing pending=%+v err=%v", page.Items, err)
	}
}

// 暂停（本机已提交）后上报超时：请求成功、状态已暂停、license_sync=pending；列表同样标 pending；
// 后台补报成功后变为 synced。同 key 重复点暂停只回放原回执，不产生第二条回执。
func TestPauseCommittedLicenseTimeoutAnswersPausedPending(t *testing.T) {
	tenantID := uuid.New()
	local := mergeView(tenantID, "acme.cache", "1.2.0", StatusEnabled, "")
	repository := &memoryLedgerRepository{resumeRepository: resumeRepository{head: local}, reported: map[uuid.UUID]uint64{}}
	resolver := &orderedReportResolver{failWith: licenseCallError{cause: "timeout", err: ErrFactUnavailable}}
	domain, err := NewProductionDomain(repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), SessionID: uuid.New(), TenantID: tenantID, RequestID: "pause-request"}
	request := MutationRequest{TenantID: tenantID, AuthorizationID: local.Installation.AuthorizationID,
		Action: ActionDisable, ExpectedRevision: local.Installation.Revision, IdempotencyKey: "pause-key",
		RequestID: actor.RequestID}
	paused, err := domain.Mutate(context.Background(), actor, request)
	if err != nil || paused.Installation.Status != StatusDisabled || paused.LicenseSync != LicenseSyncPending ||
		len(repository.receipts) != 1 {
		t.Fatalf("pause status=%s sync=%s receipts=%d err=%v", paused.Installation.Status, paused.LicenseSync,
			len(repository.receipts), err)
	}
	page, err := domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50})
	if err != nil || len(page.Items) != 1 || page.Items[0].LicenseSync != LicenseSyncPending {
		t.Fatalf("list=%+v err=%v", page.Items, err)
	}
	// The failed pause report backs off in the background; once that runs out the next round delivers it.
	if repository.failures[repository.receipts[0].ID] == 0 {
		t.Fatal("failed pause report not backing off")
	}
	resolver.failWith, repository.failures = nil, nil
	if _, err := domain.deliverAll(context.Background(), repository); err != nil {
		t.Fatal(err)
	}
	page, err = domain.List(context.Background(), actor, ListRequest{TenantID: tenantID, Limit: 50})
	if err != nil || len(page.Items) != 1 || page.Items[0].LicenseSync != LicenseSyncSynced ||
		repository.reported[repository.receipts[0].ID] == 0 {
		t.Fatalf("after background replay list=%+v reported=%v err=%v", page.Items, repository.reported, err)
	}
}

// 后台循环：启动即补报一轮，ctx 结束即退出；没有账本时拒绝启动。
// 等账本的签收信号再停，不在测试 goroutine 里读替身被后台追加的切片。
func TestRunLicenseReportsDeliversAndStops(t *testing.T) {
	receipt := Receipt{ID: uuid.New(), AuthorizationID: uuid.New(), ToRevision: 2}
	repository := &memoryLedgerRepository{reported: map[uuid.UUID]uint64{}, receipts: []Receipt{receipt},
		marked: make(chan uuid.UUID, 1)}
	resolver := &orderedReportResolver{}
	domain, err := NewProductionDomain(repository, resolver)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- domain.RunLicenseReports(ctx, time.Hour) }()
	select {
	case <-repository.marked:
	case <-time.After(5 * time.Second):
		t.Error("background round did not acknowledge the receipt")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || repository.reported[receipt.ID] != 12 {
		t.Fatalf("run err=%v reported=%v", err, repository.reported)
	}
	plain, _ := NewProductionDomain(&resumeRepository{}, resolver)
	if err := plain.RunLicenseReports(context.Background(), time.Second); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("run without a ledger err=%v", err)
	}
}

// 写操作的应答：200、状态已暂停、license_sync=pending（不再是 503 plugin_installation_result_unknown）。
func TestHandlerAnswersCommittedPauseWithLicenseSyncPending(t *testing.T) {
	tenantID, authorizationID := uuid.New(), uuid.New()
	view := handlerTestView(tenantID, authorizationID)
	view.Installation.Status, view.LicenseSync = StatusDisabled, LicenseSyncPending
	handler := newHandlerForTest(t, tenantID, &handlerTestDomain{mutationResult: view})
	request := authenticatedHandlerRequest(http.MethodPost, "/v1/tenant-scopes/"+tenantID.String()+
		"/plugin-installations/"+authorizationID.String()+"/disable", bytes.NewBufferString(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"7"`)
	request.Header.Set("Idempotency-Key", "plugin-pause-pending")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var body struct {
		Installation map[string]any `json:"installation"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
		body.Installation["status"] != StatusDisabled || body.Installation["license_sync"] != LicenseSyncPending {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// 失败原因进日志：超时、不可达、授权端拒绝码、签名应答被拒分开。
func TestLicenseReportCauseNamesTransportAndRefusal(t *testing.T) {
	for want, err := range map[string]error{
		"timeout":                 licenseCallError{cause: "timeout", err: ErrFactUnavailable},
		"refused:lifecycle_stale": licenseCallError{cause: "refused:lifecycle_stale", err: ErrRevisionConflict},
		"response_invalid":        ErrActivationInvalid,
		"context_deadline":        context.DeadlineExceeded,
		"storage":                 ErrStorageUnavailable,
	} {
		if got := LicenseReportCause(err); got != want {
			t.Errorf("cause(%v)=%s want %s", err, got, want)
		}
	}
	if !errors.Is(licenseCallError{cause: "timeout", err: ErrFactUnavailable}, ErrFactUnavailable) {
		t.Fatal("cause wrapper changed the classification")
	}
}
