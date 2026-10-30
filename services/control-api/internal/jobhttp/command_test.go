package jobhttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fixtureCommandAudit struct {
	action string
	result string
	reason string
}

type fixtureCommandReceipt struct {
	digest [32]byte
	jobID  uuid.UUID
	data   Job
}

func (reader *fixtureReader) Execute(ctx context.Context, input CommandInput) (CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return CommandResult{}, err
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.commandCalls++
	if reader.commandErr != nil {
		return CommandResult{}, reader.commandErr
	}
	if input.Audience == AudiencePlatform && input.Principal.ScopeKind != ScopePlatform ||
		input.Audience == AudienceTenant && input.Principal.ScopeKind != ScopeTenant {
		reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
			action: commandAction(input.Operation), result: "denied", reason: "scope_forbidden",
		})
		return CommandResult{}, ErrScopeForbidden
	}
	if input.Operation == CommandReplay && input.Audience != AudiencePlatform {
		reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
			action: commandAction(input.Operation), result: "denied", reason: "scope_forbidden",
		})
		return CommandResult{}, ErrScopeForbidden
	}
	permission := PermissionManage
	if input.Audience == AudiencePlatform {
		permission = PermissionManageAll
	}
	if !input.Principal.HasPermission(permission) &&
		!(input.Audience == AudiencePlatform && input.Principal.HasPermission(PermissionAdmin)) {
		reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
			action: commandAction(input.Operation), result: "denied", reason: "permission_denied",
		})
		return CommandResult{}, ErrPermissionDenied
	}
	if reader.commandKeys == nil {
		reader.commandKeys = make(map[string]fixtureCommandReceipt)
	}
	receiptKey := input.Principal.ScopeID.String() + "/" + input.Principal.UserID.String() + "/" + input.IdempotencyKey
	if receipt, ok := reader.commandKeys[receiptKey]; ok {
		if receipt.digest != input.Digest || receipt.jobID != input.TaskID {
			reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
				action: commandAction(input.Operation), result: "denied", reason: "idempotency_conflict",
			})
			return CommandResult{}, ErrIdempotencyConflict
		}
		return CommandResult{Data: receipt.data, Replayed: true}, nil
	}
	jobIndex := -1
	for index := range reader.jobs {
		job := reader.jobs[index]
		if job.TaskID == input.TaskID &&
			(input.Audience == AudiencePlatform || reader.scopeTenants[input.Principal.ScopeID] == job.TenantID) {
			jobIndex = index
			break
		}
	}
	if jobIndex < 0 {
		reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
			action: commandAction(input.Operation), result: "denied", reason: "not_found",
		})
		return CommandResult{}, ErrNotFound
	}
	original := reader.jobs[jobIndex]
	job := original
	switch input.Operation {
	case CommandCancel:
		if job.Status != StateQueued && job.Status != StateRunning {
			reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
				action: commandAction(input.Operation), result: "denied", reason: "invalid_transition",
			})
			return CommandResult{}, ErrInvalidTransition
		}
		job.Status = StateCancelled
		job.Progress.Completed = job.Progress.Total
		job.Progress.Cancelled += job.Progress.Pending
		job.Progress.Pending = 0
		job.FailureCode = "cancelled"
		job.CompletedAt = timePointer(fixtureNow)
		job.UpdatedAt = fixtureNow
	case CommandRetry:
		if job.Status != StateFailed && job.Status != StatePartialFailed {
			reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
				action: commandAction(input.Operation), result: "denied", reason: "invalid_transition",
			})
			return CommandResult{}, ErrInvalidTransition
		}
		if job.Attempt >= job.MaxAttempts {
			reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
				action: commandAction(input.Operation), result: "denied", reason: "retries_exhausted",
			})
			return CommandResult{}, ErrRetriesExhausted
		}
		job.Status = StateQueued
		job.Progress.Completed = job.Progress.Succeeded
		job.Progress.Failed = 0
		job.Progress.Cancelled = 0
		job.Progress.Pending = job.Progress.Total - job.Progress.Succeeded
		job.FailureCode = ""
		job.CompletedAt = nil
		job.UpdatedAt = fixtureNow
	case CommandReplay:
		if job.Status != StateFailed && job.Status != StatePartialFailed || job.Attempt < job.MaxAttempts {
			reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
				action: commandAction(input.Operation), result: "denied", reason: "invalid_transition",
			})
			return CommandResult{}, ErrInvalidTransition
		}
		job.MaxAttempts++
		job.Status = StateQueued
		job.Progress.Completed = job.Progress.Succeeded
		job.Progress.Failed = 0
		job.Progress.Cancelled = 0
		job.Progress.Pending = job.Progress.Total - job.Progress.Succeeded
		job.FailureCode = ""
		job.CompletedAt = nil
		job.UpdatedAt = fixtureNow
	default:
		return CommandResult{}, ErrInvalidRequest
	}
	if reader.failQueue {
		return CommandResult{}, ErrStoreUnavailable
	}
	reader.jobs[jobIndex] = job
	reader.commandKeys[receiptKey] = fixtureCommandReceipt{digest: input.Digest, jobID: input.TaskID, data: job}
	if reader.failAudit {
		reader.jobs[jobIndex] = original
		delete(reader.commandKeys, receiptKey)
		return CommandResult{}, ErrStoreUnavailable
	}
	reader.commandAudits = append(reader.commandAudits, fixtureCommandAudit{
		action: commandAction(input.Operation), result: "success",
	})
	return CommandResult{Data: job}, nil
}

func commandAction(operation CommandOperation) string {
	return "job." + string(operation)
}

func TestCommandDigestCharacterContract(t *testing.T) {
	principal := Principal{
		UserID:    uuid.MustParse("00000000-0000-4000-8000-000000000002"),
		ScopeID:   uuid.MustParse("20000000-0000-4000-8000-000000000001"),
		ScopeKind: ScopeTenant,
	}
	digest := commandDigest(principal, AudienceTenant,
		uuid.MustParse("40000000-0000-4000-8000-000000000001"), CommandCancel)
	const want = "3b508fe079e1e84279d9108c0dc0ccf03eb198ca21673c77014b39cdc0520f42"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("command digest = %s, want %s", got, want)
	}
}

func TestCommandJobSnapshotDetectsWaiterDrift(t *testing.T) {
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000099")
	initial := commandJobSnapshot{
		tenantID: tenantID, tupleVersion: "700", state: string(StateQueued), attempt: 1,
	}
	if !sameCommandJobSnapshot(initial, initial) {
		t.Fatal("identical job snapshots reported drift")
	}
	for _, test := range []struct {
		name   string
		locked commandJobSnapshot
	}{
		{name: "xmin", locked: commandJobSnapshot{
			tenantID: tenantID, tupleVersion: "701", state: string(StateQueued), attempt: 1,
		}},
		{name: "state", locked: commandJobSnapshot{
			tenantID: tenantID, tupleVersion: "700", state: string(StateCancelled), attempt: 1,
		}},
		{name: "attempt", locked: commandJobSnapshot{
			tenantID: tenantID, tupleVersion: "700", state: string(StateQueued), attempt: 2,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if sameCommandJobSnapshot(initial, test.locked) {
				t.Fatalf("waiter drift was not detected: initial=%+v locked=%+v", initial, test.locked)
			}
		})
	}
}

func TestDeniedCommandAuditReplayRequiresExactFacts(t *testing.T) {
	input := CommandInput{
		Principal: Principal{
			UserID:  uuid.MustParse("00000000-0000-4000-8000-000000000099"),
			ScopeID: uuid.MustParse("20000000-0000-4000-8000-000000000099"),
		},
		Audience:  AudienceTenant,
		TaskID:    uuid.MustParse("40000000-0000-4000-8000-000000000099"),
		Operation: CommandCancel, IdempotencyKey: "denied-replay",
		Digest: commandDigest(Principal{
			UserID:    uuid.MustParse("00000000-0000-4000-8000-000000000099"),
			ScopeID:   uuid.MustParse("20000000-0000-4000-8000-000000000099"),
			ScopeKind: ScopeTenant,
		}, AudienceTenant, uuid.MustParse("40000000-0000-4000-8000-000000000099"), CommandCancel),
		RequestID: "denied-request",
	}
	payload, err := json.Marshal(commandAuditPayload(input, "permission_denied", uuid.Nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	stored := storedDeniedCommandAudit{
		resourceType: "background_job", resourceID: input.TaskID.String(), payload: payload,
	}
	if !validDeniedCommandAudit(stored, input, "permission_denied") {
		t.Fatal("exact denied audit facts did not replay")
	}
	stored.resourceID = uuid.NewString()
	if validDeniedCommandAudit(stored, input, "permission_denied") {
		t.Fatal("mismatched denied resource replayed")
	}
	if !errors.Is(commandDenialPublicError("concurrent_state_changed"), ErrInvalidTransition) {
		t.Fatal("concurrent waiter denial did not preserve the public invalid-transition error")
	}
	if !errors.Is(normalizeCommandError(t.Context(), ErrInvalidStoreResponse), ErrInvalidStoreResponse) {
		t.Fatal("invalid denied facts were normalized to store unavailable")
	}
}

func TestValidCommandReceiptUsesLogicalFactsAfterRestore(t *testing.T) {
	principal := Principal{
		UserID:    uuid.MustParse("00000000-0000-4000-8000-000000000098"),
		ScopeID:   uuid.MustParse("20000000-0000-4000-8000-000000000098"),
		ScopeKind: ScopeTenant,
	}
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000098")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000098")
	input := CommandInput{
		Principal: principal, Audience: AudienceTenant, TaskID: taskID,
		Operation: CommandCancel, IdempotencyKey: "restored-receipt",
		Digest:    commandDigest(principal, AudienceTenant, taskID, CommandCancel),
		RequestID: "restored-command-request",
	}
	job := fixtureJob(taskID, tenantID, StateCancelled, fixtureNow)
	payload, err := json.Marshal(commandAuditPayload(input, "", tenantID, &job))
	if err != nil {
		t.Fatal(err)
	}
	actorID := principal.UserID
	receipt := storedCommandReceipt{
		digest: input.Digest[:], audience: string(input.Audience), tenantID: tenantID,
		jobID: taskID, operation: string(input.Operation), requestID: input.RequestID,
		result: job, createdAt: fixtureNow, completedAt: fixtureNow.Add(time.Second),
		auditScopeID: principal.ScopeID, auditActorUserID: &actorID,
		auditAction: commandAuditAction(input.Operation), auditResource: taskID.String(),
		auditRequestID: input.RequestID, auditResult: "success", auditPayload: payload,
	}
	if !validCommandReceipt(receipt, input) {
		t.Fatal("logically restored receipt with exact immutable facts did not replay")
	}

	mismatched := receipt
	mismatched.auditAction = commandAuditAction(CommandRetry)
	if validCommandReceipt(mismatched, input) {
		t.Fatal("receipt with mismatched immutable audit action replayed")
	}
	mismatched = receipt
	mismatched.auditPayload = []byte(`{"audience":"tenant"}`)
	if validCommandReceipt(mismatched, input) {
		t.Fatal("receipt with mismatched immutable audit payload replayed")
	}
}

func TestServiceCommandsEnforceRBACScopeReplayAndTransitions(t *testing.T) {
	tenantScope := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	foreignScope := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000001")
	foreignTenantID := uuid.MustParse("30000000-0000-4000-8000-000000000002")
	queuedID := uuid.MustParse("40000000-0000-4000-8000-000000000001")
	failedID := uuid.MustParse("40000000-0000-4000-8000-000000000002")
	exhaustedID := uuid.MustParse("40000000-0000-4000-8000-000000000003")
	foreignID := uuid.MustParse("40000000-0000-4000-8000-000000000004")
	failed := fixtureJob(failedID, tenantID, StateFailed, fixtureNow)
	exhausted := fixtureJob(exhaustedID, tenantID, StateFailed, fixtureNow)
	exhausted.MaxAttempts = exhausted.Attempt
	reader := &fixtureReader{
		jobs: []Job{
			fixtureJob(queuedID, tenantID, StateQueued, fixtureNow), failed, exhausted,
			fixtureJob(foreignID, foreignTenantID, StateQueued, fixtureNow),
		},
		scopeTenants: map[uuid.UUID]uuid.UUID{tenantScope: tenantID, foreignScope: foreignTenantID},
	}
	service := fixtureService(reader)
	tenant := tenantPrincipal(tenantScope)
	tenant.Permissions[PermissionManage] = struct{}{}

	cancel, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedID, Operation: CommandCancel, IdempotencyKey: "cancel-1",
	})
	if err != nil || cancel.Replayed || cancel.Data.Status != StateCancelled {
		t.Fatalf("cancel = %+v, err=%v", cancel, err)
	}
	replay, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedID, Operation: CommandCancel, IdempotencyKey: "cancel-1",
	})
	if err != nil || !replay.Replayed || replay.Data.Status != StateCancelled {
		t.Fatalf("cancel replay = %+v, err=%v", replay, err)
	}
	if _, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: failedID, Operation: CommandRetry, IdempotencyKey: "cancel-1",
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different digest error = %v", err)
	}

	retry, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: failedID, Operation: CommandRetry, IdempotencyKey: "retry-1",
	})
	if err != nil || retry.Data.Status != StateQueued || retry.Data.Attempt != failed.Attempt {
		t.Fatalf("retry = %+v, err=%v", retry, err)
	}
	reader.mu.Lock()
	for index := range reader.jobs {
		if reader.jobs[index].TaskID == failedID {
			reader.jobs[index].Status = StateRunning
			reader.jobs[index].Attempt++
			reader.jobs[index].UpdatedAt = fixtureNow.Add(time.Second)
		}
	}
	reader.mu.Unlock()
	retryReplay, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: failedID, Operation: CommandRetry, IdempotencyKey: "retry-1",
	})
	if err != nil || !retryReplay.Replayed || !reflect.DeepEqual(retryReplay.Data, retry.Data) {
		t.Fatalf("retry replay = %+v, err=%v, want immutable %+v", retryReplay, err, retry.Data)
	}
	if _, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: exhaustedID, Operation: CommandRetry, IdempotencyKey: "retry-exhausted",
	}); !errors.Is(err, ErrRetriesExhausted) {
		t.Fatalf("exhausted error = %v", err)
	}
	if _, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: foreignID, Operation: CommandCancel, IdempotencyKey: "foreign",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant error = %v", err)
	}

	readOnly := tenantPrincipal(tenantScope)
	if _, err := service.Command(t.Context(), readOnly, CommandRequest{
		Audience: AudienceTenant, TaskID: exhaustedID, Operation: CommandCancel, IdempotencyKey: "read-only",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("read-only error = %v", err)
	}
	platform := platformPrincipal(platformScope)
	platform.Permissions[PermissionManageAll] = struct{}{}
	if _, err := service.Command(t.Context(), platform, CommandRequest{
		Audience: AudiencePlatform, TaskID: foreignID, Operation: CommandCancel, IdempotencyKey: "platform-cancel",
	}); err != nil {
		t.Fatalf("platform command: %v", err)
	}
	if _, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudiencePlatform, TaskID: failedID, Operation: CommandRetry, IdempotencyKey: "wrong-audience",
	}); !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("wrong audience error = %v", err)
	}
	// 只读与错 audience 两次请求在 Service 凭据校验处拒绝，不进入 store，故无 store 审计（API-JOBS-01）。
	if got := len(reader.commandAudits); got != 6 {
		t.Fatalf("command audits = %+v (count %d), want 6", reader.commandAudits, got)
	}
}

func TestServiceCommandsHaveSingleConcurrentWinner(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000010")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000010")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000010")
	reader := &fixtureReader{
		jobs:         []Job{fixtureJob(taskID, tenantID, StateQueued, fixtureNow)},
		scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
	}
	principal := tenantPrincipal(scopeID)
	principal.Permissions[PermissionManage] = struct{}{}
	service := fixtureService(reader)
	results := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(1)
	for _, key := range []string{"winner-a", "winner-b"} {
		go func(key string) {
			start.Wait()
			_, err := service.Command(context.Background(), principal, CommandRequest{
				Audience: AudienceTenant, TaskID: taskID, Operation: CommandCancel, IdempotencyKey: key,
			})
			results <- err
		}(key)
	}
	start.Done()
	succeeded, rejected := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrInvalidTransition):
			rejected++
		default:
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent results success=%d rejected=%d", succeeded, rejected)
	}
}

func TestServiceCommandsReturnIdenticalDataForConcurrentSameKey(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000011")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000011")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000011")
	reader := &fixtureReader{
		jobs:         []Job{fixtureJob(taskID, tenantID, StateQueued, fixtureNow)},
		scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
	}
	principal := tenantPrincipal(scopeID)
	principal.Permissions[PermissionManage] = struct{}{}
	service := fixtureService(reader)
	results := make(chan CommandResult, 2)
	errors := make(chan error, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			result, err := service.Command(context.Background(), principal, CommandRequest{
				Audience: AudienceTenant, TaskID: taskID, Operation: CommandCancel, IdempotencyKey: "same-key",
			})
			results <- result
			errors <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("same-key command: %v", err)
		}
	}
	collected := make([]CommandResult, 0, 2)
	for result := range results {
		collected = append(collected, result)
	}
	if len(collected) != 2 || collected[0].Replayed == collected[1].Replayed ||
		!reflect.DeepEqual(collected[0].Data, collected[1].Data) {
		t.Fatalf("same-key results = %+v", collected)
	}
}

func TestServiceCommandFailuresRollbackMutationAndReceipt(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000020")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000020")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000020")
	principal := tenantPrincipal(scopeID)
	principal.Permissions[PermissionManage] = struct{}{}
	for _, test := range []struct {
		name      string
		failAudit bool
		failQueue bool
	}{
		{name: "audit", failAudit: true},
		{name: "queue", failQueue: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &fixtureReader{
				jobs:         []Job{fixtureJob(taskID, tenantID, StateQueued, fixtureNow)},
				scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
				failAudit:    test.failAudit, failQueue: test.failQueue,
			}
			service := fixtureService(reader)
			input := CommandRequest{
				Audience: AudienceTenant, TaskID: taskID, Operation: CommandCancel, IdempotencyKey: "rollback",
			}
			if _, err := service.Command(t.Context(), principal, input); !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("first error = %v", err)
			}
			reader.failAudit, reader.failQueue = false, false
			result, err := service.Command(t.Context(), principal, input)
			if err != nil || result.Replayed || result.Data.Status != StateCancelled {
				t.Fatalf("after rollback = %+v, err=%v", result, err)
			}
		})
	}
}

func TestHandlerCommandContract(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000030")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000030")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000030")
	reader := &fixtureReader{
		jobs:         []Job{fixtureJob(taskID, tenantID, StateQueued, fixtureNow)},
		scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
	}
	principal := tenantPrincipal(scopeID)
	principal.Permissions[PermissionManage] = struct{}{}
	handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
		return principal, nil
	}, HandlerConfig{})
	request := httptest.NewRequest(http.MethodPost, "/v1/jobs/"+taskID.String()+"/cancel", strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "handler-cancel")
	request.Header.Set("If-Match", `"1"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var result CommandResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Replayed || result.Data.TaskID != taskID || result.Data.Status != StateCancelled {
		t.Fatalf("response = %+v", result)
	}

	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/v1/jobs/"+taskID.String()+"/cancel", nil))
	if get.Code != http.StatusMethodNotAllowed || get.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET command status=%d allow=%q", get.Code, get.Header().Get("Allow"))
	}
	postDetail := httptest.NewRecorder()
	handler.ServeHTTP(postDetail, httptest.NewRequest(http.MethodPost, "/v1/jobs/"+taskID.String(), nil))
	if postDetail.Code != http.StatusMethodNotAllowed || postDetail.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST detail status=%d allow=%q", postDetail.Code, postDetail.Header().Get("Allow"))
	}
}

func TestHandlerRejectsInvalidCommandEnvelopeBeforeStore(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000031")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000031")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000031")
	principal := tenantPrincipal(scopeID)
	principal.Permissions[PermissionManage] = struct{}{}
	tests := []struct {
		name        string
		body        string
		contentType string
		key         []string
		query       string
	}{
		{name: "missing content type", body: "{}", key: []string{"valid"}},
		{name: "content type parameters", body: "{}", contentType: "application/json; charset=utf-8", key: []string{"valid"}},
		{name: "empty body", contentType: "application/json", key: []string{"valid"}},
		{name: "null body", body: "null", contentType: "application/json", key: []string{"valid"}},
		{name: "array body", body: "[]", contentType: "application/json", key: []string{"valid"}},
		{name: "member body", body: `{"unexpected":true}`, contentType: "application/json", key: []string{"valid"}},
		{name: "multiple json", body: "{} {}", contentType: "application/json", key: []string{"valid"}},
		{name: "over limit", body: strings.Repeat(" ", maximumCommandBodyBytes+1) + "{}", contentType: "application/json", key: []string{"valid"}},
		{name: "missing key", body: "{}", contentType: "application/json"},
		{name: "duplicate key", body: "{}", contentType: "application/json", key: []string{"valid", "other"}},
		{name: "invalid key", body: "{}", contentType: "application/json", key: []string{"contains space"}},
		{name: "overlong key", body: "{}", contentType: "application/json", key: []string{strings.Repeat("a", 129)}},
		{name: "query string", body: "{}", contentType: "application/json", key: []string{"valid"}, query: "?force=true"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &fixtureReader{
				jobs:         []Job{fixtureJob(taskID, tenantID, StateQueued, fixtureNow)},
				scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
			}
			handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
				return principal, nil
			}, HandlerConfig{})
			request := httptest.NewRequest(http.MethodPost,
				"/v1/jobs/"+taskID.String()+"/cancel"+test.query, bytes.NewBufferString(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			for _, key := range test.key {
				request.Header.Add("Idempotency-Key", key)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || errorCode(t, response.Body.Bytes()) != "job_invalid_request" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if reader.commandCalls != 0 {
				t.Fatalf("command calls=%d, want 0", reader.commandCalls)
			}
		})
	}
}

func TestPublicCommandErrorsAreStable(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{err: ErrIdempotencyConflict, status: http.StatusConflict, code: "job_idempotency_conflict"},
		{err: ErrInvalidTransition, status: http.StatusConflict, code: "job_invalid_transition"},
		{err: ErrRetriesExhausted, status: http.StatusConflict, code: "job_retries_exhausted"},
		{err: ErrStoreUnavailable, status: http.StatusServiceUnavailable, code: "job_store_unavailable"},
	}
	for _, test := range tests {
		status, code, _ := publicError(test.err)
		if status != test.status || code != test.code {
			t.Fatalf("publicError(%v) = (%d,%q), want (%d,%q)", test.err, status, code, test.status, test.code)
		}
	}
}

// strictCommandStore 不做任何权限判断，模拟真实 PostgresReader 只查所属用户角色、
// 不看本次凭据有效权限的行为，避免替身比生产多做授权导致假绿（API-JOBS-01）。
type strictCommandStore struct {
	*fixtureReader
	executeCalls int
}

func (store *strictCommandStore) Execute(_ context.Context, input CommandInput) (CommandResult, error) {
	store.executeCalls++
	return CommandResult{Data: fixtureJob(input.TaskID, uuid.Nil, StateCancelled, fixtureNow)}, nil
}

func TestServiceCommandRequiresCredentialPermissionBeforeExecute(t *testing.T) {
	tenantScope := uuid.MustParse("20000000-0000-4000-8000-000000000061")
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000061")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000061")
	withPermissions := func(principal Principal, permissions ...string) Principal {
		principal.Permissions = map[string]struct{}{}
		for _, permission := range permissions {
			principal.Permissions[permission] = struct{}{}
		}
		return principal
	}
	tests := []struct {
		name      string
		principal Principal
		audience  Audience
		operation CommandOperation
		want      error
	}{
		{name: "tenant read-only key cancel", principal: withPermissions(tenantPrincipal(tenantScope), PermissionRead),
			audience: AudienceTenant, operation: CommandCancel, want: ErrPermissionDenied},
		{name: "tenant read-only key retry", principal: withPermissions(tenantPrincipal(tenantScope), PermissionRead),
			audience: AudienceTenant, operation: CommandRetry, want: ErrPermissionDenied},
		{name: "tenant key without jobs permissions", principal: withPermissions(tenantPrincipal(tenantScope), "sites.read"),
			audience: AudienceTenant, operation: CommandCancel, want: ErrPermissionDenied},
		{name: "tenant manage_all does not grant tenant command", principal: withPermissions(tenantPrincipal(tenantScope), PermissionManageAll, PermissionAdmin),
			audience: AudienceTenant, operation: CommandRetry, want: ErrPermissionDenied},
		{name: "tenant manage cancel", principal: withPermissions(tenantPrincipal(tenantScope), PermissionRead, PermissionManage),
			audience: AudienceTenant, operation: CommandCancel},
		{name: "tenant manage retry", principal: withPermissions(tenantPrincipal(tenantScope), PermissionManage),
			audience: AudienceTenant, operation: CommandRetry},
		{name: "tenant principal on platform audience", principal: withPermissions(tenantPrincipal(tenantScope), PermissionManage, PermissionManageAll),
			audience: AudiencePlatform, operation: CommandCancel, want: ErrScopeForbidden},
		{name: "platform principal on tenant audience", principal: withPermissions(platformPrincipal(platformScope), PermissionManage, PermissionManageAll),
			audience: AudienceTenant, operation: CommandCancel, want: ErrScopeForbidden},
		{name: "platform read-only key", principal: withPermissions(platformPrincipal(platformScope), PermissionReadAll),
			audience: AudiencePlatform, operation: CommandReplay, want: ErrPermissionDenied},
		{name: "platform tenant-manage only", principal: withPermissions(platformPrincipal(platformScope), PermissionManage),
			audience: AudiencePlatform, operation: CommandCancel, want: ErrPermissionDenied},
		{name: "platform manage_all", principal: withPermissions(platformPrincipal(platformScope), PermissionManageAll),
			audience: AudiencePlatform, operation: CommandCancel},
		{name: "platform admin", principal: withPermissions(platformPrincipal(platformScope), PermissionAdmin),
			audience: AudiencePlatform, operation: CommandCancel},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &strictCommandStore{fixtureReader: &fixtureReader{}}
			service, err := NewService(store, fixtureServiceConfig())
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Command(t.Context(), test.principal, CommandRequest{
				Audience: test.audience, TaskID: taskID, Operation: test.operation, IdempotencyKey: "credential-scope",
			})
			if test.want != nil {
				if !errors.Is(err, test.want) || store.executeCalls != 0 {
					t.Fatalf("err=%v execute calls=%d, want %v and 0 calls", err, store.executeCalls, test.want)
				}
				return
			}
			if store.executeCalls != 1 {
				t.Fatalf("err=%v execute calls=%d, want 1 call", err, store.executeCalls)
			}
		})
	}
}

var _ CommandStore = (*fixtureReader)(nil)

// CACHE-ADD-05 (P15/P16): the generic cancel/retry only moves the unified
// job; a cache operation's own projection (queued/failed) is left behind and
// its scheduler then refuses or ignores it. The task center refuses these
// commands for kinds whose producer owns cancel/retry.
func TestGenericCommandsRefuseProducerOwnedKinds(t *testing.T) {
	for _, kind := range []string{"cache.operation"} {
		for _, operation := range []CommandOperation{CommandCancel, CommandRetry, CommandReplay} {
			if genericCommandSupported(kind, operation) {
				t.Fatalf("%s %s is accepted by the generic command", kind, operation)
			}
		}
	}
	if !genericCommandSupported("dns_reconcile", CommandCancel) || !genericCommandSupported("cache.purge", CommandRetry) {
		t.Fatal("kinds without a producer-owned command were refused")
	}
	if !errors.Is(commandDenialPublicError("producer_command"), ErrProducerCommand) {
		t.Fatal("producer command denial lost its public error")
	}
	status, code, _ := publicError(ErrProducerCommand)
	if status != http.StatusConflict || code != "job_producer_command_required" {
		t.Fatalf("publicError = (%d,%q)", status, code)
	}
}
