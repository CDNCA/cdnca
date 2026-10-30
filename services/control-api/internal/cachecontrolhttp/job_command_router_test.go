package cachecontrolhttp

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/jobhttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newTestJobCommandRouter(t *testing.T, control *fakeControl) *JobCommandRouter {
	t.Helper()
	service, err := NewService(runtimeControlStore{inner: control}, &fakeReader{}, bytes.Repeat([]byte{0x4c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// Tenant audiences never read the pool; any non-nil pool passes the guard.
	return &JobCommandRouter{service: service, pool: new(pgxpool.Pool)}
}

// fix-cacheflow2 §2: the task center's cancel/retry runs the cache module's
// own command with the caller's session, a namespaced key and the request ID.
func TestJobCommandRouterRunsTheCacheCommandWithTheCallerSession(t *testing.T) {
	scopeID, userID, operationID := uuid.New(), uuid.New(), uuid.New()
	var gotActor cachecontrol.Actor
	var gotCancel cachecontrol.CancelRequest
	var gotRetry cachecontrol.RetryRequest
	control := &fakeControl{
		cancel: func(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.CancelRequest) (cachecontrol.OperationWriteResult, error) {
			// runtimeControlStore only reaches the cache store when the session
			// in the context matches the actor (formal session authorization).
			gotActor, gotCancel = actor, request
			return cachecontrol.OperationWriteResult{Operation: testOperation(operationID)}, nil
		},
		retry: func(_ context.Context, actor cachecontrol.Actor, request cachecontrol.RetryRequest) (cachecontrol.OperationWriteResult, error) {
			gotActor, gotRetry = actor, request
			return cachecontrol.OperationWriteResult{Operation: testOperation(operationID), Replayed: true}, nil
		},
	}
	router := newTestJobCommandRouter(t, control)
	principal := jobhttp.Principal{
		UserID: userID, ScopeID: scopeID, ScopeKind: jobhttp.ScopeTenant,
		Permissions: map[string]struct{}{jobhttp.PermissionManage: {}, PermissionOperationsManage: {}},
	}.WithSessionCredential("session-token")
	input := jobhttp.ProducerCommandInput{
		Principal: principal, Audience: jobhttp.AudienceTenant, Operation: jobhttp.CommandCancel,
		Job: jobhttp.Job{TaskID: operationID, Kind: "cache.operation"}, IdempotencyKey: "cancel-1", RequestID: "request-1",
	}
	if _, err := router.ExecuteProducerCommand(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if gotActor != (cachecontrol.Actor{UserID: userID, ScopeID: scopeID, ActorScopeID: scopeID}) ||
		gotCancel.OperationID != operationID || gotCancel.IdempotencyKey != "job-cancel-1" || gotCancel.RequestID != "request-1" {
		t.Fatalf("cancel actor=%+v request=%+v", gotActor, gotCancel)
	}
	input.Operation = jobhttp.CommandRetry
	result, err := router.ExecuteProducerCommand(t.Context(), input)
	if err != nil || !result.Replayed || gotRetry.IdempotencyKey != "job-cancel-1" {
		t.Fatalf("retry result=%+v err=%v request=%+v", result, err, gotRetry)
	}
}

// fix-cacheflow3 §1: a tenant API key runs the same cache command; the cache
// store re-authorizes the key (scopes ∩ holder permissions) in its transaction.
func TestJobCommandRouterRunsTheCacheCommandWithATenantAPIKey(t *testing.T) {
	scopeID, userID, operationID := uuid.New(), uuid.New(), uuid.New()
	var gotActor cachecontrol.Actor
	var gotCancel cachecontrol.CancelRequest
	control := &fakeControl{cancel: func(_ context.Context, actor cachecontrol.Actor, request cachecontrol.CancelRequest) (cachecontrol.OperationWriteResult, error) {
		gotActor, gotCancel = actor, request
		return cachecontrol.OperationWriteResult{Operation: testOperation(operationID)}, nil
	}}
	router := newTestJobCommandRouter(t, control)
	principal := jobhttp.Principal{
		UserID: userID, ScopeID: scopeID, ScopeKind: jobhttp.ScopeTenant,
		Permissions: map[string]struct{}{jobhttp.PermissionManage: {}, PermissionOperationsManage: {}},
	}.WithAPIKeyCredential(uuid.New(), "cdnca_test_key")
	_, err := router.ExecuteProducerCommand(t.Context(), jobhttp.ProducerCommandInput{
		Principal: principal, Audience: jobhttp.AudienceTenant, Operation: jobhttp.CommandCancel,
		Job: jobhttp.Job{TaskID: operationID, Kind: "cache.operation"}, IdempotencyKey: "cancel-1", RequestID: "request-1",
	})
	if err != nil || gotActor != (cachecontrol.Actor{UserID: userID, ScopeID: scopeID, ActorScopeID: scopeID}) ||
		gotCancel.IdempotencyKey != "job-cancel-1" {
		t.Fatalf("err=%v actor=%+v request=%+v", err, gotActor, gotCancel)
	}
}

func TestJobCommandRouterRefusesWhatTheCacheModuleCannotAuthorize(t *testing.T) {
	operationID := uuid.New()
	called := false
	control := &fakeControl{cancel: func(context.Context, cachecontrol.Actor, cachecontrol.CancelRequest) (cachecontrol.OperationWriteResult, error) {
		called = true
		return cachecontrol.OperationWriteResult{}, nil
	}}
	router := newTestJobCommandRouter(t, control)
	base := jobhttp.ProducerCommandInput{
		Audience: jobhttp.AudienceTenant, Operation: jobhttp.CommandCancel,
		Job: jobhttp.Job{TaskID: operationID, Kind: "cache.operation"}, IdempotencyKey: "cancel-1", RequestID: "request-1",
	}
	withManage := jobhttp.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: jobhttp.ScopeTenant,
		Permissions: map[string]struct{}{PermissionOperationsManage: {}}}
	for name, input := range map[string]jobhttp.ProducerCommandInput{
		"no credential": func() jobhttp.ProducerCommandInput { in := base; in.Principal = withManage; return in }(),
		"session and API key": func() jobhttp.ProducerCommandInput {
			in := base
			in.Principal = withManage.WithSessionCredential("t").WithAPIKeyCredential(uuid.New(), "k")
			return in
		}(),
		"API key on the platform audience": func() jobhttp.ProducerCommandInput {
			in := base
			in.Audience = jobhttp.AudiencePlatform
			in.Principal = jobhttp.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: jobhttp.ScopePlatform,
				Permissions: map[string]struct{}{"platform.admin": {}}}.WithAPIKeyCredential(uuid.New(), "k")
			return in
		}(),
		"API key without sites.manage": func() jobhttp.ProducerCommandInput {
			in := base
			in.Principal = jobhttp.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: jobhttp.ScopeTenant,
				Permissions: map[string]struct{}{jobhttp.PermissionManage: {}}}.WithAPIKeyCredential(uuid.New(), "k")
			return in
		}(),
		"no sites.manage": func() jobhttp.ProducerCommandInput {
			in := base
			in.Principal = jobhttp.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: jobhttp.ScopeTenant,
				Permissions: map[string]struct{}{jobhttp.PermissionManage: {}}}.WithSessionCredential("t")
			return in
		}(),
		"other kind": func() jobhttp.ProducerCommandInput {
			in := base
			in.Principal = withManage.WithSessionCredential("t")
			in.Job.Kind = "dns_reconcile"
			return in
		}(),
		"replay": func() jobhttp.ProducerCommandInput {
			in := base
			in.Principal = withManage.WithSessionCredential("t")
			in.Operation = jobhttp.CommandReplay
			return in
		}(),
	} {
		called = false
		if _, err := router.ExecuteProducerCommand(t.Context(), input); err == nil || called {
			t.Errorf("%s: err=%v cache command called=%v", name, err, called)
		}
	}
}

func TestJobCommandErrorsKeepTheCacheModuleReason(t *testing.T) {
	for cacheErr, want := range map[error]error{
		ErrInvalidTransition:   jobhttp.ErrInvalidTransition,
		ErrRetriesExhausted:    jobhttp.ErrRetriesExhausted,
		ErrNotFound:            jobhttp.ErrNotFound,
		ErrPermissionDenied:    jobhttp.ErrPermissionDenied,
		ErrEntitlementDenied:   jobhttp.ErrPermissionDenied,
		ErrIdempotencyConflict: jobhttp.ErrIdempotencyConflict,
		ErrStoreUnavailable:    jobhttp.ErrStoreUnavailable,
	} {
		if got := jobCommandError(cacheErr); !errors.Is(got, want) {
			t.Errorf("%v -> %v, want %v", cacheErr, got, want)
		}
	}
}

func testOperation(id uuid.UUID) cachecontrol.Operation {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	return cachecontrol.Operation{ID: id, Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
		State: cachecontrol.StateCancelled, MaxAttempts: 1,
		Progress: cachecontrol.Progress{Total: 1, Completed: 1, Cancelled: 1}, CreatedAt: now, UpdatedAt: now}
}
