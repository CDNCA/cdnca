package jobhttp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type recordingProducerRouter struct {
	inputs []ProducerCommandInput
	result ProducerCommandResult
	err    error
	after  func()
}

func (router *recordingProducerRouter) ExecuteProducerCommand(
	_ context.Context, input ProducerCommandInput,
) (ProducerCommandResult, error) {
	router.inputs = append(router.inputs, input)
	if router.after != nil {
		router.after()
	}
	return router.result, router.err
}

// fix-cacheflow2 §2: the task center's cancel/retry of a cache operation is
// executed by the cache module (its own transaction and audit), not refused.
func TestCacheOperationCommandsAreRoutedToTheProducer(t *testing.T) {
	tenantScope := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000001")
	queuedID := uuid.MustParse("40000000-0000-4000-8000-000000000011")
	queued := fixtureJob(queuedID, tenantID, StateQueued, fixtureNow)
	queued.Kind = "cache.operation"
	reader := &fixtureReader{jobs: []Job{queued}, scopeTenants: map[uuid.UUID]uuid.UUID{tenantScope: tenantID}}
	router := &recordingProducerRouter{}
	router.after = func() {
		reader.mu.Lock()
		cancelled := fixtureJob(queuedID, tenantID, StateCancelled, fixtureNow)
		cancelled.Kind = "cache.operation"
		cancelled.Revision = "2"
		reader.jobs[0] = cancelled
		reader.mu.Unlock()
	}
	config := fixtureServiceConfig()
	config.ProducerCommands = map[string]ProducerCommandRouter{"cache.operation": router}
	service, err := NewService(reader, config)
	if err != nil {
		t.Fatal(err)
	}
	tenant := tenantPrincipal(tenantScope)
	tenant.Permissions[PermissionManage] = struct{}{}

	result, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedID, Operation: CommandCancel,
		IdempotencyKey: "cancel-cache", ExpectedRevision: queued.Revision,
	})
	if err != nil || result.Data.Status != StateCancelled || len(router.inputs) != 1 {
		t.Fatalf("routed cancel = %+v err=%v inputs=%d", result, err, len(router.inputs))
	}
	input := router.inputs[0]
	if input.Operation != CommandCancel || input.IdempotencyKey != "cancel-cache" || input.Job.TaskID != queuedID ||
		input.Audience != AudienceTenant || input.Principal.UserID != tenant.UserID || input.RequestID == "" {
		t.Fatalf("router input = %+v", input)
	}
	if reader.commandCalls != 0 {
		t.Fatalf("generic command store was used %d times", reader.commandCalls)
	}

	// A stale If-Match runs nothing: the producer is only asked whether the
	// key was already accepted; a key it never accepted is a revision conflict.
	router.inputs, router.after = nil, nil
	if _, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedID, Operation: CommandRetry,
		IdempotencyKey: "retry-stale", ExpectedRevision: queued.Revision,
	}); !errors.Is(err, ErrRevisionConflict) || len(router.inputs) != 1 || !router.inputs[0].ReplayOnly {
		t.Fatalf("stale revision err=%v inputs=%+v", err, router.inputs)
	}
	// Replaying the accepted cancel with the If-Match it was sent with is a replay.
	router.inputs, router.result = nil, ProducerCommandResult{Replayed: true}
	replayed, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedID, Operation: CommandCancel,
		IdempotencyKey: "cancel-cache", ExpectedRevision: queued.Revision,
	})
	if err != nil || !replayed.Replayed || len(router.inputs) != 1 || !router.inputs[0].ReplayOnly {
		t.Fatalf("stale replay = %+v err=%v inputs=%+v", replayed, err, router.inputs)
	}
	router.inputs, router.result = nil, ProducerCommandResult{}
	// The producer's refusal is returned as is.
	router.err = ErrInvalidTransition
	if _, err := service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedID, Operation: CommandRetry, IdempotencyKey: "retry-cancelled",
	}); !errors.Is(err, ErrInvalidTransition) || len(router.inputs) != 1 {
		t.Fatalf("producer refusal err=%v inputs=%d", err, len(router.inputs))
	}
	// Replay has no producer command: it stays on the generic path.
	router.inputs, router.err = nil, nil
	_, _ = service.Command(t.Context(), tenant, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedID, Operation: CommandReplay, IdempotencyKey: "replay-cache",
	})
	if len(router.inputs) != 0 {
		t.Fatal("replay was routed to the producer")
	}
}

func TestPrincipalSessionCredentialIsNotPrinted(t *testing.T) {
	principal := tenantPrincipal(uuid.New()).WithSessionCredential("session-secret")
	if principal.SessionToken() != "session-secret" {
		t.Fatal("session credential was not kept")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if text := fmt.Sprintf(format, principal); strings.Contains(text, "session-secret") {
			t.Fatalf("%s printed the session credential: %s", format, text)
		}
	}
}
