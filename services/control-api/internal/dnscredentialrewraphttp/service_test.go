package dnscredentialrewraphttp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
)

func TestServicePersistsPerItemCompletedReplayConflictAndFailure(t *testing.T) {
	owner := testOwner()
	providers := []uuid.UUID{
		uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		uuid.MustParse("55555555-5555-5555-5555-555555555555"),
		uuid.MustParse("66666666-6666-6666-6666-666666666666"),
		uuid.MustParse("77777777-7777-7777-7777-777777777777"),
	}
	repository := &stubRepository{
		claim: Claim{
			ID:        uuid.MustParse("33333333-3333-3333-3333-333333333333"),
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		},
		completedKeys: map[string]bool{},
	}
	rewrapper := &stubRewrapper{results: map[uuid.UUID]rewrapOutcome{
		providers[0]: {progress: dnsacme.CredentialRewrapProgress{Requested: 1, Completed: 1, NextIndex: 1,
			Items: []dnsacme.CredentialRewrapResult{{ProviderID: providers[0], Revision: 8, CredentialVersion: 2}}}},
		providers[1]: {progress: dnsacme.CredentialRewrapProgress{Requested: 1, Completed: 1, NextIndex: 1,
			Items: []dnsacme.CredentialRewrapResult{{ProviderID: providers[1], Revision: 4, CredentialVersion: 9}}}},
		providers[2]: {err: dnsacme.ErrRevisionConflict},
		providers[3]: {err: dnsacme.ErrCredentialUnavailable},
	}}
	repository.completedKeys[deriveItemIdempotencyKey(owner.SessionID, "batch-key", providers[1])] = true
	service, err := NewService(repository, rewrapper)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]BatchItem, len(providers))
	for index, providerID := range providers {
		items[index] = BatchItem{ProviderID: providerID, ExpectedRevision: int64([]int{7, 3, 9, 5}[index])}
	}
	repository.claim.Items = append([]BatchItem(nil), items...)

	job, replayed, err := service.Submit(t.Context(), SubmitRequest{
		Owner: owner, IdempotencyKey: "batch-key", RequestID: "request-1", Items: items,
	})

	if err != nil || replayed || job.State != JobCompletedWithErrors || job.Completed != 4 ||
		job.Succeeded != 2 || job.Replayed != 1 || job.Conflicted != 1 || job.Failed != 1 {
		t.Fatalf("job=%+v replayed=%t error=%v", job, replayed, err)
	}
	wantStatus := []ItemStatus{ItemCompleted, ItemReplayed, ItemConflict, ItemFailed}
	for index, want := range wantStatus {
		if job.Items[index].ProviderID != providers[index] || job.Items[index].Status != want {
			t.Fatalf("item[%d]=%+v want status=%s", index, job.Items[index], want)
		}
	}
	if job.Items[2].ErrorCode != ItemCodeRevisionConflict || job.Items[3].ErrorCode != ItemCodeCredentialUnavailable {
		t.Fatalf("item errors=%+v", job.Items)
	}
	if repository.completed.Job.ID != job.ID || len(repository.itemCompletions) != len(items) || len(rewrapper.requests) != len(items) {
		t.Fatalf("completion=%+v item completions=%d requests=%d", repository.completed, len(repository.itemCompletions), len(rewrapper.requests))
	}
	for index, request := range rewrapper.requests {
		if request.actor.ScopeKind != "platform" || request.actor.UserID != owner.UserID ||
			request.request.RequestID != "request-1" || len(request.request.Items) != 1 ||
			request.request.Items[0].ProviderID != providers[index] || request.request.Items[0].IdempotencyKey == "batch-key" {
			t.Fatalf("rewrap request[%d]=%+v", index, request)
		}
	}
	encoded, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ciphertext", "key_id", "secret", "credentials"} {
		if containsFold(string(encoded), forbidden) {
			t.Fatalf("job JSON leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestServiceReplaysCompletedBatchWithoutCallingRewrapper(t *testing.T) {
	owner := testOwner()
	providerID := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	stored := Job{
		ID: uuid.MustParse("33333333-3333-3333-3333-333333333333"), State: JobCompleted,
		Requested: 1, Completed: 1, Succeeded: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		Items: []ItemProgress{{ProviderID: providerID, ExpectedRevision: 1, Status: ItemCompleted, Revision: 2, CredentialVersion: 4}},
	}
	repository := &stubRepository{claim: Claim{ID: stored.ID, Complete: true, Job: stored}}
	rewrapper := &stubRewrapper{}
	service, err := NewService(repository, rewrapper)
	if err != nil {
		t.Fatal(err)
	}

	job, replayed, err := service.Submit(t.Context(), SubmitRequest{
		Owner: owner, IdempotencyKey: "batch-key", RequestID: "request-1",
		Items: []BatchItem{{ProviderID: providerID, ExpectedRevision: 1}},
	})

	if err != nil || !replayed || job.Items[0].Status != ItemReplayed || job.Replayed != 1 || len(rewrapper.requests) != 0 {
		t.Fatalf("job=%+v replayed=%t requests=%d error=%v", job, replayed, len(rewrapper.requests), err)
	}
}

func TestServiceReturnsDurableProcessingWhenAnotherRequestOwnsJobLock(t *testing.T) {
	item := BatchItem{ProviderID: uuid.New(), ExpectedRevision: 1}
	repository := &stubRepository{
		claim: Claim{
			ID:        uuid.MustParse("33333333-3333-3333-3333-333333333333"),
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Items: []BatchItem{item},
		},
		lockUnavailable: true,
	}
	service, err := NewService(repository, &stubRewrapper{})
	if err != nil {
		t.Fatal(err)
	}
	job, replayed, err := service.Submit(t.Context(), SubmitRequest{
		Owner: testOwner(), IdempotencyKey: "batch-key", RequestID: "request-1",
		Items: []BatchItem{item},
	})
	if err != nil || replayed || job.State != JobProcessing || job.Requested != 1 || len(job.Items) != 1 ||
		job.Items[0].Status != ItemPending || job.Items[0].ExpectedRevision != 1 {
		t.Fatalf("job=%+v replayed=%t error=%v", job, replayed, err)
	}
}

func TestServiceCompletesEveryIntentBeforeFinalBatchReceipt(t *testing.T) {
	providerID := uuid.New()
	item := BatchItem{ProviderID: providerID, ExpectedRevision: 4}
	repository := &stubRepository{claim: Claim{
		ID: uuid.New(), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Items: []BatchItem{item},
	}}
	rewrapper := &stubRewrapper{results: map[uuid.UUID]rewrapOutcome{
		providerID: {err: dnsacme.ErrNotFound},
	}}
	service, err := NewService(repository, rewrapper)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = service.Submit(t.Context(), SubmitRequest{
		Owner: testOwner(), IdempotencyKey: "batch-key", RequestID: "request-1", Items: []BatchItem{item},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.events) != 2 || repository.events[0] != "item" || repository.events[1] != "batch" {
		t.Fatalf("durable completion order=%v", repository.events)
	}
}

type stubRepository struct {
	claim           Claim
	claimErr        error
	completedKeys   map[string]bool
	itemProgress    map[int]ItemProgress
	itemCompletions []CompleteItemRequest
	completed       CompleteRequest
	completeJob     Job
	completeErr     error
	getJob          Job
	getErr          error
	lockUnavailable bool
	events          []string
}

func (repository *stubRepository) Claim(context.Context, ClaimRequest) (Claim, error) {
	return repository.claim, repository.claimErr
}

func (repository *stubRepository) ItemCompleted(_ context.Context, owner Owner, key string) (bool, error) {
	return repository.completedKeys[key], nil
}

func (repository *stubRepository) Item(_ context.Context, _ Owner, _ uuid.UUID, ordinal int) (ItemProgress, bool, error) {
	progress, found := repository.itemProgress[ordinal]
	return progress, found, nil
}

func (repository *stubRepository) CompleteItem(_ context.Context, request CompleteItemRequest) (ItemProgress, error) {
	repository.itemCompletions = append(repository.itemCompletions, request)
	repository.events = append(repository.events, "item")
	return request.Item, nil
}

func (repository *stubRepository) Complete(_ context.Context, request CompleteRequest) (Job, error) {
	repository.completed = request
	repository.events = append(repository.events, "batch")
	if repository.completeJob.ID == uuid.Nil {
		request.Job.UpdatedAt = time.Now().UTC()
		request.Job.CompletedAt = request.Job.UpdatedAt
		return request.Job, repository.completeErr
	}
	return repository.completeJob, repository.completeErr
}

func (repository *stubRepository) Get(context.Context, GetRequest) (Job, error) {
	if repository.getJob.ID == uuid.Nil && repository.getErr == nil {
		return processingJob(repository.claim), nil
	}
	return repository.getJob, repository.getErr
}

func (repository *stubRepository) WithJobLock(ctx context.Context, _ uuid.UUID, run func(context.Context) error) (bool, error) {
	if repository.lockUnavailable {
		return false, nil
	}
	return true, run(ctx)
}

type rewrapOutcome struct {
	progress dnsacme.CredentialRewrapProgress
	err      error
}

type rewrapCall struct {
	actor   dnsacme.Actor
	request dnsacme.CredentialRewrapRequest
}

type stubRewrapper struct {
	results  map[uuid.UUID]rewrapOutcome
	requests []rewrapCall
}

func (rewrapper *stubRewrapper) RewrapProviderCredentials(_ context.Context, actor dnsacme.Actor,
	request dnsacme.CredentialRewrapRequest,
) (dnsacme.CredentialRewrapProgress, error) {
	rewrapper.requests = append(rewrapper.requests, rewrapCall{actor: actor, request: request})
	if len(request.Items) != 1 {
		return dnsacme.CredentialRewrapProgress{}, errors.New("expected one item")
	}
	outcome := rewrapper.results[request.Items[0].ProviderID]
	return outcome.progress, outcome.err
}

func containsFold(value, fragment string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(fragment))
}

var _ = errors.Is
