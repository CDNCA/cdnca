package l4lineswitch

import (
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

type memoryStore struct{ item *Switch }

func (store *memoryStore) Claim(_ context.Context, _ Actor, claim Claim) (Switch, bool, error) {
	if store.item != nil {
		result := cloneSwitch(*store.item)
		result.Replayed = true
		return result, true, nil
	}
	item := cloneSwitch(claim.Switch)
	store.item = &item
	return cloneSwitch(item), false, nil
}

func (store *memoryStore) Get(_ context.Context, _ Actor, scopeID, switchID uuid.UUID, _ string) (Switch, error) {
	if store.item == nil || store.item.ConfigurationScopeID != scopeID || store.item.ID != switchID {
		return Switch{}, ErrNotFound
	}
	return cloneSwitch(*store.item), nil
}

func (store *memoryStore) Latest(_ context.Context, _ Actor, scopeID uuid.UUID, _ string) (Switch, error) {
	if store.item == nil || store.item.ConfigurationScopeID != scopeID {
		return Switch{}, ErrNotFound
	}
	return cloneSwitch(*store.item), nil
}

func (store *memoryStore) CompareAndSwap(_ context.Context, _ Actor, before, after Switch) error {
	if store.item == nil || store.item.StateRevision != before.StateRevision {
		return ErrConflict
	}
	item := cloneSwitch(after)
	store.item = &item
	return nil
}

type snapshotResolver struct{ values map[uuid.UUID]Snapshot }

func (resolver snapshotResolver) Resolve(_ context.Context, _ Actor, _ uuid.UUID, reference SnapshotReference) (Snapshot, error) {
	value, ok := resolver.values[reference.ID]
	if !ok || value.Reference != reference {
		return Snapshot{}, ErrNotFound
	}
	return value, nil
}

type publicationCoordinator struct {
	prepareCalls, compensateCalls   int
	prepareStatus, compensateStatus string
}

func (coordinator *publicationCoordinator) Prepare(_ context.Context, _ Actor, value Switch) (Publication, error) {
	coordinator.prepareCalls++
	return Publication{ID: uuid.NewSHA1(value.ID, []byte("prepare")), RolloutID: uuid.NewSHA1(value.ID, []byte("prepare-rollout")), ConfigVersionID: uuid.NewSHA1(value.ID, []byte("prepare-config"))}, nil
}

func (coordinator *publicationCoordinator) Compensate(_ context.Context, _ Actor, value Switch) (Publication, error) {
	coordinator.compensateCalls++
	return Publication{ID: uuid.NewSHA1(value.ID, []byte("compensate")), RolloutID: uuid.NewSHA1(value.ID, []byte("compensate-rollout")), ConfigVersionID: uuid.NewSHA1(value.ID, []byte("compensate-config"))}, nil
}

func (coordinator *publicationCoordinator) RolloutStatus(_ context.Context, _ Actor, _ Switch, rolloutID uuid.UUID) (string, error) {
	if rolloutID == uuid.Nil {
		return "", errors.New("missing rollout")
	}
	if coordinator.compensateCalls > 0 && coordinator.compensateStatus != "" {
		return coordinator.compensateStatus, nil
	}
	return coordinator.prepareStatus, nil
}

type targetCoordinator struct{ activates, restores int }

func (coordinator *targetCoordinator) Activate(context.Context, Actor, Switch) error {
	coordinator.activates++
	return nil
}
func (coordinator *targetCoordinator) Restore(context.Context, Actor, Switch) error {
	coordinator.restores++
	return nil
}

type drainCoordinator struct {
	builds, publishes int
	publishFailures   int
	statuses          map[uuid.UUID]string
}

func (coordinator *drainCoordinator) Build(_ context.Context, _ Actor, value Switch) (map[uuid.UUID]*agentv1.DrainCommand, error) {
	coordinator.builds++
	result := make(map[uuid.UUID]*agentv1.DrainCommand, len(value.RetiringNodes))
	for _, nodeID := range value.RetiringNodes {
		commandID := uuid.NewSHA1(value.ID, nodeID[:])
		result[nodeID] = &agentv1.DrainCommand{CommandId: commandID.String(), NodeId: nodeID.String()}
	}
	return result, nil
}

func (coordinator *drainCoordinator) Publish(_ context.Context, _ Actor, command *agentv1.DrainCommand) error {
	coordinator.publishes++
	if coordinator.publishFailures > 0 {
		coordinator.publishFailures--
		return ErrPersistence
	}
	if coordinator.statuses == nil {
		coordinator.statuses = make(map[uuid.UUID]string)
	}
	commandID := uuid.MustParse(command.CommandId)
	if _, exists := coordinator.statuses[commandID]; !exists {
		coordinator.statuses[commandID] = DrainPending
	}
	return nil
}

func TestSwitchPersistsCommandsBeforePublishingAndRestartRepublishes(t *testing.T) {
	service, store, publications, targets, drains, request := switchFixture(t)
	started, err := service.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	publications.prepareStatus = RolloutSucceeded
	drains.publishFailures = 1

	draining, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if !errors.Is(err, ErrPersistence) || draining.State != StateDrainingOld ||
		store.item.State != StateDrainingOld || len(store.item.DrainCommands) != len(store.item.RetiringNodes) ||
		publications.compensateCalls != 0 {
		t.Fatalf("first reconcile=%+v error=%v stored=%+v compensate=%d", draining, err, store.item, publications.compensateCalls)
	}
	commands := maps.Clone(store.item.DrainCommands)

	recovered, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || recovered.State != StateDrainingOld || !maps.Equal(recovered.DrainCommands, commands) ||
		drains.builds != 2 || drains.publishes != len(commands)+1 || targets.activates != 2 {
		t.Fatalf("recovered=%+v error=%v builds=%d publishes=%d activates=%d", recovered, err, drains.builds, drains.publishes, targets.activates)
	}
}

func TestSwitchDoesNotRetireUntilEveryExactCommandCompletes(t *testing.T) {
	service, _, publications, _, drains, request := switchFixture(t)
	started, err := service.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	publications.prepareStatus = RolloutSucceeded
	draining, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || len(draining.DrainCommands) < 2 {
		t.Fatalf("draining=%+v error=%v", draining, err)
	}
	for _, commandID := range draining.DrainCommands {
		drains.statuses[commandID] = DrainCompleted
		break
	}
	result, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || result.State != StateDrainingOld {
		t.Fatalf("partial terminal result=%+v error=%v", result, err)
	}
}

func TestSwitchDeadlineCompensationResumesTheSamePlan(t *testing.T) {
	service, _, publications, targets, _, request := switchFixture(t)
	started, err := service.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return request.Deadline.Add(time.Second) }
	compensating, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || compensating.State != StateCompensatingOld || publications.compensateCalls != 1 {
		t.Fatalf("compensating=%+v error=%v calls=%d", compensating, err, publications.compensateCalls)
	}
	publications.compensateStatus = RolloutSucceeded
	rolledBack, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || rolledBack.State != StateRolledBack || publications.compensateCalls != 1 || targets.restores != 0 {
		t.Fatalf("rolled back=%+v error=%v compensate=%d restores=%d", rolledBack, err, publications.compensateCalls, targets.restores)
	}
}

func (coordinator *drainCoordinator) Status(_ context.Context, _ Actor, command *agentv1.DrainCommand) (string, error) {
	return coordinator.statuses[uuid.MustParse(command.CommandId)], nil
}

func TestSwitchWaitsForNewTargetHealthBeforeActivatingOrDraining(t *testing.T) {
	service, store, publications, targets, drains, request := switchFixture(t)
	started, err := service.Start(t.Context(), request)
	if err != nil || started.State != StateHealthGate || publications.prepareCalls != 1 {
		t.Fatalf("start = %+v, error = %v, prepare calls = %d", started, err, publications.prepareCalls)
	}
	result, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || result.State != StateHealthGate || targets.activates != 0 || drains.publishes != 0 {
		t.Fatalf("pending reconcile = %+v, error = %v, activates=%d drains=%d", result, err, targets.activates, drains.publishes)
	}
	if store.item.State != StateHealthGate {
		t.Fatalf("stored state = %s", store.item.State)
	}
}

func TestSwitchActivatesThenDrainsAndCompletes(t *testing.T) {
	service, _, publications, targets, drains, request := switchFixture(t)
	started, err := service.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	publications.prepareStatus = RolloutSucceeded
	result, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || result.State != StateDrainingOld || targets.activates != 1 || drains.publishes != len(result.RetiringNodes) {
		t.Fatalf("healthy reconcile = %+v, error=%v activates=%d publishes=%d", result, err, targets.activates, drains.publishes)
	}
	for _, commandID := range result.DrainCommands {
		drains.statuses[commandID] = DrainCompleted
	}
	result, err = service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || result.State != StateCompleted || targets.restores != 0 {
		t.Fatalf("completed reconcile = %+v, error=%v restores=%d", result, err, targets.restores)
	}
}

func TestSwitchHealthFailureRollsBackWithoutDrain(t *testing.T) {
	service, _, publications, targets, drains, request := switchFixture(t)
	started, err := service.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	publications.prepareStatus = RolloutFailed
	result, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || result.State != StateCompensatingOld || publications.compensateCalls != 1 ||
		drains.publishes != 0 || targets.activates != 0 {
		t.Fatalf("failed reconcile = %+v, error=%v compensate=%d activates=%d drains=%d", result, err, publications.compensateCalls, targets.activates, drains.publishes)
	}
	publications.compensateStatus = RolloutSucceeded
	result, err = service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || result.State != StateRolledBack || targets.restores != 0 {
		t.Fatalf("rollback reconcile = %+v, error=%v restores=%d", result, err, targets.restores)
	}
}

func TestSwitchDrainFailureCompensatesBeforeRestoringOldTarget(t *testing.T) {
	service, _, publications, targets, drains, request := switchFixture(t)
	started, err := service.Start(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	publications.prepareStatus = RolloutSucceeded
	draining, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, commandID := range draining.DrainCommands {
		drains.statuses[commandID] = DrainFailed
		break
	}
	result, err := service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || result.State != StateCompensatingOld || publications.compensateCalls != 1 || targets.restores != 0 {
		t.Fatalf("compensating reconcile = %+v error=%v compensate=%d restores=%d", result, err, publications.compensateCalls, targets.restores)
	}
	publications.compensateStatus = RolloutSucceeded
	result, err = service.Reconcile(t.Context(), request.Actor, request.ConfigurationScopeID, started.ID)
	if err != nil || result.State != StateRolledBack || targets.restores != 1 {
		t.Fatalf("restored reconcile = %+v error=%v restores=%d", result, err, targets.restores)
	}
}

func switchFixture(t *testing.T) (*Service, *memoryStore, *publicationCoordinator, *targetCoordinator, *drainCoordinator, StartRequest) {
	t.Helper()
	now := time.Date(2026, 8, 7, 3, 0, 0, 0, time.UTC)
	oldA, oldB, shared, newA := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	fromRef := snapshotReference(uuid.New(), 3, 0x31)
	toRef := snapshotReference(uuid.New(), 7, 0x72)
	store := &memoryStore{}
	publications := &publicationCoordinator{prepareStatus: RolloutPending}
	targets := &targetCoordinator{}
	drains := &drainCoordinator{statuses: make(map[uuid.UUID]string)}
	service, err := NewService(store, snapshotResolver{values: map[uuid.UUID]Snapshot{
		fromRef.ID: {Reference: fromRef, NodeIDs: []uuid.UUID{oldA, oldB, shared}},
		toRef.ID:   {Reference: toRef, NodeIDs: []uuid.UUID{shared, newA}},
	}}, publications, targets, drains, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := StartRequest{
		Actor:                Actor{UserID: uuid.New(), ScopeID: uuid.New(), SessionID: uuid.New(), ScopeKind: "tenant", Credential: "session-token"},
		ConfigurationScopeID: uuid.New(), ExpectedSourceRevision: 19, From: fromRef, To: toRef,
		Health: HealthPolicy{ActivationTimeout: time.Minute, ObservationWindow: 30 * time.Second, RequiredConsecutiveSuccesses: 3},
		Drain:  DrainPolicy{HealthTimeout: 30 * time.Second, MaxDrain: 10 * time.Minute}, MaxAttempts: 3,
		Deadline: now.Add(time.Hour), IdempotencyKey: "line-switch-1", RequestID: uuid.New(), CorrelationID: uuid.New(),
		Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
	}
	return service, store, publications, targets, drains, request
}

func snapshotReference(id uuid.UUID, revision int64, fill byte) SnapshotReference {
	var digest [32]byte
	for index := range digest {
		digest[index] = fill
	}
	return SnapshotReference{ID: id, Revision: revision, SHA256: digest}
}
