package l4lineswitch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type activeSwitchReaderStub struct {
	items []ActiveSwitch
	limit int
}

func (reader *activeSwitchReaderStub) ListActive(_ context.Context, limit int) ([]ActiveSwitch, error) {
	reader.limit = limit
	return append([]ActiveSwitch(nil), reader.items...), nil
}

type reconcileRunnerStub struct {
	actors []Actor
	items  []ActiveSwitch
	errors []error
}

func (runner *reconcileRunnerStub) Reconcile(_ context.Context, actor Actor, scopeID, switchID uuid.UUID) (Switch, error) {
	runner.actors = append(runner.actors, actor)
	runner.items = append(runner.items, ActiveSwitch{ConfigurationScopeID: scopeID, SwitchID: switchID})
	index := len(runner.items) - 1
	if index < len(runner.errors) {
		return Switch{}, runner.errors[index]
	}
	return Switch{}, nil
}

func TestReconcilerUsesBoundedWorkloadAuthorityAndContinuesAfterCASConflict(t *testing.T) {
	items := []ActiveSwitch{
		{ConfigurationScopeID: uuid.New(), SwitchID: uuid.New()},
		{ConfigurationScopeID: uuid.New(), SwitchID: uuid.New()},
	}
	reader := &activeSwitchReaderStub{items: items}
	runner := &reconcileRunnerStub{errors: []error{ErrConflict, nil}}
	config := DefaultReconcilerConfig()
	config.BatchSize = 2
	config.OperationTimeout = time.Second
	reconciler, err := NewReconciler(reader, runner, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reader.limit != 2 || len(runner.items) != 2 {
		t.Fatalf("limit=%d reconciled=%d", reader.limit, len(runner.items))
	}
	for index, actor := range runner.actors {
		if !workloadAuthority(actor) || actor.Credential != "" || runner.items[index] != items[index] {
			t.Fatalf("actor=%+v item=%+v", actor, runner.items[index])
		}
	}
}

func TestReconcilerReturnsProductionErrorsAndRejectsInvalidConfiguration(t *testing.T) {
	item := ActiveSwitch{ConfigurationScopeID: uuid.New(), SwitchID: uuid.New()}
	reader := &activeSwitchReaderStub{items: []ActiveSwitch{item}}
	runner := &reconcileRunnerStub{errors: []error{ErrPersistence}}
	config := DefaultReconcilerConfig()
	reconciler, err := NewReconciler(reader, runner, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.RunOnce(t.Context()); !errors.Is(err, ErrPersistence) {
		t.Fatalf("RunOnce() error=%v", err)
	}
	config.BatchSize = 0
	if _, err := NewReconciler(reader, runner, config); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("NewReconciler() error=%v", err)
	}
}
