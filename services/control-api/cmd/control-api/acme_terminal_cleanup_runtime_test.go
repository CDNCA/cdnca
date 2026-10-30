package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type acmeTerminalCleanupTestLoop38 struct {
	started  chan struct{}
	active   atomic.Bool
	stopped  atomic.Bool
	runError error
}

func newACMETerminalCleanupTestLoop38() *acmeTerminalCleanupTestLoop38 {
	return &acmeTerminalCleanupTestLoop38{started: make(chan struct{})}
}

func (loop *acmeTerminalCleanupTestLoop38) Run(ctx context.Context) error {
	loop.active.Store(true)
	close(loop.started)
	defer func() {
		loop.active.Store(false)
		loop.stopped.Store(true)
	}()
	if loop.runError != nil {
		return loop.runError
	}
	<-ctx.Done()
	return ctx.Err()
}

func (loop *acmeTerminalCleanupTestLoop38) Ready() error {
	if loop == nil || !loop.active.Load() {
		return errors.New("test loop is unavailable")
	}
	return nil
}

func TestACMETerminalCleanupRuntimeRequiresAllThreeLoops38(t *testing.T) {
	issuance := newACMETerminalCleanupTestLoop38()
	renewal := newACMETerminalCleanupTestLoop38()
	cleanup := newACMETerminalCleanupTestLoop38()
	for index, loops := range [][3]acmeRunnable{
		{nil, renewal, cleanup},
		{issuance, nil, cleanup},
		{issuance, renewal, nil},
	} {
		if _, err := newACMEProcessRuntime(loops[0], loops[1], loops[2]); err == nil {
			t.Fatalf("missing required loop %d was accepted", index)
		}
	}
}

func TestACMETerminalCleanupRuntimeRunsReadiesAndClosesThreeLoops38(t *testing.T) {
	issuance := newACMETerminalCleanupTestLoop38()
	renewal := newACMETerminalCleanupTestLoop38()
	cleanup := newACMETerminalCleanupTestLoop38()
	runtime, err := newACMEProcessRuntime(issuance, renewal, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	for _, started := range []<-chan struct{}{issuance.started, renewal.started, cleanup.started} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("required ACME process loop did not start")
		}
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("three-loop readiness error=%v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("closed runtime error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join all three ACME process loops")
	}
	if !issuance.stopped.Load() || !renewal.stopped.Load() || !cleanup.stopped.Load() {
		t.Fatalf("stopped issuance=%t renewal=%t cleanup=%t",
			issuance.stopped.Load(), renewal.stopped.Load(), cleanup.stopped.Load())
	}
}

func TestACMETerminalCleanupRuntimeFailureCancelsPeersAndPreservesError38(t *testing.T) {
	issuance := newACMETerminalCleanupTestLoop38()
	renewal := newACMETerminalCleanupTestLoop38()
	cleanup := newACMETerminalCleanupTestLoop38()
	terminal := errors.New("terminal cleanup loop stopped")
	cleanup.runError = terminal
	runtime, err := newACMEProcessRuntime(issuance, renewal, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(context.Background()); err != terminal {
		t.Fatalf("runtime error=%v want exact terminal error", err)
	}
	if !issuance.stopped.Load() || !renewal.stopped.Load() || !cleanup.stopped.Load() {
		t.Fatalf("peer cancellation issuance=%t renewal=%t cleanup=%t",
			issuance.stopped.Load(), renewal.stopped.Load(), cleanup.stopped.Load())
	}
}

func TestACMETerminalCleanupCompositionBuildsRequiredSharedWorkerLoop38(t *testing.T) {
	components, err := openACMERuntimeComponents(
		validACMERuntimeConfig(), new(pgxpool.Pool), acmeRuntimeProviders{
			http01: inertHTTP01Provider{}, dns01: inertDNS01Provider{}, issuerOverride: inertIssuer{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if components == nil || components.issuance == nil || components.cleanup == nil {
		t.Fatalf("ACME runtime components=%+v", components)
	}
	if components.issuance.Ready() == nil || components.cleanup.Ready() == nil {
		t.Fatal("constructed inactive component unexpectedly ready")
	}
}
