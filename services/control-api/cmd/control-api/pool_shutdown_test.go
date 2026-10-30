package main

import (
	"context"
	"testing"
	"time"
)

// heldPool stands in for pgxpool: Close returns only after the connection a
// background loop borrowed is released, which happens when ctx ends.
type heldPool struct{ released <-chan struct{} }

func (pool heldPool) Close() { <-pool.released }

func TestClosePoolAfterStopCancelsBeforeClosing(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	released := make(chan struct{})
	go func() { // a LISTEN loop holding its connection until ctx ends
		<-ctx.Done()
		close(released)
	}()
	done := make(chan struct{})
	go func() {
		closePoolAfterStop(stop, heldPool{released: released})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pool close waited on a connection whose loop was never canceled")
	}
}
