package gateway

import (
	"context"
	"strings"
	"time"
)

// The per-node pull consumers allow a single waiting pull (MaxWaiting: 1). A
// pull still held by the server answers the next one with 409 "Exceeded
// MaxWaiting": after a client-side fetch timeout the expiring pull lingers a
// moment, and when a node reconnects the superseded session's pull is still
// waiting until that session stops and the server drops it. That is
// transient: the pull is retried after pendingPullBackoff instead of being a
// delivery failure (which warns and, repeated, ends the session).
const pendingPullBackoff = 50 * time.Millisecond

func pullStillPending(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "exceeded maxwaiting")
}

// waitPendingPull waits pendingPullBackoff, or returns ctx's error.
func waitPendingPull(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(pendingPullBackoff):
		return nil
	}
}
