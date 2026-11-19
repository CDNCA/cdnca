package gateway

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nats-io/nats.go"
)

// The 409 a pull gets while another pull of the consumer
// is still waiting (as nats.go reports it, wrapped or not) is the transient
// case; timeouts and other errors are not. The gateway address, site drop
// and SSH access consumers are per-session ephemeral (server default
// MaxWaiting), so no session overlap reaches them; their Next takes the same
// path should the server answer so.
func TestPullStillPending(t *testing.T) {
	for _, err := range []error{errors.New("nats: Exceeded MaxWaiting"), fmt.Errorf("fetch: %w", errors.New("nats: exceeded maxwaiting"))} {
		if !pullStillPending(err) {
			t.Fatalf("%v must be transient", err)
		}
	}
	for _, err := range []error{nil, nats.ErrTimeout, context.DeadlineExceeded, errors.New("nats: connection closed")} {
		if pullStillPending(err) {
			t.Fatalf("%v must not be transient", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitPendingPull(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled wait = %v", err)
	}
	if err := waitPendingPull(context.Background()); err != nil {
		t.Fatalf("wait = %v", err)
	}
}
