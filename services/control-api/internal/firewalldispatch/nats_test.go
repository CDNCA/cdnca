package firewalldispatch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNextStatusUsesCallerDeadlineWithoutMaxWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := (&natsTransport{
		statuses: new(nats.Subscription),
		config:   DefaultConfig(),
	}).nextStatus(ctx)
	if errors.Is(err, nats.ErrContextAndTimeout) {
		t.Fatalf("nextStatus() combined caller context and MaxWait: %v", err)
	}
	if !errors.Is(err, nats.ErrTypeSubscription) {
		t.Fatalf("nextStatus() error = %v, want subscription validation after options are accepted", err)
	}
}
