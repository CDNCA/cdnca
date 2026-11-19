package nodegatewayaddr

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// unboundReceipts is a transport whose receipt stream the gateway has not
// created yet (a controller without nodes).
type unboundReceipts struct {
	Transport
	calls int
}

func (u *unboundReceipts) NextReceipt(context.Context) (ReceiptDelivery, error) {
	u.calls++
	return nil, fmt.Errorf("bind receipts: %w", nats.ErrStreamNotFound)
}

// While the receipt stream does not exist the consumer
// backs off from its interval (natsready.Waiter) and logs once, instead of
// retrying and logging every interval.
func TestReceiptConsumerBacksOffWhileUnbound(t *testing.T) {
	var out bytes.Buffer
	transport := &unboundReceipts{}
	logger := slog.New(slog.NewTextHandler(&out, nil))
	consumer := &Distributor{config: DistributorConfig{Transport: transport, Logger: logger, Interval: time.Millisecond}}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	consumer.consumeReceipts(ctx)
	if lines := strings.Count(out.String(), "receipts unavailable"); lines != 1 || transport.calls < 3 || transport.calls > 15 {
		t.Fatalf("logged %d lines over %d tries: %q", lines, transport.calls, out.String())
	}
}
