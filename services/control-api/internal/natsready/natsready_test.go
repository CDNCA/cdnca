package natsready

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
)

func TestLogUnboundStreamNotFoundIsInfo(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&out, nil))
	LogUnbound(logger, "security ban receipts unavailable",
		fmt.Errorf("security ban receipt consumer: %w", nats.ErrStreamNotFound))
	line := out.String()
	if !strings.Contains(line, "level=INFO") || !strings.Contains(line, "waiting for agent-gateway to create the stream") {
		t.Fatalf("stream not found must be logged at info while waiting for the gateway: %q", line)
	}
}

func TestLogUnboundOtherErrorsStayWarnings(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&out, nil))
	LogUnbound(logger, "security ban receipts unavailable", errors.New("nats: connection closed"))
	line := out.String()
	if !strings.Contains(line, "level=WARN") || strings.Contains(line, "waiting for agent-gateway") {
		t.Fatalf("other errors must stay warnings: %q", line)
	}
}
