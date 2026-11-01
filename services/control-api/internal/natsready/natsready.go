// Package natsready logs a JetStream consumer that could not be bound yet.
package natsready

import (
	"errors"
	"log/slog"

	"github.com/nats-io/nats.go"
)

// LogUnbound logs why a receipt/report consumer is not bound yet. agent-gateway
// creates the edge streams when it starts, and systemd starts it after
// control-api, so "stream not found" on a fresh start is expected until the
// gateway is up: it is logged at info. Any other error stays a warning.
func LogUnbound(logger *slog.Logger, message string, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	if errors.Is(err, nats.ErrStreamNotFound) {
		logger.Info(message+"; waiting for agent-gateway to create the stream", "error", err)
		return
	}
	logger.Warn(message, "error", err)
}
