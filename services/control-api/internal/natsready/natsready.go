// Package natsready logs a JetStream consumer that could not be bound yet.
package natsready

import (
	"errors"
	"log/slog"
	"time"

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

// Waiter paces the binding retries of one consumer and their log. The wait
// starts at First and doubles up to Max. "Stream not found" is logged (at
// info, LogUnbound) on the first try and then at most once per LogEvery with
// the tries so far: a controller without nodes never gets the gateway's
// stream and would otherwise log every try. Any other error is logged every
// time. Not for concurrent use.
type Waiter struct {
	Message              string
	First, Max, LogEvery time.Duration

	tries  int
	wait   time.Duration
	logged time.Time
	now    func() time.Time // nil: time.Now
}

// NewWaiter is a Waiter for a receipt consumer polled every interval: from
// interval up to five minutes (interval if longer), "stream not found"
// logged once an hour.
func NewWaiter(message string, interval time.Duration) *Waiter {
	return &Waiter{Message: message, First: interval, Max: max(interval, 5*time.Minute), LogEvery: time.Hour}
}

// Reset starts over after a success: the next failure waits First and is
// logged.
func (w *Waiter) Reset() {
	w.tries, w.wait = 0, 0
}

// Next logs err as due and returns how long to wait before the next try.
func (w *Waiter) Next(logger *slog.Logger, err error) time.Duration {
	now := time.Now
	if w.now != nil {
		now = w.now
	}
	w.tries++
	w.wait = min(max(2*w.wait, w.First), w.Max)
	at := now()
	if w.tries == 1 || !errors.Is(err, nats.ErrStreamNotFound) || at.Sub(w.logged) >= w.LogEvery {
		w.logged = at
		if logger == nil {
			logger = slog.Default()
		}
		if w.tries > 1 {
			logger = logger.With("tries", w.tries)
		}
		LogUnbound(logger, w.Message, err)
	}
	return w.wait
}
