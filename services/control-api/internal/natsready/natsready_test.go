package natsready

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

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

// A controller without nodes never gets the gateway's stream (one INFO
// every 10 s, 125k lines). The wait
// doubles from First up to Max; "stream not found" is logged on the first
// try and then at most once per LogEvery; other errors stay warnings each
// time.
func TestWaiterBacksOffAndLogsStreamNotFoundRarely(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&out, nil))
	at := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	w := &Waiter{Message: "autodefense report consumer not bound yet", First: 10 * time.Second, Max: 5 * time.Minute,
		LogEvery: time.Hour, now: func() time.Time { return at }}
	notFound := fmt.Errorf("autodefense report consumer: %w", nats.ErrStreamNotFound)
	var waits []time.Duration
	for range 8 {
		wait := w.Next(logger, notFound)
		waits = append(waits, wait)
		at = at.Add(wait)
	}
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second,
		5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	if fmt.Sprint(waits) != fmt.Sprint(want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	if lines := strings.Count(out.String(), "\n"); lines != 1 {
		t.Fatalf("first hour logged %d lines: %q", lines, out.String())
	}
	// A day of waiting at the cap: about one line an hour.
	for range 24 * 12 {
		at = at.Add(w.Next(logger, notFound))
	}
	if lines := strings.Count(out.String(), "\n"); lines < 24 || lines > 26 {
		t.Fatalf("a day logged %d lines", lines)
	}
	if !strings.Contains(out.String(), "tries=") {
		t.Fatalf("later lines carry the tries so far: %q", out.String())
	}
	out.Reset()
	w.Next(logger, errors.New("nats: connection closed"))
	w.Next(logger, errors.New("nats: connection closed"))
	if strings.Count(out.String(), "level=WARN") != 2 {
		t.Fatalf("other errors are warned every time: %q", out.String())
	}
}

// After a success the wait and the log start over.
func TestWaiterResetStartsOver(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&out, nil))
	at := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	w := NewWaiter("receipts unavailable", 10*time.Second)
	w.now = func() time.Time { return at }
	if w.Max != 5*time.Minute || NewWaiter("x", 10*time.Minute).Max != 10*time.Minute {
		t.Fatalf("max = %s", w.Max)
	}
	notFound := fmt.Errorf("receipts: %w", nats.ErrStreamNotFound)
	w.Next(logger, notFound)
	if wait := w.Next(logger, notFound); wait != 20*time.Second {
		t.Fatalf("second wait = %s", wait)
	}
	w.Reset()
	if wait := w.Next(logger, notFound); wait != 10*time.Second {
		t.Fatalf("wait after reset = %s", wait)
	}
	if lines := strings.Count(out.String(), "\n"); lines != 2 {
		t.Fatalf("first failure after a success is logged again: %d %q", lines, out.String())
	}
}
