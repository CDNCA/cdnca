package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The analytics connections, L4 analytics and node metrics runtimes close NATS with
// closeNATSAfterFlush, not Drain. A real nats:2.10 -js probe of the three
// production Close methods showed analytics connections and node metrics calling Close right
// after Drain (the drain cut off), and L4 analytics returning while the connection was still draining (closed
// 2s later with a leaked pending subscription, "draining connection timed out").
func TestCloseNATSAfterFlush(t *testing.T) {
	var operations []string
	connection := &fakeOrderedNATSConnection{connected: true,
		onFlush: func(timeout time.Duration) { operations = append(operations, "flush "+timeout.String()) },
		onClose: func() { operations = append(operations, "close") }}
	if err := closeNATSAfterFlush(connection, 3*time.Second, "node metrics"); err != nil || !connection.IsClosed() ||
		strings.Join(operations, ",") != "flush 3s,close" {
		t.Fatalf("connected: error=%v closed=%t operations=%v", err, connection.IsClosed(), operations)
	}
	operations = nil
	if err := closeNATSAfterFlush(connection, time.Second, "node metrics"); err != nil || len(operations) != 0 {
		t.Fatalf("already closed: error=%v operations=%v", err, operations)
	}
	disconnected := &fakeOrderedNATSConnection{onFlush: func(time.Duration) { operations = append(operations, "flush") },
		onClose: func() { operations = append(operations, "close") }}
	if err := closeNATSAfterFlush(disconnected, time.Second, "node metrics"); err != nil || strings.Join(operations, ",") != "close" {
		t.Fatalf("disconnected: error=%v operations=%v", err, operations)
	}
	operations = nil
	sentinel := errors.New("flush timed out")
	failing := &fakeFlushFailingNATSConnection{fakeOrderedNATSConnection{connected: true,
		onFlush: func(time.Duration) { operations = append(operations, "flush") },
		onClose: func() { operations = append(operations, "close") }}, sentinel}
	if err := closeNATSAfterFlush(failing, time.Second, "L4 analytics"); !errors.Is(err, sentinel) ||
		err.Error() != "flush L4 analytics NATS: flush timed out" || strings.Join(operations, ",") != "flush,close" {
		t.Fatalf("flush failure: error=%v operations=%v", err, operations)
	}
}

type fakeFlushFailingNATSConnection struct {
	fakeOrderedNATSConnection
	err error
}

func (c *fakeFlushFailingNATSConnection) FlushTimeout(timeout time.Duration) error {
	_ = c.fakeOrderedNATSConnection.FlushTimeout(timeout)
	return c.err
}
