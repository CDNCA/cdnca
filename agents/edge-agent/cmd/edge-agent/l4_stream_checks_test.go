package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

type fixedDegradedStreams struct {
	streams []l4runtime.DegradedStream
	err     error
}

func (value fixedDegradedStreams) DegradedStreams(context.Context) ([]l4runtime.DegradedStream, error) {
	return value.streams, value.err
}

// the deployment receipt names each degraded forward.
func TestL4StreamChecksNameTheDegradedForwards(t *testing.T) {
	healthy := l4StreamChecks(fixedDegradedStreams{})()
	if len(healthy) != 1 || healthy[0].Name != l4StreamsCheckName || !healthy[0].Succeeded {
		t.Fatalf("no degraded forward: %+v", healthy)
	}
	checks := l4StreamChecks(fixedDegradedStreams{streams: []l4runtime.DegradedStream{
		{StreamID: "stream-a", ReasonCode: l4runtime.DNSReasonStaticUnreachable}}})()
	if len(checks) != 1 || checks[0].Succeeded || !strings.Contains(checks[0].Summary, "stream stream-a L4_STATIC_ADDRESS_UNREACHABLE") {
		t.Fatalf("degraded forward: %+v", checks)
	}
	many := make([]l4runtime.DegradedStream, 40)
	for index := range many {
		many[index] = l4runtime.DegradedStream{StreamID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", ReasonCode: l4runtime.DNSReasonUnavailable}
	}
	if summary := l4StreamChecks(fixedDegradedStreams{streams: many})()[0].Summary; len(summary) > 500 || !strings.HasPrefix(summary, "40 L4 forwards") {
		t.Fatalf("bounded summary (%d): %s", len(summary), summary)
	}
	if failed := l4StreamChecks(fixedDegradedStreams{err: errors.New("locked")})(); failed[0].Succeeded {
		t.Fatalf("unreadable state: %+v", failed)
	}
}
