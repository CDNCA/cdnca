package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

const l4StreamsCheckName = "edge_l4_streams"

type degradedStreamSource interface {
	DegradedStreams(context.Context) ([]l4runtime.DegradedStream, error)
}

// l4StreamChecks reports, with every terminal deployment, the forwards of the
// active L4 release that run degraded: an origin that did not
// answer the probe, or a host without an address set (refusing connections).
// The release itself is healthy; the forward recovers with the next
// resolution that reaches its origin.
func l4StreamChecks(source degradedStreamSource) func() []*agentv1.CheckResult {
	return func() []*agentv1.CheckResult {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		degraded, err := source.DegradedStreams(ctx)
		if err != nil {
			return []*agentv1.CheckResult{{Name: l4StreamsCheckName, Succeeded: false,
				Summary: "L4 forward state unreadable: " + err.Error(), LatencyDuration: durationpb.New(0)}}
		}
		summary := "every L4 forward origin answered"
		if len(degraded) != 0 {
			streams := make([]string, len(degraded))
			for index, stream := range degraded {
				streams[index] = fmt.Sprintf("stream %s %s", stream.StreamID, stream.ReasonCode)
			}
			summary = fmt.Sprintf("%d L4 forwards degraded (origin unreachable or unresolved): %s",
				len(degraded), strings.Join(streams, ", "))
			// Status summaries are bounded (gateway sanitizeSummary keeps 512).
			if len(summary) > 500 {
				summary = summary[:497] + "..."
			}
		}
		return []*agentv1.CheckResult{{Name: l4StreamsCheckName, Succeeded: len(degraded) == 0,
			Summary: summary, LatencyDuration: durationpb.New(0)}}
	}
}
