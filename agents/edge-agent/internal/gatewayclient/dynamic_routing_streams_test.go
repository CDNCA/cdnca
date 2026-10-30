package gatewayclient

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// L4_STREAM_SELECTION: the node serves the root's forwards but those its key
// document withholds; withholding all leaves no L4 runtime, and a withheld
// forward the release does not carry is an integrity failure.
func TestSelectNodeStreamsLeavesWithheldForwardsOut(t *testing.T) {
	const a, b = "33333333-3333-4333-8333-333333333331", "33333333-3333-4333-8333-333333333332"
	streams := &edgeconfig.StreamRuntime{TenantID: "t", StreamsV2: []edgeconfig.L4StreamRuntimeV2{{StreamID: a}, {StreamID: b}}}
	if got, err := SelectNodeStreams(streams, nil); err != nil || got != streams {
		t.Fatalf("nothing withheld = %v, %v", got, err)
	}
	got, err := SelectNodeStreams(streams, []string{a})
	if err != nil || got == nil || len(got.StreamsV2) != 1 || got.StreamsV2[0].StreamID != b || got.TenantID != "t" {
		t.Fatalf("withhold a = %+v, %v", got, err)
	}
	if len(streams.StreamsV2) != 2 {
		t.Fatal("the root's streams were modified")
	}
	if got, err := SelectNodeStreams(streams, []string{a, b}); err != nil || got != nil {
		t.Fatalf("withhold all = %+v, %v", got, err)
	}
	if _, err := SelectNodeStreams(streams, []string{"33333333-3333-4333-8333-333333333339"}); err == nil {
		t.Fatal("unknown withheld forward accepted")
	}
	if _, err := SelectNodeStreams(nil, []string{a}); err == nil {
		t.Fatal("withheld forward of a release without streams accepted")
	}
}
