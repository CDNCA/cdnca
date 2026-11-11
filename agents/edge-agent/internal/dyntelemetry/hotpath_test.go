package dyntelemetry

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

// the tail's per-line attribution (ResolveTail + a checked parse)
// gives exactly the envelope of Resolve + ParseSourceLineBound, without
// re-encoding the line to fill config_version_id or scanning it again.

func oldTailParse(resolver *Resolver, line []byte) (eventspool.Envelope, error) {
	resolved, err := resolver.Resolve(line)
	if err != nil {
		return eventspool.Envelope{}, err
	}
	return eventspool.ParseSourceLineBound(resolved.Line, resolved.CapturePolicy, resolved.Identity)
}

func newTailParse(resolver *Resolver, line []byte) (eventspool.Envelope, error) {
	resolved, err := resolver.ResolveTail(line)
	if err != nil {
		return eventspool.Envelope{}, err
	}
	return eventspool.ParseSourceLineChecked(resolved.Line, resolved.CapturePolicy, resolved.Identity, resolved.Checked)
}

func TestResolveTailIsResolvePlusParse(t *testing.T) {
	corpus := goldenFixture(t)
	clock := func() time.Time { return corpus.now }
	lines := append(append([]string{}, corpus.access...), corpus.security...)
	// a version longer than the generated ones and a line with a forged
	// non-empty config_version_id
	lines = append(lines, strings.Replace(corpus.access[0], `"config_version_id":""`, `"config_version_id":"x"`, 1))
	for index, line := range lines {
		before := &Resolver{Registry: corpus.registry, Sites: corpus.sites, NodeID: nodeID, Grace: time.Minute, Now: clock}
		after := &Resolver{Registry: corpus.registry, Sites: corpus.sites, NodeID: nodeID, Grace: time.Minute, Now: clock}
		want, wantErr := oldTailParse(before, []byte(line))
		got, gotErr := newTailParse(after, []byte(line))
		if (wantErr == nil) != (gotErr == nil) || wantErr != nil && wantErr.Error() != gotErr.Error() ||
			errors.Is(wantErr, eventspool.ErrLineSkipped) != errors.Is(gotErr, eventspool.ErrLineSkipped) {
			t.Fatalf("line %d: error %v, before %v", index, gotErr, wantErr)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("line %d: envelope differs\n got %+v\nwant %+v", index, got, want)
		}
		if before.Counts() != after.Counts() {
			t.Fatalf("line %d: counts %+v, before %+v", index, after.Counts(), before.Counts())
		}
	}
}

func TestResolveTailAllocatesLess(t *testing.T) {
	corpus := goldenFixture(t)
	resolver := &Resolver{Registry: corpus.registry, Sites: corpus.sites, NodeID: nodeID}
	for _, line := range []string{corpus.access[0], corpus.security[0]} {
		raw := []byte(line)
		before := testing.AllocsPerRun(50, func() { _, _ = oldTailParse(resolver, raw) })
		after := testing.AllocsPerRun(50, func() { _, _ = newTailParse(resolver, raw) })
		t.Logf("%.30s…: %.0f allocations per line, before %.0f", line, after, before)
		if after > before*0.75 {
			t.Fatalf("%.30s…: %.0f allocations per line, before %.0f: want at least 25%% fewer", line, after, before)
		}
	}
}
