package dyntelemetry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// perfSender acknowledges every record (the gateway's side is not the
// agent's CPU).
type perfSender struct{ records, events int }

func (s *perfSender) Send(_ context.Context, batch telemetryclient.Batch) (telemetryclient.SendAck, error) {
	for _, record := range batch.Records {
		s.events += record.EventCount
	}
	s.records += len(batch.Records)
	return telemetryclient.SendAck{Accepted: len(batch.Records)}, nil
}

// perfLines renders n lines from testdata/perf-<kind>.jsonl: a capture line
// a node wrote under k6 load, ids replaced by
// placeholders; sites round robin.
func perfLines(t testing.TB, kind string, n int, sites []perfSite) []byte {
	raw, err := os.ReadFile(filepath.Join("testdata", "perf-"+kind+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	template := strings.TrimSpace(string(raw))
	now := time.Now().UTC().Format("2006-01-02T15:04:05+00:00")
	var output []byte
	for i := 0; i < n; i++ {
		site := sites[i%len(sites)]
		line := strings.NewReplacer("__SITE__", site.site.SiteID, "__TENANT__", site.site.TenantID,
			"__SCOPE__", site.site.ConfigurationScopeID, "__DIGEST__", site.digest, "__HOST__", site.site.Hosts.Primary,
			"__RID__", fmt.Sprintf("%032x", i), "__AT__", now, "__CONN__", strconv.Itoa(i/100+1)).Replace(template)
		output = append(append(output, line...), '\n')
	}
	return output
}

type perfSite struct {
	site   edgesite.Site
	digest string
}

func cpuNow() time.Duration {
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

// profiled runs fn under a CPU profile written to $CDNCA_PIPE_PERF_PROF/<name>.cpu
// (when set) and returns the process CPU it used.
func profiled(t *testing.T, name string, fn func()) time.Duration {
	directory := os.Getenv("CDNCA_PIPE_PERF_PROF")
	if directory != "" {
		file, err := os.Create(filepath.Join(directory, name+".cpu"))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		_ = pprof.StartCPUProfile(file)
		defer pprof.StopCPUProfile()
	}
	started := cpuNow()
	fn()
	return cpuNow() - started
}

// TestPipelinePerf measures the agent CPU per request of the dynamic routing
// telemetry path end to end: tail access.jsonl + security.jsonl, attribute,
// append to a spool configured as the daemon defaults, flush through the
// telemetry publisher (fake sender). Opt-in: CDNCA_PIPE_PERF_LINES (lines per
// log, e.g. 200000); CDNCA_PIPE_PERF_PROF writes tail.cpu / flush.cpu.
func TestPipelinePerf(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("CDNCA_PIPE_PERF_LINES"))
	if n <= 0 {
		t.Skip("set CDNCA_PIPE_PERF_LINES to run the pipeline measurement")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	var sites []perfSite
	objects := mapSites{}
	scopes := map[string]string{}
	for i := 0; i < 4; i++ {
		site := testSite(fmt.Sprintf("0d120000-0000-4000-8000-%012d", 100+i), fmt.Sprintf("0d120000-0000-4000-8000-%012d", 200+i),
			fmt.Sprintf("0d120000-0000-4000-8000-%012d", 300+i), fmt.Sprintf("s%d.perf.test", i), nil, true, 80)
		site.Telemetry.Capture.ResponseHeaderAllowlist = []string{"Content-Type"}
		digest := digestOf(t, site)
		objects[digest] = site
		scopes[site.ConfigurationScopeID] = fmt.Sprintf("0d120000-0000-4000-8000-%012d", 400+i)
		sites = append(sites, perfSite{site: site, digest: digest})
	}
	registry := NewRegistry()
	if err := registry.Register(1, 1, scopes); err != nil {
		t.Fatal(err)
	}
	access, security := filepath.Join(root, "access.jsonl"), filepath.Join(root, "security.jsonl")
	if err := os.WriteFile(access, perfLines(t, "access", n, sites), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(security, perfLines(t, "security", n, sites), 0o600); err != nil {
		t.Fatal(err)
	}
	spool, err := eventspool.New(eventspool.Config{Root: filepath.Join(root, "spool"), MaxEventBytes: 64 << 10, MaxSegmentBytes: 16 << 20,
		SoftLimitBytes: 4 << 30, HardLimitBytes: 8 << 30, MaxTenantBytes: 4 << 30, MaxBatchEvents: 10000,
		PressureMode: eventspool.PressureBackpressure, SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 168 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &Resolver{Registry: registry, Sites: objects, NodeID: nodeID}
	var tailers []*eventspool.Tailer
	for _, path := range []string{access, security} {
		tailer, err := eventspool.NewTailer(eventspool.TailConfig{SourcePath: path, StateDir: filepath.Join(root, "tail-state"),
			Identity: eventspool.TrustedIdentity{EnrollmentNodeID: nodeID}, MaxLineBytes: 64 << 10, MaxBatchEvents: 10000,
			MaxQuarantineBytes: 64 << 20, Resolve: resolver.ResolveTail})
		if err != nil {
			t.Fatal(err)
		}
		tailers = append(tailers, tailer)
	}
	appended := 0
	tailCPU := profiled(t, "tail", func() {
		for _, tailer := range tailers {
			result, err := tailer.TailOnce(context.Background(), spool)
			if err != nil || result.QuarantinedLines != 0 {
				t.Fatalf("tail %+v %v", result, err)
			}
			appended += result.AppendedEvents
		}
	})
	if appended != 2*n {
		t.Fatalf("appended %d want %d", appended, 2*n)
	}
	sender := &perfSender{}
	publisher, err := telemetryclient.NewPublisher(nodeID, sender)
	if err != nil {
		t.Fatal(err)
	}
	flushCPU := profiled(t, "flush", func() {
		for {
			result, err := spool.Flush(context.Background(), publisher, 1000)
			if err != nil {
				t.Fatal(err)
			}
			if result.Published == 0 {
				return
			}
		}
	})
	if sender.events != 2*n {
		t.Fatalf("published %d want %d", sender.events, 2*n)
	}
	perEvent := func(d time.Duration) float64 { return float64(d.Microseconds()) / float64(2*n) }
	t.Logf("PERF pipeline events=%d tail_cpu=%s (%.1f us/event) flush_cpu=%s (%.1f us/event) records=%d",
		2*n, tailCPU.Round(time.Millisecond), perEvent(tailCPU), flushCPU.Round(time.Millisecond), perEvent(flushCPU), sender.records)
}
