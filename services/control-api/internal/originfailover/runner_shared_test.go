package originfailover

import (
	"context"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe/dnspuptest"
	"github.com/google/uuid"
)

// sharedOriginPools are sites whose pools reach the same origin the same way
// (73: three sites on example.com:80).
func sharedOriginPools(paths ...string) []Pool {
	var pools []Pool
	for index, path := range paths {
		site := uuid.New()
		pools = append(pools, Pool{SiteID: site, Domain: "s" + string(rune('a'+index)) + ".example.org", HealthCheckPath: path,
			Scheme: "http", RequestHostMode: "origin", Origins: []Origin{{Host: "example.com", Port: 80, Enabled: true}}})
	}
	return pools
}

// probeAll probes pools at once, as RunOnce does.
func probeAll(runner *Runner, pools []Pool, plan dnspupprobe.Runtime, round int64) []map[string]Outcome {
	out := make([]map[string]Outcome, len(pools))
	var group sync.WaitGroup
	for index, pool := range pools {
		group.Add(1)
		go func() {
			defer group.Done()
			out[index] = runner.probe(context.Background(), pool, nil, plan, round)
		}()
	}
	group.Wait()
	return out
}

func newSharedDNSPup(t *testing.T) (*dnspuptest.Server, dnspupprobe.Runtime, *lockedController) {
	t.Helper()
	fake, server := dnspuptest.New()
	t.Cleanup(server.Close)
	fake.Do(func(s *dnspuptest.Server) {
		s.PollsUntilDone = -1
		s.Answer = func(dnspuptest.ProbeRequest) []dnspuptest.Result {
			return []dnspuptest.Result{{NodeID: "a", Region: "广东", ISP: "电信", Status: "ok", HTTPStatus: 502},
				{NodeID: "b", Region: "北京", ISP: "联通", Status: "ok", HTTPStatus: 502},
				{NodeID: "c", Region: "上海", ISP: "移动", Status: "unavailable"}}
		}
	})
	client, err := dnspupprobe.NewClient(dnspupprobe.Credentials{BaseURL: server.URL, APIKey: fake.APIKey, APISecret: fake.Secret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	prober := dnspupprobe.NewProber(client, nil)
	return fake, dnspupprobe.Runtime{OriginSources: dnspupprobe.DefaultOriginSources, Probe: prober.Run}, &lockedController{}
}

type lockedController struct {
	mu     sync.Mutex
	probed int
}

func (controller *lockedController) Probe(context.Context, Target) Outcome {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.probed++
	return Outcome{OK: true, Voted: true}
}

// Three sites on the same origin URL: one dnspup job per round, and each
// site's verdict comes from its checkpoints (two 502 votes: down).
func TestSitesSharingAnOriginShareOneDNSPupJob(t *testing.T) {
	fake, plan, controller := newSharedDNSPup(t)
	runner := NewRunner(nil, nil, controller, nil, nil)
	pools := sharedOriginPools("/", "/", "/")
	for index, outcomes := range probeAll(runner, pools, plan, 7) {
		if got, ok := outcomes["example.com|80"]; !ok || got.OK || !got.Voted || got.Reason != "status_5xx" {
			t.Fatalf("site %d outcome %+v (%v)", index, got, ok)
		}
	}
	if fake.Creates != 1 || controller.probed != 0 {
		t.Fatalf("creates %d controller %d, want one shared job", fake.Creates, controller.probed)
	}
	// Another path, port or scheme is another dnspup request.
	other := sharedOriginPools("/health")
	other = append(other, Pool{SiteID: uuid.New(), Domain: "p.example.org", HealthCheckPath: "/", Scheme: "http",
		RequestHostMode: "origin", Origins: []Origin{{Host: "example.com", Port: 8080, Enabled: true}}})
	other = append(other, Pool{SiteID: uuid.New(), Domain: "q.example.org", HealthCheckPath: "/", Scheme: "https",
		RequestHostMode: "origin", Trust: "system", Origins: []Origin{{Host: "example.com", Port: 443, Enabled: true}}})
	probeAll(runner, other, plan, 7)
	if fake.Creates != 4 || len(fake.Bodies) != 4 {
		t.Fatalf("creates %d bodies %+v", fake.Creates, fake.Bodies)
	}
	// The next round probes again, once.
	probeAll(runner, pools, plan, 8)
	if fake.Creates != 5 || controller.probed != 0 {
		t.Fatalf("next round creates %d controller %d", fake.Creates, controller.probed)
	}
}

// dnspup failing: every site sharing the job falls back to the control plane.
func TestSharedDNSPupFailureFallsBackForEverySite(t *testing.T) {
	fake, plan, controller := newSharedDNSPup(t)
	fake.Do(func(s *dnspuptest.Server) { s.MonthlyLimit = 0 })
	runner := NewRunner(nil, nil, controller, nil, nil)
	for index, outcomes := range probeAll(runner, sharedOriginPools("/", "/", "/"), plan, 7) {
		if got := outcomes["example.com|80"]; !got.OK {
			t.Fatalf("site %d outcome %+v", index, got)
		}
	}
	if controller.probed != 3 || len(fake.Requests) != 1 {
		t.Fatalf("controller %d dnspup requests %v", controller.probed, fake.Requests)
	}
}
