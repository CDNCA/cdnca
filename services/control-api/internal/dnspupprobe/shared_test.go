package dnspupprobe

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// runSites runs request for every site of sites at once (as the origin runner
// does for the sites of one round).
func runSites(prober *Prober, consumer string, round int64, request ProbeRequest, sites ...string) ([][]Result, []error) {
	results, errs := make([][]Result, len(sites)), make([]error, len(sites))
	var group sync.WaitGroup
	for index, site := range sites {
		group.Add(1)
		go func() {
			defer group.Done()
			results[index], errs[index] = prober.Run(context.Background(), consumer, site, "example.com|80", round, request)
		}()
	}
	group.Wait()
	return results, errs
}

// Three sites with the same origin URL in one round: one charged dnspup job,
// all three get its results; a site looking again in the round does not count
// them twice; the next round probes again.
func TestSharedRequestIsOneJobPerRound(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer, fake.PollsUntilDone = httpAnswer(200, 502, 200), 1
	prober, _ := newTestProber(t, fake, server.URL)
	request := ProbeRequest{Type: "http", Target: "http://example.com/", Method: "GET"}
	results, errs := runSites(prober, ConsumerOrigin, 5, request, "site-a", "site-b", "site-c")
	for index := range results {
		if errs[index] != nil || len(results[index]) != 3 {
			t.Fatalf("site %d: %v, %v", index, results[index], errs[index])
		}
	}
	if fake.Creates != 1 || fake.MonthlyUsed != 1 {
		t.Fatalf("creates %d used %d, want one shared job", fake.Creates, fake.MonthlyUsed)
	}
	if _, err := prober.Run(context.Background(), ConsumerOrigin, "site-b", "example.com|80", 5, request); !errors.Is(err, ErrDelivered) {
		t.Fatalf("second look of a site = %v, want ErrDelivered", err)
	}
	// A site first asking later in the same round gets the cached results.
	if late, err := prober.Run(context.Background(), ConsumerOrigin, "site-d", "example.com|80", 5, request); err != nil || len(late) != 3 {
		t.Fatalf("late site = %v, %v", late, err)
	}
	if fake.Creates != 1 {
		t.Fatalf("late site created a job: %d", fake.Creates)
	}
	if _, errs := runSites(prober, ConsumerOrigin, 6, request, "site-a", "site-b", "site-c"); errs[0] != nil || errs[1] != nil || errs[2] != nil {
		t.Fatalf("next round: %v", errs)
	}
	if fake.Creates != 2 {
		t.Fatalf("next round creates %d, want 2", fake.Creates)
	}
}

// Requests differing in path, port, scheme, type or consumer are not merged.
func TestSharedRequestKeepsDifferentRequestsApart(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer, fake.PollsUntilDone = httpAnswer(200), -1
	prober, _ := newTestProber(t, fake, server.URL)
	requests := []ProbeRequest{
		{Type: "http", Target: "http://example.com/", Method: "GET"},
		{Type: "http", Target: "http://example.com/health", Method: "GET"},
		{Type: "http", Target: "http://example.com:8080/", Method: "GET"},
		{Type: "http", Target: "https://example.com/", Method: "GET"},
		{Type: "tcping", Target: "example.com", Port: 80},
	}
	for _, request := range requests {
		if _, err := prober.Run(context.Background(), ConsumerOrigin, "site-a", request.Target, 1, request); err != nil {
			t.Fatalf("%+v: %v", request, err)
		}
	}
	if _, err := prober.Run(context.Background(), ConsumerEdge, "site-a", "x", 1, requests[0]); err != nil {
		t.Fatal(err)
	}
	if fake.Creates != len(requests)+1 {
		t.Fatalf("creates %d, want %d", fake.Creates, len(requests)+1)
	}
	if IdempotencyKey(ConsumerOrigin, requests[0], 1) == IdempotencyKey(ConsumerOrigin, requests[1], 1) ||
		IdempotencyKey(ConsumerOrigin, requests[0], 1) == IdempotencyKey(ConsumerOrigin, requests[0], 2) ||
		IdempotencyKey(ConsumerOrigin, requests[0], 1) == IdempotencyKey(ConsumerEdge, requests[0], 1) {
		t.Fatal("idempotency key must differ per request, round and consumer")
	}
}

// A failing shared job fails every site that waited on it (each falls back as
// before) with one dnspup call and one degrade.
func TestSharedRequestFailureReachesEverySite(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer, fake.MonthlyLimit = httpAnswer(200), 0
	prober, degraded := newTestProber(t, fake, server.URL)
	request := ProbeRequest{Type: "http", Target: "http://example.com/", Method: "GET"}
	_, errs := runSites(prober, ConsumerOrigin, 1, request, "site-a", "site-b", "site-c")
	var apiErr *APIError
	for index, err := range errs {
		if !errors.As(err, &apiErr) || apiErr.Code != "quota_exceeded" {
			t.Fatalf("site %d: %v", index, err)
		}
	}
	if len(fake.Requests) != 1 || len(*degraded) != 1 {
		t.Fatalf("requests %v degraded %v, want one call", fake.Requests, *degraded)
	}
	// Refused targets stay refused for every site of the round.
	fake.MonthlyLimit = 1000
	fake.Restricted["http://gov.example.cn/"] = true
	restricted := ProbeRequest{Type: "http", Target: "http://gov.example.cn/", Method: "GET"}
	_, errs = runSites(prober, ConsumerOrigin, 1, restricted, "site-a", "site-b")
	if !errors.Is(errs[0], ErrRefused) || !errors.Is(errs[1], ErrRefused) || fake.MonthlyUsed != 0 {
		t.Fatalf("restricted: %v used %d", errs, fake.MonthlyUsed)
	}
}

// One observation per job: the hook runs for the job, not per site.
func TestSharedRequestReportsResultsOnce(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer, fake.PollsUntilDone = httpAnswer(200), 1
	prober, _ := newTestProber(t, fake, server.URL)
	var mu sync.Mutex
	reported := 0
	prober.onResults = func(consumer string, _ ProbeRequest, results []Result) {
		mu.Lock()
		defer mu.Unlock()
		if consumer == ConsumerEdge && len(results) == 1 {
			reported++
		}
	}
	request := ProbeRequest{Type: "tcping", Target: "edge.example.net", Port: 443}
	if _, errs := runSites(prober, ConsumerEdge, 1, request, "site-a", "site-b", "site-c"); errs[0] != nil {
		t.Fatal(errs)
	}
	if reported != 1 || fake.Creates != 1 {
		t.Fatalf("reported %d creates %d", reported, fake.Creates)
	}
}

// Rounds of different consumers are different clocks: a consumer moving to its
// next round drops only its own old entries.
func TestRoundSwitchKeepsOtherConsumers(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer, fake.PollsUntilDone = httpAnswer(200), -1
	prober, _ := newTestProber(t, fake, server.URL)
	node := ProbeRequest{Type: "tcping", Target: "198.51.100.1", Port: 443}
	if _, err := prober.Run(context.Background(), ConsumerNode, "node-1", "x", 100, node); err != nil {
		t.Fatal(err)
	}
	origin := ProbeRequest{Type: "http", Target: "http://example.com/", Method: "GET"}
	if _, err := prober.Run(context.Background(), ConsumerOrigin, "site-a", "x", 200, origin); err != nil {
		t.Fatal(err)
	}
	if _, err := prober.Run(context.Background(), ConsumerNode, "node-1", "x", 100, node); !errors.Is(err, ErrDelivered) {
		t.Fatalf("node round lost by an origin round switch: %v", err)
	}
	if _, err := prober.Run(context.Background(), ConsumerOrigin, "site-a", "x", 203, origin); err != nil {
		t.Fatal(err)
	}
	prober.mu.Lock()
	defer prober.mu.Unlock()
	if len(prober.cache) != 2 {
		t.Fatalf("cache %d entries, want node 100 and origin 203", len(prober.cache))
	}
}
