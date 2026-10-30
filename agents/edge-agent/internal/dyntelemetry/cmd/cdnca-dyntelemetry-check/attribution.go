package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const (
	portA        = 18080
	portB        = 18081
	originAddr   = "127.0.0.1:19501"
	scopeCount   = 8 // scopes; tenant = scope's tenant (two scopes share one tenant)
	blockedPath  = "/blocked/x"
	missingPath  = "/missing"
	idSiteFormat = "0d12a000-0000-4000-8000-%012d"
)

func scopeID(index int) string  { return fmt.Sprintf("0d12b000-0000-4000-8000-%012d", index) }
func tenantID(index int) string { return fmt.Sprintf("0d12c000-0000-4000-8000-%012d", index/2) }

// attributionSite i: primary s<i>.d12.test, alias a<i>.d12.test, every 5th a
// wildcard *.w<i>.d12.test; every 3rd on both ports; scope i % scopeCount.
func attributionSite(i int, revision int64) edgesite.Site {
	scope := i % scopeCount
	aliases := []string{fmt.Sprintf("a%d.d12.test", i)}
	if i%5 == 0 {
		aliases = append(aliases, fmt.Sprintf("*.w%d.d12.test", i))
	}
	ports := []int{}
	if i%3 == 0 {
		ports = append(ports, portB)
	}
	return baseSite(scopeID(scope), tenantID(scope), fmt.Sprintf(idSiteFormat, i), revision,
		fmt.Sprintf("s%d.d12.test", i), aliases, originAddr, portA, ports...)
}

// a request and the site the node must attribute it to ("" = not logged)
type expectation struct {
	site, tenant, scope string
	port                int
	status              int
}

func checkAttribution(n *node) {
	ctx := context.Background()
	count := *sites
	objects := make([]siteindex.Object, count)
	// One WAF policy shared by every site: /blocked → 403 + security event.
	policy := []edgeconfig.SecurityPolicy{{Kind: edgeconfig.SecurityWAF, PolicyID: "0d12d000-0000-4000-8000-000000000001",
		PolicyVersion: 1, BindingRevision: 1, RuntimeSHA256: strings.Repeat("0", 64), Enabled: true, DefaultAction: edgeconfig.WAFAllow,
		Rules: []edgeconfig.WAFRule{{RuleID: "0d12d000-0000-4000-8000-0000000000e1", Action: edgeconfig.WAFBlock, Control: edgeconfig.WAFStop,
			Match: edgeconfig.WAFMatch{Path: &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathPrefix, Value: "/blocked"}}}}}}
	started := time.Now()
	for i := range count {
		objects[i] = encode(attributionSite(i, 1))
		writePlan(objects[i].Site.SiteID, policy)
	}
	stopOrigin := startOrigin(originAddr, "o", map[string]int{missingPath: 404}, map[string]string{missingPath: "nf"})
	defer stopOrigin()
	versions := func(generation int) map[string]string {
		result := map[string]string{}
		for scope := range scopeCount {
			result[scopeID(scope)] = fmt.Sprintf("0d12e%03d-0000-4000-8000-%012d", generation, scope)
		}
		return result
	}
	n.versions = versions(1)
	activation, err := n.activator.Activate(ctx, objects)
	check("attribution-activate", err == nil, "%d sites gen %d in %s (objects+plans %s) %v", count, activation.Generation,
		activation.Duration.Round(time.Millisecond), time.Since(started).Round(time.Millisecond), err)
	if err != nil {
		return
	}

	// Mixed traffic from 32 clients while two activations change a tenth
	// of the sites (new revision = new digest; scope versions change).
	var mu sync.Mutex
	sent := map[string]expectation{} // request id (X-D12) -> expectation
	var unknownSent, nodeSent, total atomic.Int64
	stopSwitch := make(chan struct{})
	switchesDone := make(chan []uint64)
	go func() {
		var generations []uint64
		for round := 2; round <= 3; round++ {
			// at a third and two thirds of the traffic
			for total.Load() < int64(*requests*(round-1)/3) {
				select {
				case <-stopSwitch:
				case <-time.After(5 * time.Millisecond):
					continue
				}
				break
			}
			changed := append([]siteindex.Object(nil), objects...)
			for i := round; i < count; i += 10 {
				changed[i] = encode(attributionSite(i, int64(round)))
			}
			n.versions = versions(round)
			activation, err := n.activator.Activate(ctx, changed)
			if err != nil {
				check("attribution-switch", false, "%v", err)
				break
			}
			generations = append(generations, activation.Generation)
		}
		switchesDone <- generations
	}()
	var wait sync.WaitGroup
	perClient := *requests / 32
	for client := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			random := rand.New(rand.NewPCG(uint64(client), 12))
			for k := range perClient {
				i := random.IntN(count)
				site := objects[i].Site
				port := portA
				if i%3 == 0 && random.IntN(2) == 0 {
					port = portB
				}
				host := site.Hosts.Primary
				switch random.IntN(4) {
				case 1:
					host = fmt.Sprintf("a%d.d12.test", i)
				case 2:
					if i%5 == 0 {
						host = fmt.Sprintf("x%d.w%d.d12.test", k, i)
					}
				}
				path, status := "/p", 200
				switch random.IntN(10) {
				case 0:
					path, status = blockedPath, 403
				case 1:
					path, status = missingPath, 404
				case 2: // a host no site serves on this port
					if port == portA {
						host = fmt.Sprintf("nope%d.d12.test", k)
					} else {
						host = fmt.Sprintf("s%d.d12.test", i+1) // a portA-only site, unless i+1 is a multiple of 3
						if (i+1)%3 == 0 || i+1 >= count {
							host = fmt.Sprintf("nope%d.d12.test", k)
						}
					}
					status = 421
				case 3:
					host, path, status = fmt.Sprintf("nope%d.d12.test", k), "/.well-known/cdnca-market-probe", 204
				}
				id := fmt.Sprintf("c%d-%d", client, k)
				got := send(port, host, "GET", path, map[string]string{"Traceparent": id}, "")
				total.Add(1)
				switch status {
				case 421:
					unknownSent.Add(1)
				case 204:
					nodeSent.Add(1)
				}
				if got != status {
					check("attribution-status", false, "%s port %d %s%s -> %d want %d", id, port, host, path, got, status)
					continue
				}
				if status == 421 || status == 204 {
					continue
				}
				mu.Lock()
				sent[id] = expectation{site: site.SiteID, tenant: site.TenantID, scope: site.ConfigurationScopeID, port: port, status: status}
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	close(stopSwitch)
	generations := <-switchesDone
	// Requests after the last switch (the tail of the traffic) are served
	// by it; a few more make sure every generation has lines.
	for i := range 200 {
		site := objects[i].Site
		id := fmt.Sprintf("tail-%d", i)
		if send(portA, site.Hosts.Primary, "GET", "/p", map[string]string{"Traceparent": id}, "") == 200 {
			sent[id] = expectation{site: site.SiteID, tenant: site.TenantID, scope: site.ConfigurationScopeID, port: portA, status: 200}
		}
		total.Add(1)
	}
	time.Sleep(500 * time.Millisecond)

	// The Agent path: every line through the Resolver as the tailer runs it.
	resolver := &dyntelemetry.Resolver{Registry: n.registry, Sites: n.sites(), NodeID: nodeID}
	type seen struct{ access, security int }
	lines := map[string]*seen{}
	wrong, unattributed, foreign := 0, 0, 0
	generationsSeen := map[uint64]int{}
	for _, stream := range []string{"access", "security"} {
		for _, line := range n.lines(stream) {
			resolved, err := resolver.Resolve(line)
			if err != nil {
				unattributed++
				if unattributed <= 5 {
					fmt.Printf("  unattributed %s: %v\n  %s\n", stream, err, line)
				}
				continue
			}
			var fields struct {
				Path       string `json:"path"`
				Host       string `json:"host"`
				StatusCode int    `json:"status_code"`
				TenantID   string `json:"tenant_id"`
				SiteID     string `json:"site_id"`
				Version    string `json:"config_version_id"`
				ListenPort int    `json:"listen_port"`
			}
			_ = json.Unmarshal(resolved.Line, &fields)
			_, attribution, _ := dyntelemetry.Split(line)
			generationsSeen[attribution.Generation]++
			id := requestID(line)
			want, ok := sent[id]
			if !ok {
				foreign++
				if foreign <= 5 {
					fmt.Printf("  line of no expected request: %s\n", line)
				}
				continue
			}
			identity := resolved.Identity
			if identity.SiteID != want.site || identity.TenantID != want.tenant || fields.SiteID != want.site ||
				fields.TenantID != want.tenant || int(identity.ListenPort) != want.port || fields.StatusCode != want.status ||
				identity.ConfigVersionID != fields.Version || fields.Version != versions(int(attribution.Generation))[want.scope] {
				wrong++
				if wrong <= 5 {
					fmt.Printf("  wrong attribution %s: want %+v got %+v %+v\n", id, want, identity, fields)
				}
			}
			entry := lines[id]
			if entry == nil {
				entry = &seen{}
				lines[id] = entry
			}
			if stream == "access" {
				entry.access++
			} else {
				entry.security++
			}
		}
	}
	missing, duplicated := 0, 0
	for id, want := range sent {
		entry := lines[id]
		switch {
		case entry == nil || entry.access == 0:
			missing++
		case entry.access > 1 || want.status == 403 && entry.security != 1 || want.status != 403 && entry.security != 0:
			duplicated++
		}
	}
	logged := len(sent)
	accuracy := 0.0
	if logged > 0 {
		accuracy = 100 * float64(logged-missing-duplicated-wrong) / float64(logged)
	}
	fmt.Printf("ATTRIBUTION sites=%d requests=%d logged_expected=%d unknown_host=%d node_location=%d generations=%v lines_by_generation=%v\n",
		count, total.Load(), logged, unknownSent.Load(), nodeSent.Load(), generations, generationsSeen)
	fmt.Printf("ATTRIBUTION wrong=%d missing=%d duplicated_or_missing_security=%d unattributed=%d foreign=%d accuracy=%.4f%% resolver=%+v\n",
		wrong, missing, duplicated, unattributed, foreign, accuracy, resolver.Counts())
	check("attribution-100pct", wrong == 0 && missing == 0 && duplicated == 0 && unattributed == 0 && foreign == 0 && logged > 0,
		"accuracy %.4f%% of %d logged requests", accuracy, logged)
	check("attribution-switches", len(generations) == 2 && len(generationsSeen) >= 2, "generations %v seen %v", generations, generationsSeen)
}

// requestID: the check sends each request's id as its traceparent header,
// which the line logs as trace_id ($http_traceparent).
func requestID(line []byte) string {
	var fields struct {
		TraceID string `json:"trace_id"`
	}
	_ = json.Unmarshal(line, &fields)
	return fields.TraceID
}
