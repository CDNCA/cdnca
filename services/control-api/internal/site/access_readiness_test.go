package site

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// 接入状态逐项判定（套餐、线路组、CNAME、解析、证书、发布）。
func TestBuildAccessReadiness(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	done, failed, pending := "done", "failed", "pending"
	noPackage, disabled, deleted := PackageUnavailableNoPackage, PackageUnavailableDisabled, PackageUnavailableDeleted
	lineCode := "cname_no_default_line_group"
	before, after := now.Add(-time.Hour), now.Add(time.Hour)
	checked := now.Add(-time.Minute)
	ready := func() accessFacts {
		return accessFacts{
			Enabled: true, CNAME: "a1.cdn.example.net", CNAMEState: &done, Domains: []string{"www.example.com"},
			LineGroupFound: true, OnlineNodes: 2, PublishState: "succeeded",
			DNS: &dnsCheckRow{OK: true, CNAME: "a1.cdn.example.net", Domains: []string{"www.example.com"}, CheckedAt: &checked},
		}
	}
	for name, c := range map[string]struct {
		mutate func(*accessFacts)
		state  string
		code   string
		ok     bool
		detail string
	}{
		"all checks pass":          {mutate: func(*accessFacts) {}, state: AccessReady, code: AccessCheckDNS, ok: true},
		// fix-readiness2 ④：无有效套餐不下发，接入受阻（与 package_unavailable_reason 同一口径）。
		"valid package":    {mutate: func(*accessFacts) {}, state: AccessReady, code: AccessCheckPackage, ok: true},
		"no package":       {mutate: func(f *accessFacts) { f.PackageUnavailable = &noPackage }, state: AccessBlocked, code: AccessCheckPackage, detail: PackageUnavailableNoPackage},
		"package disabled": {mutate: func(f *accessFacts) { f.PackageUnavailable = &disabled }, state: AccessBlocked, code: AccessCheckPackage, detail: PackageUnavailableDisabled},
		"package deleted":  {mutate: func(f *accessFacts) { f.PackageUnavailable = &deleted }, state: AccessBlocked, code: AccessCheckPackage, detail: PackageUnavailableDeleted},
		"no line group":            {mutate: func(f *accessFacts) { f.LineGroupFound = false }, state: AccessBlocked, code: AccessCheckLineGroup, detail: "no_line_group"},
		"no online node":           {mutate: func(f *accessFacts) { f.OnlineNodes = 0 }, state: AccessBlocked, code: AccessCheckLineGroup, detail: "no_online_nodes"},
		"cname failed":             {mutate: func(f *accessFacts) { f.CNAMEState, f.CNAMEFailureCode = &failed, &lineCode }, state: AccessBlocked, code: AccessCheckCNAME, detail: lineCode},
		"cname failed no code":     {mutate: func(f *accessFacts) { f.CNAMEState = &failed }, state: AccessBlocked, code: AccessCheckCNAME, detail: "cname_failed"},
		"cname generating":         {mutate: func(f *accessFacts) { f.CNAMEState = &pending }, state: AccessPending, code: AccessCheckCNAME, detail: "cname_pending"},
		"no cname yet":             {mutate: func(f *accessFacts) { f.CNAME, f.CNAMEState = "", nil }, state: AccessPending, code: AccessCheckDNS, detail: "waiting_cname"},
		"dns never checked":        {mutate: func(f *accessFacts) { f.DNS = nil }, state: AccessPending, code: AccessCheckDNS, detail: "not_checked"},
		"dns checked old cname":    {mutate: func(f *accessFacts) { f.DNS.CNAME = "old.cdn.example.net" }, state: AccessPending, code: AccessCheckDNS, detail: "not_checked"},
		"dns checked other domain": {mutate: func(f *accessFacts) { f.Domains = []string{"api.example.com"} }, state: AccessPending, code: AccessCheckDNS, detail: "not_checked"},
		"dns points elsewhere": {mutate: func(f *accessFacts) { f.DNS.OK, f.DNS.Detail = false, DNSPointsElsewhere }, state: AccessPending,
			code: AccessCheckDNS, detail: DNSPointsElsewhere},
		"https off passes":     {mutate: func(f *accessFacts) { f.HTTPSEnabled = false }, state: AccessReady, code: AccessCheckHTTPS, ok: true, detail: "https_disabled"},
		"https no certificate": {mutate: func(f *accessFacts) { f.HTTPSEnabled = true }, state: AccessBlocked, code: AccessCheckHTTPS, detail: "certificate_missing"},
		"https expired": {mutate: func(f *accessFacts) {
			f.HTTPSEnabled, f.CertBound, f.CertActive, f.CertNotBefore, f.CertNotAfter = true, true, true, &before, &before
		}, state: AccessBlocked, code: AccessCheckHTTPS, detail: "certificate_expired"},
		"https not yet valid": {mutate: func(f *accessFacts) {
			f.HTTPSEnabled, f.CertBound, f.CertActive, f.CertNotBefore, f.CertNotAfter = true, true, true, &after, &after
		}, state: AccessBlocked, code: AccessCheckHTTPS, detail: "certificate_not_yet_valid"},
		"https awaiting active": {mutate: func(f *accessFacts) {
			f.HTTPSEnabled, f.CertBound, f.CertNotBefore, f.CertNotAfter = true, true, &before, &after
		}, state: AccessPending, code: AccessCheckHTTPS, detail: "certificate_not_active"},
		"https valid": {mutate: func(f *accessFacts) {
			f.HTTPSEnabled, f.CertBound, f.CertActive, f.CertNotBefore, f.CertNotAfter = true, true, true, &before, &after
		}, state: AccessReady, code: AccessCheckHTTPS, ok: true},
		"site disabled":   {mutate: func(f *accessFacts) { f.Enabled = false }, state: AccessBlocked, code: AccessCheckPublished, detail: "site_disabled"},
		"publish failed":  {mutate: func(f *accessFacts) { f.PublishState = "failed" }, state: AccessBlocked, code: AccessCheckPublished, detail: "publish_failed"},
		"publishing":      {mutate: func(f *accessFacts) { f.PublishState = "pending" }, state: AccessPending, code: AccessCheckPublished, detail: "publishing"},
		"never published": {mutate: func(f *accessFacts) { f.PublishState = "" }, state: AccessPending, code: AccessCheckPublished, detail: "not_published"},
		// fix-readiness2 ③：最近一次发布不含本站 = 未发布，给出原因。
		"latest publication excludes site": {mutate: func(f *accessFacts) { f.PublishState = publishExcluded }, state: AccessPending,
			code: AccessCheckPublished, detail: "site_not_in_publication"},
		// blocked wins over pending
		"blocked and pending": {mutate: func(f *accessFacts) { f.OnlineNodes, f.DNS = 0, nil }, state: AccessBlocked, code: AccessCheckLineGroup, detail: "no_online_nodes"},
	} {
		t.Run(name, func(t *testing.T) {
			facts := ready()
			c.mutate(&facts)
			got := buildAccessReadiness(facts, now)
			if got.State != c.state {
				t.Fatalf("state=%s want %s (%+v)", got.State, c.state, got.Checks)
			}
			if len(got.Checks) != 6 {
				t.Fatalf("checks=%d", len(got.Checks))
			}
			for _, check := range got.Checks {
				if check.Code != c.code {
					continue
				}
				if check.OK != c.ok || check.Detail != c.detail {
					t.Fatalf("%s ok=%v detail=%q want %v %q", check.Code, check.OK, check.Detail, c.ok, c.detail)
				}
				// dns_resolved has no time until a check of the current CNAME/domains ran.
				if check.CheckedAt == nil && !(check.Code == AccessCheckDNS && (check.Detail == "not_checked" || check.Detail == "waiting_cname")) {
					t.Fatalf("%s has no checked_at", check.Code)
				}
				return
			}
			t.Fatalf("no check %s", c.code)
		})
	}
	// dns_resolved carries the stored check time, the others the read time.
	got := buildAccessReadiness(ready(), now)
	for _, check := range got.Checks {
		want := now
		if check.Code == AccessCheckDNS {
			want = checked
		}
		if !check.CheckedAt.Equal(want) {
			t.Fatalf("%s checked_at=%v want %v", check.Code, check.CheckedAt, want)
		}
	}
	order := make([]string, len(got.Checks))
	for index, check := range got.Checks {
		order[index] = check.Code
	}
	if want := []string{AccessCheckPackage, AccessCheckLineGroup, AccessCheckCNAME, AccessCheckDNS, AccessCheckHTTPS,
		AccessCheckPublished}; !slices.Equal(order, want) {
		t.Fatalf("order=%v want %v", order, want)
	}
}

// published：判定在 site_publication_outcome_618（迁移 618，PG 集成测试覆盖）；
// 这里只验 publish_failed 带出失败节点与失败原因，其余状态不带。
func TestAccessReadinessPublishFailedDetails(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	code := "ERROR_CODE_PRECHECK_FAILED"
	nodes := []PublishFailedNode{{NodeID: "n1", NodeName: "hk-1", State: "failed", ErrorCode: &code}}
	facts := accessFacts{Enabled: true, PublishState: "failed", PublishFailedNodes: nodes, PublishFailureCode: ""}
	published := buildAccessReadiness(facts, now).Checks[5]
	if published.Detail != "publish_failed" || len(published.FailedNodes) != 1 || published.FailedNodes[0].NodeName != "hk-1" {
		t.Fatalf("publish_failed check = %+v", published)
	}
	facts = accessFacts{Enabled: true, PublishState: "failed", PublishFailureCode: "no_target_nodes"}
	if published := buildAccessReadiness(facts, now).Checks[5]; published.FailureCode != "no_target_nodes" || published.FailedNodes != nil {
		t.Fatalf("request failure check = %+v", published)
	}
	facts = accessFacts{Enabled: true, PublishState: "succeeded", PublishFailedNodes: nodes, PublishFailureCode: "x"}
	if published := buildAccessReadiness(facts, now).Checks[5]; !published.OK || published.FailedNodes != nil || published.FailureCode != "" {
		t.Fatalf("succeeded check carries failure details: %+v", published)
	}
}

// fix-readiness2 ①②③：只认已对外发布的端点（node_line_endpoint_published.published）与发布事实里的站点集合。
func TestAccessReadinessSQLReadsPublishedFacts(t *testing.T) {
	for _, want := range []string{"FROM node_line_endpoint_published endpoint", "endpoint.published",
		"site_publication_outcome_618(site.scope_id, site.id)"} {
		if !strings.Contains(accessReadinessSQL, want) {
			t.Errorf("accessReadinessSQL lacks %q", want)
		}
	}
	for _, stale := range []string{"node_line_endpoint_serving", "published.created_at >= site.created_at"} {
		if strings.Contains(accessReadinessSQL, stale) {
			t.Errorf("accessReadinessSQL still reads %q", stale)
		}
	}
	for _, want := range []string{"FROM node_line_endpoint_published endpoint", "endpoint.published"} {
		if !strings.Contains(dnsTargetSQL, want) {
			t.Errorf("dnsTargetSQL lacks %q", want)
		}
	}
	if strings.Contains(dnsTargetSQL, "FROM node_line_endpoints endpoint") {
		t.Error("dnsTargetSQL still accepts every endpoint address, unpublished standby ones included")
	}
}

// 限频：成功 10 分钟后再查；失败 10m·2^(n-1) 上限 1 小时。
func TestDNSCheckBackoff(t *testing.T) {
	for failures, want := range map[int]time.Duration{0: 10 * time.Minute, 1: 10 * time.Minute, 2: 20 * time.Minute,
		3: 40 * time.Minute, 4: time.Hour, 5: time.Hour, 60: time.Hour} {
		if got := dnsCheckDelay(failures, 10*time.Minute, time.Hour); got != want {
			t.Errorf("failures=%d delay=%v want %v", failures, got, want)
		}
	}
	// A longer configured interval is never cut by the cap.
	if got := dnsCheckDelay(1, 2*time.Hour, time.Hour); got != 2*time.Hour {
		t.Fatalf("interval above cap = %v", got)
	}
}

// 立即检查：同站点 1 分钟一次。
func TestManualAccessCheckWait(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	if wait := manualAccessCheckWait(nil, now); wait != 0 {
		t.Fatalf("first check wait=%v", wait)
	}
	last := now.Add(-20 * time.Second)
	if wait := manualAccessCheckWait(&last, now); wait != 40*time.Second {
		t.Fatalf("wait=%v", wait)
	}
	last = now.Add(-time.Minute)
	if wait := manualAccessCheckWait(&last, now); wait != 0 {
		t.Fatalf("after a minute wait=%v", wait)
	}
	last = now.Add(-1500 * time.Millisecond)
	if wait := manualAccessCheckWait(&last, now); wait != 59*time.Second {
		t.Fatalf("sub-second wait rounds up to whole seconds: %v", wait)
	}
}

type fakeResolver struct {
	cname map[string]string
	ips   map[string][]string
	err   map[string]error
}

func (r fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if err := r.err[host]; err != nil {
		return "", err
	}
	if value, ok := r.cname[host]; ok {
		return value, nil
	}
	return host + ".", nil
}

func (r fakeResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	if err := r.err[host]; err != nil {
		return nil, err
	}
	values, ok := r.ips[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	addresses := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addresses = append(addresses, netip.MustParseAddr(value))
	}
	return addresses, nil
}

// 解析判定：CNAME 到分配的 CNAME，或 A/AAAA 全部落在线路组节点 IP。
func TestResolveSiteDNS(t *testing.T) {
	target := dnsTarget{CNAME: "a1.cdn.example.net", Expected: []string{"192.0.2.10", "2001:db8::10"}}
	resolver := fakeResolver{
		cname: map[string]string{"www.example.com": "A1.CDN.example.net.", "chain.example.com": "a1.cdn.example.net",
			"cdnca-access-check.wild.example.com": "a1.cdn.example.net."},
		ips: map[string][]string{"apex.example.com": {"192.0.2.10", "2001:db8::10"}, "other.example.com": {"198.51.100.1"},
			"mixed.example.com": {"192.0.2.10", "198.51.100.1"}},
		err: map[string]error{"timeout.example.com": &net.DNSError{Err: "i/o timeout", Name: "timeout.example.com", IsTimeout: true},
			"broken.example.com": errors.New("boom")},
	}
	for domain, want := range map[string]string{
		"www.example.com":     "",
		"chain.example.com":   "",
		"*.wild.example.com":  "",
		"apex.example.com":    "",
		"other.example.com":   DNSPointsElsewhere,
		"mixed.example.com":   DNSPointsElsewhere,
		"missing.example.com": DNSNotFound,
		"timeout.example.com": DNSLookupFailed,
		"broken.example.com":  DNSLookupFailed,
	} {
		if got := resolveDomain(context.Background(), resolver, domain, target); got.Code != want || got.Domain != domain {
			t.Errorf("%s = %+v want %q", domain, got, want)
		}
	}
	outcome := resolveSiteDNS(context.Background(), resolver, dnsTarget{CNAME: target.CNAME, Expected: target.Expected,
		Domains: []string{"www.example.com", "other.example.com", "missing.example.com"}})
	if outcome.OK || outcome.Detail != DNSPointsElsewhere || len(outcome.Results) != 3 {
		t.Fatalf("site outcome = %+v", outcome)
	}
	outcome = resolveSiteDNS(context.Background(), resolver, dnsTarget{CNAME: target.CNAME, Expected: target.Expected,
		Domains: []string{"www.example.com", "apex.example.com"}})
	if !outcome.OK || outcome.Detail != "" {
		t.Fatalf("site outcome = %+v", outcome)
	}
	if outcome := resolveSiteDNS(context.Background(), resolver, dnsTarget{Domains: []string{"www.example.com"}}); outcome.OK ||
		outcome.Detail != "waiting_cname" {
		t.Fatalf("no cname outcome = %+v", outcome)
	}
	if outcome := resolveSiteDNS(context.Background(), resolver, dnsTarget{CNAME: target.CNAME}); outcome.OK ||
		outcome.Detail != DNSNoDomains {
		t.Fatalf("no domains outcome = %+v", outcome)
	}
}

// 平台节点名不给用户看：发布失败给所有身份失败节点数与归一化原因，节点明细只给平台身份。
func TestPublishFailureRedactedForTenant(t *testing.T) {
	precheck, internal := "ERROR_CODE_PRECHECK_FAILED", "ERROR_CODE_INTERNAL"
	nodes := []PublishFailedNode{
		{NodeID: "n1", NodeName: "hk-1", State: "failed", ErrorCode: &precheck},
		{NodeID: "n2", NodeName: "hk-2", State: "failed", ErrorCode: &precheck},
		{NodeID: "n3", NodeName: "sg-1", State: "reverted"},
		{NodeID: "n4", NodeName: "sg-2", State: "failed", ErrorCode: &internal},
	}
	build := func() AccessReadiness {
		return buildAccessReadiness(accessFacts{Enabled: true, PublishState: "failed", PublishFailedNodes: nodes}, time.Now())
	}
	platform := build()
	platform.redactForActor(Actor{ScopeKind: "platform"})
	if got := platform.Checks[5]; len(got.FailedNodes) != 4 || got.FailedNodeCount != 4 ||
		!slices.Equal(got.FailedNodeReasons, []string{"internal", "precheck_failed", "reverted"}) {
		t.Fatalf("platform published = %+v", got)
	}
	tenant := build()
	tenant.redactForActor(Actor{ScopeKind: "tenant"})
	if got := tenant.Checks[5]; got.Detail != "publish_failed" || got.FailedNodes != nil || got.FailedNodeCount != 4 ||
		!slices.Equal(got.FailedNodeReasons, []string{"internal", "precheck_failed", "reverted"}) {
		t.Fatalf("tenant published = %+v", got)
	}
	encoded, _ := json.Marshal(tenant)
	for _, leak := range []string{"hk-1", "sg-1", "n1", "node_name", "node_id"} {
		if strings.Contains(string(encoded), leak) {
			t.Fatalf("tenant readiness leaks %q: %s", leak, encoded)
		}
	}
}
