package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/sitedrop"
)

const (
	dropTestNode   = "11111111-1111-4111-8111-111111111111"
	dropTestTenant = "33333333-3333-4333-8333-333333333333"
	dropSiteA      = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" // level D, exclusive 8443 + shared 443/80
	dropSiteB      = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" // normal, shares 443/80
	dropSiteC      = "cccccccc-cccc-4ccc-8ccc-cccccccccccc" // level D, 9000 shared with an L4 stream
	dropSiteGone   = "dddddddd-dddd-4ddd-8ddd-dddddddddddd" // listed, not run here
)

type fakeSiteDropExecutor struct {
	applied []siteDropPlan
	clears  int
	err     error
}

func (executor *fakeSiteDropExecutor) Apply(_ context.Context, plan siteDropPlan) error {
	if executor.err != nil {
		return executor.err
	}
	executor.applied = append(executor.applied, plan)
	return nil
}

func (executor *fakeSiteDropExecutor) Clear(context.Context) error {
	if executor.err != nil {
		return executor.err
	}
	executor.clears++
	return nil
}

func dropTestSites() ([]edgesite.Site, []ddos.PortRange) {
	tls := &edgesite.TLS{CertificateVersionID: "cert"}
	return []edgesite.Site{
		{SiteID: dropSiteA, TenantID: dropTestTenant, Hosts: edgesite.Hosts{Primary: "a.example", Aliases: []string{"*.a.example", "www.a.example"}},
			Listeners: []edgesite.Listener{{Port: 80}, {Port: 443, TLS: tls}, {Port: 8443, TLS: tls}, {Port: 8443, TLS: tls, AddressFamily: edgesite.FamilyIPv6}}},
		{SiteID: dropSiteB, TenantID: dropTestTenant, Hosts: edgesite.Hosts{Primary: "b.example"},
			Listeners: []edgesite.Listener{{Port: 80}, {Port: 443, TLS: tls}}},
		{SiteID: dropSiteC, TenantID: dropTestTenant, Hosts: edgesite.Hosts{Primary: "c.example"},
			Listeners: []edgesite.Listener{{Port: 9000, TLS: tls}}},
	}, []ddos.PortRange{{First: 8990, Last: 9010}}
}

func signedDropList(t *testing.T, private ed25519.PrivateKey, node string, revision uint64, now time.Time, sites ...sitedrop.Site) []byte {
	t.Helper()
	encoded, err := sitedrop.Sign(sitedrop.List{NodeID: node, Revision: revision, IssuedAt: now.Unix(), Sites: sites}, "edge-publish", private)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func dropSite(id string, now time.Time, until time.Duration) sitedrop.Site {
	return sitedrop.Site{SiteID: id, TenantID: dropTestTenant, Since: now.Unix() - 60, Until: now.Add(until).Unix()}
}

func newTestSiteDropRuntime(t *testing.T, xdp bool, now *time.Time) (*siteDropRuntime, *fakeSiteDropExecutor, ed25519.PrivateKey) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(nil)
	trusted := func(keyID string) (ed25519.PublicKey, bool) { return public, keyID == "edge-publish" }
	executor := &fakeSiteDropExecutor{}
	runtime := newSiteDropRuntime(dropTestNode, trusted, dropTestSites, func() bool { return xdp }, executor, func() time.Time { return *now })
	if runtime == nil {
		t.Fatal("runtime not built")
	}
	return runtime, executor, private
}

// Exclusive ports are the ports only level D sites use (an L4 stream counts
// as another user); with XDP the shared TLS ports drop the D sites' names.
func TestSiteDropDerivesExclusivePortsAndServerNamesWithXDP(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	runtime, executor, private := newTestSiteDropRuntime(t, true, &now)
	result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 1, now,
		dropSite(dropSiteA, now, time.Hour), dropSite(dropSiteC, now, time.Hour), dropSite(dropSiteGone, now, time.Hour)))
	want := gatewayclient.SiteDropResult{Applied: true, Mode: siteDropModeXDP, Sites: 2, Ports: 1, ServerNames: 4,
		Rejected: []gatewayclient.SiteDropRejection{{SiteID: dropSiteGone, Reason: sitedrop.RejectNotServed}}}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	plan := siteDropPlan{Mode: siteDropModeXDP, SiteIDs: []string{dropSiteA, dropSiteC}, Ports: []uint16{8443},
		SNIPorts:    []uint16{443, 9000},
		ServerNames: []string{"*.a.example", "a.example", "c.example", "www.a.example"},
		KeepNames:   []string{"b.example"},
		Hosts:       []string{"*.a.example", "a.example", "c.example", "www.a.example"}}
	if len(executor.applied) != 1 || !reflect.DeepEqual(executor.applied[0], plan) {
		t.Fatalf("plans = %+v, want %+v", executor.applied, plan)
	}
}

// Without XDP shared TLS ports are not dropped: the receipt names each such
// (site, port) sni_unavailable; plain HTTP shared ports are left to OpenResty.
func TestSiteDropWithoutXDPReportsSNIUnavailable(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	runtime, executor, private := newTestSiteDropRuntime(t, false, &now)
	result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 1, now,
		dropSite(dropSiteA, now, time.Hour), dropSite(dropSiteC, now, time.Hour)))
	want := gatewayclient.SiteDropResult{Applied: true, Mode: siteDropModeNFTables, Sites: 2, Ports: 1,
		Rejected: []gatewayclient.SiteDropRejection{
			{SiteID: dropSiteA, Port: 443, Reason: sitedrop.RejectSNIUnavailable},
			{SiteID: dropSiteC, Port: 9000, Reason: sitedrop.RejectSNIUnavailable}}}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	if got := executor.applied[0]; got.Mode != siteDropModeNFTables || len(got.ServerNames) != 0 || len(got.SNIPorts) != 0 ||
		!reflect.DeepEqual(got.Ports, []uint16{8443}) || len(got.Hosts) != 4 {
		t.Fatalf("plan = %+v", got)
	}
}

// A snapshot not signed by the trusted key, for another node, or older than
// the held one is refused and the previous one stays.
func TestSiteDropRefusesUntrustedWrongNodeAndStale(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	runtime, executor, private := newTestSiteDropRuntime(t, true, &now)
	_, stranger, _ := ed25519.GenerateKey(nil)
	if result := runtime.ApplySiteDrop(signedDropList(t, stranger, dropTestNode, 5, now, dropSite(dropSiteA, now, time.Hour))); result.Applied ||
		result.ErrorCode != sitedrop.ErrorUntrusted {
		t.Fatalf("untrusted result = %+v", result)
	}
	if result := runtime.ApplySiteDrop([]byte(`{"schema":"x"}`)); result.Applied || result.ErrorCode != sitedrop.ErrorInvalid {
		t.Fatalf("invalid result = %+v", result)
	}
	other := "99999999-9999-4999-8999-999999999999"
	if result := runtime.ApplySiteDrop(signedDropList(t, private, other, 5, now, dropSite(dropSiteA, now, time.Hour))); result.Applied ||
		result.ErrorCode != sitedrop.ErrorWrongNode {
		t.Fatalf("wrong node result = %+v", result)
	}
	if len(executor.applied) != 0 {
		t.Fatalf("refused snapshots reached the executor: %+v", executor.applied)
	}
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 2, now, dropSite(dropSiteA, now, time.Hour))); !result.Applied {
		t.Fatalf("revision 2 = %+v", result)
	}
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 1, now)); result.Applied || result.ErrorCode != sitedrop.ErrorStale {
		t.Fatalf("revision 1 after 2 = %+v", result)
	}
	if len(executor.applied) != 1 || executor.clears != 0 {
		t.Fatalf("stale snapshot changed the drop: %+v clears %d", executor.applied, executor.clears)
	}
	// The same revision again (redelivery) is accepted.
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 2, now, dropSite(dropSiteA, now, time.Hour))); !result.Applied {
		t.Fatalf("revision 2 again = %+v", result)
	}
}

// An executor failure answers runtime_unavailable and keeps the previous
// snapshot (a later older revision is still stale against it).
func TestSiteDropExecutorFailureKeepsPrevious(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	runtime, executor, private := newTestSiteDropRuntime(t, true, &now)
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 3, now, dropSite(dropSiteA, now, time.Hour))); !result.Applied {
		t.Fatalf("revision 3 = %+v", result)
	}
	executor.err = errors.New("xdp map full")
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 4, now)); result.Applied || result.ErrorCode != sitedrop.ErrorRuntime {
		t.Fatalf("failed apply = %+v", result)
	}
	executor.err = nil
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 3, now, dropSite(dropSiteA, now, time.Hour))); !result.Applied {
		t.Fatalf("revision 3 after failed 4 = %+v", result)
	}
	// An executor without the OpenResty host pusher answers not_supported.
	runtime.executor = kernelSiteDropExecutor{nft: &fakeSiteDropNFT{}}
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 5, now, dropSite(dropSiteA, now, time.Hour))); result.Applied ||
		result.ErrorCode != sitedrop.ErrorNotSupported {
		t.Fatalf("unsupported executor = %+v", result)
	}
}

// Each site is lifted at its until by the node itself; when none is left the
// executor is cleared. An empty snapshot clears at once.
func TestSiteDropLiftsExpiredSites(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	runtime, executor, private := newTestSiteDropRuntime(t, true, &now)
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 1, now,
		dropSite(dropSiteA, now, time.Hour), dropSite(dropSiteC, now, 2*time.Hour))); !result.Applied {
		t.Fatalf("apply = %+v", result)
	}
	runtime.refresh(context.Background())
	if len(executor.applied) != 1 {
		t.Fatalf("unchanged plan re-applied: %d", len(executor.applied))
	}
	now = now.Add(time.Hour)
	runtime.refresh(context.Background())
	if len(executor.applied) != 2 || !reflect.DeepEqual(executor.applied[1].SiteIDs, []string{dropSiteC}) ||
		len(executor.applied[1].Ports) != 0 {
		t.Fatalf("after A expired: %+v", executor.applied)
	}
	now = now.Add(time.Hour)
	runtime.refresh(context.Background())
	if executor.clears != 1 || len(executor.applied) != 2 {
		t.Fatalf("after all expired: applied %d clears %d", len(executor.applied), executor.clears)
	}
	runtime.refresh(context.Background())
	if executor.clears != 1 {
		t.Fatalf("cleared twice: %d", executor.clears)
	}

	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 2, now, dropSite(dropSiteA, now, time.Hour))); !result.Applied {
		t.Fatalf("revision 2 = %+v", result)
	}
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 3, now)); !result.Applied || result.Sites != 0 {
		t.Fatalf("empty snapshot = %+v", result)
	}
	if executor.clears != 2 {
		t.Fatalf("empty snapshot did not clear: %d", executor.clears)
	}
}

// A site that was not served when the snapshot came is dropped once it runs.
func TestSiteDropFollowsRunningSites(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	public, private, _ := ed25519.GenerateKey(nil)
	running := []edgesite.Site(nil)
	executor := &fakeSiteDropExecutor{}
	runtime := newSiteDropRuntime(dropTestNode, func(string) (ed25519.PublicKey, bool) { return public, true },
		func() ([]edgesite.Site, []ddos.PortRange) { return running, nil }, func() bool { return true }, executor,
		func() time.Time { return now })
	result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 1, now, dropSite(dropSiteA, now, time.Hour)))
	if !result.Applied || result.Sites != 0 || len(result.Rejected) != 1 || executor.clears != 1 {
		t.Fatalf("not served = %+v clears %d", result, executor.clears)
	}
	running, _ = dropTestSites()
	runtime.refresh(context.Background())
	if len(executor.applied) != 1 || !reflect.DeepEqual(executor.applied[0].Ports, []uint16{8443}) {
		t.Fatalf("after the site runs: %+v", executor.applied)
	}
}

// A plan the executor failed on is retried no sooner than every 30 seconds;
// a different plan (a site expired, sites changed) is tried at once.
func TestSiteDropRefreshThrottlesFailedPlan(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	runtime, executor, private := newTestSiteDropRuntime(t, true, &now)
	calls := 0
	failing := &countingSiteDropExecutor{inner: executor, calls: &calls}
	runtime.executor = failing
	failing.err = errors.New("nft busy")
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 1, now,
		dropSite(dropSiteA, now, time.Hour), dropSite(dropSiteC, now, 2*time.Hour))); result.Applied {
		t.Fatalf("failed apply = %+v", result)
	}
	failing.err = nil
	if result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 1, now,
		dropSite(dropSiteA, now, time.Hour), dropSite(dropSiteC, now, 2*time.Hour))); !result.Applied {
		t.Fatalf("apply = %+v", result)
	}
	failing.err = errors.New("nft busy")
	runtime.executed = nil // the executor lost its state
	calls = 0
	// Fails at +1s, then waits until +31s.
	for second := 0; second < 30; second++ {
		now = now.Add(time.Second)
		runtime.refresh(context.Background())
	}
	if calls != 1 {
		t.Fatalf("failed plan retried %d times within 30 seconds, want 1", calls)
	}
	now = now.Add(time.Second)
	runtime.refresh(context.Background())
	if calls != 2 {
		t.Fatalf("not retried after 30 seconds: %d", calls)
	}
	// A changed plan (A expires) is executed at once.
	now = time.Unix(1_800_000_000, 0).Add(time.Hour)
	runtime.refresh(context.Background())
	if calls != 3 {
		t.Fatalf("changed plan waited for the throttle: %d", calls)
	}
	failing.err = nil
	runtime.refresh(context.Background())
	if calls != 3 {
		t.Fatalf("same failed plan retried within 30 seconds: %d", calls)
	}
	now = now.Add(siteDropRetryInterval)
	runtime.refresh(context.Background())
	if calls != 4 || runtime.executed == nil || runtime.failed != nil {
		t.Fatalf("recovery: calls %d executed %v failed %v", calls, runtime.executed, runtime.failed)
	}
}

type countingSiteDropExecutor struct {
	inner *fakeSiteDropExecutor
	calls *int
	err   error
}

func (executor *countingSiteDropExecutor) Apply(ctx context.Context, plan siteDropPlan) error {
	*executor.calls++
	if executor.err != nil {
		return executor.err
	}
	return executor.inner.Apply(ctx, plan)
}

func (executor *countingSiteDropExecutor) Clear(ctx context.Context) error {
	*executor.calls++
	if executor.err != nil {
		return executor.err
	}
	return executor.inner.Clear(ctx)
}
