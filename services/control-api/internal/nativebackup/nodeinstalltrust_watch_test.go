package nativebackup

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fix-btenv5: control-api checks the published node install trust against the
// current resolution of the control-plane domain, control.env's download port
// and root CA at start and every 10 minutes, and republishes on a difference.

type watchProbe struct {
	fixture   trustFixture
	addresses map[string][]string
	lookups   int
	publishes int
	alerts    []NodeInstallTrustAlert
	alertErr  error
	published []NodeInstallTrustChange
	now       time.Time
}

func newWatchProbe(t *testing.T) (*watchProbe, *NodeInstallTrustWatcher) {
	probe := &watchProbe{fixture: newTrustFixture(t, ""), addresses: map[string][]string{"cdnca.com": {"203.0.113.20"}},
		now: time.Date(2026, 10, 28, 5, 0, 0, 0, time.UTC)}
	lookup := func(ctx context.Context, name string) ([]string, error) {
		probe.lookups++
		return lookupTable(probe.addresses)(ctx, name)
	}
	watcher := &NodeInstallTrustWatcher{Layout: probe.fixture.layout, Lookup: lookup,
		Now: func() time.Time { return probe.now },
		Publish: func(ctx context.Context, layout Layout, lookup func(context.Context, string) ([]string, error)) (NodeInstallTrust, error) {
			probe.publishes++
			return PublishNodeInstallTrust(ctx, layout, lookup)
		},
		OnPublished: func(_ context.Context, change NodeInstallTrustChange) {
			probe.published = append(probe.published, change)
		},
		OnAlert: func(_ context.Context, alert NodeInstallTrustAlert) error {
			probe.alerts = append(probe.alerts, alert)
			return probe.alertErr
		}}
	return probe, watcher
}

func (probe *watchProbe) files() string {
	return probe.fixture.read(NodeInstallTrustFile) + probe.fixture.read(NodeInstallDefaultsFile) + probe.fixture.read(WebRuntimeConfigFile)
}

func TestNodeInstallTrustWatcherRepublishesWhenTheResolutionChanges(t *testing.T) {
	probe, watcher := newWatchProbe(t)
	// The restored document still names the source host (198.51.100.7:443, system root).
	check := watcher.Check(context.Background())
	if check.Outcome != NodeInstallTrustRepublished || check.Err != nil || probe.publishes != 1 {
		t.Fatalf("first check = %+v, publishes %d", check, probe.publishes)
	}
	if !strings.Contains(probe.fixture.read(NodeInstallDefaultsFile), "upgrade_trust_sha256="+check.Trust.SHA256+"\n") ||
		!strings.Contains(probe.fixture.read(WebRuntimeConfigFile), check.Trust.SHA256) {
		t.Fatal("node-install-defaults / runtime-config.js do not pin the republished document")
	}
	if len(probe.published) != 1 || probe.published[0].Before == nil || probe.published[0].Before.Port != 443 ||
		strings.Join(probe.published[0].Before.Addresses, ",") != "198.51.100.7" ||
		probe.published[0].After.Port != 19445 || strings.Join(probe.published[0].After.Addresses, ",") != "203.0.113.20" {
		t.Fatalf("published change = %+v", probe.published)
	}
	// The DNS switch: the domain now resolves to another address.
	probe.addresses = map[string][]string{"cdnca.com": {"203.0.113.30", "203.0.113.31"}}
	moved := watcher.Check(context.Background())
	if moved.Outcome != NodeInstallTrustRepublished || moved.Trust.SHA256 == check.Trust.SHA256 || probe.publishes != 2 ||
		strings.Join(moved.Trust.Download.Addresses, ",") != "203.0.113.30,203.0.113.31" {
		t.Fatalf("after the DNS switch = %+v", moved)
	}
	if !strings.Contains(probe.fixture.read(NodeInstallDefaultsFile), moved.Trust.SHA256) {
		t.Fatal("the install command digest did not follow the new resolution")
	}
	// control.env changes (a port profile change) are picked up the same way.
	probe.fixture.write(ConfigDirectory+"/control.env", strings.Replace(probe.fixture.read(ConfigDirectory+"/control.env"),
		"https://cdnca.com:19445/", "https://cdnca.com:19446/", 1), 0o600)
	if ported := watcher.Check(context.Background()); ported.Outcome != NodeInstallTrustRepublished || ported.Trust.Download.Port != 19446 {
		t.Fatalf("after a port change = %+v", ported)
	}
}

func TestNodeInstallTrustWatcherLeavesAConsistentDocumentAlone(t *testing.T) {
	probe, watcher := newWatchProbe(t)
	if first := watcher.Check(context.Background()); first.Outcome != NodeInstallTrustRepublished {
		t.Fatalf("first check = %+v", first)
	}
	before, publishes := probe.files(), probe.publishes
	for range 3 {
		if check := watcher.Check(context.Background()); check.Outcome != NodeInstallTrustInSync || check.Err != nil {
			t.Fatalf("consistent check = %+v", check)
		}
	}
	if probe.publishes != publishes || probe.files() != before || len(probe.published) != 1 {
		t.Fatalf("a consistent document was republished (%d publishes)", probe.publishes-publishes)
	}
	// Loopback answers are filtered: still the same policy.
	probe.addresses = map[string][]string{"cdnca.com": {"203.0.113.20", "127.0.0.1"}}
	if check := watcher.Check(context.Background()); check.Outcome != NodeInstallTrustInSync {
		t.Fatalf("loopback-only difference = %+v", check)
	}
	// A digest pin left behind (crash between the document and the pins) is resynced.
	probe.fixture.write(WebRuntimeConfigFile, "window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = \""+oldTrustSHA+"\";\n", 0o644)
	if check := watcher.Check(context.Background()); check.Outcome != NodeInstallTrustRepublished ||
		!strings.Contains(probe.fixture.read(WebRuntimeConfigFile), check.Trust.SHA256) {
		t.Fatalf("stale pin = %+v", check)
	}
}

func TestNodeInstallTrustWatcherResolutionFailureWritesNothing(t *testing.T) {
	cases := map[string]map[string][]string{
		"lookup error":  {},
		"loopback only": {"cdnca.com": {"127.0.0.1", "::1"}},
	}
	for name, table := range cases {
		t.Run(name, func(t *testing.T) {
			probe, watcher := newWatchProbe(t)
			probe.addresses = table
			before := probe.files()
			check := watcher.Check(context.Background())
			if check.Outcome != NodeInstallTrustFailed || check.Err == nil || check.Host != "cdnca.com" || check.Port != 19445 {
				t.Fatalf("check = %+v", check)
			}
			if probe.publishes != 0 || probe.files() != before || len(probe.published) != 0 {
				t.Fatal("a resolution failure published or changed files")
			}
		})
	}
}

func TestNodeInstallTrustWatcherSkipsWithoutTheUpgradeRuntime(t *testing.T) {
	probe, watcher := newWatchProbe(t)
	probe.fixture.write(ConfigDirectory+"/control.env", "CONTROL_INSTALLATION_ID="+testInstallation+"\n", 0o600)
	if check := watcher.Check(context.Background()); check.Outcome != NodeInstallTrustSkipped || probe.lookups != 0 {
		t.Fatalf("no upgrade runtime = %+v", check)
	}
	empty := &NodeInstallTrustWatcher{Layout: Layout{Root: t.TempDir()}}
	if check := empty.Check(context.Background()); check.Outcome != NodeInstallTrustSkipped {
		t.Fatalf("no control.env = %+v", check)
	}
}

// Consecutive failures alert once per failure streak; a success ends the streak.
func TestNodeInstallTrustWatcherAlertsOncePerFailureStreak(t *testing.T) {
	probe, watcher := newWatchProbe(t)
	probe.addresses = map[string][]string{}
	start := probe.now
	tick := func() NodeInstallTrustCheck {
		check := watcher.tick(context.Background())
		probe.now = probe.now.Add(NodeInstallTrustCheckInterval)
		return check
	}
	for index := 1; index < NodeInstallTrustAlertAfter; index++ {
		tick()
		if len(probe.alerts) != 0 {
			t.Fatalf("alerted after %d failures", index)
		}
	}
	tick()
	if len(probe.alerts) != 1 {
		t.Fatalf("alerts after %d failures = %d", NodeInstallTrustAlertAfter, len(probe.alerts))
	}
	alert := probe.alerts[0]
	if !alert.Since.Equal(start) || alert.Failures != NodeInstallTrustAlertAfter || alert.Host != "cdnca.com" || alert.Port != 19445 ||
		!strings.Contains(alert.Reason, "cannot resolve cdnca.com") {
		t.Fatalf("alert = %+v", alert)
	}
	for range 5 {
		tick()
	}
	if len(probe.alerts) != 1 {
		t.Fatalf("the same failure streak alerted %d times", len(probe.alerts))
	}
	// Recovery ends the streak; a later streak alerts again with its own start.
	probe.addresses = map[string][]string{"cdnca.com": {"203.0.113.20"}}
	if check := tick(); check.Outcome != NodeInstallTrustRepublished {
		t.Fatalf("recovery = %+v", check)
	}
	probe.addresses = map[string][]string{}
	second := probe.now
	for range NodeInstallTrustAlertAfter {
		tick()
	}
	if len(probe.alerts) != 2 || !probe.alerts[1].Since.Equal(second) {
		t.Fatalf("second streak alerts = %+v", probe.alerts)
	}
	// An alert that could not be queued is retried on the next failure.
	probe.addresses = map[string][]string{"cdnca.com": {"203.0.113.20"}}
	tick()
	probe.addresses, probe.alertErr = map[string][]string{}, errors.New("database unavailable")
	for range NodeInstallTrustAlertAfter + 1 {
		tick()
	}
	if len(probe.alerts) != 4 || !probe.alerts[2].Since.Equal(probe.alerts[3].Since) {
		t.Fatalf("failed alert enqueue was not retried: %+v", probe.alerts)
	}
}

// Run checks at start and then on every interval of the injected clock.
func TestNodeInstallTrustWatcherRunChecksAtStartAndEveryInterval(t *testing.T) {
	probe, watcher := newWatchProbe(t)
	ticks := make(chan time.Time)
	intervals := make(chan time.Duration, 4)
	watcher.After = func(interval time.Duration) <-chan time.Time {
		intervals <- interval
		return ticks
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watcher.Run(ctx)
		close(done)
	}()
	if interval := <-intervals; interval != 10*time.Minute {
		t.Fatalf("interval = %s", interval)
	}
	if probe.publishes != 1 {
		t.Fatalf("start check publishes = %d", probe.publishes)
	}
	probe.addresses = map[string][]string{"cdnca.com": {"203.0.113.30"}}
	ticks <- probe.now
	<-intervals
	if probe.publishes != 2 {
		t.Fatalf("interval check publishes = %d", probe.publishes)
	}
	cancel()
	<-done
}
