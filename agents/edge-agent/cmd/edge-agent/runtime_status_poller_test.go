package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
)

func TestRuntimeStatusPollerRunsEverySecondUntilCancelled(t *testing.T) {
	poller := newRuntimeStatusPoller("http://127.0.0.1:1/healthz", 50*time.Millisecond)
	ctx, cancel := context.WithCancel(t.Context())
	waits := 0
	poller.wait = func(_ context.Context, interval time.Duration) error {
		if interval != time.Second {
			t.Fatalf("interval = %v", interval)
		}
		waits++
		if waits == 2 {
			cancel()
			return context.Canceled
		}
		return nil
	}
	if err := poller.Run(ctx); err != context.Canceled || waits != 2 {
		t.Fatalf("Run() = %v after %d waits", err, waits)
	}
	if newRuntimeStatusPoller("", time.Second) != nil {
		t.Fatal("a poller without a health URL was built")
	}
}

type recordingCCNotifier struct {
	events []gatewayclient.CCAutoSwitchEvent
	fail   bool
}

func (notifier *recordingCCNotifier) NotifyCCAutoSwitch(_ context.Context, event gatewayclient.CCAutoSwitchEvent) error {
	if notifier.fail {
		notifier.fail = false
		return context.DeadlineExceeded
	}
	notifier.events = append(notifier.events, event)
	return nil
}

// FX65: each engagement (engaged site, engage second) is reported once; a
// recovered site's next engagement is reported again; a failed queue retries.
func TestRuntimeStatusPollerReportsEachCCAutoSwitchEngagementOnce(t *testing.T) {
	site := `{"tenant_scope_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7a02","site_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7a03",` +
		`"policy_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7a04","policy_version":3,"active":%s,"sequence":1,"since":%d,` +
		`"trigger_qps":900,"trigger_5xx":0,"observed_qps":900,"observed_5xx":0,"qps_total":500,"qps_5xx":0,"recover_seconds":300}`
	body := ""
	set := func(active string, since int64) {
		body = `{"schema_version":"cdnca.edge.cc-auto-switch/v1","observed_at":1760000100,"sites":[` + fmt.Sprintf(site, active, since) + `]}`
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz/cc-auto-switch" {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write([]byte(body))
	}))
	defer server.Close()
	notifier := &recordingCCNotifier{fail: true}
	poller := newRuntimeStatusPoller(server.URL+"/healthz", time.Second).
		withCCAutoSwitchNotifier("018f47a2-5b9c-7d31-8a60-104c9c0b7a01", notifier)

	set("false", 0)
	poller.pollOnce(t.Context())
	set("true", 1760000000)
	poller.pollOnce(t.Context()) // queue fails, retried
	poller.pollOnce(t.Context())
	poller.pollOnce(t.Context())
	if len(notifier.events) != 1 {
		t.Fatalf("events = %+v", notifier.events)
	}
	event := notifier.events[0]
	if event.NodeID != "018f47a2-5b9c-7d31-8a60-104c9c0b7a01" || event.PolicyVersion != 3 || event.TriggerQPS != 900 ||
		event.QPSTotal != 500 || event.RecoverSeconds != 300 || !event.EngagedAt.Equal(time.Unix(1760000000, 0)) {
		t.Fatalf("event = %+v", event)
	}
	set("false", 1760000400)
	poller.pollOnce(t.Context())
	set("true", 1760000500)
	poller.pollOnce(t.Context())
	if len(notifier.events) != 2 || !notifier.events[1].EngagedAt.Equal(time.Unix(1760000500, 0)) {
		t.Fatalf("events after a second engagement = %+v", notifier.events)
	}
	body = `{"schema_version":"cdnca.edge.cc-auto-switch/v1","observed_at":1,"sites":{}}`
	poller.pollOnce(t.Context())
	if len(poller.engaged) != 0 {
		t.Fatalf("engaged = %v after the site left", poller.engaged)
	}
}

// b3-fix: before the node's first Apply OpenResty is not running by design;
// the poller sends no request (and so logs no warning) until ready, then
// polls as before.
func TestRuntimeStatusPollerWaitsForFirstApply(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		http.NotFound(writer, request)
	}))
	defer server.Close()
	applied := false
	poller := newRuntimeStatusPoller(server.URL+"/healthz", time.Second).
		withCCAutoSwitchNotifier("018f47a2-5b9c-7d31-8a60-104c9c0b7a01", &recordingCCNotifier{}).
		withReady(func() bool { return applied })
	poller.pollOnce(t.Context())
	poller.pollOnce(t.Context())
	if requests != 0 {
		t.Fatalf("requests before the first apply = %d", requests)
	}
	applied = true
	poller.pollOnce(t.Context())
	if requests == 0 {
		t.Fatal("no request after the first apply")
	}
	if (*runtimeStatusPoller)(nil).withReady(func() bool { return true }) != nil {
		t.Fatal("withReady built a poller")
	}
}
