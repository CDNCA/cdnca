package ddos

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fix-adwhitelist2 §3 (SEC-CONTROL-RECOVERY-01): a released auto defense kernel ban is deleted at once from the ban
// set and the XDP front. Only bans Ban wrote are touched (a kernel rate ban is not the release's); every element is
// its own batch (an element the kernel timed out meanwhile must not keep the others).
func TestUnbanDeletesOnlyOwnBans(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := NewManager(t.Context(), runner, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	front := &fakeFront{running: true}
	manager.SetFront(front)
	spec, _ := NewSpec(testDDoS(t), []PortRange{{80, 80}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	own4, own6 := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:5::2")
	if _, err := manager.Ban(t.Context(), []netip.Addr{own4, own6}, time.Minute); err != nil {
		t.Fatal(err)
	}
	before := len(runner.batches)
	n, err := manager.Unban(t.Context(), []netip.Addr{own4, own6, netip.MustParseAddr("203.0.113.9")})
	if err != nil || n != 2 {
		t.Fatalf("unban n=%d err=%v", n, err)
	}
	batches := runner.batches[before:]
	if len(batches) != 2 || !strings.Contains(batches[0], "delete element inet cdnca_ddos ban_v4 { 198.51.100.1 }") ||
		!strings.Contains(batches[1], "delete element inet cdnca_ddos ban_v6 { 2001:db8:5:: }") {
		t.Fatalf("unban batches %q", batches)
	}
	if len(front.unbans) != 2 || front.unbans[1] != netip.MustParseAddr("2001:db8:5::") {
		t.Fatalf("front unbans %v", front.unbans)
	}
	// released once: a second release finds nothing of its own
	before = len(runner.batches)
	if n, err := manager.Unban(t.Context(), []netip.Addr{own4}); err != nil || n != 0 || len(runner.batches) != before {
		t.Fatalf("second unban n=%d err=%v batches=%d", n, err, len(runner.batches)-before)
	}
	// a failing element does not keep the next one banned
	if _, err := manager.Ban(t.Context(), []netip.Addr{own4, netip.MustParseAddr("198.51.100.2")}, time.Minute); err != nil {
		t.Fatal(err)
	}
	runner.fail = "--file"
	if n, err := manager.Unban(t.Context(), []netip.Addr{own4}); err == nil || n != 0 {
		t.Fatalf("failed unban n=%d err=%v", n, err)
	}
	runner.fail = ""
	if n, err := manager.Unban(t.Context(), []netip.Addr{own4, netip.MustParseAddr("198.51.100.2")}); err != nil || n != 2 {
		t.Fatalf("retried unban n=%d err=%v (a failed delete keeps the ban its own)", n, err)
	}
}
