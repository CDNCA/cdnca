package ddos

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SEC-CONTROL-RECOVERY-01/R3: the bans Ban wrote survive an agent restart
// (the adopted table keeps them, so must the manager): the restarted manager
// deletes its own ban, still leaves a ban it did not write, and an own ban
// that ended meanwhile is not an error.
func TestOwnBansSurviveManagerRestart(t *testing.T) {
	runner := &fakeRunner{}
	root := t.TempDir()
	manager, err := NewManager(t.Context(), runner, root)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := NewSpec(testDDoS(t), []PortRange{{80, 80}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	own4, own6, short := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:7::9"), netip.MustParseAddr("198.51.100.3")
	if n, err := manager.Ban(t.Context(), []netip.Addr{own4, own6}, time.Hour); err != nil || n != 2 {
		t.Fatalf("ban n=%d err=%v", n, err)
	}
	if _, err := manager.Ban(t.Context(), []netip.Addr{short}, time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // short's ban ended
	restarted, err := NewManager(t.Context(), runner, root)
	if err != nil || restarted.Active() == nil {
		t.Fatalf("restart: %v adopted %v", err, restarted.Active() != nil)
	}
	before := len(runner.batches)
	n, err := restarted.Unban(t.Context(), []netip.Addr{own4, own6, short, netip.MustParseAddr("203.0.113.9")})
	if err != nil || n != 2 || len(runner.batches)-before != 2 {
		t.Fatalf("unban after restart n=%d err=%v batches=%d", n, err, len(runner.batches)-before)
	}
	// deleted for good: a third manager has nothing of its own left
	third, err := NewManager(t.Context(), runner, root)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := third.Unban(t.Context(), []netip.Addr{own4}); err != nil || n != 0 {
		t.Fatalf("unban after it was deleted n=%d err=%v", n, err)
	}
}

// An unreadable own ban record: the manager cannot tell its bans from the
// others, so Unban answers an error (never a silent success) instead of
// deleting a ban it may not have written.
func TestUnreadableOwnBansRefuseUnban(t *testing.T) {
	runner := &fakeRunner{}
	root := t.TempDir()
	manager, err := NewManager(t.Context(), runner, root)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := NewSpec(testDDoS(t), []PortRange{{80, 80}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("198.51.100.1")
	if _, err := manager.Ban(t.Context(), []netip.Addr{addr}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ownFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(t.Context(), runner, root)
	if err != nil {
		t.Fatal(err)
	}
	before := len(runner.batches)
	if n, err := restarted.Unban(t.Context(), []netip.Addr{addr}); !errors.Is(err, ErrOwnershipUnknown) || n != 0 || len(runner.batches) != before {
		t.Fatalf("unban with an unreadable record n=%d err=%v batches=%d", n, err, len(runner.batches)-before)
	} // a ban written now is recorded, but the unknown stays across a restart
	if _, err := restarted.Ban(t.Context(), []netip.Addr{netip.MustParseAddr("198.51.100.8")}, time.Hour); err != nil {
		t.Fatal(err)
	}
	again, err := NewManager(t.Context(), runner, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Unban(t.Context(), []netip.Addr{addr}); !errors.Is(err, ErrOwnershipUnknown) {
		t.Fatalf("unknown ownership forgotten by a restart: %v", err)
	}
	// once every earlier ban could have ended, releases work again
	again.ownUnknownUntil = time.Now().Add(-time.Second)
	if n, err := again.Unban(t.Context(), []netip.Addr{netip.MustParseAddr("198.51.100.8")}); err != nil || n != 1 {
		t.Fatalf("unban after the unknown window n=%d err=%v", n, err)
	}
}
