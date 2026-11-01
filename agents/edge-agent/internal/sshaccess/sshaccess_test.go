package sshaccess

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mu      sync.Mutex
	batches []string
	fail    map[string]bool
}

func (runner *fakeRunner) Run(_ context.Context, stdin []byte, arguments ...string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	mode := strings.Join(arguments, " ")
	runner.batches = append(runner.batches, mode+"\n"+string(stdin))
	if runner.fail[mode] {
		return errors.New("nft failed")
	}
	return nil
}

func (runner *fakeRunner) last() string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.batches[len(runner.batches)-1]
}

func TestBatchOnlyAllowsListedSourcesOnSSHPort(t *testing.T) {
	policy, err := Normalize(Policy{Revision: 3, Enabled: true, SSHPort: 2222,
		CIDRs: []string{"2001:db8::/48", "203.0.113.7/32", "198.51.100.0/24", "203.0.113.7/32"}})
	if err != nil {
		t.Fatal(err)
	}
	batch := string(Batch(policy))
	for _, want := range []string{
		"add table inet cdnca_ssh_access\ndelete table inet cdnca_ssh_access\n",
		`add table inet cdnca_ssh_access { comment "cdnca ssh-access revision=3"; }`,
		"add element inet cdnca_ssh_access allow_v4 { 198.51.100.0/24, 203.0.113.7/32 }",
		"add element inet cdnca_ssh_access allow_v6 { 2001:db8::/48 }",
		"type filter hook input priority -20; policy accept;",
		`input iifname "lo" accept`,
		"input tcp dport 2222 ct state established,related accept",
		"input tcp dport 2222 ip saddr @allow_v4 accept",
		"input tcp dport 2222 ip6 saddr @allow_v6 accept",
		`input tcp dport 2222 counter drop comment "cdnca ssh-access"`,
	} {
		if !strings.Contains(batch, want) {
			t.Errorf("batch missing %q:\n%s", want, batch)
		}
	}
	// The drop is the last rule and only matches the SSH port.
	if strings.Count(batch, " drop") != 1 || strings.Contains(batch, "cdnca_firewall") {
		t.Fatalf("batch:\n%s", batch)
	}
}

func TestNormalizeRefusesUnsafePolicies(t *testing.T) {
	for name, policy := range map[string]Policy{
		"no revision":     {Enabled: true, SSHPort: 22, CIDRs: []string{"203.0.113.7/32"}},
		"no port":         {Revision: 1, Enabled: true, CIDRs: []string{"203.0.113.7/32"}},
		"no source":       {Revision: 1, Enabled: true, SSHPort: 22},
		"whole internet":  {Revision: 1, Enabled: true, SSHPort: 22, CIDRs: []string{"0.0.0.0/0"}},
		"wide v4":         {Revision: 1, Enabled: true, SSHPort: 22, CIDRs: []string{"10.0.0.0/8"}},
		"wide v6":         {Revision: 1, Enabled: true, SSHPort: 22, CIDRs: []string{"2000::/3"}},
		"unmasked":        {Revision: 1, Enabled: true, SSHPort: 22, CIDRs: []string{"203.0.113.7/24"}},
		"not a prefix":    {Revision: 1, Enabled: true, SSHPort: 22, CIDRs: []string{"203.0.113.7"}},
		"nft injection":   {Revision: 1, Enabled: true, SSHPort: 22, CIDRs: []string{"203.0.113.7/32 }; flush ruleset; {"}},
		"mapped v4 in v6": {Revision: 1, Enabled: true, SSHPort: 22, CIDRs: []string{"::ffff:203.0.113.7/128"}},
	} {
		if _, err := Normalize(policy); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s accepted", name)
		}
	}
	disabled, err := Normalize(Policy{Revision: 2, SSHPort: 22, CIDRs: []string{"0.0.0.0/0"}})
	if err != nil || disabled.Enabled || len(disabled.CIDRs) != 0 {
		t.Fatalf("disabled = %+v, %v", disabled, err)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUnconfirmedPolicyRevertsAfterWindowAndConfirmedStays(t *testing.T) {
	runner := &fakeRunner{}
	path := filepath.Join(t.TempDir(), "ssh-access.json")
	manager, err := NewManager(runner, path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	manager.window = 50 * time.Millisecond
	policy := Policy{Revision: 1, Enabled: true, SSHPort: 22, CIDRs: []string{"203.0.113.7/32"}}
	state, err := manager.Apply(context.Background(), policy)
	if err != nil || !state.Applied || state.RevertAt == nil {
		t.Fatalf("apply = %+v, %v", state, err)
	}
	if !strings.HasPrefix(runner.batches[0], "-c -f -\n") || !strings.HasPrefix(runner.batches[1], "-f -\n") {
		t.Fatalf("check before apply: %q", runner.batches)
	}
	waitFor(t, func() bool { return manager.State().Reverted })
	if state := manager.State(); state.Applied || state.FailureCode != "confirmation_timeout" ||
		!strings.Contains(runner.last(), "delete table inet cdnca_ssh_access") {
		t.Fatalf("reverted state = %+v, last %q", state, runner.last())
	}
	if _, err := manager.Confirm(1); !errors.Is(err, ErrStaleRevision) {
		t.Fatal("a reverted revision was confirmed")
	}

	// A confirmed revision keeps its rules, also across a restart.
	manager2, err := NewManager(runner, filepath.Join(t.TempDir(), "ssh-access.json"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager2.Apply(context.Background(), Policy{Revision: 2, Enabled: true, SSHPort: 22,
		CIDRs: []string{"203.0.113.7/32"}}); err != nil {
		t.Fatal(err)
	}
	if state, err := manager2.Confirm(2); err != nil || !state.Confirmed || state.RevertAt != nil {
		t.Fatalf("confirm = %+v, %v", state, err)
	}
	if _, err := manager2.Apply(context.Background(), Policy{Revision: 1, Enabled: true, SSHPort: 22,
		CIDRs: []string{"203.0.113.7/32"}}); !errors.Is(err, ErrStaleRevision) {
		t.Fatal("an older revision was applied")
	}
	// Turning it off removes the table at once.
	state, err = manager2.Apply(context.Background(), Policy{Revision: 3, SSHPort: 22})
	if err != nil || state.Applied || !strings.Contains(runner.last(), "delete table inet cdnca_ssh_access") {
		t.Fatalf("disable = %+v, %v", state, err)
	}
}

func TestPendingPolicyRevertsAfterAgentRestart(t *testing.T) {
	runner := &fakeRunner{}
	path := filepath.Join(t.TempDir(), "ssh-access.json")
	manager, err := NewManager(runner, path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), Policy{Revision: 5, Enabled: true, SSHPort: 22,
		CIDRs: []string{"203.0.113.7/32"}}); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.stopLocked()
	manager.mu.Unlock()
	// The agent restarts after the deadline.
	restarted, err := NewManager(runner, path, func() time.Time { return time.Now().Add(RollbackWindow + time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	restarted.Resume(context.Background())
	waitFor(t, func() bool { return restarted.State().Reverted })
}

func TestCheckFailureLeavesRulesUnapplied(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{"-c -f -": true}}
	manager, err := NewManager(runner, filepath.Join(t.TempDir(), "ssh-access.json"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	state, err := manager.Apply(context.Background(), Policy{Revision: 1, Enabled: true, SSHPort: 22,
		CIDRs: []string{"203.0.113.7/32"}})
	if err == nil || state.Applied || state.FailureCode != "nft_check_failed" || len(runner.batches) != 1 {
		t.Fatalf("state = %+v, %v, batches %d", state, err, len(runner.batches))
	}
}

// The rollback notification fires once per reverted revision, also for the
// timer re-armed by Resume after a restart (the daemon queues it as an
// unprompted SSHAccessReceipt).
func TestRevertNotifiesOnceAfterRestart(t *testing.T) {
	runner := &fakeRunner{}
	path := filepath.Join(t.TempDir(), "ssh-access.json")
	manager, err := NewManager(runner, path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), Policy{Revision: 9, Enabled: true, SSHPort: 22,
		CIDRs: []string{"203.0.113.7/32"}}); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.stopLocked()
	manager.mu.Unlock()
	restarted, err := NewManager(runner, path, func() time.Time { return time.Now().Add(RollbackWindow) })
	if err != nil {
		t.Fatal(err)
	}
	notified := make(chan State, 2)
	restarted.OnRevert(func(state State) { notified <- state })
	restarted.Resume(context.Background())
	select {
	case state := <-notified:
		if state.Policy.Revision != 9 || !state.Reverted || state.FailureCode != "confirmation_timeout" {
			t.Fatalf("notified %+v", state)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no rollback notification")
	}
	restarted.revert(context.Background(), 9) // a late second timer is a no-op
	select {
	case state := <-notified:
		t.Fatalf("notified twice: %+v", state)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSystemRunnerNeedsAbsoluteBinary(t *testing.T) {
	for _, binary := range []string{"", "nft", "/usr/sbin/../sbin/nft"} {
		if _, err := NewSystemRunner(binary); err == nil {
			t.Fatalf("%q accepted", binary)
		}
	}
}
