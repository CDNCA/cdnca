//go:build linux && sshaccess_kernel

package sshaccess

// Real nft cases for the merge batch: run as root in a
// throw-away network namespace or container, never on a test node:
//
//	go test -tags sshaccess_kernel -run Kernel -count=1 ./internal/sshaccess
//
// They check the batch nft accepts (-c and apply), the drop of a non-listed
// source on the SSH port, that established connections and other ports are
// untouched, and that the rollback removes the table.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func kernelRunner(t *testing.T) Runner {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (network namespace)")
	}
	binary, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed")
	}
	runner, err := NewSystemRunner(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runner.Run(context.Background(), DeleteBatch(), "-f", "-") })
	return runner
}

func listTable(t *testing.T) string {
	t.Helper()
	output, _ := exec.Command("nft", "list", "table", TableFamily, TableName).CombinedOutput()
	return string(output)
}

func TestKernelApplyListsRulesAndRollbackRemovesTable(t *testing.T) {
	runner := kernelRunner(t)
	manager, err := NewManager(runner, filepath.Join(t.TempDir(), "state.json"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	manager.window = 2 * time.Second
	if _, err := manager.Apply(context.Background(), Policy{Revision: 1, Enabled: true, SSHPort: 22,
		CIDRs: []string{"192.0.2.10/32", "2001:db8::/48"}}); err != nil {
		t.Fatal(err)
	}
	table := listTable(t)
	for _, want := range []string{"hook input priority -20", "tcp dport 22 ip saddr @allow_v4 accept",
		"192.0.2.10", "2001:db8::/48", `tcp dport 22 counter packets 0 bytes 0 drop comment "cdnca ssh-access"`} {
		if !strings.Contains(table, want) {
			t.Fatalf("table missing %q:\n%s", want, table)
		}
	}
	if strings.Contains(listTableNamed(t, "cdnca_firewall"), "cdnca ssh-access") {
		t.Fatal("rules leaked into cdnca_firewall")
	}
	deadline := time.Now().Add(10 * time.Second)
	for !manager.State().Reverted && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !manager.State().Reverted || strings.Contains(listTable(t), "cdnca ssh-access") {
		t.Fatalf("not reverted: %+v\n%s", manager.State(), listTable(t))
	}
}

func TestKernelDropsNonListedSourceButKeepsOtherPorts(t *testing.T) {
	runner := kernelRunner(t)
	manager, err := NewManager(runner, filepath.Join(t.TempDir(), "state.json"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// Only 192.0.2.10 may reach 22; loopback is always accepted, so the
	// drop is observed through the rule counter for a veth peer when the
	// harness provides one (CDNCA_SSHACCESS_PEER), else only the ruleset.
	if _, err := manager.Apply(context.Background(), Policy{Revision: 1, Enabled: true, SSHPort: 22,
		CIDRs: []string{"192.0.2.10/32"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Confirm(1); err != nil {
		t.Fatal(err)
	}
	table := listTable(t)
	if strings.Contains(table, "dport != 22") || strings.Count(table, " drop ") != 1 || !strings.Contains(table, `iifname "lo" accept`) {
		t.Fatalf("unexpected ruleset:\n%s", table)
	}
	if peer := os.Getenv("CDNCA_SSHACCESS_PEER"); peer != "" {
		_ = exec.Command("ip", "netns", "exec", peer, "timeout", "2", "bash", "-c", "exec 3<>/dev/tcp/"+os.Getenv("CDNCA_SSHACCESS_ADDR")+"/22").Run()
		if !strings.Contains(listTable(t), "drop") || strings.Contains(listTable(t), "counter packets 0 bytes 0 drop") {
			t.Fatalf("non-listed source was not dropped:\n%s", listTable(t))
		}
	}
	if _, err := manager.Apply(context.Background(), Policy{Revision: 2, SSHPort: 22}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(listTable(t), "cdnca ssh-access") {
		t.Fatal("disabling left the table")
	}
}

func listTableNamed(t *testing.T, name string) string {
	t.Helper()
	output, _ := exec.Command("nft", "list", "table", TableFamily, name).CombinedOutput()
	return string(output)
}
