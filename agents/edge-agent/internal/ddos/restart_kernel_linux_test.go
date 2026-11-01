//go:build linux

package ddos

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Real kernel test of unban after an Agent restart: two
// processes over one state directory, driven by
// scripts/edge-ddos-restart-smoke.sh in privileged disposable containers
// (needs a real Linux kernel; never run on a host). Phase 1 applies the
// table, bans through Ban (generic XDP in front when BPF is available), adds
// a ban the Agent did not write, and exits without cleanup like a stopped
// Agent. Phase 2 is a new process: it must adopt the table, still drop the
// client, delete only its own ban with Unban, and then pass a normal
// session while the foreign ban keeps dropping. XDP maps do not outlive the
// process (xdp_linux.go), so after the restart the nft set does the drop.
//
//	CDNCA_DDOS_KERNEL_TEST=1 CDNCA_DDOS_RESTART_PHASE=1|2 \
//	  CDNCA_DDOS_RESTART_STATE=/dir CDNCA_DDOS_RESTART_EXPECT=xdp|nftables \
//	  ddos.test -test.run KernelUnbanAfterAgentRestart
const restartForeignClient = "10.78.0.4" // banned with nft directly, not by Ban

func restartNamespace(t *testing.T, create bool, state string) string {
	t.Helper()
	if create {
		_ = exec.Command("ip", "netns", "del", flagNamespace).Run()
		_ = exec.Command("ip", "link", "del", "ddosf0").Run()
		run(t, "ip", "netns", "add", flagNamespace)
		run(t, "ip", "link", "add", "ddosf0", "type", "veth", "peer", "name", "ddosf1")
		run(t, "ip", "link", "set", "ddosf1", "netns", flagNamespace)
		run(t, "ip", "addr", "add", flagServer+"/24", "dev", "ddosf0")
		run(t, "ip", "link", "set", "ddosf0", "up")
		for _, address := range []string{flagClient, flagExemptClient, restartForeignClient} {
			run(t, "ip", "netns", "exec", flagNamespace, "ip", "addr", "add", address+"/24", "dev", "ddosf1")
		}
		run(t, "ip", "netns", "exec", flagNamespace, "ip", "link", "set", "ddosf1", "up")
		run(t, "ip", "netns", "exec", flagNamespace, "ip", "link", "set", "lo", "up")
	} else if _, err := exec.Command("ip", "netns", "pids", flagNamespace).CombinedOutput(); err != nil {
		t.Fatalf("phase 1 namespace %s is gone: %v", flagNamespace, err)
	}
	script := filepath.Join(state, "client.py")
	if err := os.WriteFile(script, []byte(scapyClient), 0o600); err != nil {
		t.Fatal(err)
	}
	return script
}

// restartEcho listens on port (0: any) and echoes until the client closes.
func restartEcho(t *testing.T, port uint16) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", net.JoinHostPort(flagServer, strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func restartFront(t *testing.T) *xdp.Manager {
	t.Helper()
	front := xdp.Probe(xdp.Options{Interfaces: []string{"ddosf0"}, Modes: []xdp.Mode{xdp.ModeGeneric}})
	t.Logf("xdp status: %+v running=%v", front.Status(), front.Running())
	switch want := os.Getenv("CDNCA_DDOS_RESTART_EXPECT"); {
	case want == "xdp" && !front.Running():
		t.Fatalf("XDP expected to run: %+v", front.Status())
	case want == "nftables" && front.Running():
		t.Fatalf("XDP expected not to run: %+v", front.Status())
	}
	return front
}

func restartBanSet(t *testing.T) string {
	t.Helper()
	return run(t, "nft", "list", "set", TableFamily, TableName, BanSetIPv4)
}

// restartSetHas reports whether address is an element of the listed set
// ("10.78.0.2" must not match "10.78.0.20").
func restartSetHas(set, address string) bool {
	for _, field := range strings.FieldsFunc(set, func(r rune) bool { return r == ' ' || r == ',' || r == '{' || r == '}' || r == '\n' || r == '\t' }) {
		if field == address {
			return true
		}
	}
	return false
}

func TestKernelUnbanAfterAgentRestart(t *testing.T) {
	if os.Getenv("CDNCA_DDOS_KERNEL_TEST") != "1" {
		t.Skip("CDNCA_DDOS_KERNEL_TEST is not set (privileged disposable container only)")
	}
	state := os.Getenv("CDNCA_DDOS_RESTART_STATE")
	phase := os.Getenv("CDNCA_DDOS_RESTART_PHASE")
	if state == "" || (phase != "1" && phase != "2") {
		t.Skip("two-process case: run through scripts/edge-ddos-restart-smoke.sh")
	}
	binary, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	runner := execRunner{binary}
	root := filepath.Join(state, "ddos")
	portFile := filepath.Join(state, "port")
	script := restartNamespace(t, phase == "1", state)
	ownClient := netip.MustParseAddr(flagClient)

	if phase == "1" {
		manager, err := NewManager(t.Context(), runner, root)
		if err != nil {
			t.Fatal(err)
		}
		front := restartFront(t)
		manager.SetFront(front)
		port := restartEcho(t, 0)
		if err := os.WriteFile(portFile, []byte(strconv.Itoa(int(port))), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := manager.Apply(t.Context(), kernelFlagSpec(t, flagProtection(true, edgeconfig.DDoSDefaultTCPFlagTypes, true), port)); err != nil {
			t.Fatal(err)
		}
		if got := client(t, script, "session", flagClient, port, 0); got != "echo=ping-cdnca eof=True" {
			t.Fatalf("baseline session: %s", got)
		}
		if n, err := manager.Ban(t.Context(), []netip.Addr{ownClient}, 10*time.Minute); err != nil || n != 1 {
			t.Fatalf("ban n=%d err=%v", n, err)
		}
		run(t, "nft", "add", "element", TableFamily, TableName, BanSetIPv4, "{ "+restartForeignClient+" timeout 600s }")
		if got := client(t, script, "syn", flagClient, port, 2); got != "replies=0" {
			t.Fatalf("banned client answered before restart: %s", got)
		}
		if front.Running() {
			counters, _ := front.Counters()
			t.Logf("phase 1 xdp counters %+v", counters)
		}
		t.Logf("phase 1 ban set: %s", strings.Join(strings.Fields(restartBanSet(t)), " "))
		return // no Apply(nil)/Close: the process ends like a stopped Agent
	}

	// Phase 2: a new process over the same state directory.
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", flagNamespace).Run()
		_ = exec.Command("ip", "link", "del", "ddosf0").Run()
	})
	raw, err := os.ReadFile(portFile)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(value)
	manager, err := NewManager(t.Context(), runner, root)
	if err != nil || manager.Active() == nil {
		t.Fatalf("restart did not adopt the table: err=%v adopted=%v", err, err == nil && manager.Active() != nil)
	}
	// t.Context is canceled before cleanups run.
	t.Cleanup(func() {
		if err := manager.Apply(context.Background(), nil); err != nil {
			t.Errorf("remove the table: %v", err)
		}
	})
	front := restartFront(t)
	t.Cleanup(func() { front.Close() })
	manager.SetFront(front)
	restartEcho(t, port)
	set := restartBanSet(t)
	if !restartSetHas(set, flagClient) || !restartSetHas(set, restartForeignClient) {
		t.Fatalf("ban set after restart: %s", set)
	}
	if got := client(t, script, "syn", flagClient, port, 2); got != "replies=0" {
		t.Fatalf("banned client answered after restart, before unban: %s", got)
	}
	n, err := manager.Unban(t.Context(), []netip.Addr{ownClient, netip.MustParseAddr(restartForeignClient)})
	if err != nil || n != 1 {
		t.Fatalf("unban after restart n=%d err=%v (want 1: only the own ban)", n, err)
	}
	set = restartBanSet(t)
	if restartSetHas(set, flagClient) {
		t.Fatalf("own ban still in the set after unban: %s", set)
	}
	if !restartSetHas(set, restartForeignClient) {
		t.Fatalf("foreign ban deleted by unban: %s", set)
	}
	if got := client(t, script, "session", flagClient, port, 0); got != "echo=ping-cdnca eof=True" {
		t.Fatalf("session after unban: %s", got)
	}
	if got := client(t, script, "syn", restartForeignClient, port, 2); got != "replies=0" {
		t.Fatalf("foreign-banned client answered: %s", got)
	}
	t.Logf("phase 2 ban set after unban: %s", strings.Join(strings.Fields(set), " "))
}
