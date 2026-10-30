//go:build linux

package l4guard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Real kernel test (scripts/edge-l4guard-smoke.sh: a privileged disposable
// container, never the host; A4): a queued L4 guard ban
// becomes a real nftables deny of the stream's port in inet cdnca_firewall,
// the banned client's SYN is dropped while another client still connects,
// and the F4 node event callback fires once for the ban.
//
//	CDNCA_L4GUARD_KERNEL_TEST=1 go test -run Kernel ./internal/l4guard/
const (
	kernelServer  = "10.78.0.1"
	kernelBanned  = "10.78.0.2"
	kernelAllowed = "10.78.0.3"
)

func kernelSetup(t *testing.T) {
	t.Helper()
	if os.Getenv("CDNCA_L4GUARD_KERNEL_TEST") != "1" {
		t.Skip("CDNCA_L4GUARD_KERNEL_TEST is not set (privileged disposable container only)")
	}
	for _, command := range [][]string{
		{"ip", "link", "add", "guard0", "type", "dummy"},
		{"ip", "link", "set", "guard0", "up"},
		{"ip", "addr", "add", kernelServer + "/24", "dev", "guard0"},
		{"ip", "addr", "add", kernelBanned + "/24", "dev", "guard0"},
		{"ip", "addr", "add", kernelAllowed + "/24", "dev", "guard0"},
	} {
		if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil &&
			!strings.Contains(string(output), "File exists") && !strings.Contains(string(output), "already assigned") {
			t.Fatalf("%v: %v %s", command, err, output)
		}
	}
}

func kernelListen(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", kernelServer+":0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return listener.Addr().(*net.TCPAddr).Port
}

func kernelDial(source string, port int) bool {
	dialer := net.Dialer{Timeout: 400 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	connection, err := dialer.Dial("tcp4", net.JoinHostPort(kernelServer, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	connection.Close()
	return true
}

func TestKernelGuardBanDropsClientAndReportsOnce(t *testing.T) {
	kernelSetup(t)
	port := kernelListen(t)
	binary, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := firewall.NewManager(filepath.Join(root, "firewall"), binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command(binary, "delete", "table", firewall.TableFamily, firewall.TableName).Run() })
	ban := []l4runtime.GuardRuleV2{{ID: "66666666-6666-4666-8666-666666666661", Action: edgeconfig.L4GuardActionBan, BanSeconds: 600,
		Threshold: 1, ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"0.0.0.0/0"}}}}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("guard-kernel", 1, []l4runtime.StreamRuntimeSpecV2{
		stream(streamA, l4runtime.ProtocolTCP, port, 0, ban),
	})
	if err != nil {
		t.Fatal(err)
	}
	bans := &queue{}
	kernel, err := New(bans, active{&config}, manager, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var reported []string
	kernel.OnBan = func(client netip.Addr, count int, remaining time.Duration) {
		reported = append(reported, client.String()+" "+strconv.Itoa(count))
		if remaining < 590*time.Second || remaining > 600*time.Second {
			t.Errorf("remaining %s, want about 10m", remaining)
		}
	}
	if !kernelDial(kernelBanned, port) || !kernelDial(kernelAllowed, port) {
		t.Fatal("clients cannot connect before the ban")
	}
	until := time.Now().Add(10 * time.Minute)
	bans.lines = []string{line(streamA, kernelBanned, until)}
	if err := kernel.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if kernelDial(kernelBanned, port) {
		output, _ := exec.Command(binary, "list", "table", firewall.TableFamily, firewall.TableName).CombinedOutput()
		t.Fatalf("banned client still connects; table:\n%s", output)
	}
	if !kernelDial(kernelAllowed, port) {
		t.Fatal("another client is blocked")
	}
	// The queue drains each ban once; an empty drain reports nothing more.
	if err := kernel.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(reported, ",") != kernelBanned+" 1" {
		t.Fatalf("reported %q, want one report of the ban", reported)
	}
	output, err := exec.Command(binary, "list", "table", firewall.TableFamily, firewall.TableName).CombinedOutput()
	if err != nil || !strings.Contains(string(output), kernelBanned) {
		t.Fatalf("kernel table lacks the ban: %v\n%s", err, output)
	}
}
