//go:build linux

package ddos

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Real kernel test (scripts/edge-ddos-smoke.sh: a privileged disposable
// container, never the host): the table's limits hold for real TCP
// connections. Clients are addresses of a dummy interface; the server
// listens on another, so traffic passes the input hook.
//
//	CDNCA_DDOS_KERNEL_TEST=1 go test -run Kernel ./internal/ddos/
type execRunner struct{ binary string }

func (runner execRunner) Run(ctx context.Context, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, runner.binary, arguments...).CombinedOutput()
}

func kernelManager(t *testing.T) (*Manager, execRunner) {
	t.Helper()
	if os.Getenv("CDNCA_DDOS_KERNEL_TEST") != "1" {
		t.Skip("CDNCA_DDOS_KERNEL_TEST is not set (privileged disposable container only)")
	}
	binary, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	runner := execRunner{binary}
	manager, err := NewManager(t.Context(), runner, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Apply(context.Background(), nil) })
	return manager, runner
}

const (
	serverAddress = "10.77.0.1"
	clientA       = "10.77.0.2"
	clientB       = "10.77.0.3"
	exemptClient  = "10.77.0.4"
)

func setupInterface(t *testing.T) {
	t.Helper()
	for _, command := range [][]string{
		{"ip", "link", "add", "ddos0", "type", "dummy"},
		{"ip", "link", "set", "ddos0", "up"},
		{"ip", "addr", "add", serverAddress + "/24", "dev", "ddos0"},
		{"ip", "addr", "add", clientA + "/24", "dev", "ddos0"},
		{"ip", "addr", "add", clientB + "/24", "dev", "ddos0"},
		{"ip", "addr", "add", exemptClient + "/24", "dev", "ddos0"},
	} {
		if output, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil &&
			!strings.Contains(string(output), "File exists") && !strings.Contains(string(output), "already assigned") {
			t.Fatalf("%v: %v %s", command, err, output)
		}
	}
}

// listen accepts and holds connections until the test ends.
func listen(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", serverAddress+":0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 4096)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- connection
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		close(accepted)
		for connection := range accepted {
			connection.Close()
		}
	})
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// dial connects from source; false when the kernel dropped the SYN (timeout).
func dial(t *testing.T, source string, port uint16) (net.Conn, bool) {
	t.Helper()
	dialer := net.Dialer{Timeout: 400 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	connection, err := dialer.Dial("tcp4", net.JoinHostPort(serverAddress, strconv.Itoa(int(port))))
	if err != nil {
		return nil, false
	}
	t.Cleanup(func() { connection.Close() })
	return connection, true
}

func spec(t *testing.T, protection edgeconfig.DDoSProtection, port uint16) *Spec {
	t.Helper()
	protection.CCKernelBan = edgeconfig.CCKernelBanOff
	if protection.AllowNetworks == nil {
		protection.AllowNetworks = []string{exemptClient + "/32"}
	}
	value, err := edgeconfig.NewSiteRuntimeDDoS(protection, []string{"10.77.0.250"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewSpec(&value, []PortRange{{port, port}})
	if err != nil || result == nil {
		t.Fatal(err)
	}
	return result
}

func TestKernelPerClientConnectionLimit(t *testing.T) {
	manager, _ := kernelManager(t)
	setupInterface(t)
	port := listen(t)
	if err := manager.Apply(t.Context(), spec(t, edgeconfig.DDoSProtection{MaxConnectionsPerIP: 3}, port)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if _, ok := dial(t, clientA, port); !ok {
			t.Fatalf("connection %d within the limit dropped", index+1)
		}
	}
	if _, ok := dial(t, clientA, port); ok {
		t.Fatal("4th concurrent connection of one client accepted")
	}
	if _, ok := dial(t, clientB, port); !ok {
		t.Fatal("another client is limited by the first one's connections")
	}
	for index := 0; index < 5; index++ {
		if _, ok := dial(t, exemptClient, port); !ok {
			t.Fatal("an allow network client is limited")
		}
	}
}

func TestKernelNewConnectionRateBansAndBanSurvivesReapply(t *testing.T) {
	manager, runner := kernelManager(t)
	setupInterface(t)
	port := listen(t)
	first := spec(t, edgeconfig.DDoSProtection{NewConnectionsPerSecond: 5, RateBanSeconds: 120}, port)
	if err := manager.Apply(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for index := 0; index < 20; index++ {
		if connection, ok := dial(t, clientA, port); ok {
			accepted++
			connection.Close()
		}
	}
	if accepted < 5 || accepted > 6 {
		t.Fatalf("accepted %d of 20 new connections at a burst of 5", accepted)
	}
	output, err := runner.Run(t.Context(), "--json", "list", "set", TableFamily, TableName, BanSetIPv4)
	if err != nil || !strings.Contains(string(output), `"`+clientA+`"`) {
		t.Fatalf("client not banned: %s %v", output, err)
	}
	// The watch finds the kernel's own ban (F4) once, with its remaining time.
	watch := NewRateBanWatch(manager, time.Now)
	var reported []RateBan
	watch.OnBan = func(client netip.Addr, _ int, remaining time.Duration) {
		reported = append(reported, RateBan{Client: client, Remaining: remaining})
	}
	if err := watch.Step(t.Context()); err != nil || len(reported) != 1 || reported[0].Client.String() != clientA ||
		reported[0].Remaining <= 100*time.Second || reported[0].Remaining > 120*time.Second {
		t.Fatalf("rate ban watch %+v %v", reported, err)
	}
	if err := watch.Step(t.Context()); err != nil || len(reported) != 1 {
		t.Fatalf("rate ban reported twice %+v %v", reported, err)
	}
	// A new release (another limit) keeps the ban.
	second := spec(t, edgeconfig.DDoSProtection{NewConnectionsPerSecond: 1000, RateBanSeconds: 120, MaxConnectionsPerIP: 50}, port)
	if err := manager.Apply(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if _, ok := dial(t, clientA, port); ok {
		t.Fatal("ban lost on reapply")
	}
	if _, ok := dial(t, clientB, port); !ok {
		t.Fatal("an unbanned client is dropped")
	}
	// Ban() of the empty connection detector and CC.
	if banned, err := manager.Ban(t.Context(), []netip.Addr{netip.MustParseAddr(clientB), netip.MustParseAddr(exemptClient)}, time.Minute); err != nil || banned != 1 {
		t.Fatalf("Ban = %d, %v", banned, err)
	}
	if _, ok := dial(t, clientB, port); ok {
		t.Fatal("Ban did not drop the client")
	}
	if _, ok := dial(t, exemptClient, port); !ok {
		t.Fatal("an exempt client was banned")
	}
	// The agent's own ban is not a rate ban.
	if err := watch.Step(t.Context()); err != nil || len(reported) != 1 {
		t.Fatalf("agent ban reported as a rate ban %+v %v", reported, err)
	}
	if err := manager.Apply(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(t.Context(), "list", "table", TableFamily, TableName); err == nil {
		t.Fatal("table left after removal")
	}
}

func TestKernelPortConnectionLimit(t *testing.T) {
	manager, _ := kernelManager(t)
	setupInterface(t)
	port := listen(t)
	if err := manager.Apply(t.Context(), spec(t, edgeconfig.DDoSProtection{MaxConnectionsPerPort: 4}, port)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		source := clientA
		if index%2 == 1 {
			source = clientB
		}
		if _, ok := dial(t, source, port); !ok {
			t.Fatalf("connection %d within the port limit dropped", index+1)
		}
	}
	if _, ok := dial(t, clientB, port); ok {
		t.Fatal("5th connection on the port accepted")
	}
}

func TestKernelEmptyConnectionsAreFoundBannedAndClosed(t *testing.T) {
	manager, _ := kernelManager(t)
	setupInterface(t)
	port := listen(t)
	if err := manager.Apply(t.Context(), spec(t, edgeconfig.DDoSProtection{
		EmptyConnection: &edgeconfig.DDoSEmptyConnection{IdleSeconds: 5, Threshold: 3, WindowSeconds: 60, BanSeconds: 300},
	}, port)); err != nil {
		t.Fatal(err)
	}
	var empty []net.Conn
	for range 3 {
		connection, ok := dial(t, clientA, port)
		if !ok {
			t.Fatal("dial")
		}
		empty = append(empty, connection)
	}
	// A client that sends a request is never empty.
	talker, ok := dial(t, clientB, port)
	if !ok {
		t.Fatal("dial")
	}
	if _, err := talker.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second)
	found, err := SockDiag{}.EmptySockets(t.Context(), manager.Active().Ports, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clients := map[string]int{}
	for _, socket := range found {
		clients[socket.Client.String()]++
	}
	if clients[clientA] != 3 || clients[clientB] != 0 {
		t.Fatalf("empty sockets by client = %v", clients)
	}
	detector := NewEmptyConnections(manager, SockDiag{}, time.Now)
	var banned []string
	detector.OnBan = func(client netip.Addr, _ int, _ time.Duration) { banned = append(banned, client.String()) }
	if err := detector.Step(t.Context()); err != nil {
		t.Fatalf("step: %v", err)
	}
	if len(banned) != 1 || banned[0] != clientA {
		t.Fatalf("banned = %v", banned)
	}
	if _, ok := dial(t, clientA, port); ok {
		t.Fatal("a banned client connected")
	}
	// The empty connections were reset by SOCK_DESTROY where the kernel
	// supports it (CONFIG_INET_DIAG_DESTROY); otherwise the ban cuts them.
	if destroyErr := (SockDiag{}).Destroy(t.Context(), found[:1]); errors.Is(destroyErr, ErrDestroyUnsupported) {
		t.Logf("kernel without SOCK_DESTROY: %v", destroyErr)
	} else {
		_ = empty[0].SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := empty[0].Read(make([]byte, 1)); err == nil || strings.Contains(err.Error(), "timeout") {
			t.Fatalf("empty connection still open: %v", err)
		}
	}
	if _, err := talker.Write([]byte("x")); err != nil {
		t.Fatalf("the talking client's connection was closed: %v", err)
	}
}
