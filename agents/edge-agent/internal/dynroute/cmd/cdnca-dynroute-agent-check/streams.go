package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// L4 forwards on the dynamic routing node (D13-c0): the node's L4 runtime
// (l4runtime.Manager on a second OpenResty, as the daemon runs it) serves
// the scopes' v2 streams beside the skeleton.
const (
	scopeL4      = "0d130000-0000-4000-8000-0000000000b1" // a second scope
	tenantL4     = "0d130000-0000-4000-8000-0000000000b2"
	portL4TCP    = 18390
	portL4UDP    = 18391
	originL4TCP  = 19890
	originL4UDP  = 19891
	originL4TLS  = 19892
	passthroughL = "db.d13.test"
)

// l4Echo answers "<tag>:<first line>" on TCP (the TLS passthrough origin
// terminates TLS itself) and "<tag>:<datagram>" on UDP.
func l4Echo(tag string, port int, config *tls.Config) error {
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	if config != nil {
		listener = tls.NewListener(listener, config)
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				line, _ := bufio.NewReader(connection).ReadString('\n')
				fmt.Fprintf(connection, "%s:%s\n", tag, strings.TrimSpace(line))
			}()
		}
	}()
	return nil
}

func l4EchoUDP(tag string, port int) error {
	connection, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, peer, err := connection.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = connection.WriteTo([]byte(tag+":"+string(buffer[:n])), peer)
		}
	}()
	return nil
}

func tcpExchange(port int, message string, config *tls.Config) (string, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	var connection net.Conn
	var err error
	if config != nil {
		connection, err = tls.DialWithDialer(dialer, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), config)
	} else {
		connection, err = dialer.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	}
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(connection, "%s\n", message); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(connection).ReadString('\n')
	return strings.TrimSpace(line), err
}

func udpExchange(port int, message string) (string, error) {
	connection, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := connection.Write([]byte(message)); err != nil {
		return "", err
	}
	buffer := make([]byte, 2048)
	n, err := connection.Read(buffer)
	return string(buffer[:n]), err
}

func l4Stream(id, protocol string, port, origin int) edgeconfig.L4StreamRuntimeV2 {
	return edgeconfig.L4StreamRuntimeV2{SchemaVersion: "cdnca.edge.l4/v2", TenantID: tenantL4,
		StreamID: id, Revision: 1, Listener: edgeconfig.L4ListenerV2{Protocol: protocol, Address: "*", Port: port},
		Endpoint:         edgeconfig.L4EndpointV2{Address: "127.0.0.1", Port: origin},
		Geo:              edgeconfig.L4GeoPolicyV2{TenantID: tenantL4, StreamID: id, Revision: 1, UnknownRegionAction: "allow"},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 5000, MaxConnectionsPerClient: 50, DrainTimeoutMS: 30000}
}

type checkResolver struct{}

func (checkResolver) LookupIP(context.Context, string) (l4runtime.DNSLookupResult, error) {
	return l4runtime.DNSLookupResult{}, errors.New("no DNS in the check")
}

// l4Runtime is the daemon's adapter (cmd/edge-agent dynamicRoutingL4) over
// a real L4 runtime manager.
type l4Runtime struct {
	manager *l4runtime.Manager
	dns     *l4runtime.DNSCoordinator
}

func (l4 *l4Runtime) Begin(ctx context.Context, versionID string) error {
	return l4.manager.BeginRelease(ctx, versionID)
}

func (l4 *l4Runtime) Apply(ctx context.Context, versionID string, config *l4runtime.ConfigV2) error {
	if config != nil {
		for _, listener := range config.Listeners {
			version := listener.ConfigVersionID
			if version == "" {
				version = config.VersionID
			}
			path, err := l4runtime.L4TelemetryLogPathForConfigListener("/var/lib/cdnca-edge", version, listener)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
		}
		_, err := l4.manager.ApplyV2(ctx, *config, l4.dns)
		return err
	}
	_, err := l4.manager.Apply(ctx, l4runtime.Config{SchemaVersion: l4runtime.SchemaVersionV1, VersionID: versionID,
		Listeners: []l4runtime.Listener{}, UpstreamPools: []l4runtime.UpstreamPool{}, DrainTimeoutMS: 30000})
	return err
}

func (l4 *l4Runtime) Finish(ctx context.Context, versionID string, succeeded bool) error {
	return l4.manager.FinishRelease(ctx, versionID, succeeded)
}

func checkStreams(h *harness, config dynroute.Config, previous *dynroute.Runtime, roots *x509.CertPool) *dynroute.Runtime {
	ctx := h.ctx
	_ = previous.Stop(ctx)
	ca := newAuthority()
	chain, key, _ := ca.issue(passthroughL)
	pair, err := tls.X509KeyPair(chain, key)
	check("l4-origins", err == nil && l4Echo("tcp", originL4TCP, nil) == nil && l4EchoUDP("udp", originL4UDP) == nil &&
		l4Echo("pass", originL4TLS, &tls.Config{Certificates: []tls.Certificate{pair}}) == nil, "%v", err)
	passRoots := x509.NewCertPool()
	passRoots.AddCert(ca.certificate)

	l4State := filepath.Join(*state, "l4")
	openResty, err := l4runtime.NewOpenResty(*binary, filepath.Join(l4State, "run", "nginx.pid"), 30*time.Second)
	var manager *l4runtime.Manager
	var dns *l4runtime.DNSCoordinator
	if err == nil {
		manager, err = l4runtime.NewDeploymentManager(l4State, openResty)
	}
	if err == nil {
		dns, err = l4runtime.NewDNSCoordinator(filepath.Join(l4State, "dns"), checkResolver{},
			func(context.Context, l4runtime.ListenerV2, []netip.Addr) error { return nil }, time.Now)
	}
	check("l4-runtime", err == nil, "%v", err)
	if err != nil {
		return previous
	}
	l4 := &l4Runtime{manager: manager, dns: dns}
	table := &recordedDDoS{}
	l4Config := config
	l4Config.L4, l4Config.DDoS = l4, table
	l4Config.MuxRoot = "/run/cdnca/mux"
	runtime, err := dynroute.New(l4Config)
	if err == nil {
		err = runtime.Recover(ctx)
	}
	check("l4-node-runtime", err == nil, "%v", err)
	h.runtime = runtime
	h.input.Systems = []*edgeconfig.SiteRuntimeSystem{testSystem(3, edgeconfig.CCKernelBanExclusivePorts)}
	sites := objectsSites(h.input.Objects)
	var secure edgesite.Site
	for _, site := range sites {
		if len(site.Listeners) == 1 && site.Listeners[0].TLS != nil {
			secure = site
		}
	}
	tcpStream := l4Stream("0d130000-0000-4000-8000-0000000004c1", "tcp", portL4TCP, originL4TCP)
	udpStream := l4Stream("0d130000-0000-4000-8000-0000000004c2", "udp", portL4UDP, originL4UDP)
	pass := l4Stream("0d130000-0000-4000-8000-0000000004c3", "tcp", portTLS, originL4TLS)
	pass.TLSPassthrough, pass.ServerNames = true, []string{passthroughL}
	streams := func(values ...edgeconfig.L4StreamRuntimeV2) []dynroute.ScopeStreams {
		return []dynroute.ScopeStreams{{ScopeID: scopeL4, ConfigVersionID: "0d130000-0000-4000-8000-0000000004f1", Revision: 2,
			Runtime: edgeconfig.StreamRuntime{TenantID: tenantL4, StreamsV2: values}}}
	}

	// exclusive TCP and UDP forwards of a second scope
	h.input.Streams = streams(tcpStream, udpStream)
	h.apply("l4-exclusive-apply", sites...)
	got, err := tcpExchange(portL4TCP, "hello", nil)
	check("l4-tcp", err == nil && got == "tcp:hello", "%q %v", got, err)
	got, err = udpExchange(portL4UDP, "ping")
	check("l4-udp", err == nil && got == "udp:ping", "%q %v", got, err)
	a := get(portPlain, "shop.d13.test", "/index.html")
	check("l4-sites-unaffected", a.status == 200, "shop %d %s", a.status, a.err)
	var last *ddos.Spec
	if len(table.specs) > 0 {
		last = table.specs[len(table.specs)-1]
	}
	covered := false
	for _, port := range ddosPorts(last) {
		covered = covered || port.First <= portL4TCP && port.Last >= portL4TCP
	}
	check("l4-ddos-ports", last != nil && covered, "%+v", last)

	// per-node-dist (L4_STREAM_SELECTION): one release, the TCP forward on
	// line group 1 and the UDP forward on line group 2. Node 1's key
	// document withholds the UDP forward, node 2's the TCP forward; each node
	// applies what gatewayclient selects (one container is one node: the two
	// nodes in turn on this OpenResty).
	checkNodeStreamSelection(h, sites, streams, tcpStream, udpStream)

	// TLS passthrough on the TLS site's port: by SNI to the stream, the
	// site's names to the skeleton's internal socket (PROXY protocol)
	h.input.Streams = streams(tcpStream, udpStream, pass)
	shared := h.apply("l4-shared-apply", sites...)
	got, err = tcpExchange(portTLS, "through", &tls.Config{ServerName: passthroughL, RootCAs: passRoots, MinVersion: tls.VersionTLS12})
	check("l4-passthrough", err == nil && got == "pass:through", "%q %v", got, err)
	a = getTLS(secure.Hosts.Primary, "/shared", roots)
	check("l4-shared-site", shared.Reloaded && a.status == 200 && strings.Contains(a.body, "/shared"), "reloaded %v status %d %s",
		shared.Reloaded, a.status, a.err)
	_, statErr := os.Stat(fmt.Sprintf("/run/cdnca/mux/%d-tls.sock", portTLS))
	check("l4-mux-socket", statErr == nil, "%v", statErr)
	ports := runtime.CCKernelBanPorts(scope, secure.SiteID)
	check("l4-cc-not-exclusive", len(ports) == 0, "%d is shared with a stream: %v", portTLS, ports)

	// installation ban (ADR 0014 LIC-BAN-05) with sites, cache and L4 running
	checkInstallationBan(h, secure.Hosts.Primary, roots)

	// streams removed: the L4 runtime stops, the port goes back to the
	// skeleton's 0.0.0.0 listener
	h.input.Streams = nil
	removed := h.apply("l4-removed-apply", sites...)
	_, err = tcpExchange(portL4TCP, "gone", nil)
	check("l4-removed-tcp", err != nil, "%v", err)
	a = getTLS(secure.Hosts.Primary, "/back", roots)
	check("l4-port-back", removed.Reloaded && a.status == 200, "reloaded %v status %d %s", removed.Reloaded, a.status, a.err)
	h.input.Systems = nil
	return runtime
}

// ddosPorts are the protected ports of a DDoS table (none for nil: removed
// or never applied).
func ddosPorts(spec *ddos.Spec) []ddos.PortRange {
	if spec == nil {
		return nil
	}
	return spec.Ports
}

// checkNodeStreamSelection: each node's L4 listeners are only the forwards
// of its line groups.
func checkNodeStreamSelection(h *harness, sites []edgesite.Site,
	streams func(...edgeconfig.L4StreamRuntimeV2) []dynroute.ScopeStreams, tcpStream, udpStream edgeconfig.L4StreamRuntimeV2) {
	root := streams(tcpStream, udpStream)[0]
	for _, node := range []struct {
		name     string
		withheld string
		tcp, udp bool
	}{
		{"node1", udpStream.StreamID, true, false},
		{"node2", tcpStream.StreamID, false, true},
	} {
		selected, err := gatewayclient.SelectNodeStreams(&root.Runtime, []string{node.withheld})
		check("l4-select-"+node.name, err == nil && selected != nil && len(selected.StreamsV2) == 1, "%+v %v", selected, err)
		if err != nil || selected == nil {
			continue
		}
		scoped := root
		scoped.Runtime = *selected
		h.input.Streams = []dynroute.ScopeStreams{scoped}
		h.apply("l4-select-"+node.name+"-apply", sites...)
		got, tcpErr := tcpExchange(portL4TCP, "sel", nil)
		check("l4-select-"+node.name+"-tcp", (tcpErr == nil && got == "tcp:sel") == node.tcp, "tcp %q %v", got, tcpErr)
		got, udpErr := udpExchange(portL4UDP, "sel")
		check("l4-select-"+node.name+"-udp", (udpErr == nil && got == "udp:sel") == node.udp, "udp %q %v", got, udpErr)
		listening := listeningPorts()
		check("l4-select-"+node.name+"-listeners", listening[portL4TCP] == node.tcp && listening[portL4UDP] == node.udp,
			"tcp %d listening %v (want %v), udp %d listening %v (want %v)", portL4TCP, listening[portL4TCP], node.tcp,
			portL4UDP, listening[portL4UDP], node.udp)
	}
	// back to both forwards for the parts that follow
	h.input.Streams = streams(tcpStream, udpStream)
	h.apply("l4-select-restore-apply", sites...)
}

// listeningPorts are the local ports with a TCP listener or a bound UDP
// socket (/proc/net/{tcp,tcp6,udp,udp6}).
func listeningPorts() map[int]bool {
	ports := map[int]bool{}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		udp := strings.Contains(file, "udp")
		for _, line := range strings.Split(string(content), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			// TCP state 0A = LISTEN; a bound UDP socket is 07 (unconnected).
			if !udp && fields[3] != "0A" || udp && fields[3] != "07" {
				continue
			}
			local := fields[1]
			colon := strings.LastIndexByte(local, ':')
			if colon < 0 {
				continue
			}
			var port int
			if _, err := fmt.Sscanf(local[colon+1:], "%X", &port); err == nil {
				ports[port] = true
			}
		}
	}
	return ports
}
