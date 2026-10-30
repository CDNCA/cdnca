package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

const (
	tcpListenPort   = 18110
	udpListenPort   = 18111
	proxyListenPort = 18112
	ipv6ListenPort  = 18113
	limitListenPort = 18114

	originAPort     = 19110
	originBPort     = 19111
	udpOriginPort   = 19112
	proxyOriginPort = 19113
	ipv6OriginPort  = 19114
	limitOriginPort = 19115
)

type evidence struct {
	SchemaVersion                  string         `json:"schema_version"`
	AppliedVersions                []string       `json:"applied_versions"`
	V1Digest                       string         `json:"v1_digest"`
	V2Digest                       string         `json:"v2_digest"`
	TCPWeightedResponses           map[string]int `json:"tcp_weighted_responses"`
	TCPWeightedAccepted            uint64         `json:"tcp_weighted_accepted"`
	TCPWeightedEchoed              uint64         `json:"tcp_weighted_echoed"`
	TCPFailoverResponses           int            `json:"tcp_failover_responses"`
	UDPResponse                    string         `json:"udp_response"`
	IPv6Response                   string         `json:"ipv6_response"`
	ProxyProtocolHeader            string         `json:"proxy_protocol_header"`
	ProxyProtocolResponse          string         `json:"proxy_protocol_response"`
	ProxyProtocolDisabledPlain     bool           `json:"proxy_protocol_disabled_plain"`
	ProxyProtocolInboundV1         bool           `json:"proxy_protocol_inbound_v1"`
	ProxyProtocolInboundV2         bool           `json:"proxy_protocol_inbound_v2"`
	ProxyProtocolUntrustedRejected bool           `json:"proxy_protocol_untrusted_spoof_rejected"`
	UDPProxyProtocolRejected       bool           `json:"udp_proxy_protocol_rejected"`
	BackendIncompatibleRejected    bool           `json:"backend_incompatible_rejected"`
	ConcurrentLongConnections      int            `json:"concurrent_long_connections"`
	LongConnectionsSurvivedReload  bool           `json:"long_connections_survived_reload"`
	ConnectionLimitRejected        bool           `json:"connection_limit_rejected"`
	SyntaxPrecheckRejected         bool           `json:"syntax_precheck_rejected"`
	StrictValidationRejected       bool           `json:"strict_validation_rejected"`
	LastKnownGoodVersion           string         `json:"last_known_good_version"`
	TrafficAfterRejectedConfigs    string         `json:"traffic_after_rejected_configs"`
	ProcessIdentityRecorded        bool           `json:"process_identity_recorded"`
	PendingStartIdentityCleared    bool           `json:"pending_start_identity_cleared"`
	MasterOwnerUID                 uint32         `json:"master_owner_uid"`
	WorkerOwnerUID                 uint32         `json:"worker_owner_uid"`
	WorkerOwnerDropped             bool           `json:"worker_owner_dropped"`
}

type tcpOrigin struct {
	listener    net.Listener
	network     string
	address     string
	marker      string
	expectProxy bool
	observed    chan string
	ready       chan struct{}
	accepted    atomic.Uint64
	echoed      atomic.Uint64
	closeOnce   sync.Once
	wait        sync.WaitGroup
}

func startTCPOrigin(network, address, marker string, expectProxy bool) (*tcpOrigin, error) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	origin := &tcpOrigin{
		listener: listener, network: network, address: address, marker: marker, expectProxy: expectProxy,
		observed: make(chan string, 8), ready: make(chan struct{}),
	}
	origin.wait.Add(1)
	go origin.serve()
	select {
	case <-origin.ready:
	case <-time.After(time.Second):
		origin.close()
		return nil, fmt.Errorf("origin %s %s did not become ready", network, address)
	}
	return origin, nil
}

func (o *tcpOrigin) serve() {
	defer o.wait.Done()
	close(o.ready)
	for {
		connection, err := o.listener.Accept()
		if err != nil {
			return
		}
		o.accepted.Add(1)
		o.wait.Add(1)
		go o.handle(connection)
	}
}

func (o *tcpOrigin) handle(connection net.Conn) {
	defer o.wait.Done()
	defer connection.Close()
	reader := bufio.NewReader(connection)
	if o.expectProxy {
		header, err := reader.ReadString('\n')
		if err != nil || !validProxyHeader(header) {
			return
		}
		select {
		case o.observed <- strings.TrimSpace(header):
		default:
		}
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		response := o.marker + line
		if line == "health\n" {
			response = "health:ok\n"
		}
		if _, err := io.WriteString(connection, response); err != nil {
			return
		}
		o.echoed.Add(1)
	}
}

func (o *tcpOrigin) waitReady() error {
	select {
	case <-o.ready:
	case <-time.After(time.Second):
		return fmt.Errorf("origin %s %s did not start serving", o.network, o.address)
	}
	connection, err := net.DialTimeout(o.network, o.address, time.Second)
	if err != nil {
		return fmt.Errorf("dial origin %s %s: %w", o.network, o.address, err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	if o.expectProxy {
		if _, err := io.WriteString(connection, "PROXY TCP4 127.0.0.1 127.0.0.1 1 1\r\n"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(connection, "health\n"); err != nil {
		return err
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		return err
	}
	if response != "health:ok\n" {
		return fmt.Errorf("origin readiness response = %q", response)
	}
	return nil
}

func (o *tcpOrigin) discardObserved() {
	for {
		select {
		case <-o.observed:
		default:
			return
		}
	}
}

func (o *tcpOrigin) close() {
	o.closeOnce.Do(func() {
		_ = o.listener.Close()
		o.wait.Wait()
	})
}

type udpOrigin struct {
	connection *net.UDPConn
	done       chan struct{}
}

func startUDPOrigin(address string) (*udpOrigin, error) {
	resolved, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return nil, err
	}
	connection, err := net.ListenUDP("udp4", resolved)
	if err != nil {
		return nil, err
	}
	origin := &udpOrigin{connection: connection, done: make(chan struct{})}
	go origin.serve()
	return origin, nil
}

func (o *udpOrigin) serve() {
	defer close(o.done)
	buffer := make([]byte, 64<<10)
	for {
		count, peer, err := o.connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		response := append([]byte("udp:"), buffer[:count]...)
		_, _ = o.connection.WriteToUDP(response, peer)
	}
}

func (o *udpOrigin) close() {
	_ = o.connection.Close()
	<-o.done
}

type origins struct {
	a, b, proxy, ipv6, limit *tcpOrigin
	udp                      *udpOrigin
}

func startOrigins() (*origins, error) {
	value := &origins{}
	var err error
	if value.a, err = startTCPOrigin("tcp4", address4(originAPort), "a:", false); err != nil {
		return nil, err
	}
	if value.b, err = startTCPOrigin("tcp4", address4(originBPort), "b:", false); err != nil {
		value.close()
		return nil, err
	}
	if value.proxy, err = startTCPOrigin("tcp4", address4(proxyOriginPort), "proxy:", true); err != nil {
		value.close()
		return nil, err
	}
	if value.ipv6, err = startTCPOrigin("tcp6", fmt.Sprintf("[::1]:%d", ipv6OriginPort), "ipv6:", false); err != nil {
		value.close()
		return nil, err
	}
	if value.limit, err = startTCPOrigin("tcp4", address4(limitOriginPort), "limit:", false); err != nil {
		value.close()
		return nil, err
	}
	if value.udp, err = startUDPOrigin(address4(udpOriginPort)); err != nil {
		value.close()
		return nil, err
	}
	if err := value.a.waitReady(); err != nil {
		value.close()
		return nil, fmt.Errorf("origin A readiness: %w", err)
	}
	if err := value.b.waitReady(); err != nil {
		value.close()
		return nil, fmt.Errorf("origin B readiness: %w", err)
	}
	if err := value.proxy.waitReady(); err != nil {
		value.close()
		return nil, fmt.Errorf("proxy origin readiness: %w", err)
	}
	if err := value.ipv6.waitReady(); err != nil {
		value.close()
		return nil, fmt.Errorf("IPv6 origin readiness: %w", err)
	}
	if err := value.limit.waitReady(); err != nil {
		value.close()
		return nil, fmt.Errorf("limit origin readiness: %w", err)
	}
	value.proxy.discardObserved()
	return value, nil
}

func (o *origins) close() {
	for _, origin := range []*tcpOrigin{o.a, o.b, o.proxy, o.ipv6, o.limit} {
		if origin != nil {
			origin.close()
		}
	}
	if o.udp != nil {
		o.udp.close()
	}
}

type syntaxFaultRuntime struct {
	inner          *l4runtime.OpenResty
	corruptVersion string
}

func (r *syntaxFaultRuntime) Precheck(ctx context.Context, candidatePath string) error {
	content, err := os.ReadFile(filepath.Join(candidatePath, "config.json"))
	if err != nil {
		return err
	}
	var config l4runtime.Config
	if err := json.Unmarshal(content, &config); err != nil {
		return err
	}
	if config.VersionID == r.corruptVersion {
		file, err := os.OpenFile(filepath.Join(candidatePath, "nginx.conf"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		if _, err := file.WriteString("invalid_stream_directive;\n"); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	return r.inner.Precheck(ctx, candidatePath)
}

func (r *syntaxFaultRuntime) Activate(ctx context.Context, currentPath string) error {
	return r.inner.Activate(ctx, currentPath)
}

func (r *syntaxFaultRuntime) Healthy(ctx context.Context, config l4runtime.Config) error {
	return r.inner.Healthy(ctx, config)
}

func (r *syntaxFaultRuntime) Stop(ctx context.Context, currentPath string) error {
	return r.inner.Stop(ctx, currentPath)
}

func main() {
	stateRoot := flag.String("state-root", "/var/lib/cdnca-edge-l4", "private L4 runtime state root")
	openrestyBinary := flag.String("openresty", "/usr/local/openresty/bin/openresty", "OpenResty executable")
	flag.Parse()
	if err := run(*stateRoot, *openrestyBinary); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(stateRoot, binary string) error {
	started, err := startOrigins()
	if err != nil {
		return fmt.Errorf("start echo origins: %w", err)
	}
	defer started.close()
	controller, err := l4runtime.NewOpenResty(binary, filepath.Join(stateRoot, "run", "nginx.pid"), 10*time.Second)
	if err != nil {
		return err
	}
	runtime := &syntaxFaultRuntime{inner: controller, corruptVersion: "l4-bad-syntax"}
	manager, err := l4runtime.NewManager(stateRoot, runtime)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = controller.Stop(ctx, filepath.Join(stateRoot, "current"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v1, err := manager.Apply(ctx, runtimeConfig("l4-v1", 30_000))
	if err != nil {
		return fmt.Errorf("apply v1: %w", err)
	}
	weighted := map[string]int{"a": 0, "b": 0}
	for index := 0; index < 40; index++ {
		response, err := tcpRoundTrip("tcp4", address4(tcpListenPort), fmt.Sprintf("weighted-%d\n", index))
		if err != nil {
			return fmt.Errorf("weighted TCP request: %w", err)
		}
		marker := strings.SplitN(response, ":", 2)[0]
		if _, exists := weighted[marker]; !exists {
			return fmt.Errorf("unexpected weighted response %q", response)
		}
		weighted[marker]++
	}
	if weighted["a"] <= weighted["b"] || weighted["b"] == 0 {
		return fmt.Errorf("weighted distribution was not observed: %v", weighted)
	}
	plainResponse, err := tcpRoundTrip("tcp4", address4(tcpListenPort), "proxy-off\n")
	proxyDisabledPlain := err == nil && (plainResponse == "a:proxy-off" || plainResponse == "b:proxy-off")
	if !proxyDisabledPlain {
		return fmt.Errorf("Proxy Protocol disabled response = %q, %v", plainResponse, err)
	}
	weightedAccepted := started.a.accepted.Load() + started.b.accepted.Load()
	weightedEchoed := started.a.echoed.Load() + started.b.echoed.Load()
	if weightedAccepted == 0 || weightedEchoed == 0 {
		return fmt.Errorf("weighted origin lifecycle counters were empty: accepted=%d echoed=%d", weightedAccepted, weightedEchoed)
	}

	udpResponse, err := udpRoundTrip(address4(udpListenPort), "hello")
	if err != nil || udpResponse != "udp:hello" {
		return fmt.Errorf("UDP echo = %q, %v", udpResponse, err)
	}
	ipv6Response, err := tcpRoundTrip("tcp6", fmt.Sprintf("[::1]:%d", ipv6ListenPort), "hello\n")
	if err != nil || ipv6Response != "ipv6:hello" {
		return fmt.Errorf("IPv6 echo = %q, %v", ipv6Response, err)
	}
	proxyResponse, err := tcpRoundTrip("tcp4", address4(proxyListenPort), "hello\n")
	if err != nil || proxyResponse != "proxy:hello" {
		return fmt.Errorf("Proxy Protocol echo = %q, %v", proxyResponse, err)
	}
	var proxyHeader string
	select {
	case proxyHeader = <-started.proxy.observed:
	case <-time.After(2 * time.Second):
		return errors.New("Proxy Protocol header was not observed upstream")
	}
	if !validProxyHeader(proxyHeader) {
		return fmt.Errorf("invalid upstream Proxy Protocol header %q", proxyHeader)
	}
	if source := strings.Fields(proxyHeader)[2]; source != "127.0.0.1" {
		return fmt.Errorf("upstream Proxy Protocol source = %q, want real client 127.0.0.1", source)
	}

	inbound := runtimeConfig("l4-inbound", 46_000)
	inbound.Listeners[2].Address = "0.0.0.0"
	inbound.Listeners[2].ProxyProtocolInbound = true
	inbound.Listeners[2].TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	if _, err := manager.Apply(ctx, inbound); err != nil {
		return fmt.Errorf("apply trusted inbound Proxy Protocol: %w", err)
	}
	spoofedSource := net.ParseIP("198.51.100.77")
	v1Response, err := proxyRoundTrip(address4(proxyListenPort), proxyV1Header(spoofedSource, net.ParseIP("127.0.0.1"), 40_001, proxyListenPort), "inbound-v1\n", nil)
	if err != nil || v1Response != "proxy:inbound-v1" {
		return fmt.Errorf("inbound Proxy Protocol v1 response = %q, %v", v1Response, err)
	}
	v1Header, err := nextProxyHeader(started.proxy)
	proxyInboundV1 := err == nil && proxyHeaderSource(v1Header) == spoofedSource.String()
	if !proxyInboundV1 {
		return fmt.Errorf("trusted inbound v1 source was not forwarded: header=%q error=%v", v1Header, err)
	}
	v2Response, err := proxyRoundTrip(address4(proxyListenPort), proxyV2Header(spoofedSource, net.ParseIP("127.0.0.1"), 40_002, proxyListenPort), "inbound-v2\n", nil)
	if err != nil || v2Response != "proxy:inbound-v2" {
		return fmt.Errorf("inbound Proxy Protocol v2 response = %q, %v", v2Response, err)
	}
	v2Header, err := nextProxyHeader(started.proxy)
	proxyInboundV2 := err == nil && proxyHeaderSource(v2Header) == spoofedSource.String()
	if !proxyInboundV2 {
		return fmt.Errorf("trusted inbound v2 source was not forwarded: header=%q error=%v", v2Header, err)
	}
	untrustedIP, err := firstNonLoopbackIPv4()
	if err != nil {
		return err
	}
	untrustedResponse, err := proxyRoundTrip(net.JoinHostPort(untrustedIP.String(), strconv.Itoa(proxyListenPort)),
		proxyV1Header(spoofedSource, untrustedIP, 40_003, proxyListenPort), "untrusted\n", untrustedIP)
	if err != nil || untrustedResponse != "proxy:untrusted" {
		return fmt.Errorf("untrusted Proxy Protocol response = %q, %v", untrustedResponse, err)
	}
	untrustedHeader, err := nextProxyHeader(started.proxy)
	proxyUntrustedRejected := err == nil && proxyHeaderSource(untrustedHeader) == untrustedIP.String()
	if !proxyUntrustedRejected {
		return fmt.Errorf("untrusted Proxy Protocol source was spoofed: header=%q peer=%s error=%v", untrustedHeader, untrustedIP, err)
	}

	connections, err := openPersistentConnections(24)
	if err != nil {
		return err
	}
	defer closePersistent(connections)
	v2, err := manager.Apply(ctx, runtimeConfig("l4-v2", 45_000))
	if err != nil {
		return fmt.Errorf("reload v2: %w", err)
	}
	if err := verifyPersistentConcurrently(connections); err != nil {
		return err
	}
	closePersistent(connections)
	connections = nil

	udpInboundInvalid := runtimeConfig("l4-udp-inbound-invalid", 46_000)
	udpInboundInvalid.Listeners[1].ProxyProtocolInbound = true
	udpInboundInvalid.Listeners[1].TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	_, udpInboundErr := manager.Apply(ctx, udpInboundInvalid)
	udpOutboundInvalid := runtimeConfig("l4-udp-outbound-invalid", 46_000)
	udpOutboundInvalid.Listeners[1].ProxyProtocolOutbound = true
	udpOutboundInvalid.Listeners[1].ProxyProtocolV1 = true
	_, udpOutboundErr := manager.Apply(ctx, udpOutboundInvalid)
	udpProxyRejected := errors.Is(udpInboundErr, l4runtime.ErrUnsupported) && errors.Is(udpOutboundErr, l4runtime.ErrUnsupported)
	if !udpProxyRejected {
		return fmt.Errorf("UDP Proxy Protocol contract errors: inbound=%v outbound=%v", udpInboundErr, udpOutboundErr)
	}

	incompatible := runtimeConfig("l4-backend-incompatible", 46_000)
	incompatible.Listeners[2].ProxyProtocolOutbound = false
	incompatible.Listeners[2].ProxyProtocolV1 = false
	incompatible.Listeners[2].TrafficHealth = &l4runtime.TrafficHealthPolicy{
		Request: []byte("health\n"), ExpectedResponse: []byte("health:ok\n"), TimeoutMS: 500, Attempts: 1,
	}
	incompatibleResult, incompatibleErr := manager.Apply(ctx, incompatible)
	backendIncompatibleRejected := errors.Is(incompatibleErr, l4runtime.ErrActivation) &&
		incompatibleResult.ErrorCode == "TRAFFIC_HEALTH_FAILED" && incompatibleResult.RunningVersionUnchanged &&
		incompatibleResult.ActiveVersionID == "l4-v2"
	if !backendIncompatibleRejected {
		return fmt.Errorf("incompatible Proxy Protocol backend did not preserve LKG: result=%+v error=%v", incompatibleResult, incompatibleErr)
	}

	limitRejected, err := verifyConnectionLimit()
	if err != nil || !limitRejected {
		return fmt.Errorf("connection limit verification = %v, %v", limitRejected, err)
	}

	syntaxBad := runtimeConfig("l4-bad-syntax", 46_000)
	failed, syntaxErr := manager.Apply(ctx, syntaxBad)
	syntaxRejected := errors.Is(syntaxErr, l4runtime.ErrPrecheck) && failed.RunningVersionUnchanged && failed.ActiveVersionID == "l4-v2"
	if !syntaxRejected {
		return fmt.Errorf("syntax fault did not preserve LKG: result=%+v error=%v", failed, syntaxErr)
	}
	invalid := runtimeConfig("l4-invalid", 46_000)
	invalid.Listeners = append(invalid.Listeners, invalid.Listeners[0])
	invalid.Listeners[len(invalid.Listeners)-1].ID = "duplicate-bind"
	_, validationErr := manager.Apply(ctx, invalid)
	validationRejected := errors.Is(validationErr, l4runtime.ErrInvalidConfig)
	if !validationRejected {
		return fmt.Errorf("duplicate bind error = %v", validationErr)
	}
	status, err := manager.Status()
	if err != nil || !status.Active || status.VersionID != "l4-v2" || status.Digest != v2.Digest {
		return fmt.Errorf("LKG status = %+v, %v", status, err)
	}
	afterRejected, err := tcpRoundTrip("tcp4", address4(tcpListenPort), "after-rejected\n")
	if err != nil {
		return fmt.Errorf("traffic after rejected configuration: %w", err)
	}

	started.a.close()
	failoverResponses := 0
	for index := 0; index < 12; index++ {
		response, err := tcpRoundTrip("tcp4", address4(tcpListenPort), fmt.Sprintf("failover-%d\n", index))
		if err != nil || !strings.HasPrefix(response, "b:") {
			return fmt.Errorf("failover response %d = %q, %v", index, response, err)
		}
		failoverResponses++
	}
	identityRecorded, pendingCleared, masterOwnerUID, workerOwnerUID, err := verifyProcessIdentityEvidence(filepath.Join(stateRoot, "run", "nginx.pid"))
	if err != nil {
		return err
	}

	result := evidence{
		SchemaVersion: l4runtime.SchemaVersionV1, AppliedVersions: []string{v1.VersionID, v2.VersionID},
		V1Digest: v1.Digest, V2Digest: v2.Digest, TCPWeightedResponses: weighted,
		TCPWeightedAccepted: weightedAccepted, TCPWeightedEchoed: weightedEchoed,
		TCPFailoverResponses: failoverResponses, UDPResponse: udpResponse, IPv6Response: ipv6Response,
		ProxyProtocolHeader: proxyHeader, ProxyProtocolResponse: proxyResponse,
		ProxyProtocolDisabledPlain:     proxyDisabledPlain,
		ProxyProtocolInboundV1:         proxyInboundV1,
		ProxyProtocolInboundV2:         proxyInboundV2,
		ProxyProtocolUntrustedRejected: proxyUntrustedRejected,
		UDPProxyProtocolRejected:       udpProxyRejected, BackendIncompatibleRejected: backendIncompatibleRejected,
		ConcurrentLongConnections: 24, LongConnectionsSurvivedReload: true,
		ConnectionLimitRejected: limitRejected, SyntaxPrecheckRejected: syntaxRejected,
		StrictValidationRejected: validationRejected, LastKnownGoodVersion: status.VersionID,
		TrafficAfterRejectedConfigs: afterRejected, ProcessIdentityRecorded: identityRecorded,
		PendingStartIdentityCleared: pendingCleared, MasterOwnerUID: masterOwnerUID, WorkerOwnerUID: workerOwnerUID,
		WorkerOwnerDropped: workerOwnerUID != masterOwnerUID,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func verifyProcessIdentityEvidence(pidFile string) (bool, bool, uint32, uint32, error) {
	pidContent, err := os.ReadFile(pidFile)
	if err != nil {
		return false, false, 0, 0, fmt.Errorf("read OpenResty PID evidence: %w", err)
	}
	pidText := strings.TrimSpace(string(pidContent))
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 1 || string(pidContent) != strconv.Itoa(pid)+"\n" {
		return false, false, 0, 0, errors.New("OpenResty PID evidence is invalid")
	}
	identityPath := pidFile + ".identity"
	identityInfo, err := os.Lstat(identityPath)
	if err != nil || !identityInfo.Mode().IsRegular() || identityInfo.Mode().Perm()&0o022 != 0 {
		return false, false, 0, 0, errors.New("OpenResty process identity evidence is unsafe")
	}
	identityContent, err := os.ReadFile(identityPath)
	if err != nil {
		return false, false, 0, 0, fmt.Errorf("read OpenResty process identity evidence: %w", err)
	}
	fields := strings.Fields(string(identityContent))
	if len(fields) != 6 || fields[0] != pidText || string(identityContent) != strings.Join(fields, " ")+"\n" {
		return false, false, 0, 0, errors.New("OpenResty process identity evidence is invalid")
	}
	masterOwner, err := strconv.ParseUint(fields[4], 10, 32)
	if err != nil || uint32(masterOwner) != uint32(os.Geteuid()) || masterOwner != 0 {
		return false, false, 0, 0, errors.New("OpenResty master owner evidence is invalid")
	}
	workerOwner, err := observedWorkerOwner(pid)
	if err != nil || workerOwner == uint32(masterOwner) {
		return false, false, 0, 0, errors.Join(errors.New("OpenResty worker owner evidence is invalid"), err)
	}
	_, err = os.Lstat(pidFile + ".identity.pending")
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return true, false, uint32(masterOwner), workerOwner, errors.New("pending OpenResty process identity was not cleared")
	}
	return true, true, uint32(masterOwner), workerOwner, nil
}

func observedWorkerOwner(masterPID int) (uint32, error) {
	children, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(masterPID), "task", strconv.Itoa(masterPID), "children"))
	if err != nil {
		return 0, err
	}
	var owner uint32
	found := false
	for _, field := range strings.Fields(string(children)) {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 1 {
			return 0, errors.New("OpenResty worker PID evidence is invalid")
		}
		info, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
		if err != nil {
			return 0, errors.New("OpenResty worker owner evidence is unavailable")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, errors.New("OpenResty worker owner evidence is unavailable")
		}
		if found && stat.Uid != owner {
			return 0, errors.New("OpenResty worker owner evidence is inconsistent")
		}
		owner = stat.Uid
		found = true
	}
	if !found {
		return 0, errors.New("OpenResty worker owner evidence is missing")
	}
	return owner, nil
}

func runtimeConfig(versionID string, idleTimeoutMS int) l4runtime.Config {
	endpoint := func(address string, port, weight int) l4runtime.Endpoint {
		return l4runtime.Endpoint{Address: address, Port: port, Weight: weight, MaxFails: 1, FailTimeoutMS: 1_000}
	}
	listener := func(id string, protocol l4runtime.Protocol, address string, port int, pool string, limit int) l4runtime.Listener {
		return l4runtime.Listener{
			ID: id, Protocol: protocol, Address: address, Port: port, UpstreamPoolID: pool,
			ConnectTimeoutMS: 500, IdleTimeoutMS: idleTimeoutMS, MaxConnectionsPerClient: limit,
			TrafficHealth: &l4runtime.TrafficHealthPolicy{Request: []byte("health\n"), ExpectedResponse: []byte("health:ok\n"), TimeoutMS: 1500, Attempts: 1},
		}
	}
	config := l4runtime.Config{
		SchemaVersion: l4runtime.SchemaVersionV1, VersionID: versionID,
		UpstreamPools: []l4runtime.UpstreamPool{
			{ID: "weighted", Endpoints: []l4runtime.Endpoint{endpoint("127.0.0.1", originAPort, 3), endpoint("127.0.0.1", originBPort, 1)}},
			{ID: "udp", Endpoints: []l4runtime.Endpoint{endpoint("127.0.0.1", udpOriginPort, 1)}},
			{ID: "proxy", Endpoints: []l4runtime.Endpoint{endpoint("127.0.0.1", proxyOriginPort, 1)}},
			{ID: "ipv6", Endpoints: []l4runtime.Endpoint{endpoint("::1", ipv6OriginPort, 1)}},
			{ID: "limit", Endpoints: []l4runtime.Endpoint{endpoint("127.0.0.1", limitOriginPort, 1)}},
		},
		Listeners: []l4runtime.Listener{
			listener("tcp-weighted", l4runtime.ProtocolTCP, "127.0.0.1", tcpListenPort, "weighted", 100),
			listener("udp-echo", l4runtime.ProtocolUDP, "127.0.0.1", udpListenPort, "udp", 100),
			listener("tcp-proxy", l4runtime.ProtocolTCP, "0.0.0.0", proxyListenPort, "proxy", 100),
			listener("tcp-ipv6", l4runtime.ProtocolTCP, "::1", ipv6ListenPort, "ipv6", 100),
			listener("tcp-limit", l4runtime.ProtocolTCP, "127.0.0.1", limitListenPort, "limit", 2),
		},
	}
	for index := range config.Listeners {
		if config.Listeners[index].ID != "tcp-weighted" {
			config.Listeners[index].TrafficHealth = nil
		}
	}
	config.Listeners[2].ProxyProtocolOutbound = true
	config.Listeners[2].ProxyProtocolV1 = true
	return config
}

type persistentConnection struct {
	connection net.Conn
	reader     *bufio.Reader
	marker     string
}

func openPersistentConnections(count int) ([]persistentConnection, error) {
	connections := make([]persistentConnection, 0, count)
	for index := 0; index < count; index++ {
		connection, err := net.DialTimeout("tcp4", address4(tcpListenPort), 2*time.Second)
		if err != nil {
			closePersistent(connections)
			return nil, err
		}
		entry := persistentConnection{connection: connection, reader: bufio.NewReader(connection)}
		if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			connection.Close()
			closePersistent(connections)
			return nil, err
		}
		if _, err := io.WriteString(connection, fmt.Sprintf("before-%d\n", index)); err != nil {
			connection.Close()
			closePersistent(connections)
			return nil, err
		}
		response, err := entry.reader.ReadString('\n')
		if err != nil || (!strings.HasPrefix(response, "a:") && !strings.HasPrefix(response, "b:")) {
			connection.Close()
			closePersistent(connections)
			return nil, fmt.Errorf("persistent setup response = %q, %v", response, err)
		}
		entry.marker = strings.SplitN(response, ":", 2)[0]
		connections = append(connections, entry)
	}
	return connections, nil
}

func verifyPersistentConcurrently(connections []persistentConnection) error {
	var wait sync.WaitGroup
	errorsFound := make(chan error, len(connections))
	for index := range connections {
		entry := &connections[index]
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if err := entry.connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				errorsFound <- err
				return
			}
			payload := fmt.Sprintf("after-%d\n", index)
			if _, err := io.WriteString(entry.connection, payload); err != nil {
				errorsFound <- err
				return
			}
			response, err := entry.reader.ReadString('\n')
			if err != nil || response != entry.marker+":"+payload {
				errorsFound <- fmt.Errorf("persistent response = %q, %v", response, err)
			}
		}(index)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			return fmt.Errorf("connection did not survive reload: %w", err)
		}
	}
	return nil
}

func closePersistent(connections []persistentConnection) {
	for _, entry := range connections {
		_ = entry.connection.Close()
	}
}

func verifyConnectionLimit() (bool, error) {
	first, err := net.DialTimeout("tcp4", address4(limitListenPort), 2*time.Second)
	if err != nil {
		return false, err
	}
	defer first.Close()
	second, err := net.DialTimeout("tcp4", address4(limitListenPort), 2*time.Second)
	if err != nil {
		return false, err
	}
	defer second.Close()
	for index, connection := range []net.Conn{first, second} {
		if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return false, err
		}
		payload := fmt.Sprintf("held-%d\n", index)
		if _, err := io.WriteString(connection, payload); err != nil {
			return false, err
		}
		response, err := bufio.NewReader(connection).ReadString('\n')
		if err != nil || response != "limit:"+payload {
			return false, fmt.Errorf("held connection response = %q, %v", response, err)
		}
	}
	third, err := net.DialTimeout("tcp4", address4(limitListenPort), 2*time.Second)
	if err != nil {
		return true, nil
	}
	defer third.Close()
	_ = third.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(third, "rejected\n")
	buffer := make([]byte, 1)
	_, err = third.Read(buffer)
	return err != nil, nil
}

func tcpRoundTrip(network, address, payload string) (string, error) {
	connection, err := net.DialTimeout(network, address, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	if _, err := io.WriteString(connection, payload); err != nil {
		return "", err
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	return strings.TrimSpace(response), err
}

func proxyRoundTrip(address string, header []byte, payload string, localIP net.IP) (string, error) {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP}
	}
	connection, err := dialer.Dial("tcp4", address)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	if _, err := connection.Write(append(append([]byte(nil), header...), []byte(payload)...)); err != nil {
		return "", err
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	return strings.TrimSpace(response), err
}

func proxyV1Header(source, destination net.IP, sourcePort, destinationPort int) []byte {
	return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", source.To4(), destination.To4(), sourcePort, destinationPort))
}

func proxyV2Header(source, destination net.IP, sourcePort, destinationPort int) []byte {
	header := []byte{'\r', '\n', '\r', '\n', 0, '\r', '\n', 'Q', 'U', 'I', 'T', '\n', 0x21, 0x11, 0, 12}
	header = append(header, source.To4()...)
	header = append(header, destination.To4()...)
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports[:2], uint16(sourcePort))
	binary.BigEndian.PutUint16(ports[2:], uint16(destinationPort))
	return append(header, ports...)
}

func nextProxyHeader(origin *tcpOrigin) (string, error) {
	select {
	case header := <-origin.observed:
		return header, nil
	case <-time.After(2 * time.Second):
		return "", errors.New("Proxy Protocol header was not observed upstream")
	}
}

func proxyHeaderSource(header string) string {
	if !validProxyHeader(header) {
		return ""
	}
	return strings.Fields(header)[2]
}

func firstNonLoopbackIPv4() (net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, value := range addresses {
			ip, _, err := net.ParseCIDR(value.String())
			if err == nil && ip.To4() != nil && ip.IsGlobalUnicast() {
				return ip.To4(), nil
			}
		}
	}
	return nil, errors.New("no non-loopback IPv4 address for untrusted Proxy Protocol smoke")
}

func udpRoundTrip(address, payload string) (string, error) {
	resolved, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return "", err
	}
	connection, err := net.DialUDP("udp4", nil, resolved)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	if _, err := connection.Write([]byte(payload)); err != nil {
		return "", err
	}
	buffer := make([]byte, 1024)
	count, err := connection.Read(buffer)
	return string(buffer[:count]), err
}

func validProxyHeader(value string) bool {
	fields := strings.Fields(value)
	if len(fields) != 6 || fields[0] != "PROXY" || (fields[1] != "TCP4" && fields[1] != "TCP6") {
		return false
	}
	if net.ParseIP(fields[2]) == nil || net.ParseIP(fields[3]) == nil {
		return false
	}
	return true
}

func address4(port int) string {
	return fmt.Sprintf("127.0.0.1:%d", port)
}
