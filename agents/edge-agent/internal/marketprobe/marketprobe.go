// Package marketprobe executes node-market probes for the control plane: one
// HTTP GET to the fixed market probe path on other sellers' edge nodes, or,
// when the command carries a MarketBenchmarkSpec (capability 34), a timed
// parallel download of the fixed benchmark object for admission grading.
//
// MARKET_PROBE v2 adds host targets (a third-party CDN access name, ADR
// 0008 §6.2): the Agent resolves the name itself and probes it over HTTPS
// with the business Host/SNI, verifying the certificate.
//
// MARKET_PROBE v3 adds origin targets (MarketProbeTarget.scheme) for origin
// failover: http or https, any port, a DNS name or a public IP literal, the
// Host header and the SNI given separately, and optional PEM roots that are
// used for that one probe only. The status rule is the expected status, or
// with none any answer below 500 (an origin that answers is up).
//
// Safety boundary: commands arrive only on the authenticated gateway stream.
// The executor dials literal public unicast addresses only (re-checked at dial
// time; a host is resolved and only a public answer is dialled), on ports 80
// and 443 (origin targets: any port), never follows redirects, reads at most 1 KiB of a response, and
// bounds per-probe time, concurrency and probes per minute. Anything refused
// is reported SKIPPED, never as a failure of the target.
package marketprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

var (
	dnsNamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	probePath      = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,255}$`)
)

const (
	// Path is the market probe path; edges answer it with 204.
	Path = contract.Path

	MaxTargets     = contract.MaxTargets
	MaxTimeout     = contract.MaxTimeoutMillis * time.Millisecond
	MinTimeout     = contract.MinTimeoutMillis * time.Millisecond
	maxBodyBytes   = 1 << 10
	maxHeaderBytes = 8 << 10
)

var ErrInvalidCommand = errors.New("market probe command is invalid")

// Limits bounds the executor. Zero values take the defaults.
type Limits struct {
	Concurrency int // probes in flight at once
	PerMinute   int // probes started per rolling minute
	// Benchmark lets the executor run benchmark downloads (capability 34).
	Benchmark bool
}

func (l Limits) withDefaults() Limits {
	if l.Concurrency <= 0 {
		l.Concurrency = 8
	}
	if l.PerMinute <= 0 {
		l.PerMinute = 120
	}
	return l
}

type Executor struct {
	nodeID string
	limits Limits
	now    func() time.Time
	slots  chan struct{}
	// dial is the transport dialer; tests replace it to reach local servers.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
	// resolve looks a host target up (the system resolver); roots verifies
	// host target certificates (nil: system roots). Tests replace both.
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	roots   *x509.CertPool

	mu      sync.Mutex
	started []time.Time
}

func New(nodeID string, limits Limits, now func() time.Time) (*Executor, error) {
	if nodeID == "" || now == nil {
		return nil, errors.New("market probe executor requires a node ID and a clock")
	}
	limits = limits.withDefaults()
	dialer := &net.Dialer{}
	return &Executor{nodeID: nodeID, limits: limits, now: now, slots: make(chan struct{}, limits.Concurrency),
		dial: dialer.DialContext, resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}}, nil
}

// spec is one admitted target: a literal address, or a host resolved at
// probe time. https, port, hostHeader, roots and expect apply to host and
// origin targets (v2/v3); expect 0 means any answer below 500.
type spec struct {
	address    netip.AddrPort
	host       string
	port       uint16
	https      bool
	hostHeader string
	serverName string
	path       string
	expect     int
	roots      *x509.CertPool
	request    bool // a host or origin target, not a market probe path
	// method and headers (AGGREGATED_EDGE_PROBE v1): host targets only.
	method  string
	headers []*agentv1.MarketProbeHeader
}

// APIVersion is the AGGREGATED_EDGE_PROBE version the executor implements:
// GET or HEAD and extra request headers on host targets.
const APIVersion = 1

// MaxHeaders bounds a host target's extra request headers.
const MaxHeaders = 8

var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")

// reservedHeaders are the probe's own (Host is the business name).
var reservedHeaders = []string{"host", "connection", "content-length", "transfer-encoding", "upgrade", "te",
	"keep-alive", "proxy-connection", "trailer", "user-agent"}

// validHeaders accepts at most MaxHeaders distinct tokens, none reserved,
// with printable values of at most 256 bytes.
func validHeaders(headers []*agentv1.MarketProbeHeader) bool {
	if len(headers) > MaxHeaders {
		return false
	}
	seen := map[string]bool{}
	for _, header := range headers {
		name := strings.ToLower(header.GetName())
		if !headerName.MatchString(header.GetName()) || slices.Contains(reservedHeaders, name) || seen[name] ||
			len(header.GetValue()) > 256 {
			return false
		}
		for _, r := range header.GetValue() {
			if r < 0x20 && r != '\t' || r == 0x7f {
				return false
			}
		}
		seen[name] = true
	}
	return true
}

// Validate checks the command carrier. Per-target problems are reported as
// SKIPPED results by Execute instead.
func (e *Executor) Validate(command *agentv1.MarketProbeCommand) error {
	if command == nil || command.NodeId != e.nodeID || command.Event == nil || command.Event.EventId == "" ||
		len(command.Targets) == 0 || len(command.Targets) > MaxTargets || command.ExpireTime == nil ||
		command.ExpireTime.CheckValid() != nil {
		return ErrInvalidCommand
	}
	timeout := time.Duration(command.TimeoutMillis) * time.Millisecond
	if timeout < MinTimeout || timeout > MaxTimeout {
		return ErrInvalidCommand
	}
	return nil
}

// BenchmarkEnabled reports whether benchmark downloads are executed.
func (e *Executor) BenchmarkEnabled() bool { return e.limits.Benchmark }

// Execute probes every target and returns one result per target, in order.
func (e *Executor) Execute(ctx context.Context, command *agentv1.MarketProbeCommand) ([]*agentv1.MarketProbeTargetResult, error) {
	if err := e.Validate(command); err != nil {
		return nil, err
	}
	benchmark := command.GetBenchmark()
	timeout := time.Duration(command.TimeoutMillis) * time.Millisecond
	expires := command.ExpireTime.AsTime()
	results := make([]*agentv1.MarketProbeTargetResult, len(command.Targets))
	seen := make(map[string]bool, len(command.Targets))
	var wg sync.WaitGroup
	for i, target := range command.Targets {
		result := &agentv1.MarketProbeTargetResult{TaskId: target.GetTaskId()}
		results[i] = result
		probe, reason := e.admit(target, seen, expires, benchmark != nil)
		address := probe.address
		switch {
		case reason != "":
		case benchmark != nil && !e.limits.Benchmark:
			reason = "benchmark_disabled"
		case benchmark != nil && address.Port() != 80:
			reason = "rejected_port" // the benchmark object is served on plain port 80 only
		case benchmark != nil && (benchmark.Connections < 1 || benchmark.Connections > contract.MaxBenchmarkConnections):
			reason = "invalid_benchmark"
		}
		if reason != "" {
			skip(result, reason)
			continue
		}
		select {
		case e.slots <- struct{}{}:
		case <-ctx.Done():
			skip(result, "cancelled")
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-e.slots; wg.Done() }()
			switch {
			case benchmark != nil:
				e.benchmark(ctx, address, int(benchmark.Connections), timeout, result)
			case probe.request:
				e.probeHost(ctx, probe, timeout, result)
			default:
				e.probe(ctx, address, timeout, result)
			}
		}()
	}
	wg.Wait()
	return results, nil
}

// admit returns the probe, or the reason the target is skipped.
func (e *Executor) admit(target *agentv1.MarketProbeTarget, seen map[string]bool, expires time.Time,
	benchmark bool,
) (spec, string) {
	if target == nil || target.TaskId == "" || len(target.TaskId) > 128 || seen[target.TaskId] {
		return spec{}, "invalid_target"
	}
	seen[target.TaskId] = true
	var probe spec
	if target.Method != "" || len(target.Headers) > 0 {
		// Method and headers belong to host targets only.
		if target.Scheme != "" || target.Host == "" || (target.Method != "" && target.Method != http.MethodGet &&
			target.Method != http.MethodHead) || !validHeaders(target.Headers) {
			return spec{}, "invalid_target"
		}
	}
	if target.Scheme != "" {
		var reason string
		if probe, reason = admitOrigin(target, benchmark); reason != "" {
			return spec{}, reason
		}
	} else if target.Host != "" || target.ServerName != "" || target.Path != "" || target.ExpectStatus != 0 ||
		target.HostHeader != "" || target.CaPem != "" {
		// A v2 host target: HTTPS on 443 only, never a benchmark.
		if benchmark || target.Ip != "" || target.Port != 443 || !validDNSName(target.Host) ||
			!validDNSName(target.ServerName) || !probePath.MatchString(target.Path) ||
			target.ExpectStatus < 100 || target.ExpectStatus > 599 || target.HostHeader != "" || target.CaPem != "" {
			return spec{}, "invalid_target"
		}
		probe = spec{host: target.Host, port: 443, https: true, hostHeader: target.ServerName,
			serverName: target.ServerName, path: target.Path, expect: int(target.ExpectStatus), request: true,
			method: target.Method, headers: target.Headers}
	} else {
		if target.Port != 80 && target.Port != 443 {
			return spec{}, "rejected_port"
		}
		ip, err := netip.ParseAddr(target.Ip)
		if err != nil || ip.Zone() != "" || !Public(ip) {
			return spec{}, "rejected_address"
		}
		probe.address = netip.AddrPortFrom(ip.Unmap(), uint16(target.Port))
	}
	if !e.now().Before(expires) {
		return spec{}, "expired"
	}
	if !e.take() {
		return spec{}, "rate_limited"
	}
	return probe, ""
}

// admitOrigin checks a v3 origin target: http or https on any port, a DNS
// name or a public IP literal, a Host header, for https an SNI and optional
// PEM roots (CA certificates only, used for this probe only).
func admitOrigin(target *agentv1.MarketProbeTarget, benchmark bool) (spec, string) {
	https := target.Scheme == "https"
	if benchmark || target.Ip != "" || (!https && target.Scheme != "http") || target.Port < 1 || target.Port > 65_535 ||
		!validHostHeader(target.HostHeader) || !probePath.MatchString(target.Path) ||
		target.ExpectStatus != 0 && (target.ExpectStatus < 100 || target.ExpectStatus > 599) ||
		len(target.CaPem) > contract.MaxCAPEMBytes {
		return spec{}, "invalid_target"
	}
	probe := spec{port: uint16(target.Port), https: https, hostHeader: target.HostHeader, path: target.Path,
		expect: int(target.ExpectStatus), request: true}
	if https {
		if !validDNSName(target.ServerName) && !validIPLiteral(target.ServerName) {
			return spec{}, "invalid_target"
		}
		probe.serverName = target.ServerName
		if target.CaPem != "" {
			if probe.roots = caPool(target.CaPem); probe.roots == nil {
				return spec{}, "invalid_target"
			}
		}
	} else if target.ServerName != "" || target.CaPem != "" {
		return spec{}, "invalid_target"
	}
	if ip, err := netip.ParseAddr(target.Host); err == nil {
		if ip.Zone() != "" || !Public(ip) {
			return spec{}, "rejected_address"
		}
		probe.address = netip.AddrPortFrom(ip.Unmap(), probe.port)
		return probe, ""
	}
	if !validDNSName(target.Host) {
		return spec{}, "invalid_target"
	}
	probe.host = target.Host
	return probe, ""
}

// caPool parses PEM CA certificates (nothing else); nil if there are none or
// anything else is in the bundle.
func caPool(bundle string) *x509.CertPool {
	pool := x509.NewCertPool()
	rest, count := []byte(bundle), 0
	for len(strings.TrimSpace(string(rest))) > 0 {
		block, remainder := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return nil
		}
		pool.AddCert(certificate)
		rest, count = remainder, count+1
	}
	if count == 0 {
		return nil
	}
	return pool
}

// validIPLiteral accepts a canonical IP literal without a zone.
func validIPLiteral(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Zone() == "" && ip.String() == value
}

// validHostHeader accepts name, IPv4 or [IPv6], each with an optional :port.
func validHostHeader(value string) bool {
	host, port := value, ""
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end < 0 || !validIPLiteral(value[1:end]) || !strings.Contains(value[1:end], ":") {
			return false
		}
		host, port = "", value[end+1:]
		if port != "" && !strings.HasPrefix(port, ":") {
			return false
		}
		port = strings.TrimPrefix(port, ":")
		if port == "" && value[end+1:] != "" {
			return false
		}
	} else {
		if index := strings.LastIndex(value, ":"); index >= 0 {
			host, port = value[:index], value[index+1:]
			if port == "" {
				return false
			}
		}
		if !validDNSName(host) && !(validIPLiteral(host) && !strings.Contains(host, ":")) {
			return false
		}
	}
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65_535 || strconv.Itoa(number) != port {
			return false
		}
	}
	return true
}

// validDNSName accepts a lower-case hostname that is not an IP literal.
func validDNSName(name string) bool {
	if len(name) > 253 || !dnsNamePattern.MatchString(name) {
		return false
	}
	_, err := netip.ParseAddr(name)
	return err != nil
}

// pickPublic returns the first public answer, IPv4 before IPv6.
func pickPublic(addresses []netip.Addr) (netip.Addr, bool) {
	var v6 netip.Addr
	for _, address := range addresses {
		address = address.Unmap()
		if address.Zone() != "" || !Public(address) {
			continue
		}
		if address.Is4() {
			return address, true
		}
		if !v6.IsValid() {
			v6 = address
		}
	}
	return v6, v6.IsValid()
}

// probeHost sends one GET of a host or origin target's path with its Host
// header (https: verified for its SNI, with its own roots if it has any) to
// the target's literal address or the first public answer for its name.
func (e *Executor) probeHost(ctx context.Context, probe spec, timeout time.Duration,
	result *agentv1.MarketProbeTargetResult,
) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	address := probe.address
	if probe.host != "" {
		answers, err := e.resolve(ctx, probe.host)
		if err != nil || len(answers) == 0 {
			fail(result, "resolve")
			if ctx.Err() != nil {
				fail(result, "timeout")
			}
			return
		}
		ip, ok := pickPublic(answers)
		if !ok {
			skip(result, "rejected_address") // says nothing about the target
			return
		}
		address = netip.AddrPortFrom(ip, probe.port)
	}
	client, transport := e.client(address)
	defer transport.CloseIdleConnections()
	scheme := "http"
	if probe.https {
		scheme = "https"
		roots := e.roots
		if probe.roots != nil {
			roots = probe.roots
		}
		transport.TLSClientConfig = &tls.Config{ServerName: probe.serverName, RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	method := http.MethodGet
	if probe.method != "" {
		method = probe.method
	}
	request, err := http.NewRequestWithContext(ctx, method, scheme+"://"+address.String()+"/", nil)
	if err != nil {
		fail(result, "request")
		return
	}
	pathOnly, query, _ := strings.Cut(probe.path, "?")
	request.URL.Path, request.URL.RawQuery = pathOnly, query
	request.Host = probe.hostHeader
	for _, header := range probe.headers {
		request.Header.Add(header.Name, header.Value)
	}
	request.Header.Set("User-Agent", "cdnca-edge-probe/2")
	response, err := client.Do(request)
	latency := time.Since(started)
	if err != nil {
		var certificate *tls.CertificateVerificationError
		switch {
		case ctx.Err() != nil:
			fail(result, "timeout")
		case errors.As(err, &certificate):
			fail(result, "tls")
		default:
			fail(result, "connect")
		}
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxBodyBytes))
	_ = response.Body.Close()
	result.LatencyMillis = uint32(min(latency.Milliseconds(), int64(MaxTimeout/time.Millisecond)))
	result.StatusCode = uint32(response.StatusCode)
	if probe.expect != 0 && response.StatusCode != probe.expect ||
		probe.expect == 0 && response.StatusCode >= http.StatusInternalServerError {
		fail(result, "status")
		return
	}
	result.Outcome = agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK
}

// take reserves one probe in the rolling one-minute budget.
func (e *Executor) take() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := e.now().Add(-time.Minute)
	kept := e.started[:0]
	for _, at := range e.started {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	e.started = kept
	if len(e.started) >= e.limits.PerMinute {
		return false
	}
	e.started = append(e.started, e.now())
	return true
}

// client builds a one-shot HTTP client that can only dial address.
func (e *Executor) client(address netip.AddrPort) (*http.Client, *http.Transport) {
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: maxHeaderBytes, ForceAttemptHTTP2: false,
		// Availability and latency are measured, not certificates; nothing secret is sent.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec
		DialContext: func(ctx context.Context, network, dialAddress string) (net.Conn, error) {
			// Defence in depth: only the admitted literal address is ever dialled.
			if dialAddress != address.String() {
				return nil, errors.New("unexpected dial address")
			}
			return e.dial(ctx, network, dialAddress)
		},
	}
	return &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport
}

func targetURL(address netip.AddrPort, path string) string {
	scheme := "http"
	if address.Port() == 443 {
		scheme = "https"
	}
	host := address.Addr().String()
	if address.Addr().Is6() {
		host = "[" + host + "]"
	}
	return scheme + "://" + host + path
}

func (e *Executor) probe(ctx context.Context, address netip.AddrPort, timeout time.Duration,
	result *agentv1.MarketProbeTargetResult,
) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, transport := e.client(address)
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL(address, Path), nil)
	if err != nil {
		fail(result, "request")
		return
	}
	request.Header.Set("User-Agent", "cdnca-market-probe/1")
	started := time.Now()
	response, err := client.Do(request)
	latency := time.Since(started)
	if err != nil {
		if ctx.Err() != nil {
			fail(result, "timeout")
		} else {
			fail(result, "connect")
		}
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxBodyBytes))
	_ = response.Body.Close()
	result.LatencyMillis = uint32(min(latency.Milliseconds(), int64(MaxTimeout/time.Millisecond)))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		fail(result, "status")
		return
	}
	result.Outcome = agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK
}

// benchmark downloads the benchmark object over connections parallel GETs
// within timeout. The result is OK only when every connection got a 200 and
// the whole object; throughput is the aggregate over the slowest
// connection's time, TTFB the median of the connections.
func (e *Executor) benchmark(ctx context.Context, address netip.AddrPort, connections int, timeout time.Duration,
	result *agentv1.MarketProbeTargetResult,
) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, transport := e.client(address)
	defer transport.CloseIdleConnections()
	type sample struct {
		ttfb  time.Duration
		bytes int64
		code  string
	}
	samples := make([]sample, connections)
	started := time.Now()
	var wg sync.WaitGroup
	for i := range samples {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := &samples[i]
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL(address, contract.BenchmarkPath), nil)
			if err != nil {
				s.code = "request"
				return
			}
			request.Header.Set("User-Agent", "cdnca-market-benchmark/1")
			request.Header.Set("Accept-Encoding", "identity")
			begin := time.Now()
			response, err := client.Do(request)
			if err != nil {
				s.code = "connect"
				if ctx.Err() != nil {
					s.code = "timeout"
				}
				return
			}
			defer response.Body.Close()
			s.ttfb = time.Since(begin)
			if response.StatusCode != http.StatusOK {
				s.code = "status"
				return
			}
			s.bytes, err = io.Copy(io.Discard, io.LimitReader(response.Body, contract.BenchmarkBytes))
			switch {
			case err != nil && ctx.Err() != nil:
				s.code = "timeout"
			case err != nil:
				s.code = "read"
			case s.bytes != contract.BenchmarkBytes:
				s.code = "short"
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(started)
	var total int64
	ttfbs := make([]time.Duration, 0, connections)
	code := ""
	for _, s := range samples {
		total += s.bytes
		if s.ttfb > 0 {
			ttfbs = append(ttfbs, s.ttfb)
		}
		if code == "" {
			code = s.code
		}
	}
	result.BytesReceived = uint64(total)
	if elapsed > 0 {
		result.ThroughputKbps = uint64(float64(total) * 8 / 1000 / elapsed.Seconds())
	}
	if len(ttfbs) > 0 {
		slices.Sort(ttfbs)
		result.TtfbMillis = uint32(min(ttfbs[(len(ttfbs)-1)/2].Milliseconds(), int64(MaxTimeout/time.Millisecond)))
	}
	result.LatencyMillis = result.TtfbMillis
	if code != "" {
		fail(result, code)
		return
	}
	result.Outcome = agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK
}

func skip(result *agentv1.MarketProbeTargetResult, reason string) {
	result.Outcome, result.ErrorCode = agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, reason
}

func fail(result *agentv1.MarketProbeTargetResult, reason string) {
	result.Outcome, result.ErrorCode = agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, reason
}

// Public is the shared probe address rule (libs/edgeconfig/marketprobe).
func Public(ip netip.Addr) bool { return contract.Public(ip) }
