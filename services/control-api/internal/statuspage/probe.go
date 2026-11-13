package statuspage

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	probeTimeout = 3 * time.Second
	// probeFresh: a probe result older than this is treated as missing (the sampler stopped).
	probeFresh = 3 * time.Minute
	// slowConsole: a console answer slower than this counts as degraded.
	slowConsole = 3 * time.Second
	// maxGatewayProbes bounds the standalone gateways dialled per minute.
	maxGatewayProbes = 20
)

// ProbeConfig holds the server-side probe targets. Both come from the
// control-api environment, never from request input.
type ProbeConfig struct {
	// ConsoleURL: URL of the console (http/https). Empty: web_console is unconfigured.
	ConsoleURL string
	// LocalGatewayAddress: host:port of the co-located Gateway agent port. Empty: none.
	LocalGatewayAddress string
}

type probeResult struct {
	status string
	note   Text
	up     bool
	at     time.Time
	// reason is why the probe failed (HTTP code, timeout, connection refused), for the per-minute detail.
	reason string
}

type probeCache struct {
	mu      sync.Mutex
	results map[string]probeResult
	gateway struct {
		total, up int
		at        time.Time
	}
	gatewayReason string
}

// SetProbeConfig sets the probe targets. Call before Run.
func (s *Service) SetProbeConfig(config ProbeConfig) { s.probe = config }

func (c *probeCache) set(key string, result probeResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.results == nil {
		c.results = map[string]probeResult{}
	}
	c.results[key] = result
}

func (c *probeCache) get(key string, now time.Time) (probeResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	result, found := c.results[key]
	if !found || now.Sub(result.at) > probeFresh {
		return probeResult{}, false
	}
	return result, true
}

// setGatewayReason keeps how many gateway ports did not accept a connection, as "N/M gateway ports unreachable".
func (c *probeCache) setGatewayReason(down, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gatewayReason = ""
	if down > 0 {
		c.gatewayReason = strconv.Itoa(down) + "/" + strconv.Itoa(total) + " gateway ports unreachable"
	}
}

// reasonFor is why a probed source is not operational right now, or "".
func (c *probeCache) reasonFor(source string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if source == SourceGateway {
		return c.gatewayReason
	}
	return c.results[source].reason
}

func (c *probeCache) setGateways(total, up int, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gateway.total, c.gateway.up, c.gateway.at = total, up, at
}

func (c *probeCache) gateways(now time.Time) (int, int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gateway.at.IsZero() || now.Sub(c.gateway.at) > probeFresh {
		return 0, 0, false
	}
	return c.gateway.total, c.gateway.up, true
}

// dial reports whether a TCP connection to address succeeds. It sends nothing.
func dial(ctx context.Context, address string) bool {
	dialer := net.Dialer{Timeout: probeTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// loopbackOf rewrites host:port to 127.0.0.1:port: the co-located Gateway is probed on the
// loopback so a public address behind NAT does not read as down.
func loopbackOf(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// probeConsole fetches the configured console URL. The target is the administrator's own
// console, so TLS verification is skipped (a private CA or an IP certificate is normal on a
// fresh install): this checks that it answers, it sends no credential and reads no body.
func probeConsole(ctx context.Context, raw string, now time.Time) probeResult {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return probeResult{status: StatusUnconfigured, note: Text{ZH: "未配置控制台拨测地址", EN: "Console probe address is not configured"}, at: now}
	}
	client := &http.Client{Timeout: probeTimeout, Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- reachability check of the operator's own console
		DisableKeepAlives: true,
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return probeResult{status: StatusUnconfigured, at: now}
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return probeResult{status: StatusOutage, at: now, reason: failureReason(err)}
	}
	_ = response.Body.Close()
	switch {
	case response.StatusCode >= 500 || response.StatusCode == http.StatusNotFound:
		return probeResult{status: StatusOutage, at: now, reason: "HTTP " + strconv.Itoa(response.StatusCode)}
	case time.Since(started) > slowConsole:
		return probeResult{status: StatusDegraded, up: true, at: now, reason: "slow response"}
	}
	return probeResult{status: StatusOperational, up: true, at: now}
}

// runProbes refreshes the cache: console, co-located Gateway and the active standalone
// Gateways. The control API itself is operational whenever this runs against the database.
func (s *Service) runProbes(ctx context.Context, q queryer, now time.Time) error {
	s.probes.set(SourceControlAPI, probeResult{status: StatusOperational, up: true, at: now})
	if s.probe.ConsoleURL == "" {
		s.probes.set(SourceWebConsole, probeResult{status: StatusUnconfigured, note: Text{ZH: "未配置控制台拨测地址", EN: "Console probe address is not configured"}, at: now})
	} else {
		s.probes.set(SourceWebConsole, probeConsole(ctx, s.probe.ConsoleURL, now))
	}
	total, up := 0, 0
	downPorts := 0
	if local := loopbackOf(s.probe.LocalGatewayAddress); local != "" {
		total++
		if dial(ctx, local) {
			up++
		} else {
			downPorts++
		}
	}
	rows, err := q.Query(ctx, `SELECT host, agent_port FROM agent_gateways
		WHERE status = 'active' AND agent_port IS NOT NULL ORDER BY created_at, id LIMIT $1`, maxGatewayProbes)
	if err != nil {
		return err
	}
	type target struct {
		host string
		port int
	}
	targets, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (target, error) {
		var item target
		return item, row.Scan(&item.host, &item.port)
	})
	if err != nil {
		return err
	}
	for _, item := range targets {
		total++
		if dial(ctx, net.JoinHostPort(item.host, strconv.Itoa(item.port))) {
			up++
		} else {
			downPorts++
		}
	}
	s.probes.setGateways(total, up, now)
	s.probes.setGatewayReason(downPorts, total)
	return nil
}

// failureReason names why a request failed without leaking the address.
func failureReason(err error) string {
	var network net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	}
	return "request failed"
}

// probed returns the status of a source judged by the cached probes.
func (s *Service) probed(source string, now time.Time) (string, Text) {
	switch source {
	case SourceControlAPI, SourceWebConsole:
		if result, found := s.probes.get(source, now); found {
			return result.status, result.note
		}
	case SourceGateway:
		if total, up, found := s.probes.gateways(now); found {
			status := ratioStatus(total, up)
			if status == StatusUnconfigured {
				return status, Text{ZH: "没有节点网关", EN: "No node gateway"}
			}
			return status, Text{}
		}
	}
	return StatusUnconfigured, Text{ZH: "暂无监测数据", EN: "No monitoring data yet"}
}
