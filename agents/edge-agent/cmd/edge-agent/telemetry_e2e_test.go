package main

// Telemetry half of tests/telemetry-e2e/run.sh, inside TestDynRouteAgentProcess when
// DYNROUTE_E2E_TELEMETRY=1: the daemon's telemetry pipeline (assembleTelemetryPipeline: spool, telemetry client,
// worker, the dynamic routing node's shared access/security logs and subscription minutes) over mTLS to the gateway.
// The dialer can be cut (POST /telemetry/offline): every dial fails as with the gateway unreachable, the open
// stream is closed, and the spool keeps what the node logs until POST /telemetry/online.
//
// HTTP for the control half: POST /telemetry/offline, /telemetry/online; GET /telemetry/stats (spool pending,
// acked sequence, worker state, node-side line counts); GET /telemetry/burst?host=&path=&source=&count= (count
// requests from source, a loopback address of the container; their statuses).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	"github.com/google/uuid"
)

type telemetryE2EAgent struct {
	pipeline *telemetryPipeline
	dialer   *pausableTelemetryDialer
	access   string
	security string
}

// pausableTelemetryDialer is the production mTLS dialer that can be cut: offline closes the open connections and
// refuses dials until online.
type pausableTelemetryDialer struct {
	base    telemetryclient.Dialer
	offline atomic.Bool
	mu      sync.Mutex
	open    []telemetryclient.Connection
}

func (dialer *pausableTelemetryDialer) Dial(ctx context.Context) (telemetryclient.Connection, error) {
	if dialer.offline.Load() {
		return nil, errors.New("telemetry e2e: gateway unreachable")
	}
	connection, err := dialer.base.Dial(ctx)
	if err == nil {
		dialer.mu.Lock()
		dialer.open = append(dialer.open, connection)
		dialer.mu.Unlock()
	}
	return connection, err
}

func (dialer *pausableTelemetryDialer) cut() {
	dialer.offline.Store(true)
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	for _, connection := range dialer.open {
		_ = connection.Close()
	}
	dialer.open = nil
}

func startTelemetryE2EAgent(t *testing.T, ctx context.Context, config fileConfig, gateway artifactSetGatewayFixture,
	identity string, runtime *dynroute.Runtime, manager *dynamicRoutingManager) *telemetryE2EAgent {
	t.Helper()
	base, err := telemetryclient.NewMTLSDialer(telemetryclient.MTLSDialerConfig{Address: gateway.Address,
		ServerName: gateway.ServerName, RootCAFile: filepath.Join(identity, "ca.pem"),
		ClientCertificateFile: filepath.Join(identity, "node.pem"), ClientPrivateKeyFile: filepath.Join(identity, "node-key.pem"),
		MaximumReceiveBytes: 1 << 20, MaximumSendBytes: config.Telemetry.MaxBatchBytes + (64 << 10)})
	if err != nil {
		t.Fatal(err)
	}
	timeouts, err := config.Telemetry.parse(config.DeploymentRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed := parsedTimeouts{TelemetrySoftAgeLimit: timeouts.softAge, TelemetryHardAgeLimit: timeouts.hardAge,
		TelemetryEmptyInterval: timeouts.emptyInterval, TelemetryHandshake: timeouts.handshake, TelemetryAck: timeouts.ack,
		TelemetryInitialBackoff: timeouts.initialBackoff, TelemetryMaximumBackoff: timeouts.maximumBackoff}
	dialer := &pausableTelemetryDialer{base: base}
	pipeline, err := assembleTelemetryPipeline(config, parsed, gateway.NodeID, uuid.NewString(), dialer, manager, runtime, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := pipeline.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("telemetry pipeline stopped: %v", err)
		}
	}()
	access, security := runtime.TelemetryLogs()
	return &telemetryE2EAgent{pipeline: pipeline, dialer: dialer, access: access, security: security}
}

func (agent *telemetryE2EAgent) register(handler *http.ServeMux) {
	handler.HandleFunc("/telemetry/offline", func(response http.ResponseWriter, _ *http.Request) {
		agent.dialer.cut()
		response.WriteHeader(http.StatusNoContent)
	})
	handler.HandleFunc("/telemetry/online", func(response http.ResponseWriter, _ *http.Request) {
		agent.dialer.offline.Store(false)
		response.WriteHeader(http.StatusNoContent)
	})
	handler.HandleFunc("/telemetry/stats", func(response http.ResponseWriter, _ *http.Request) {
		stats, err := agent.pipeline.spool.Stats()
		snapshot := agent.pipeline.Snapshot()
		value := map[string]any{"pending_events": stats.PendingEvents, "acked_sequence": stats.AckedSequence,
			"next_sequence": stats.NextSequence, "expired_events": stats.ExpiredEvents, "worker_running": snapshot.Running,
			"worker_degraded": snapshot.Degraded, "worker_error": snapshot.LastErrorCode, "offline": agent.dialer.offline.Load(),
			"access_lines": countTelemetryLines(agent.access, nil), "security": securityLineCounts(agent.security)}
		if err != nil {
			value["error"] = err.Error()
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(value)
	})
	handler.HandleFunc("/telemetry/burst", func(response http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		count, _ := strconv.Atoi(query.Get("count"))
		statuses := map[int]int{}
		for range count {
			statuses[telemetryE2EGet(query.Get("source"), query.Get("host"), query.Get("path"))]++
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(statuses)
	})
}

// telemetryE2EGet sends one request from source (a loopback address) to the sites' port; its status (0: error).
func telemetryE2EGet(source, host, path string) int {
	dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}, Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}}
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", dynRouteE2ESitePort, path), nil)
	if err != nil {
		return 0
	}
	request.Host = host
	request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) telemetry-e2e")
	response, err := client.Do(request)
	if err != nil {
		return 0
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func countTelemetryLines(path string, keep func(map[string]any) bool) int {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		var value map[string]any
		if json.Unmarshal([]byte(line), &value) == nil && (keep == nil || keep(value)) {
			count++
		}
	}
	return count
}

// securityLineCounts: per "<security_type>/<action>", the node's security lines and the requests they stand for
// (an aggregated line's count, else 1).
func securityLineCounts(path string) map[string][2]uint64 {
	result := map[string][2]uint64{}
	content, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		var value struct {
			Type   string  `json:"security_type"`
			Action string  `json:"action"`
			Count  *uint64 `json:"count"`
		}
		if json.Unmarshal([]byte(line), &value) != nil || value.Type == "" {
			continue
		}
		key, requests := value.Type+"/"+value.Action, uint64(1)
		if value.Count != nil {
			requests = *value.Count
		}
		entry := result[key]
		entry[0]++
		entry[1] += requests
		result[key] = entry
	}
	return result
}
