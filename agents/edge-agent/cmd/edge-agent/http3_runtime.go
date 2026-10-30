package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/http3runtime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	http3PolicyArtifactPath  = "http3-policy.v1.json"
	http3PolicyMaxBytes      = 1 << 20
	http3HealthProbeAttempts = 3
	// http3ProbeVersionSchema is what `h3probe version` prints as its schema.
	http3ProbeVersionSchema   = "cdnca.h3probe/v1"
	http3ProbeSelfTestTimeout = 5 * time.Second
)

type http3DeploymentLifecycle interface {
	deployment.Prechecker
	deployment.Runtime
}

type http3PolicyManager interface {
	Apply(context.Context, http3runtime.Policy) (http3runtime.Result, error)
	Status() (http3runtime.Status, error)
}

type http3DeploymentBridge struct {
	delegate http3DeploymentLifecycle
	manager  http3PolicyManager

	mu              sync.RWMutex
	managed         bool
	expectedVersion string
	expectedDigest  string
}

func newHTTP3DeploymentBridge(delegate http3DeploymentLifecycle, manager http3PolicyManager) (*http3DeploymentBridge, error) {
	if delegate == nil || manager == nil {
		return nil, http3runtime.ErrInvalidPolicy
	}
	status, err := manager.Status()
	if err != nil {
		return nil, err
	}
	bridge := &http3DeploymentBridge{delegate: delegate, manager: manager}
	if status.Active {
		if status.VersionID == "" || status.Digest == "" {
			return nil, http3runtime.ErrCorruptState
		}
		bridge.setExpected(true, status.VersionID, status.Digest)
	}
	return bridge, nil
}

func (bridge *http3DeploymentBridge) Precheck(ctx context.Context, versionID, releasePath string) error {
	policy, present, err := loadHTTP3Policy(releasePath)
	if err != nil {
		return err
	}
	if !present {
		managed, _, _ := bridge.expected()
		if managed {
			return http3runtime.ErrInvalidPolicy
		}
		return bridge.delegate.Precheck(ctx, versionID, releasePath)
	}
	if policy.VersionID != versionID {
		return http3runtime.ErrInvalidPolicy
	}
	if _, err = http3runtime.Compile(policy); err != nil {
		return err
	}
	return bridge.delegate.Precheck(ctx, versionID, releasePath)
}

func (bridge *http3DeploymentBridge) Reload(ctx context.Context, versionID, currentPath string) error {
	policy, present, err := loadHTTP3Policy(currentPath)
	if err != nil {
		return err
	}
	if !present {
		managed, _, _ := bridge.expected()
		if managed {
			return http3runtime.ErrInvalidPolicy
		}
		if err := bridge.delegate.Reload(ctx, versionID, currentPath); err != nil {
			return err
		}
		return nil
	}
	if policy.VersionID != versionID {
		return http3runtime.ErrInvalidPolicy
	}
	if err := bridge.delegate.Reload(ctx, versionID, currentPath); err != nil {
		return err
	}
	result, err := bridge.manager.Apply(ctx, policy)
	if err != nil {
		return err
	}
	if result.State != http3runtime.StateApplied || result.VersionID != versionID ||
		result.ActiveVersionID != versionID || result.Digest == "" || result.ActiveDigest != result.Digest {
		return http3runtime.ErrCorruptState
	}
	bridge.setExpected(true, versionID, result.Digest)
	return nil
}

func (bridge *http3DeploymentBridge) Healthy(ctx context.Context, versionID string) error {
	managed, expectedVersion, expectedDigest := bridge.expected()
	if !managed {
		return bridge.delegate.Healthy(ctx, versionID)
	}
	if expectedVersion != versionID {
		return http3runtime.ErrCorruptState
	}
	status, err := bridge.manager.Status()
	if err != nil {
		return err
	}
	if !status.Active || status.VersionID != expectedVersion || status.Digest != expectedDigest {
		return http3runtime.ErrCorruptState
	}
	return bridge.delegate.Healthy(ctx, versionID)
}

func (bridge *http3DeploymentBridge) setExpected(managed bool, version, digest string) {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	bridge.managed = managed
	bridge.expectedVersion = version
	bridge.expectedDigest = digest
}

func (bridge *http3DeploymentBridge) expected() (bool, string, string) {
	bridge.mu.RLock()
	defer bridge.mu.RUnlock()
	return bridge.managed, bridge.expectedVersion, bridge.expectedDigest
}

func loadHTTP3Policy(root string) (http3runtime.Policy, bool, error) {
	file, err := os.Open(filepath.Join(root, http3PolicyArtifactPath))
	if errors.Is(err, os.ErrNotExist) {
		return http3runtime.Policy{}, false, nil
	}
	if err != nil {
		return http3runtime.Policy{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > http3PolicyMaxBytes {
		return http3runtime.Policy{}, false, http3runtime.ErrInvalidPolicy
	}
	decoder := json.NewDecoder(io.LimitReader(file, http3PolicyMaxBytes+1))
	decoder.DisallowUnknownFields()
	var policy http3runtime.Policy
	if err := decoder.Decode(&policy); err != nil {
		return http3runtime.Policy{}, false, http3runtime.ErrInvalidPolicy
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return http3runtime.Policy{}, false, http3runtime.ErrInvalidPolicy
	}
	return policy, true, nil
}

// http3RuntimeReadiness says whether the node declares HTTP_3 and, when it
// does not, why (logged locally and reported with every terminal deployment).
type http3RuntimeReadiness struct {
	Ready  bool
	Probe  string
	Reason string
}

func assembleHTTP3DeploymentRuntime(config fileConfig, timeouts parsedTimeouts,
	delegate http3DeploymentLifecycle) (http3DeploymentLifecycle, http3RuntimeReadiness, error) {
	if config.OpenResty.Version != http3runtime.RuntimeVersionOpenResty {
		return delegate, http3RuntimeReadiness{Reason: fmt.Sprintf("openresty.version %q is not the HTTP/3 runtime version %s",
			config.OpenResty.Version, http3runtime.RuntimeVersionOpenResty)}, nil
	}
	stateRoot := filepath.Join(filepath.Dir(config.JournalDir), "http3-runtime")
	clientBinary := config.OpenResty.HTTP3Probe
	if reason := checkHTTP3Probe(clientBinary); reason != "" {
		activePath := filepath.Join(stateRoot, "state", "active.json")
		if _, activeErr := os.Lstat(activePath); activeErr == nil {
			return nil, http3RuntimeReadiness{Reason: reason}, fmt.Errorf("configure HTTP/3 runtime: durable active state requires h3probe: %s", reason)
		} else if !errors.Is(activeErr, os.ErrNotExist) {
			return nil, http3RuntimeReadiness{Reason: reason}, fmt.Errorf("configure HTTP/3 runtime: inspect durable active state: %w", activeErr)
		}
		return delegate, http3RuntimeReadiness{Reason: reason}, nil
	}
	probe := daemonHTTP3HealthProbe{clientBinary: clientBinary, timeout: timeouts.HealthRequest}
	runtime, err := http3runtime.NewOpenResty(
		config.OpenResty.Binary, filepath.Join(stateRoot, "run", "nginx.pid"), timeouts.Reload, probe,
	)
	if err != nil {
		return nil, http3RuntimeReadiness{}, fmt.Errorf("configure HTTP/3 OpenResty runtime: %w", err)
	}
	manager, err := http3runtime.NewManager(stateRoot, runtime)
	if err != nil {
		return nil, http3RuntimeReadiness{}, fmt.Errorf("configure HTTP/3 runtime manager: %w", err)
	}
	bridge, err := newHTTP3DeploymentBridge(delegate, manager)
	if err != nil {
		return nil, http3RuntimeReadiness{}, fmt.Errorf("configure HTTP/3 deployment bridge: %w", err)
	}
	return bridge, http3RuntimeReadiness{Ready: true, Probe: clientBinary}, nil
}

// checkHTTP3Probe returns why the configured h3probe cannot serve as the
// HTTP/3 health probe, or "" once `h3probe version` answered as one.
func checkHTTP3Probe(path string) string {
	if path == "" {
		return "openresty.http3_probe is not configured (the node package installs runtime/bin/h3probe)"
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Sprintf("h3probe %s not found", path)
	}
	if err != nil {
		return fmt.Sprintf("h3probe %s cannot be inspected: %v", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Sprintf("h3probe %s is not executable", path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), http3ProbeSelfTestTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "version").Output()
	var version struct {
		Schema string `json:"schema"`
		Go     string `json:"go"`
		QUICGo string `json:"quic_go"`
	}
	if err != nil || len(output) > 4096 || json.Unmarshal(output, &version) != nil ||
		version.Schema != http3ProbeVersionSchema || version.Go == "" || version.QUICGo == "" {
		return fmt.Sprintf("h3probe %s failed its self-test (`h3probe version`)", path)
	}
	return ""
}

// http3RuntimeChecks reports HTTP/3 readiness with every terminal deployment.
func http3RuntimeChecks(readiness http3RuntimeReadiness) func() []*agentv1.CheckResult {
	summary := "HTTP/3 runtime ready, h3probe " + readiness.Probe
	if !readiness.Ready {
		summary = "HTTP/3 unavailable, HTTP_3 not declared: " + readiness.Reason
	}
	if len(summary) > 1024 {
		summary = summary[:1024]
	}
	return func() []*agentv1.CheckResult {
		return []*agentv1.CheckResult{{Name: "edge_http3_runtime", Succeeded: readiness.Ready, Summary: summary,
			LatencyDuration: durationpb.New(0)}}
	}
}

func logHTTP3Readiness(output io.Writer, readiness http3RuntimeReadiness) {
	if readiness.Ready {
		fmt.Fprintf(output, "edge-agent: HTTP/3 runtime ready (h3probe %s)\n", readiness.Probe)
		return
	}
	fmt.Fprintf(output, "edge-agent: HTTP/3 unavailable, HTTP_3 not declared: %s\n", readiness.Reason)
}

// combineDeploymentChecks joins the checks reported with every terminal
// deployment (gatewayclient.WithDeploymentChecks takes one source).
func combineDeploymentChecks(sources ...func() []*agentv1.CheckResult) func() []*agentv1.CheckResult {
	return func() []*agentv1.CheckResult {
		var checks []*agentv1.CheckResult
		for _, source := range sources {
			checks = append(checks, source()...)
		}
		return checks
	}
}

type daemonHTTP3HealthProbe struct {
	clientBinary string
	timeout      time.Duration
	run          func(context.Context, string, ...string) ([]byte, error)
}

func (probe daemonHTTP3HealthProbe) TCP(ctx context.Context, policy http3runtime.Policy) error {
	address := http3ProbeAddress(policy.Listener.Address)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: probe.timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         policy.Listener.ServerName, MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
		},
	}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(policy.Listener.Port)))
	if err != nil {
		return err
	}
	defer connection.Close()
	state := connection.(*tls.Conn).ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
		return errors.New("HTTP/3 TCP health probe negotiated an unexpected protocol")
	}
	return nil
}

func (probe daemonHTTP3HealthProbe) HTTP3(ctx context.Context, policy http3runtime.Policy) error {
	target := url.URL{
		Scheme: "https", Host: net.JoinHostPort(http3ProbeAddress(policy.Listener.Address), strconv.Itoa(policy.Listener.Port)),
		Path: "/healthz",
	}
	probeCtx, cancel := context.WithTimeout(ctx, probe.timeout)
	defer cancel()
	var last error
	for attempt := 1; attempt <= http3HealthProbeAttempts; attempt++ {
		output, err := probe.runHTTP3(probeCtx,
			"request", "--url", target.String(), "--server-name", policy.Listener.ServerName,
			"--timeout", probe.timeout.String(),
		)
		if err == nil {
			var evidence struct {
				Protocol      string `json:"protocol"`
				Status        int    `json:"status"`
				VersionHeader string `json:"version_header"`
				TLSVersion    string `json:"tls_version"`
			}
			if json.Unmarshal(output, &evidence) == nil && evidence.Protocol == "HTTP/3.0" &&
				evidence.Status == 200 && evidence.VersionHeader == policy.VersionID && evidence.TLSVersion == "TLSv1.3" {
				return nil
			}
			last = errors.New("HTTP/3 health probe returned invalid evidence")
		} else {
			last = errors.New("HTTP/3 health probe connection failed")
		}
		if attempt == http3HealthProbeAttempts {
			break
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-probeCtx.Done():
			timer.Stop()
			return fmt.Errorf("HTTP/3 health probe interrupted after %d fresh connection attempts: %w", attempt, probeCtx.Err())
		case <-timer.C:
		}
	}
	return fmt.Errorf("HTTP/3 health probe failed after %d fresh connection attempts: %w", http3HealthProbeAttempts, last)
}

func (probe daemonHTTP3HealthProbe) runHTTP3(ctx context.Context, arguments ...string) ([]byte, error) {
	if probe.run != nil {
		return probe.run(ctx, probe.clientBinary, arguments...)
	}
	return exec.CommandContext(ctx, probe.clientBinary, arguments...).Output()
}

func http3ProbeAddress(address string) string {
	switch address {
	case "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	default:
		return address
	}
}
