package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/http3runtime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	// http3ProbeVersionSchema is what `h3probe version` prints as its schema.
	http3ProbeVersionSchema   = "cdnca.h3probe/v1"
	http3ProbeSelfTestTimeout = 5 * time.Second
)

// http3RuntimeReadiness says whether the node declares HTTP_3 and, when it
// does not, why (logged locally and reported with every terminal deployment).
type http3RuntimeReadiness struct {
	Ready  bool
	Probe  string
	Reason string
}

// checkHTTP3Readiness says whether the node declares HTTP_3: the OpenResty
// is the HTTP/3 runtime version and the configured h3probe passes its
// self-test.
func checkHTTP3Readiness(config fileConfig) http3RuntimeReadiness {
	if config.OpenResty.Version != http3runtime.RuntimeVersionOpenResty {
		return http3RuntimeReadiness{Reason: fmt.Sprintf("openresty.version %q is not the HTTP/3 runtime version %s",
			config.OpenResty.Version, http3runtime.RuntimeVersionOpenResty)}
	}
	if reason := checkHTTP3Probe(config.OpenResty.HTTP3Probe); reason != "" {
		return http3RuntimeReadiness{Reason: reason}
	}
	return http3RuntimeReadiness{Ready: true, Probe: config.OpenResty.HTTP3Probe}
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
