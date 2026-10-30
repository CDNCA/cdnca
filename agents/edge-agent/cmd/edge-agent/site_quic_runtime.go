package main

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// http3ModulePattern finds nginx's HTTP/3 (QUIC) module in `openresty -V`
// configure arguments.
var http3ModulePattern = regexp.MustCompile(`(?:^|\s)--with-http_v3_module(?:\s|$)`)

// openRestyServesSiteQUIC reports whether the OpenResty binary was built with
// the HTTP/3 module, i.e. whether a site runtime v2 HTTPS listener can also
// listen on QUIC (listen ... quic; http3 on). The agent declares SITE_QUIC
// only then; h3probe, which only the standalone HTTP/3 runtime needs, plays
// no part.
func openRestyServesSiteQUIC(ctx context.Context, binary string) bool {
	if binary == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// nginx prints -V to stderr.
	output, err := exec.CommandContext(ctx, binary, "-V").CombinedOutput()
	if err != nil || len(output) > 1<<20 {
		return false
	}
	for _, line := range bytes.Split(output, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("configure arguments:")) && http3ModulePattern.Match(line) {
			return true
		}
	}
	return false
}

// addHTTPProtocolCapabilities declares SITE_QUIC (site runtime v2 HTTPS
// listeners on QUIC) and HTTP_3 (the standalone HTTP/3 runtime with a working
// h3probe) independently.
func addHTTPProtocolCapabilities(capabilities *agentv1.AgentCapabilities, siteQUIC, http3Runtime bool) {
	if siteQUIC {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC, ApiVersion: 1,
		})
	}
	if http3Runtime {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_3, ApiVersion: 1,
		})
	}
}
