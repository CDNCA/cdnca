package main

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"time"
)

// ja4ModulePattern finds the native JA4 module in `openresty -V` configure
// arguments (edge/openresty/native/Dockerfile:
// --add-module=/tmp/openresty-source/bundle/cdnca-ja4).
var ja4ModulePattern = regexp.MustCompile(`(?:^|\s)--add-(?:dynamic-)?module=\S*/cdnca-ja4(?:\s|$)`)

// openRestyComputesJA4 reports whether the OpenResty binary was built with
// ngx_http_cdnca_ja4_module, i.e. whether $cdnca_ja4 holds the JA4 TLS
// fingerprint. The agent declares CAPABILITY_NAME_JA4 v1 only then, so a
// release with JA4 WAF rules never reaches a runtime where the rule would
// silently never match.
func openRestyComputesJA4(ctx context.Context, binary string) bool {
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
		if bytes.HasPrefix(line, []byte("configure arguments:")) && ja4ModulePattern.Match(line) {
			return true
		}
	}
	return false
}
