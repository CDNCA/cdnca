package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
)

// E1 (PJ-E03/E04): the node DDoS protection state reaches the
// deployment checks and the node telemetry.

type fixedDDoSStatus struct {
	status dynroute.DDoSStatus
	ok     bool
}

func (f fixedDDoSStatus) DDoSStatus() (dynroute.DDoSStatus, bool) { return f.status, f.ok }

func TestDDoSUnavailableReasonNamesWhyTheTableIsMissing(t *testing.T) {
	missing := func(string) (string, error) { return "", exec.ErrNotFound }
	present := func(string) (string, error) { return "/usr/sbin/nft", nil }
	for name, test := range map[string]struct {
		goos       string
		ready      bool
		find       func(string) (string, error)
		managerErr error
		want       string
	}{
		"darwin":          {goos: "darwin", ready: false, find: missing, want: ddosUnsupportedOS},
		"no nft":          {goos: "linux", ready: false, find: missing, want: ddosNFTMissing},
		"nft probe fails": {goos: "linux", ready: false, find: present, want: ddosNFTUnusable},
		"manager fails":   {goos: "linux", ready: true, find: present, managerErr: errors.New("nft -f: Operation not permitted"), want: ddosInitFailed},
		"ready":           {goos: "linux", ready: true, find: present, want: ""},
	} {
		reason, detail := ddosUnavailableReason(test.goos, test.ready, test.find, test.managerErr)
		if reason != test.want || (reason == "") != (detail == "") {
			t.Errorf("%s: %q %q", name, reason, detail)
		}
	}
}

func TestDDoSProtectionChecksReportFailureAndUnavailability(t *testing.T) {
	unavailable := ddosProtectionState(ddosNFTMissing, "nft command not found: install nftables", nil)
	if state := unavailable(context.Background()); state.State != "unavailable" || state.Reason != ddosNFTMissing {
		t.Fatalf("state %+v", state)
	}
	check := ddosProtectionChecks(unavailable)()[0]
	if check.Name != ddosProtectionCheckName || check.Succeeded || !strings.Contains(check.Summary, ddosNFTMissing) {
		t.Fatalf("check %+v", check)
	}

	failed := ddosProtectionState("", "", fixedDDoSStatus{ok: true,
		status: dynroute.DDoSStatus{State: dynroute.DDoSFailed, Detail: "nft: Error: syntax error\nline 3"}})
	state := failed(context.Background())
	if state.State != "failed" || state.Reason != "" || strings.ContainsAny(state.Detail, "\n\r") || state.Detail == "" {
		t.Fatalf("state %+v", state)
	}
	if check := ddosProtectionChecks(failed)()[0]; check.Succeeded || !strings.Contains(check.Summary, "not applied") {
		t.Fatalf("check %+v", check)
	}

	for _, value := range []string{dynroute.DDoSApplied, dynroute.DDoSOff} {
		source := ddosProtectionState("", "", fixedDDoSStatus{ok: true, status: dynroute.DDoSStatus{State: value}})
		if check := ddosProtectionChecks(source)()[0]; !check.Succeeded || source(context.Background()).Detail != "" {
			t.Fatalf("%s: check %+v", value, check)
		}
	}
	pending := ddosProtectionState("", "", fixedDDoSStatus{})
	if state := pending(context.Background()); state.State != "pending" {
		t.Fatalf("state %+v", state)
	}
	if long := sanitizeDDoSDetail(strings.Repeat("x", 400)); len(long) > 256 {
		t.Fatalf("detail %d bytes", len(long))
	}
}
