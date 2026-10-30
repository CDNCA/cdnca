package site

import (
	"os"
	"strings"
	"testing"
)

func TestSITE03IPv6RuntimeStateTransitions(t *testing.T) {
	if got := initialIPv6RuntimeState(false); got != IPv6RuntimeDisabled {
		t.Fatalf("initial disabled runtime = %q, want %q", got, IPv6RuntimeDisabled)
	}
	if got := initialIPv6RuntimeState(true); got != IPv6RuntimePending {
		t.Fatalf("initial enabled runtime = %q, want %q", got, IPv6RuntimePending)
	}
	for _, state := range []IPv6RuntimeState{
		IPv6RuntimeDisabled, IPv6RuntimePending, IPv6RuntimeActive, IPv6RuntimeFailed,
	} {
		if got := nextIPv6RuntimeState(true, state, true); got != state {
			t.Fatalf("unchanged desired state changed runtime %q to %q", state, got)
		}
	}
	if got := nextIPv6RuntimeState(false, IPv6RuntimeDisabled, true); got != IPv6RuntimePending {
		t.Fatalf("enable transition runtime = %q, want %q", got, IPv6RuntimePending)
	}
	if got := nextIPv6RuntimeState(true, IPv6RuntimeActive, false); got != IPv6RuntimePending {
		t.Fatalf("disable transition runtime = %q, want %q", got, IPv6RuntimePending)
	}
}

func TestSITE03StorePersistsTypedIPv6DesiredAndRuntimeState(t *testing.T) {
	source, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"ipv6_enabled, ipv6_runtime_state",
		"initialIPv6RuntimeState(request.Fields.IPv6Enabled)",
		"ipv6_runtime_state = CASE WHEN ipv6_enabled = $25 THEN ipv6_runtime_state ELSE 'pending' END",
		"ipv6_enabled = $25",
		"alias + \".ipv6_enabled\"",
		"alias + \".ipv6_runtime_state\"",
		"alias + \".ipv6_runtime_source_revision\"",
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("SITE-03 store contract missing %q", required)
		}
	}
}
