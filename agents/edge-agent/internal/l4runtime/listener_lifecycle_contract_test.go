package l4runtime

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCompileListenerLifecycleContract(t *testing.T) {
	baseline, err := Compile(validConfig("listener-lifecycle-baseline"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(baseline.CanonicalJSON), `"disabled"`) {
		t.Fatalf("disabled=false changed v1 canonical bytes: %s", baseline.CanonicalJSON)
	}

	config := validConfig("listener-lifecycle-disabled")
	disabled := config.Listeners[0]
	disabled.ID = "udp-disabled-same-bind"
	disabled.Disabled = true
	config.Listeners = append(config.Listeners, disabled)
	compiled, err := Compile(config)
	if err != nil {
		t.Fatalf("disabled listener sharing a bind must compile: %v", err)
	}
	if got := strings.Count(string(compiled.CanonicalJSON), `"disabled":true`); got != 1 {
		t.Fatalf("canonical disabled marker count = %d, want 1: %s", got, compiled.CanonicalJSON)
	}
	if strings.Contains(string(compiled.NginxConfig), "listener id=udp-disabled-same-bind") {
		t.Fatalf("disabled listener was rendered:\n%s", compiled.NginxConfig)
	}

	onlyEnabled := validConfig("listener-lifecycle-pool-filter")
	onlyEnabled.Listeners[0].Disabled = true
	compiled, err = Compile(onlyEnabled)
	if err != nil {
		t.Fatal(err)
	}
	text := string(compiled.NginxConfig)
	if strings.Contains(text, "upstream_pool id=pool-v4") || strings.Contains(text, "listener id=udp-public") {
		t.Fatalf("disabled listener or its unreferenced pool was rendered:\n%s", text)
	}
	if !strings.Contains(text, "upstream_pool id=pool-v6") || !strings.Contains(text, "listener id=tcp-v6") {
		t.Fatalf("enabled listener or its referenced pool was omitted:\n%s", text)
	}

	invalidDisabled := validConfig("listener-lifecycle-invalid-disabled")
	invalidDisabled.Listeners[0].Disabled = true
	invalidDisabled.Listeners[0].UpstreamPoolID = "missing"
	if _, err := Compile(invalidDisabled); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("disabled listener skipped full validation: %v", err)
	}

	terminal := Config{
		SchemaVersion: SchemaVersionV1,
		VersionID:     "listener-lifecycle-terminal",
		Listeners:     []Listener{},
		UpstreamPools: []UpstreamPool{},
	}
	compiled, err = Compile(terminal)
	if err != nil {
		t.Fatalf("paired empty terminal snapshot must compile: %v", err)
	}
	if len(compiled.Config.Listeners) != 0 || len(compiled.Config.UpstreamPools) != 0 {
		t.Fatalf("terminal snapshot normalized with resources: %+v", compiled.Config)
	}
	text = string(compiled.NginxConfig)
	if strings.Contains(text, "\n    upstream ") || strings.Contains(text, "\n    server {") || strings.Contains(text, "listen ") {
		t.Fatalf("terminal snapshot rendered a bind or upstream:\n%s", text)
	}

	listenersWithoutPools := validConfig("listener-lifecycle-missing-pools")
	listenersWithoutPools.UpstreamPools = nil
	if _, err := Compile(listenersWithoutPools); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("listeners without pools error = %v, want ErrInvalidConfig", err)
	}
	poolsWithoutListeners := validConfig("listener-lifecycle-missing-listeners")
	poolsWithoutListeners.Listeners = nil
	if _, err := Compile(poolsWithoutListeners); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("pools without listeners error = %v, want ErrInvalidConfig", err)
	}
}

func TestListenerLifecycleResultContract(t *testing.T) {
	want := []ListenerResult{
		{ID: "create", Operation: ListenerOperationCreate, ReasonCode: ListenerReasonCreated},
		{ID: "edit", Operation: ListenerOperationEdit, ReasonCode: ListenerReasonEdited},
		{ID: "enable", Operation: ListenerOperationEnable, ReasonCode: ListenerReasonEnabled},
		{ID: "disable", Operation: ListenerOperationDisable, ReasonCode: ListenerReasonDisabled},
		{ID: "delete", Operation: ListenerOperationDelete, ReasonCode: ListenerReasonDeleted},
		{ID: "failed", Operation: ListenerOperationEdit, ReasonCode: ListenerReasonApplyAborted},
	}
	result := Result{ListenerResults: want}
	if len(result.ListenerResults) != len(want) {
		t.Fatalf("listener result count = %d, want %d", len(result.ListenerResults), len(want))
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	const expected = `[{"id":"create","operation":"create","reason_code":"LISTENER_CREATED"},{"id":"edit","operation":"edit","reason_code":"LISTENER_EDITED"},{"id":"enable","operation":"enable","reason_code":"LISTENER_ENABLED"},{"id":"disable","operation":"disable","reason_code":"LISTENER_DISABLED"},{"id":"delete","operation":"delete","reason_code":"LISTENER_DELETED"},{"id":"failed","operation":"edit","reason_code":"LISTENER_APPLY_ABORTED"}]`
	if string(encoded) != expected {
		t.Fatalf("listener result JSON = %s, want %s", encoded, expected)
	}
}
