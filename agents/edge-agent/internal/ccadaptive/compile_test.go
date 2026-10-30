package ccadaptive

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestCompileJSONSimpleAndExpertModes(t *testing.T) {
	simple := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 100, Burst: 20}}
	canonical, compiled, err := CompileJSON(mustJSON(t, simple))
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Adaptive != nil || canonical[len(canonical)-1] != '\n' {
		t.Fatalf("simple compile = %s %+v", canonical, compiled)
	}

	expert := simple
	expert.Revision = 2
	expert.Mode = ModeExpert
	adaptive := testAdaptiveConfig()
	expert.Adaptive = &adaptive
	if _, _, err := CompileJSON(mustJSON(t, expert)); err != nil {
		t.Fatal(err)
	}
}

func TestCompileJSONRejectsAmbiguousOrUnsafePolicy(t *testing.T) {
	valid := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeSimple, Static: Limit{RatePerSecond: 1, Burst: 1}}
	for _, raw := range [][]byte{
		{},
		[]byte(`{"schema_version":"cdnca.edge.cc-adaptive/v1","schema_version":"cdnca.edge.cc-adaptive/v1"}`),
		append(mustJSON(t, valid), []byte(`{}`)...),
		[]byte(`{"schema_version":"cdnca.edge.cc-adaptive/v1","revision":1,"enabled":true,"mode":"simple","static":{"rate_per_second":1,"burst":1},"unknown":true}`),
	} {
		if _, _, err := CompileJSON(raw); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("CompileJSON(%q) error = %v", raw, err)
		}
	}
}

func TestCompileJSONRejectsLuaInexactAdaptiveIntegers(t *testing.T) {
	base := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeExpert, Static: Limit{RatePerSecond: 1, Burst: 1}}
	for _, mutate := range []func(*AdaptiveConfig){
		func(config *AdaptiveConfig) { config.SampleFreshnessMicros = MaxTimestampMicros + 1 },
		func(config *AdaptiveConfig) { config.CooldownMicros = MaxTimestampMicros + 1 },
	} {
		adaptive := testAdaptiveConfig()
		mutate(&adaptive)
		candidate := base
		candidate.Adaptive = &adaptive
		if _, _, err := CompileJSON(mustJSON(t, candidate)); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("Lua-inexact adaptive integer accepted: %+v error=%v", adaptive, err)
		}
	}
}

func TestCompileJSONRejectsUnknownAdaptiveFallback(t *testing.T) {
	adaptive := testAdaptiveConfig()
	adaptive.Fallback = "allow"
	policy := Policy{SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeExpert,
		Static: Limit{RatePerSecond: 10, Burst: 10}, Adaptive: &adaptive}
	if _, _, err := CompileJSON(mustJSON(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unsafe fallback error = %v", err)
	}
}

func TestCompileJSONAcceptsMaximumExactAdaptiveIntegers(t *testing.T) {
	adaptive := testAdaptiveConfig()
	adaptive.SampleFreshnessMicros = MaxTimestampMicros
	adaptive.CooldownMicros = MaxTimestampMicros
	policy := Policy{
		SchemaVersion: SchemaVersion, Revision: 1, Enabled: true, Mode: ModeExpert,
		Static: Limit{RatePerSecond: 1, Burst: 1}, Adaptive: &adaptive,
	}
	if _, _, err := CompileJSON(mustJSON(t, policy)); err != nil {
		t.Fatalf("maximum exact adaptive integers rejected: %v", err)
	}
}

func TestDisabledEnhancementPreservesBaselineBytes(t *testing.T) {
	baseline := []byte("{\n  \"algorithm\": \"fixed_window\", \"opaque\": true\n}\n")
	if got := PreserveDisabledBaseline(baseline); !bytes.Equal(got, baseline) {
		t.Fatalf("disabled baseline changed: %q", got)
	}
	got := PreserveDisabledBaseline(baseline)
	got[0] = 'x'
	if baseline[0] != '{' {
		t.Fatal("returned bytes alias baseline")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
