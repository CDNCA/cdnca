package nodemonitoringconfig

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

func overrideDocument(revision int64) systemconfig.CategoryDocument {
	return systemconfig.CategoryDocument{
		Category: systemconfig.CategoryNodeMonitoring, HeadRevision: revision, ActiveRevision: revision, Revision: revision,
		Value: systemconfig.NodeMonitoringConfiguration{
			PortMode: "default", ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000,
			FailureThreshold: 3, RecoveryThreshold: 3, RecoveryNotificationEnabled: true,
		},
	}
}

func TestCompileNodeDocumentWithoutOverrideIsByteIdenticalToPlatformArtifact(t *testing.T) {
	document := overrideDocument(7)
	platform, err := CompileCategoryDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	node, revision, err := CompileNodeDocument(document, Override{})
	if err != nil || revision != 7 || string(node) != string(platform) {
		t.Fatalf("CompileNodeDocument() = %s, %d, %v; want %s, 7", node, revision, err, platform)
	}
}

func TestCompileNodeDocumentOverlaysOverrideAndAdvancesRevision(t *testing.T) {
	enabled, timeout, port := false, 5_000, uint16(8080)
	payload, revision, err := CompileNodeDocument(overrideDocument(7), Override{
		Revision: 3, MonitorEnabled: &enabled, Protocol: "http", ProbeTimeoutMS: &timeout, MonitorPort: &port,
	})
	if err != nil || revision != 10 {
		t.Fatalf("CompileNodeDocument() revision = %d, err = %v", revision, err)
	}
	var artifact Artifact
	if err := json.Unmarshal(payload, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.ConfigRevision != 10 || artifact.MonitorEnabled == nil || *artifact.MonitorEnabled ||
		artifact.Protocol != "http" || artifact.ProbeTimeoutMS != 5_000 || artifact.MonitorPort == nil ||
		*artifact.MonitorPort != 8080 || artifact.ProbeIntervalMS != 10_000 || artifact.PortMode != "default" {
		t.Fatalf("artifact = %#v", artifact)
	}
}

func TestCompileNodeDocumentClampsTimeoutToPlatformInterval(t *testing.T) {
	timeout := 60_000
	payload, _, err := CompileNodeDocument(overrideDocument(2), Override{Revision: 1, ProbeTimeoutMS: &timeout})
	if err != nil {
		t.Fatal(err)
	}
	var artifact Artifact
	if err := json.Unmarshal(payload, &artifact); err != nil || artifact.ProbeTimeoutMS != 10_000 {
		t.Fatalf("timeout must not exceed the platform interval: %#v %v", artifact, err)
	}
}

func TestCompileNodeDocumentRejectsInvalidOverride(t *testing.T) {
	low, zero := 99, uint16(0)
	for name, override := range map[string]Override{
		"protocol":         {Revision: 1, Protocol: "udp"},
		"timeout":          {Revision: 1, ProbeTimeoutMS: &low},
		"port":             {Revision: 1, MonitorPort: &zero},
		"action":           {Revision: 1, MonitorAction: "stop"},
		"missing revision": {Protocol: "tcp"},
		"revision bound":   {Revision: MaxOverrideRevision + 1},
	} {
		if _, _, err := CompileNodeDocument(overrideDocument(2), override); !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestEffectiveRevisionIsStrictlyIncreasingAcrossPlatformAndOverrideChanges(t *testing.T) {
	// Both inputs only ever advance; every change advances at least one, so
	// the sum observed by the Agent never repeats or decreases.
	steps := [][2]int64{{1, 0}, {1, 1}, {2, 1}, {2, 2}, {5, 2}, {5, 3}}
	previous := int64(0)
	for _, step := range steps {
		next := EffectiveRevision(step[0], step[1])
		if next <= previous {
			t.Fatalf("effective revision %d after %d for %v", next, previous, step)
		}
		previous = next
	}
}

func TestApplyOverrideToPolicyMatchesCompiledOverlay(t *testing.T) {
	enabled, timeout, port, custom := false, 20_000, uint16(8443), uint16(81)
	base := overrideDocument(3).Value.(systemconfig.NodeMonitoringConfiguration)
	base.PortMode, base.CustomPort = "custom", &custom
	for _, override := range []Override{{}, {Revision: 1, MonitorEnabled: &enabled}, {Revision: 2, Protocol: "ping", ProbeTimeoutMS: &timeout},
		{Revision: 3, MonitorPort: &port}} {
		want := systemconfig.MonitoringPolicyFor(ApplyOverride(base, override))
		got := ApplyOverrideToPolicy(systemconfig.MonitoringPolicyFor(base), override)
		if got.Enabled != want.Enabled || got.RequestedProtocol != want.RequestedProtocol || got.ProbeTimeoutMS != want.ProbeTimeoutMS ||
			(got.RequestedPort == nil) != (want.RequestedPort == nil) || got.RequestedPort != nil && *got.RequestedPort != *want.RequestedPort {
			t.Fatalf("override %#v: policy %#v, compiled %#v", override, got, want)
		}
	}
}
