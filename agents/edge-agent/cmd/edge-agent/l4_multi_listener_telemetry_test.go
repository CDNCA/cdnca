package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func multiListenerTelemetryDocument() l4StreamSetV2Document {
	streamID := "55555555-5555-4555-8555-555555555555"
	return l4StreamSetV2Document{SchemaVersion: l4StreamSetV2Schema, VersionID: "88888888-8888-4888-8888-888888888888", Revision: 9,
		Streams: []l4runtime.StreamRuntimeSpecV2{{SchemaVersion: l4runtime.SchemaVersionV2,
			TenantID: telemetryTestTenantID, StreamID: streamID, Revision: 3,
			Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "*", Port: 18080},
			AdditionalListeners: []l4runtime.AdditionalListenerV2{
				{ID: "66666666-6666-4666-8666-666666666666", Protocol: l4runtime.ProtocolTCP, Address: "*", Port: 18081},
				{ID: "77777777-7777-4777-8777-777777777777", Protocol: l4runtime.ProtocolUDP, Address: "*", Port: 18082},
			},
			Endpoint:         l4runtime.EndpointV2{Address: "127.0.0.1", Port: 19000},
			Geo:              l4runtime.GeoPolicyV2{TenantID: telemetryTestTenantID, StreamID: streamID, Revision: 3, UnknownRegionAction: l4runtime.GeoActionAllow},
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 10, DrainTimeoutMS: 30000,
		}}}
}

func TestAdditionalListenersTelemetryPrecheckAndRegistrationWithoutHTTP(t *testing.T) {
	root := telemetrySecureRoot(t)
	document := multiListenerTelemetryDocument()
	releaseName := strings.Repeat("a", 64)
	release := filepath.Join(root, "releases", releaseName)
	if err := os.MkdirAll(release, 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, edgeconfig.L4RuntimeV2ArtifactPath), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", releaseName), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	called := false
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error { called = true; return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), "wrong-version", release); err == nil || called {
		t.Fatal("L4-only telemetry accepted a mismatched release")
	}
	if err := prechecker.Precheck(context.Background(), document.VersionID, release); err != nil || !called {
		t.Fatalf("prepare L4-only telemetry: %v", err)
	}
	sources, err := l4TelemetryRegistrations(root, telemetryTestNodeID, document)
	if err != nil || len(sources) != 3 {
		t.Fatalf("sources=%+v error=%v", sources, err)
	}
	spoolRoot := telemetrySecureRoot(t)
	spool, err := eventspool.New(eventspool.Config{Root: spoolRoot, MaxEventBytes: 64 << 10, MaxSegmentBytes: 1 << 20,
		SoftLimitBytes: 8 << 20, HardLimitBytes: 16 << 20, MaxTenantBytes: 12 << 20, MaxBatchEvents: 100,
		PressureMode: eventspool.PressureBackpressure, SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := newTelemetrySourceRunner(telemetrySourceConfig{DeploymentRoot: root, SpoolRoot: spoolRoot,
		EnrollmentNodeID: telemetryTestNodeID, PollInterval: time.Second, MaxLineBytes: 4096, MaxBatchEvents: 10, MaxQuarantineBytes: 64 << 10}, spool)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.observeActive(); err != nil {
		t.Fatal(err)
	}
	if len(runner.sources) != 3 {
		t.Fatalf("extra or L4-only sources not registered: %+v", runner.sources)
	}
	seen := make(map[string]bool)
	for index, source := range sources {
		info, err := os.Stat(source.SourcePath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("socket log not prepared privately: %s %v", source.SourcePath, err)
		}
		if seen[source.Identity.ListenerID] || source.Identity.StreamID != document.Streams[0].StreamID || source.Identity.ConfigRevision != 9 {
			t.Fatalf("listener identity collapsed: %+v", source.Identity)
		}
		seen[source.Identity.ListenerID] = true
		if _, ok := runner.sources[source.SourcePath]; !ok {
			t.Fatalf("source missing: %s", source.SourcePath)
		}
		protocol := "TCP"
		if index == 2 {
			protocol = "UDP"
		}
		line := []byte(fmt.Sprintf(`{"time":"2026-08-08T12:00:05Z","connection":"42","protocol":%q,"server_port":"%d","status":"200","bytes_sent":1200,"bytes_received":300,"session_time":5.25}`, protocol, 18080+index))
		event, err := eventspool.ParseL4SourceLineBound(line, source.Identity)
		if err != nil || event.ListenerID != source.Identity.ListenerID || event.StreamID != document.Streams[0].StreamID || event.ListenPort != uint16(18080+index) {
			t.Fatalf("wrong stream/socket event attribution: %+v %v", event, err)
		}
	}
}

func TestAdditionalListenersOldDecoderRejectsExtensionAndCapabilityCoversThem(t *testing.T) {
	// The old decoder has every historical field but no extension. It must fail
	// instead of activating only the primary socket if capability gating is bypassed.
	typeOf := reflect.TypeOf(l4runtime.StreamRuntimeSpecV2{})
	var fields []reflect.StructField
	for i := 0; i < typeOf.NumField(); i++ {
		field := typeOf.Field(i)
		if field.Name != "AdditionalListeners" {
			fields = append(fields, field)
		}
	}
	legacy := reflect.New(reflect.StructOf(fields)).Interface()
	stream := multiListenerTelemetryDocument().Streams[0]
	content, _ := json.Marshal(stream)
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(legacy); err == nil || !strings.Contains(err.Error(), "additional_listeners") {
		t.Fatalf("old decoder silently accepted extension: %v", err)
	}
	stream.AdditionalListeners = nil
	content, _ = json.Marshal(stream)
	decoder = json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(legacy); err != nil {
		t.Fatalf("old resource no longer compatible: %v", err)
	}
	capabilities := agentCapabilities("test")
	for _, name := range []agentv1.CapabilityName{agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY} {
		found := false
		for _, capability := range capabilities.Features {
			// v3 brought additional listeners; v4 (TLS passthrough, shared
			// ports), v5 (drain_max_ms), v6 (new_conn_rate), v7
			// (session_log), v8 (toa), v9 (port_end, follow_port), v10
			// (guard_rules), v11 (origins, ip_hash, listen_ipv6) and v12 (no
			// website) include them.
			if capability.Name == name && capability.ApiVersion == 12 {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing multi-listener capability3: %v", name)
		}
	}
}

// A composed runtime serves several scopes' streams under one composed version;
// each stream's telemetry stays attributed to its own scope's release.
func TestComposedL4TelemetryUsesEachStreamsOwnVersion(t *testing.T) {
	root := telemetrySecureRoot(t)
	document := multiListenerTelemetryDocument()
	document.VersionID = "composed-0123456789abcdef01234567"
	document.Streams[0].ConfigVersionID, document.Streams[0].ConfigRevision = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", 41
	sources, err := l4TelemetryRegistrations(root, telemetryTestNodeID, document)
	if err != nil || len(sources) != 3 {
		t.Fatalf("sources=%+v error=%v", sources, err)
	}
	for _, source := range sources {
		if source.Identity.ConfigVersionID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1" || source.Identity.ConfigRevision != 41 ||
			!strings.Contains(source.SourcePath, "/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1/") {
			t.Fatalf("composed stream attributed to %+v at %s", source.Identity, source.SourcePath)
		}
	}

	// The runner reads the composed release, not deployment_root/current.
	composedRoot := filepath.Join(filepath.Dir(root), "site-runtime")
	release := filepath.Join(composedRoot, "composed-releases", strings.Repeat("b", 64))
	if err := os.MkdirAll(release, 0o700); err != nil {
		t.Fatal(err)
	}
	content, _ := json.Marshal(document)
	if err := os.WriteFile(filepath.Join(release, edgeconfig.L4RuntimeV2ArtifactPath), content, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("composed-releases", strings.Repeat("b", 64)), filepath.Join(composedRoot, "composed-current")); err != nil {
		t.Fatal(err)
	}
	prechecker, err := newTelemetryPrechecker(root, precheckFunc(func(context.Context, string, string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	if err := prechecker.Precheck(context.Background(), document.VersionID, release); err != nil {
		t.Fatalf("prepare composed L4 telemetry: %v", err)
	}
	spoolRoot := telemetrySecureRoot(t)
	spool, err := eventspool.New(eventspool.Config{Root: spoolRoot, MaxEventBytes: 64 << 10, MaxSegmentBytes: 1 << 20,
		SoftLimitBytes: 8 << 20, HardLimitBytes: 16 << 20, MaxTenantBytes: 12 << 20, MaxBatchEvents: 100,
		PressureMode: eventspool.PressureBackpressure, SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := newTelemetrySourceRunner(telemetrySourceConfig{DeploymentRoot: root, SpoolRoot: spoolRoot,
		ComposedCurrent:  filepath.Join(composedRoot, "composed-current"),
		EnrollmentNodeID: telemetryTestNodeID, PollInterval: time.Second, MaxLineBytes: 4096, MaxBatchEvents: 10, MaxQuarantineBytes: 64 << 10}, spool)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.observeActive(); err != nil {
		t.Fatal(err)
	}
	if len(runner.sources) != 3 {
		t.Fatalf("composed L4 sources not registered: %+v", runner.sources)
	}
	for _, source := range sources {
		if registered, ok := runner.sources[source.SourcePath]; !ok || registered.Identity.ConfigVersionID != source.Identity.ConfigVersionID {
			t.Fatalf("source %s missing or misattributed: %+v", source.SourcePath, registered)
		}
	}
}
