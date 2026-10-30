package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

type l4BridgeRemovalRuntime struct {
	activeConfig string
	activations  int
	stops        int
}

func (*l4BridgeRemovalRuntime) Precheck(context.Context, string) error     { return nil }
func (*l4BridgeRemovalRuntime) Drain(context.Context, time.Duration) error { return nil }
func (*l4BridgeRemovalRuntime) Healthy(context.Context, l4runtime.Config) error {
	return nil
}
func (*l4BridgeRemovalRuntime) HealthyV2(_ context.Context, config l4runtime.ConfigV2) error {
	_, err := l4runtime.CanonicalV2(config)
	return err
}

func (runtime *l4BridgeRemovalRuntime) Activate(_ context.Context, currentPath string) error {
	config, err := os.ReadFile(filepath.Join(currentPath, "nginx.conf"))
	if err != nil {
		return err
	}
	runtime.activeConfig = string(config)
	runtime.activations++
	return nil
}

func (runtime *l4BridgeRemovalRuntime) Stop(context.Context, string) error {
	runtime.activeConfig = ""
	runtime.stops++
	return nil
}

// This is a bridge/manager regression, with OpenResty execution replaced by a
// recorder. Full-release signature verification and real sockets are separate gates.
func TestL4DeploymentBridgeReloadRemovesLastStream(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	runtime := &l4BridgeRemovalRuntime{}
	manager, err := l4runtime.NewManager(filepath.Join(root, "l4"), runtime)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture uses a literal address, so no DNS lookup or health dial occurs.
	dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), daemonL4DNSResolver{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpReloads := 0
	delegate, err := deployment.NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf",
		func(context.Context, string, ...string) error {
			httpReloads++
			return nil
		}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	bridge := &l4DeploymentBridge{delegate: delegate, manager: manager, dns: dns}

	const (
		tenantID = "11111111-1111-4111-8111-111111111111"
		siteID   = "22222222-2222-4222-8222-222222222222"
		streamID = "33333333-3333-4333-8333-333333333333"
	)
	firstPath := filepath.Join(root, "release-with-stream")
	if err := os.Mkdir(firstPath, 0o700); err != nil {
		t.Fatal(err)
	}
	document := l4StreamSetV2Document{
		SchemaVersion: l4StreamSetV2Schema, VersionID: "with-stream", Revision: 1,
		Streams: []l4runtime.StreamRuntimeSpecV2{{
			SchemaVersion: l4runtime.SchemaVersionV2,
			TenantID:      tenantID, StreamID: streamID, Revision: 1,
			Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: 19443},
			Endpoint: l4runtime.EndpointV2{Address: "8.8.8.8", Port: 443},
			Geo: l4runtime.GeoPolicyV2{
				TenantID: tenantID, StreamID: streamID, Revision: 1,
				UnknownRegionAction: l4runtime.GeoActionAllow,
			},
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000,
			MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
		}},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(firstPath, edgeconfig.L4RuntimeV2ArtifactPath), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Reload(ctx, document.VersionID, firstPath); err != nil {
		t.Fatalf("initial Reload: %v", err)
	}
	if err := bridge.Healthy(ctx, document.VersionID); err != nil {
		t.Fatal(err)
	}
	const oldListen = "listen 0.0.0.0:19443"
	if !strings.Contains(runtime.activeConfig, oldListen) || runtime.activations != 1 {
		t.Fatalf("initial L4 listener was not activated: activations=%d config=%s", runtime.activations, runtime.activeConfig)
	}

	// The current compiler omits l4-runtime.v2.json when the last enabled Stream
	// is deleted or disabled. The new complete release is authoritative.
	emptyPath := filepath.Join(root, "release-without-stream")
	if err := os.Mkdir(emptyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Reload(ctx, "without-stream", emptyPath); err != nil {
		t.Fatalf("removal Reload: %v", err)
	}
	if httpReloads != 2 {
		t.Fatalf("HTTP reloads = %d, want 2", httpReloads)
	}
	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(runtime.activeConfig, oldListen) {
		t.Fatalf("successful full-release reload retained deleted L4 listener: active_version=%q activations=%d stops=%d HTTP_reloads=%d",
			status.VersionID, runtime.activations, runtime.stops, httpReloads)
	}
	if err := bridge.Healthy(ctx, "without-stream"); err != nil {
		t.Fatal(err)
	}
	restarted, err := l4runtime.NewManager(filepath.Join(root, "l4"), runtime)
	if err != nil {
		t.Fatal(err)
	}
	afterRestart, err := restarted.Status()
	if err != nil || afterRestart.VersionID != "without-stream" || afterRestart.Digest != status.Digest || strings.Contains(runtime.activeConfig, oldListen) {
		t.Fatalf("removed listener revived after restart: %+v, %v", afterRestart, err)
	}
}
