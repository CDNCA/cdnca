package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestL4BridgeRestoresActualBaselineAfterHTTPFailure(t *testing.T) {
	for _, test := range []struct {
		name                    string
		baseline, healthFailure bool
	}{
		{"reload-with-baseline", true, false}, {"health-with-baseline", true, true},
		{"reload-initial", false, false}, {"health-initial", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), daemonL4DNSResolver{}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.baseline {
				config := l4runtime.ConfigV2{SchemaVersion: l4runtime.SchemaVersionV2, VersionID: "actual-before", Revision: 9,
					Listeners: []l4runtime.ListenerV2{{
						ID: "33333333-3333-4333-8333-333333333333", StreamID: "33333333-3333-4333-8333-333333333333",
						TenantID: "11111111-1111-4111-8111-111111111111", SiteID: "22222222-2222-4222-8222-222222222222", ResourceRevision: 3,
						Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: 19443, Endpoint: l4runtime.EndpointV2{Address: "8.8.8.8", Port: 443},
						ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
					}}}
				if _, err := manager.ApplyV2(ctx, config, dns); err != nil {
					t.Fatal(err)
				}
			}
			before, err := manager.Status()
			if err != nil {
				t.Fatal(err)
			}
			beforeConfig := runtime.activeConfig
			injected := errors.New("injected HTTP failure")
			failHealth := test.healthFailure
			delegate, err := deployment.NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf",
				func(context.Context, string, ...string) error {
					if !test.healthFailure {
						return injected
					}
					return nil
				},
				func(context.Context, string) error {
					if failHealth {
						return injected
					}
					return nil
				})
			if err != nil {
				t.Fatal(err)
			}
			bridge := &l4DeploymentBridge{delegate: delegate, manager: manager, dns: dns}
			release := filepath.Join(root, "release")
			if err := os.Mkdir(release, 0o700); err != nil {
				t.Fatal(err)
			}
			err = bridge.Reload(ctx, "candidate-empty", release)
			if test.healthFailure {
				if err != nil {
					t.Fatal(err)
				}
				err = bridge.Healthy(ctx, "candidate-empty")
			}
			if err == nil {
				t.Fatal("HTTP failure was accepted")
			}
			after, err := manager.Status()
			if err != nil || after != before {
				t.Fatalf("actual baseline changed: before=%+v after=%+v err=%v", before, after, err)
			}
			if runtime.activeConfig != beforeConfig {
				t.Fatal("recorded running configuration differs from restored baseline")
			}
			failHealth = false
			if err := bridge.Healthy(ctx, "candidate-empty"); err == nil {
				t.Fatal("later HTTP success certified reverted L4")
			}
			restarted, err := l4runtime.NewManager(filepath.Join(root, "l4"), runtime)
			if err != nil {
				t.Fatal(err)
			}
			after, err = restarted.Status()
			if err != nil || after != before {
				t.Fatalf("restart changed recovered baseline: %+v, %v", after, err)
			}
		})
	}
}

func TestL4BridgeRejectsMalformedSidecarBeforeRemoval(t *testing.T) {
	for _, document := range []string{`{`, `{"schema_version":"unknown"}`, `{"schema_version":"cdnca.edge.l4-stream-set/v2","version_id":"empty","revision":1,"streams":[]}`} {
		t.Run(document, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, edgeconfig.L4RuntimeV2ArtifactPath), []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			// Nil collaborators make any unintended removal/activation panic.
			bridge := &l4DeploymentBridge{}
			if err := bridge.Reload(context.Background(), "empty", root); !errors.Is(err, l4runtime.ErrInvalidConfig) {
				t.Fatalf("malformed sidecar became an empty release: %v", err)
			}
		})
	}
}

func TestAgentAdvertisesL4LifecycleV2(t *testing.T) {
	capabilities := agentCapabilities("test")
	for _, name := range []agentv1.CapabilityName{agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY} {
		found := false
		for _, capability := range capabilities.Features {
			if capability.Name == name {
				found = capability.ApiVersion >= 2
			}
		}
		if !found {
			t.Fatalf("missing L4 lifecycle v2 capability: %v", name)
		}
	}
}

func TestL4BridgeAcceptsExistingHTTPOnlyHealth(t *testing.T) {
	manager, err := l4runtime.NewDeploymentManager(filepath.Join(t.TempDir(), "l4"), &l4BridgeRemovalRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	delegate, err := deployment.NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf", nil,
		func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	bridge := &l4DeploymentBridge{delegate: delegate, manager: manager}
	if err := bridge.Healthy(context.Background(), "existing-http-only"); err != nil {
		t.Fatalf("upgrading a previously HTTP-only installation changed health: %v", err)
	}
}
