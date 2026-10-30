package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestL4DeploymentStartupRecoversInterruptedReleaseWithoutGateway(t *testing.T) {
	for _, test := range []struct {
		cut, recoveryCut string
		initial          bool
		rollback         bool
	}{
		{cut: "before-http"}, {cut: "after-http"}, {cut: "before-health"},
		{cut: "after-health"},
		{cut: "before-http", initial: true}, {cut: "after-http", initial: true}, {cut: "before-health", initial: true},
		{cut: "before-health", recoveryCut: "after-http"}, {cut: "after-http", recoveryCut: "before-health"},
		{cut: "after-http", recoveryCut: "http-failure"}, {cut: "before-health", recoveryCut: "http-failure", initial: true},
		{cut: "before-http", rollback: true}, {cut: "after-http", rollback: true}, {cut: "after-health", rollback: true},
	} {
		t.Run(fmt.Sprintf("%s/initial=%v/rollback=%v/recovery=%s", test.cut, test.initial, test.rollback, test.recoveryCut), func(t *testing.T) {
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
			l4 := &l4BridgeRemovalRuntime{}
			l4Manager, err := l4runtime.NewDeploymentManager(filepath.Join(root, "l4"), l4)
			if err != nil {
				t.Fatal(err)
			}
			dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), daemonL4DNSResolver{}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var httpVersion, interrupt string
			delegate, err := deployment.NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf",
				func(_ context.Context, _ string, args ...string) error {
					if args[0] == "-t" {
						return nil
					}
					if interrupt == "before-http" {
						panic(interrupt)
					}
					if interrupt == "http-failure" {
						return errors.New("injected recovery HTTP failure")
					}
					for i := range args {
						if args[i] == "-p" {
							content, err := os.ReadFile(filepath.Join(args[i+1], "nginx.conf"))
							if err != nil {
								return err
							}
							httpVersion = string(content)
						}
					}
					if interrupt == "after-http" {
						panic(interrupt)
					}
					return nil
				}, func(_ context.Context, versionID string) error {
					if interrupt == "before-health" {
						panic(interrupt)
					}
					if httpVersion != versionID {
						return fmt.Errorf("HTTP identity mismatch: %s != %s", httpVersion, versionID)
					}
					return nil
				})
			if err != nil {
				t.Fatal(err)
			}
			bridge := &l4DeploymentBridge{delegate: delegate, manager: l4Manager, dns: dns}
			outerRuntime := l4BridgeInterruptedHealthRuntime{bridge: bridge, interrupt: &interrupt}
			config := deployment.DefaultConfig()
			config.HealthTimeout, config.HealthInterval = 20*time.Millisecond, time.Millisecond
			manager, err := deployment.NewManagerWithConfig(filepath.Join(root, "http"), bridge, outerRuntime, config)
			if err != nil {
				t.Fatal(err)
			}
			previous := ""
			if !test.initial {
				baseline := l4BridgeDeploymentCommand(t, "baseline", "", true)
				if result, err := manager.Process(ctx, baseline); err != nil || result.State != deployment.StateHealthy {
					t.Fatalf("baseline: %+v %v", result, err)
				}
				previous = "baseline"
			}
			if test.rollback {
				current := l4BridgeDeploymentCommand(t, "current", previous, false)
				if result, err := manager.Process(ctx, current); err != nil || result.State != deployment.StateHealthy {
					t.Fatalf("current: %+v %v", result, err)
				}
				previous = "current"
			}
			before, err := l4Manager.Status()
			if err != nil {
				t.Fatal(err)
			}
			candidate := l4BridgeDeploymentCommand(t, "candidate", previous, test.initial)
			if test.rollback {
				candidate = deployment.Command{DeploymentID: "rollback", Attempt: 1, Action: deployment.ActionRollback, ConfigVersionID: "baseline", PreviousVersionID: previous}
			}
			interrupt = test.cut
			func() {
				defer func() {
					if got := recover(); got != test.cut {
						t.Fatalf("interruption = %v, want %s", got, test.cut)
					}
				}()
				_, _ = manager.Process(ctx, candidate)
			}()
			interrupt = ""
			activeBeforeConstruction := l4.activeConfig
			l4Manager, err = l4runtime.NewDeploymentManager(filepath.Join(root, "l4"), l4)
			if err != nil {
				t.Fatal(err)
			}
			if l4.activeConfig != activeBeforeConstruction {
				t.Fatal("L4 construction independently changed runtime")
			}
			bridge.manager = l4Manager
			manager, err = deployment.NewManagerWithConfig(filepath.Join(root, "http"), bridge, outerRuntime, config)
			if err != nil {
				t.Fatal(err)
			}
			if test.recoveryCut != "" {
				interrupt = test.recoveryCut
				if interrupt == "http-failure" {
					if err := manager.Recover(ctx); err == nil {
						t.Fatal("failed recovery returned success")
					}
				} else {
					func() {
						defer func() {
							if got := recover(); got != test.recoveryCut {
								t.Fatalf("recovery interruption = %v, want %s", got, test.recoveryCut)
							}
						}()
						_ = manager.Recover(ctx)
					}()
				}
				interrupt = ""
				l4Manager, err = l4runtime.NewDeploymentManager(filepath.Join(root, "l4"), l4)
				if err != nil {
					t.Fatal(err)
				}
				bridge.manager = l4Manager
				manager, err = deployment.NewManagerWithConfig(filepath.Join(root, "http"), bridge, outerRuntime, config)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := manager.Recover(ctx); err != nil {
				t.Fatal(err)
			}
			after, err := l4Manager.Status()
			if err != nil {
				t.Fatal(err)
			}
			pointers, err := manager.Pointers()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("offline restart: HTTP_running=%s HTTP_pointer=%s L4=%s digest_restored=%v", httpVersion, pointers.Current, after.VersionID, after.Digest == before.Digest)
			if httpVersion != after.VersionID || pointers.Current != after.VersionID {
				t.Errorf("offline startup left mixed HTTP/L4 versions: running=%s pointer=%s L4=%s", httpVersion, pointers.Current, after.VersionID)
			}
			if !test.initial && after.Digest != before.Digest {
				t.Fatal("recovery changed actual baseline digest")
			}
			activations := l4.activations
			if err := manager.Recover(ctx); err != nil || l4.activations != activations {
				t.Fatalf("duplicate offline recovery changed runtime: %v", err)
			}
			result, err := manager.Process(ctx, candidate)
			after, statusErr := l4Manager.Status()
			pointers, pointerErr := manager.Pointers()
			t.Logf("after Gateway replay: result=%s HTTP_running=%s HTTP_pointer=%s L4=%s err=%v", result.State, httpVersion, pointers.Current, after.VersionID, err)
			if err != nil || statusErr != nil || pointerErr != nil || httpVersion != after.VersionID || pointers.Current != after.VersionID {
				t.Fatalf("replay did not converge: result=%+v status=%+v pointers=%+v errors=%v/%v/%v", result, after, pointers, err, statusErr, pointerErr)
			}
		})
	}
}

type l4BridgeInterruptedHealthRuntime struct {
	bridge    *l4DeploymentBridge
	interrupt *string
}

type l4BridgeRejectedPrecheckRuntime struct {
	l4BridgeRemovalRuntime
	reject bool
}

func (runtime *l4BridgeRejectedPrecheckRuntime) Precheck(context.Context, string) error {
	if runtime.reject {
		return errors.New("injected L4 precheck failure")
	}
	return nil
}

func TestL4FailedInitialDeploymentCannotBecomeHealthyByReplay(t *testing.T) {
	for _, precheckFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("precheck=%v", precheckFailure), func(t *testing.T) {
			root := t.TempDir()
			t.Cleanup(func() {
				_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
					if err == nil && info.IsDir() {
						_ = os.Chmod(path, 0o700)
					}
					return nil
				})
			})
			runtime := &l4BridgeRejectedPrecheckRuntime{reject: precheckFailure}
			l4, err := l4runtime.NewDeploymentManager(filepath.Join(root, "l4"), runtime)
			if err != nil {
				t.Fatal(err)
			}
			dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), daemonL4DNSResolver{}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			healthCalls := 0
			delegate, err := deployment.NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf",
				func(_ context.Context, _ string, args ...string) error {
					if args[0] == "-t" {
						return nil
					}
					return errors.New("injected HTTP reload failure")
				}, func(context.Context, string) error { healthCalls++; return nil })
			if err != nil {
				t.Fatal(err)
			}
			bridge := &l4DeploymentBridge{delegate: delegate, manager: l4, dns: dns}
			manager, err := deployment.NewManager(filepath.Join(root, "http"), bridge, bridge)
			if err != nil {
				t.Fatal(err)
			}
			command := l4BridgeDeploymentCommand(t, "initial", "", true)
			for attempt := 0; attempt < 2; attempt++ {
				result, err := manager.Process(context.Background(), command)
				if err != nil || result.State != deployment.StateFailed || healthCalls != 0 {
					t.Fatalf("failed initial command became healthy: result=%+v healthCalls=%d err=%v", result, healthCalls, err)
				}
			}
			pointers, err := manager.Pointers()
			if err != nil || pointers.Current != "" {
				t.Fatalf("failed initial command became loaded config: %+v %v", pointers, err)
			}
			if !precheckFailure {
				if err := bridge.Healthy(context.Background(), command.ConfigVersionID); err == nil {
					t.Fatal("immutable aborted candidate accepted a later successful HTTP probe")
				}
			}
		})
	}
}

func (runtime l4BridgeInterruptedHealthRuntime) Reload(ctx context.Context, version, root string) error {
	return runtime.bridge.Reload(ctx, version, root)
}

func (runtime l4BridgeInterruptedHealthRuntime) Healthy(ctx context.Context, version string) error {
	if err := runtime.bridge.Healthy(ctx, version); err != nil {
		return err
	}
	if *runtime.interrupt == "after-health" {
		panic("after-health")
	}
	return nil
}

func l4BridgeDeploymentCommand(t *testing.T, version, previous string, stream bool) deployment.Command {
	t.Helper()
	files := map[string][]byte{"nginx.conf": []byte(version)}
	if stream {
		const tenantID, siteID, streamID = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
		document := l4StreamSetV2Document{
			SchemaVersion: l4StreamSetV2Schema, VersionID: version, Revision: 9,
			Streams: []l4runtime.StreamRuntimeSpecV2{{
				SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenantID, StreamID: streamID, Revision: 3,
				Listener:         l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: 19443},
				Endpoint:         l4runtime.EndpointV2{Address: "8.8.8.8", Port: 443},
				Geo:              l4runtime.GeoPolicyV2{TenantID: tenantID, StreamID: streamID, Revision: 3, UnknownRegionAction: l4runtime.GeoActionAllow},
				ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
			}},
		}
		content, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		files[edgeconfig.L4RuntimeV2ArtifactPath] = content
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	manifest := deployment.Manifest{}
	for _, path := range paths {
		sum := sha256.Sum256(files[path])
		manifest.Files = append(manifest.Files, deployment.FileManifest{Path: path, Size: int64(len(files[path])), SHA256: hex.EncodeToString(sum[:])})
	}
	digest, err := deployment.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return deployment.Command{DeploymentID: "deploy-" + version, Attempt: 1, Action: deployment.ActionApply,
		ConfigVersionID: version, PreviousVersionID: previous,
		Bundle: deployment.Bundle{Manifest: manifest, ManifestSHA256: digest, Files: files}}
}
