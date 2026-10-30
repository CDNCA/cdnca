package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

func TestL4BridgeHealthRetryWindow(t *testing.T) {
	for _, test := range []struct {
		name              string
		initial, stream   bool
		permanent, cancel bool
	}{
		{name: "transient-empty"},
		{name: "transient-stream", stream: true},
		{name: "transient-initial", initial: true},
		{name: "deadline-baseline", permanent: true},
		{name: "deadline-initial", initial: true, permanent: true},
		{name: "cancel-baseline", cancel: true},
		{name: "cancel-initial", initial: true, cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			l4, err := l4runtime.NewDeploymentManager(filepath.Join(root, "l4"), runtime)
			if err != nil {
				t.Fatal(err)
			}
			dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), daemonL4DNSResolver{}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var httpVersion string
			probes := 0
			delegate, err := deployment.NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf",
				func(_ context.Context, _ string, args ...string) error {
					if args[0] == "-t" {
						return nil
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
					return nil
				}, func(probeCtx context.Context, version string) error {
					if httpVersion != version {
						return fmt.Errorf("HTTP identity mismatch: %s != %s", httpVersion, version)
					}
					if version != "candidate" {
						return nil
					}
					probes++
					if !test.permanent && !test.cancel {
						active, err := l4.Status()
						if err != nil || active.VersionID != version {
							t.Fatalf("probe %d lost candidate before health deadline: %+v %v", probes, active, err)
						}
					}
					if test.cancel {
						cancel()
						return probeCtx.Err()
					}
					if test.permanent || probes <= 2 {
						return errors.New("injected transient HTTP health failure")
					}
					return nil
				})
			if err != nil {
				t.Fatal(err)
			}
			bridge := &l4DeploymentBridge{delegate: delegate, manager: l4, dns: dns, healthInterval: time.Millisecond}
			config := deployment.DefaultConfig()
			config.HealthTimeout, config.HealthInterval = 50*time.Millisecond, time.Millisecond
			manager, err := deployment.NewManagerWithConfig(filepath.Join(root, "http"), bridge, bridge, config)
			if err != nil {
				t.Fatal(err)
			}
			previous := ""
			if !test.initial {
				if result, err := manager.Process(ctx, l4BridgeDeploymentCommand(t, "baseline", "", true)); err != nil || result.State != deployment.StateHealthy {
					t.Fatalf("baseline: %+v %v", result, err)
				}
				previous = "baseline"
			}
			before, err := l4.Status()
			if err != nil {
				t.Fatal(err)
			}
			activations, stops := runtime.activations, runtime.stops
			result, err := manager.Process(ctx, l4BridgeDeploymentCommand(t, "candidate", previous, test.stream))
			if err != nil {
				t.Fatal(err)
			}
			after, err := l4.Status()
			if err != nil {
				t.Fatal(err)
			}
			if !test.permanent && !test.cancel {
				if result.State != deployment.StateHealthy || probes != 3 || after.VersionID != "candidate" || httpVersion != "candidate" {
					t.Fatalf("transient health failure did not converge: result=%+v probes=%d L4=%+v HTTP=%s", result, probes, after, httpVersion)
				}
				if runtime.activations != activations+1 || runtime.stops != stops {
					t.Fatalf("transient failure restored L4: activations=%d stops=%d", runtime.activations-activations, runtime.stops-stops)
				}
			} else {
				if after != before || result.State == deployment.StateHealthy {
					t.Fatalf("terminal health failure did not restore actual L4 baseline: before=%+v after=%+v result=%+v", before, after, result)
				}
				if !test.cancel && !test.initial && (result.State != deployment.StateReverted || httpVersion != "baseline") {
					t.Fatalf("terminal failure did not revert HTTP: result=%+v HTTP=%s", result, httpVersion)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "l4", "state", "release-journal.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("release journal remains after health completes: %v", err)
			}
		})
	}
}
