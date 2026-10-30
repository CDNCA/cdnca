//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/cccoord"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/l4analytics"
	"github.com/nats-io/nats.go"
)

// This proves resource compatibility only: no business workers, fetches, Observe,
// publications, tenant records, PostgreSQL or ClickHouse writes are run here.
func TestNativeNATSProfileAcceptedByProductionReaders(t *testing.T) {
	if os.Getenv("NATIVE_NATS_PROFILE_INTEGRATION") != "1" {
		t.Skip("set NATIVE_NATS_PROFILE_INTEGRATION=1 with private NATS 2.11.4 and CLI 0.2.4 binaries")
	}
	connection, serverURL := nativeNATSProfileTestServer(t)
	js, err := connection.JetStream(nats.MaxWait(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	info, err := js.AccountInfo()
	if err != nil || info.Streams != 0 || info.Consumers != 0 {
		t.Fatal("test must start with a new, empty, exclusively owned JetStream server")
	}
	nativeNATSProfilePython(t, serverURL, "install")
	before := nativeNATSProfileSnapshot(t, js)
	t.Run("analytics", func(t *testing.T) {
		if err := analytics.EnsureIngestJetStream(t.Context(), connection, analytics.DefaultJetStreamConfig()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("connections", func(t *testing.T) {
		config := analyticsconnections.RuntimeConfig{
			Stream: "CONNECTIONS_INGEST_V1", Durable: "control_api_connections",
			Subject: analyticsconnections.ConnectionsSubject, OperationTimeout: 5 * time.Second,
		}
		if err := ensureAnalyticsConnectionsJetStream(t.Context(), connection, config); err != nil {
			t.Fatal(err)
		}
		subscriber, err := analyticsconnections.NewNATSSubscriber(connection, config)
		if err != nil {
			t.Fatal(err)
		}
		if err := subscriber.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("l4", func(t *testing.T) {
		if err := l4analytics.EnsureL4JetStream(t.Context(), connection, l4analytics.DefaultNATSIngestConfig()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cc", func(t *testing.T) {
		consumer, err := cccoord.NewNATSConsumer(connection, nativeNATSProfileObserver{t}, cccoord.DefaultNATSConfig())
		if err != nil {
			t.Fatal(err)
		}
		if err := consumer.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("control_upgrade", func(t *testing.T) {
		if err := verifyControlUpgradeJetStream(t.Context(), js); err != nil {
			t.Fatal(err)
		}
		if _, err := controlupgrade.NewCommandBus(js, controlUpgradeCommandStream); err != nil {
			t.Fatal(err)
		}
		consumer, err := controlupgrade.BindUpgradeStatusConsumer(js, controlupgrade.DefaultStatusConsumerConfig())
		if err != nil {
			t.Fatal(err)
		}
		if err := consumer.Close(); err != nil {
			t.Fatal(err)
		}
	})
	if after := nativeNATSProfileSnapshot(t, js); !reflect.DeepEqual(before, after) {
		t.Fatal("production readers changed the pre-created resource configuration or creation epoch")
	}
	nativeNATSProfilePython(t, serverURL, "check")
}

type nativeNATSProfileObserver struct{ t *testing.T }

func (observer nativeNATSProfileObserver) Observe(context.Context, cccoord.Envelope) (cccoord.ObserveResult, error) {
	observer.t.Error("resource constructor verification must not observe business events")
	return cccoord.ObserveResult{}, errors.New("business execution forbidden in resource profile test")
}

func nativeNATSProfileTestServer(t *testing.T) (*nats.Conn, string) {
	t.Helper()
	binary := os.Getenv("NATIVE_NATS_TEST_SERVER")
	if !filepath.IsAbs(binary) {
		t.Fatal("NATIVE_NATS_TEST_SERVER must name a verified private absolute binary path")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)
	version, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil || strings.TrimSpace(string(version)) != "nats-server: v2.12.15-cdnca.1" {
		t.Fatal("this test requires NATS server 2.11.4")
	}
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	serverName := fmt.Sprintf("cdnca-native-profile-%d-%d", os.Getpid(), port)
	config, err := json.Marshal(map[string]any{
		"host": "127.0.0.1", "port": port, "server_name": serverName, "max_payload": 4 << 20,
		"jetstream": map[string]string{"store_dir": filepath.Join(directory, "store")},
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "nats.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, "-c", configPath)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	if err := command.Start(); err != nil {
		t.Fatal("start exclusively owned NATS test server")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
	})
	serverURL := fmt.Sprintf("nats://127.0.0.1:%d", port)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		connection, err := nats.Connect(serverURL, nats.NoReconnect(), nats.Timeout(100*time.Millisecond))
		if err == nil {
			if connection.ConnectedServerName() != serverName {
				connection.Close()
				t.Fatal("refusing a server not created by this test")
			}
			t.Cleanup(connection.Close)
			return connection, serverURL
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("owned NATS test server did not become ready")
	return nil, ""
}

func nativeNATSProfilePython(t *testing.T, serverURL, action string) {
	t.Helper()
	cli := os.Getenv("NATIVE_NATS_TEST_CLI")
	if !filepath.IsAbs(cli) {
		t.Fatal("NATIVE_NATS_TEST_CLI must name a verified private absolute binary path")
	}
	helper, err := filepath.Abs("../../../../scripts/native-runtime/configure-nats.py")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	// Importing the helper avoids privileged /usr/local installation in the test;
	// the exact production provisioner and its version/profile checks still run.
	program := `import importlib.util, json, pathlib, sys
spec = importlib.util.spec_from_file_location("native_nats", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = module.provision_native_nats(module.NativeNATS(sys.argv[2], cli=pathlib.Path(sys.argv[3])), install=sys.argv[4] == "install")
print(json.dumps({"streams": len(result["streams"]), "consumers": len(result["consumers"])}))`
	command := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", program, helper, serverURL, cli, action)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	output, err := command.Output()
	if err != nil {
		t.Fatalf("native Python NATS profile %s failed", action)
	}
	var counts struct{ Streams, Consumers int }
	if json.Unmarshal(output, &counts) != nil || counts.Streams != 17 || counts.Consumers != 10 {
		t.Fatal("native Python NATS profile returned an unexpected resource inventory")
	}
}

func nativeNATSProfileSnapshot(t *testing.T, js nats.JetStreamContext) map[string]string {
	t.Helper()
	account, err := js.AccountInfo(nats.Context(t.Context()))
	if err != nil || account.Streams != 17 || account.Consumers != 10 {
		t.Fatal("native profile must contain exactly 17 streams and 10 durables")
	}
	result := make(map[string]string)
	for name := range js.StreamNames(nats.Context(t.Context())) {
		info, err := js.StreamInfo(name, nats.Context(t.Context()))
		if err != nil || info.State.Msgs != 0 || info.State.Bytes != 0 {
			t.Fatal("native profile must have no business messages")
		}
		encoded, err := json.Marshal(struct {
			Config  nats.StreamConfig
			Created time.Time
		}{info.Config, info.Created})
		if err != nil {
			t.Fatal(err)
		}
		result["stream/"+name] = string(encoded)
		for durable := range js.ConsumerNames(name, nats.Context(t.Context())) {
			consumer, err := js.ConsumerInfo(name, durable, nats.Context(t.Context()))
			if err != nil || consumer.NumPending != 0 || consumer.NumAckPending != 0 || consumer.NumWaiting != 0 ||
				consumer.NumRedelivered != 0 || consumer.Delivered.Consumer != 0 || consumer.Delivered.Stream != 0 {
				t.Fatal("native profile consumer must not execute business deliveries")
			}
			encoded, err := json.Marshal(struct {
				Config  nats.ConsumerConfig
				Created time.Time
			}{consumer.Config, consumer.Created})
			if err != nil {
				t.Fatal(err)
			}
			result["consumer/"+name+"/"+durable] = string(encoded)
		}
	}
	if len(result) != 27 { // 17 流 + 10 durable（7c7954242 起）
		t.Fatal("incomplete native profile resource snapshot")
	}
	return result
}
