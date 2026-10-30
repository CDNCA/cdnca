package l4runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var errInjectedTrafficHealth = errors.New("injected traffic health failure")

// Existing test runtimes remain valid when the production Runtime contract
// gains the post-activation health phase.
func (*fakeRuntime) Healthy(context.Context, Config) error     { return nil }
func (*recoveryRuntime) Healthy(context.Context, Config) error { return nil }

type trafficHealthRuntime struct {
	healthConfigs     []Config
	precheckCalls     []string
	activateCalls     []string
	stopCalls         []string
	failHealthVersion string
	manager           *Manager
	expectedActive    []string
}

func (r *trafficHealthRuntime) Precheck(_ context.Context, path string) error {
	r.precheckCalls = append(r.precheckCalls, path)
	return nil
}

func (r *trafficHealthRuntime) Activate(_ context.Context, path string) error {
	r.activateCalls = append(r.activateCalls, currentTarget(path))
	return nil
}

func (r *trafficHealthRuntime) Stop(_ context.Context, path string) error {
	r.stopCalls = append(r.stopCalls, currentTarget(path))
	return nil
}

func (r *trafficHealthRuntime) Healthy(_ context.Context, config Config) error {
	r.healthConfigs = append(r.healthConfigs, config)
	if r.manager != nil {
		active, err := r.manager.store.loadActive()
		if err != nil {
			return err
		}
		call := len(r.healthConfigs) - 1
		if call < len(r.expectedActive) {
			wantPrevious := r.expectedActive[call]
			if wantPrevious == "" {
				if active != nil {
					return fmt.Errorf("health ran after active state was committed: %s", active.VersionID)
				}
			} else if active == nil || active.VersionID != wantPrevious {
				return fmt.Errorf("health saw active=%v, want previous=%s", active, wantPrevious)
			}
		}
	}
	if config.VersionID == r.failHealthVersion {
		return errInjectedTrafficHealth
	}
	return nil
}

func trafficHealthConfig(versionID string, protocol Protocol, policy *TrafficHealthPolicy) Config {
	config := validConfig(versionID)
	config.Listeners[0].TrafficHealth = nil
	config.Listeners[1].TrafficHealth = nil
	if protocol == ProtocolTCP {
		config.Listeners[1].TrafficHealth = policy
	} else {
		config.Listeners[0].TrafficHealth = policy
	}
	return config
}

func listenerForProtocol(t *testing.T, config Config, protocol Protocol) Listener {
	t.Helper()
	for _, listener := range config.Listeners {
		if listener.Protocol == protocol {
			return listener
		}
	}
	t.Fatalf("compiled config has no %s listener", protocol)
	return Listener{}
}

func TestCompileTrafficHealthPolicyAcceptsTCPConnectExchangeAndUDP(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol Protocol
		policy   *TrafficHealthPolicy
	}{
		{name: "tcp connect only", protocol: ProtocolTCP, policy: &TrafficHealthPolicy{TimeoutMS: 10, Attempts: 1}},
		{name: "tcp request response", protocol: ProtocolTCP, policy: &TrafficHealthPolicy{Request: []byte("PING\n"), ExpectedResponse: []byte("PONG\n"), TimeoutMS: 250, Attempts: 2}},
		{name: "udp request response", protocol: ProtocolUDP, policy: &TrafficHealthPolicy{Request: []byte("PING"), ExpectedResponse: []byte("PONG"), TimeoutMS: 500, Attempts: 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			compiled, err := Compile(trafficHealthConfig("health-"+strings.ReplaceAll(test.name, " ", "-"), test.protocol, test.policy))
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}
			listener := listenerForProtocol(t, compiled.Config, test.protocol)
			if listener.TrafficHealth == nil || !reflect.DeepEqual(listener.TrafficHealth, test.policy) {
				t.Fatalf("normalized traffic health = %+v, want %+v", listener.TrafficHealth, test.policy)
			}
			if strings.Contains(string(compiled.NginxConfig), "PING") || strings.Contains(string(compiled.NginxConfig), "PONG") {
				t.Fatal("health payload leaked into generated nginx configuration")
			}
		})
	}
}

func TestCompileTrafficHealthPolicyRejectsInvalidShapesAndBounds(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol Protocol
		policy   *TrafficHealthPolicy
	}{
		{name: "timeout below minimum", protocol: ProtocolTCP, policy: &TrafficHealthPolicy{TimeoutMS: 9, Attempts: 1}},
		{name: "timeout above maximum", protocol: ProtocolTCP, policy: &TrafficHealthPolicy{TimeoutMS: 5_001, Attempts: 1}},
		{name: "attempts zero", protocol: ProtocolTCP, policy: &TrafficHealthPolicy{TimeoutMS: 10}},
		{name: "attempts above maximum", protocol: ProtocolTCP, policy: &TrafficHealthPolicy{TimeoutMS: 10, Attempts: 4}},
		{name: "tcp request without response", protocol: ProtocolTCP, policy: &TrafficHealthPolicy{Request: []byte("PING"), TimeoutMS: 10, Attempts: 1}},
		{name: "tcp response without request", protocol: ProtocolTCP, policy: &TrafficHealthPolicy{ExpectedResponse: []byte("PONG"), TimeoutMS: 10, Attempts: 1}},
		{name: "udp connect only", protocol: ProtocolUDP, policy: &TrafficHealthPolicy{TimeoutMS: 10, Attempts: 1}},
		{name: "udp request without response", protocol: ProtocolUDP, policy: &TrafficHealthPolicy{Request: []byte("PING"), TimeoutMS: 10, Attempts: 1}},
		{name: "request too large", protocol: ProtocolTCP, policy: &TrafficHealthPolicy{Request: make([]byte, 1025), ExpectedResponse: []byte("PONG"), TimeoutMS: 10, Attempts: 1}},
		{name: "response too large", protocol: ProtocolUDP, policy: &TrafficHealthPolicy{Request: []byte("PING"), ExpectedResponse: make([]byte, 1025), TimeoutMS: 10, Attempts: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Compile(trafficHealthConfig("invalid-health", test.protocol, test.policy)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Compile() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestCompileTrafficHealthNilPreservesBaselineAndCopiesPayload(t *testing.T) {
	without := validConfig("health-baseline")
	without.Listeners[0].TrafficHealth = nil
	without.Listeners[1].TrafficHealth = nil
	withExplicitNil := trafficHealthConfig("health-baseline", ProtocolUDP, nil)
	first, err := Compile(without)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(withExplicitNil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || !reflect.DeepEqual(first.Config, second.Config) ||
		!reflect.DeepEqual(first.CanonicalJSON, second.CanonicalJSON) || !reflect.DeepEqual(first.NginxConfig, second.NginxConfig) {
		t.Fatal("nil traffic-health policy changed the baseline compiled output")
	}
	if strings.Contains(string(first.CanonicalJSON), "traffic_health") {
		t.Fatal("nil traffic-health policy was serialized")
	}

	request := []byte("PING")
	expected := []byte("PONG")
	config := trafficHealthConfig("health-copy", ProtocolUDP, &TrafficHealthPolicy{Request: request, ExpectedResponse: expected, TimeoutMS: 10, Attempts: 1})
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	request[0], expected[0] = 'X', 'Y'
	policy := listenerForProtocol(t, compiled.Config, ProtocolUDP).TrafficHealth
	if string(policy.Request) != "PING" || string(policy.ExpectedResponse) != "PONG" {
		t.Fatalf("compiled health payload changed after caller mutation: %+v", policy)
	}
}

func TestManagerTrafficHealthFailureRestoresLastKnownGood(t *testing.T) {
	runtime := &trafficHealthRuntime{failHealthVersion: "l4-v2", expectedActive: []string{"", "l4-v1", "l4-v1"}}
	manager, root := testManager(t, runtime)
	runtime.manager = manager
	first, err := manager.Apply(context.Background(), trafficHealthConfig("l4-v1", ProtocolUDP, &TrafficHealthPolicy{Request: []byte("PING"), ExpectedResponse: []byte("PONG"), TimeoutMS: 10, Attempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	failed, err := manager.Apply(context.Background(), trafficHealthConfig("l4-v2", ProtocolTCP, &TrafficHealthPolicy{TimeoutMS: 10, Attempts: 1}))
	if !errors.Is(err, ErrActivation) || failed.ErrorCode != "TRAFFIC_HEALTH_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != first.VersionID || failed.ActiveDigest != first.Digest {
		t.Fatalf("failed Apply() = %+v, %v", failed, err)
	}
	if got := currentTarget(filepath.Join(root, "current")); got != first.VersionID+"-"+first.Digest {
		t.Fatalf("current target = %q, want LKG", got)
	}
	if len(runtime.healthConfigs) < 3 || runtime.healthConfigs[0].VersionID != "l4-v1" || runtime.healthConfigs[1].VersionID != "l4-v2" || runtime.healthConfigs[len(runtime.healthConfigs)-1].VersionID != "l4-v1" {
		t.Fatalf("health order = %v, want candidate and LKG verification", runtime.healthConfigs)
	}
}

func TestManagerInitialTrafficHealthFailureStopsCandidate(t *testing.T) {
	runtime := &trafficHealthRuntime{failHealthVersion: "l4-v1", expectedActive: []string{""}}
	manager, root := testManager(t, runtime)
	runtime.manager = manager
	failed, err := manager.Apply(context.Background(), trafficHealthConfig("l4-v1", ProtocolTCP, &TrafficHealthPolicy{Request: []byte("PING"), ExpectedResponse: []byte("PONG"), TimeoutMS: 10, Attempts: 1}))
	if !errors.Is(err, ErrActivation) || failed.ErrorCode != "TRAFFIC_HEALTH_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != "" {
		t.Fatalf("failed initial Apply() = %+v, %v", failed, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed initial health left current symlink: %v", err)
	}
	if len(runtime.stopCalls) != 1 || len(runtime.healthConfigs) != 1 {
		t.Fatalf("health/stop calls = %d/%d, want one each", len(runtime.healthConfigs), len(runtime.stopCalls))
	}
}

func TestManagerRollbackTrafficHealthFailurePreservesActive(t *testing.T) {
	runtime := &trafficHealthRuntime{expectedActive: []string{"", "l4-v1", "l4-v2", "l4-v2"}}
	manager, root := testManager(t, runtime)
	runtime.manager = manager
	first, err := manager.Apply(context.Background(), trafficHealthConfig("l4-v1", ProtocolTCP, &TrafficHealthPolicy{TimeoutMS: 10, Attempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Apply(context.Background(), trafficHealthConfig("l4-v2", ProtocolUDP, &TrafficHealthPolicy{Request: []byte("PING"), ExpectedResponse: []byte("PONG"), TimeoutMS: 10, Attempts: 1}))
	if err != nil {
		t.Fatal(err)
	}
	runtime.failHealthVersion = "l4-v1"
	failed, err := manager.Rollback(context.Background(), first.VersionID, first.Digest)
	if !errors.Is(err, ErrActivation) || failed.ErrorCode != "TRAFFIC_HEALTH_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != second.VersionID || failed.ActiveDigest != second.Digest {
		t.Fatalf("failed Rollback() = %+v, %v", failed, err)
	}
	if got := currentTarget(filepath.Join(root, "current")); got != second.VersionID+"-"+second.Digest {
		t.Fatalf("current target = %q, want confirmed active", got)
	}
}

func compiledListenerHealthConfig(t *testing.T, protocol Protocol, address string, port int, policy *TrafficHealthPolicy) Config {
	t.Helper()
	config := Config{
		SchemaVersion: SchemaVersionV1,
		VersionID:     "traffic-health-runtime",
		UpstreamPools: []UpstreamPool{{
			ID: "origin", Endpoints: []Endpoint{{Address: "192.0.2.1", Port: 9000, Weight: 1, MaxFails: 1, FailTimeoutMS: 1_000}},
		}},
		Listeners: []Listener{{
			ID: "health", Protocol: protocol, Address: address, Port: port, UpstreamPoolID: "origin",
			ConnectTimeoutMS: 100, IdleTimeoutMS: 1_000, MaxConnectionsPerClient: 10, TrafficHealth: policy,
		}},
	}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return compiled.Config
}

func testHealthController(t *testing.T) *OpenResty {
	t.Helper()
	controller, err := NewOpenResty("/usr/local/openresty/nginx/sbin/nginx", filepath.Join(t.TempDir(), "nginx.pid"), time.Second)
	if err != nil {
		t.Fatalf("NewOpenResty() error = %v", err)
	}
	return controller
}

func waitHealthServer(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("health server error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("health server did not complete")
	}
}

func TestOpenRestyTrafficHealthTCPConnectAndExchange(t *testing.T) {
	t.Run("wildcard connect only", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		server := make(chan error, 1)
		go func() {
			connection, err := listener.Accept()
			if err == nil {
				err = connection.Close()
			}
			server <- err
		}()

		port := listener.Addr().(*net.TCPAddr).Port
		config := compiledListenerHealthConfig(t, ProtocolTCP, "0.0.0.0", port, &TrafficHealthPolicy{TimeoutMS: 100, Attempts: 1})
		if err := testHealthController(t).Healthy(context.Background(), config); err != nil {
			t.Fatalf("Healthy() error = %v", err)
		}
		waitHealthServer(t, server)
	})

	t.Run("exact request response", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		server := make(chan error, 1)
		go func() {
			connection, err := listener.Accept()
			if err != nil {
				server <- err
				return
			}
			defer connection.Close()
			request := make([]byte, len("PING\n"))
			if _, err = io.ReadFull(connection, request); err == nil && string(request) != "PING\n" {
				err = fmt.Errorf("request = %q", request)
			}
			if err == nil {
				_, err = connection.Write([]byte("PONG\n"))
			}
			server <- err
		}()

		port := listener.Addr().(*net.TCPAddr).Port
		config := compiledListenerHealthConfig(t, ProtocolTCP, "127.0.0.1", port, &TrafficHealthPolicy{
			Request: []byte("PING\n"), ExpectedResponse: []byte("PONG\n"), TimeoutMS: 100, Attempts: 1,
		})
		if err := testHealthController(t).Healthy(context.Background(), config); err != nil {
			t.Fatalf("Healthy() error = %v", err)
		}
		waitHealthServer(t, server)
	})
}

func TestOpenRestyTrafficHealthUDPExactDatagramAndRetry(t *testing.T) {
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	server := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		for attempt := 0; attempt < 2; attempt++ {
			if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				server <- err
				return
			}
			count, peer, err := connection.ReadFromUDP(buffer)
			if err != nil {
				server <- err
				return
			}
			if string(buffer[:count]) != "PING" {
				server <- fmt.Errorf("datagram = %q", buffer[:count])
				return
			}
			response := []byte("PONG-extra")
			if attempt == 1 {
				response = []byte("PONG")
			}
			if _, err := connection.WriteToUDP(response, peer); err != nil {
				server <- err
				return
			}
		}
		server <- nil
	}()

	config := compiledListenerHealthConfig(t, ProtocolUDP, "0.0.0.0", connection.LocalAddr().(*net.UDPAddr).Port, &TrafficHealthPolicy{
		Request: []byte("PING"), ExpectedResponse: []byte("PONG"), TimeoutMS: 100, Attempts: 2,
	})
	if err := testHealthController(t).Healthy(context.Background(), config); err != nil {
		t.Fatalf("Healthy() error = %v", err)
	}
	waitHealthServer(t, server)
}

func TestOpenRestyTrafficHealthRejectsMismatchAndTimeout(t *testing.T) {
	t.Run("tcp response mismatch", func(t *testing.T) {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		server := make(chan error, 1)
		go func() {
			connection, err := listener.Accept()
			if err == nil {
				defer connection.Close()
				request := make([]byte, len("PING"))
				_, err = io.ReadFull(connection, request)
				if err == nil {
					_, err = connection.Write([]byte("NOPE"))
				}
			}
			server <- err
		}()
		config := compiledListenerHealthConfig(t, ProtocolTCP, "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, &TrafficHealthPolicy{
			Request: []byte("PING"), ExpectedResponse: []byte("PONG"), TimeoutMS: 100, Attempts: 1,
		})
		if err := testHealthController(t).Healthy(context.Background(), config); err == nil {
			t.Fatal("Healthy() accepted mismatched response")
		}
		waitHealthServer(t, server)
	})

	t.Run("udp timeout is bounded", func(t *testing.T) {
		connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		server := make(chan error, 1)
		go func() {
			buffer := make([]byte, 64)
			if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				server <- err
				return
			}
			_, _, err := connection.ReadFromUDP(buffer)
			server <- err
		}()
		config := compiledListenerHealthConfig(t, ProtocolUDP, "127.0.0.1", connection.LocalAddr().(*net.UDPAddr).Port, &TrafficHealthPolicy{
			Request: []byte("PING"), ExpectedResponse: []byte("PONG"), TimeoutMS: 10, Attempts: 1,
		})
		started := time.Now()
		if err := testHealthController(t).Healthy(context.Background(), config); err == nil {
			t.Fatal("Healthy() accepted a timed out UDP probe")
		}
		if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
			t.Fatalf("UDP timeout took %s, want bounded failure", elapsed)
		}
		waitHealthServer(t, server)
	})
}
