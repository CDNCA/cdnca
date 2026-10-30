package l4runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type listenerPrecheckFailure interface {
	ListenerID() string
	ReasonCode() string
}

func TestOpenRestyListenerPortPrecheck(t *testing.T) {
	t.Run("TCP conflict returns stable listener failure", func(t *testing.T) {
		holder, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Close()

		listener := testPortListener(t, "tcp-conflict", ProtocolTCP, holder.Addr())
		controller, candidate := testPortPrecheck(t, Config{Listeners: []Listener{listener}}, nil)
		err = controller.Precheck(context.Background(), candidate)
		assertListenerPrecheckFailure(t, err, listener.ID, "LISTENER_PORT_CONFLICT")
	})

	t.Run("UDP conflict returns stable listener failure", func(t *testing.T) {
		holder, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Close()

		listener := testPortListener(t, "udp-conflict", ProtocolUDP, holder.LocalAddr())
		controller, candidate := testPortPrecheck(t, Config{Listeners: []Listener{listener}}, nil)
		err = controller.Precheck(context.Background(), candidate)
		assertListenerPrecheckFailure(t, err, listener.ID, "LISTENER_PORT_CONFLICT")
	})

	t.Run("successful probes release TCP and UDP ports", func(t *testing.T) {
		tcp := reserveThenRelease(t, "tcp4", "127.0.0.1:0")
		udp := reserveThenRelease(t, "udp4", "127.0.0.1:0")
		listeners := []Listener{
			testPortListener(t, "tcp-free", ProtocolTCP, tcp),
			testPortListener(t, "udp-free", ProtocolUDP, udp),
		}
		controller, candidate := testPortPrecheck(t, Config{Listeners: listeners}, nil)
		if err := controller.Precheck(context.Background(), candidate); err != nil {
			t.Fatalf("Precheck() error = %v", err)
		}
		assertPortReusable(t, "tcp4", tcp)
		assertPortReusable(t, "udp4", udp)
	})

	t.Run("current owned overlap is not rebound", func(t *testing.T) {
		holder, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Close()

		active := testPortListener(t, "active-listener", ProtocolTCP, holder.Addr())
		candidateListener := active
		candidateListener.ID = "replacement-listener"
		controller, candidate := testPortPrecheck(t, Config{Listeners: []Listener{candidateListener}}, &Config{Listeners: []Listener{active}})
		if err := controller.Precheck(context.Background(), candidate); err != nil {
			t.Fatalf("Precheck() error = %v", err)
		}
	})

	t.Run("disabled listener is not bound", func(t *testing.T) {
		holder, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Close()

		listener := testPortListener(t, "disabled-listener", ProtocolTCP, holder.Addr())
		listener.Disabled = true
		controller, candidate := testPortPrecheck(t, Config{Listeners: []Listener{listener}}, nil)
		if err := controller.Precheck(context.Background(), candidate); err != nil {
			t.Fatalf("Precheck() error = %v", err)
		}
	})

	t.Run("empty listener set has no port side effects", func(t *testing.T) {
		controller, candidate := testPortPrecheck(t, Config{Listeners: []Listener{}}, nil)
		if err := controller.Precheck(context.Background(), candidate); err != nil {
			t.Fatalf("Precheck() error = %v", err)
		}
	})

	t.Run("non-conflict bind failure has stable reason", func(t *testing.T) {
		listener := Listener{ID: "unavailable-address", Protocol: ProtocolTCP, Address: "192.0.2.1", Port: 49152}
		controller, candidate := testPortPrecheck(t, Config{Listeners: []Listener{listener}}, nil)
		err := controller.Precheck(context.Background(), candidate)
		assertListenerPrecheckFailure(t, err, listener.ID, "LISTENER_PORT_PRECHECK_FAILED")
	})

	t.Run("IPv6 TCP is probed when available", func(t *testing.T) {
		holder, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		address := holder.Addr()
		if err := holder.Close(); err != nil {
			t.Fatal(err)
		}
		listener := testPortListener(t, "tcp6-free", ProtocolTCP, address)
		controller, candidate := testPortPrecheck(t, Config{Listeners: []Listener{listener}}, nil)
		if err := controller.Precheck(context.Background(), candidate); err != nil {
			t.Fatalf("Precheck() error = %v", err)
		}
		assertPortReusable(t, "tcp6", address)
	})

	t.Run("IPv6 UDP is probed when available", func(t *testing.T) {
		holder, err := net.ListenPacket("udp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		address := holder.LocalAddr()
		if err := holder.Close(); err != nil {
			t.Fatal(err)
		}
		listener := testPortListener(t, "udp6-free", ProtocolUDP, address)
		controller, candidate := testPortPrecheck(t, Config{Listeners: []Listener{listener}}, nil)
		if err := controller.Precheck(context.Background(), candidate); err != nil {
			t.Fatalf("Precheck() error = %v", err)
		}
		assertPortReusable(t, "udp6", address)
	})
}

func TestOpenRestyHealthySkipsDisabledListener(t *testing.T) {
	config := compiledListenerHealthConfig(t, ProtocolTCP, "127.0.0.1", 9, &TrafficHealthPolicy{TimeoutMS: 10, Attempts: 1})
	config.Listeners[0].Disabled = true
	if err := testHealthController(t).Healthy(context.Background(), config); err != nil {
		t.Fatalf("Healthy() error = %v", err)
	}
}

func testPortPrecheck(t *testing.T, candidateConfig Config, activeConfig *Config) (*OpenResty, string) {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"tmp", "versions", "run"} {
		if err := os.Mkdir(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	candidate := filepath.Join(root, "tmp", "candidate")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	writePortConfig(t, filepath.Join(candidate, "config.json"), candidateConfig)
	if activeConfig != nil {
		versionName := "active-0000000000000000000000000000000000000000000000000000000000000000"
		versionPath := filepath.Join(root, "versions", versionName)
		if err := os.Mkdir(versionPath, 0o700); err != nil {
			t.Fatal(err)
		}
		writePortConfig(t, filepath.Join(versionPath, "config.json"), *activeConfig)
		if err := os.Symlink(filepath.Join("versions", versionName), filepath.Join(root, "current")); err != nil {
			t.Fatal(err)
		}
	}
	controller, err := NewOpenResty("/usr/bin/true", filepath.Join(root, "run", "nginx.pid"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return controller, candidate
}

func writePortConfig(t *testing.T, path string, config Config) {
	t.Helper()
	content, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testPortListener(t *testing.T, id string, protocol Protocol, address net.Addr) Listener {
	t.Helper()
	host, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return Listener{ID: id, Protocol: protocol, Address: host, Port: port}
}

func reserveThenRelease(t *testing.T, network, address string) net.Addr {
	t.Helper()
	if network[:3] == "udp" {
		connection, err := net.ListenPacket(network, address)
		if err != nil {
			t.Fatal(err)
		}
		result := connection.LocalAddr()
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
		return result
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	result := listener.Addr()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertPortReusable(t *testing.T, network string, address net.Addr) {
	t.Helper()
	if network[:3] == "udp" {
		connection, err := net.ListenPacket(network, address.String())
		if err != nil {
			t.Fatalf("port was not released: %v", err)
		}
		_ = connection.Close()
		return
	}
	listener, err := net.Listen(network, address.String())
	if err != nil {
		t.Fatalf("port was not released: %v", err)
	}
	_ = listener.Close()
}

func assertListenerPrecheckFailure(t *testing.T, err error, listenerID, reason string) {
	t.Helper()
	if err == nil {
		t.Fatal("Precheck() unexpectedly succeeded")
	}
	var failure listenerPrecheckFailure
	if !errors.As(err, &failure) {
		t.Fatalf("Precheck() error = %v, want typed listener failure", err)
	}
	if failure.ListenerID() != listenerID || failure.ReasonCode() != reason {
		t.Fatalf("listener failure = (%q, %q), want (%q, %q)", failure.ListenerID(), failure.ReasonCode(), listenerID, reason)
	}
}
