// l4-restart-probe checks, under a real systemd, that restarting the Agent
// unit keeps the L4 OpenResty master and its established TCP sessions.
//
//	agent: what the Agent does for L4 — build the Manager (which resumes the
//	       active version), apply one fixed version, then wait for SIGTERM
//	       without stopping L4, exactly like edge-agent on shutdown.
//	echo:  TCP echo upstream.
//	hold:  one long-lived TCP session through the L4 listener; it writes
//	       "ok <n>" after every round trip and "broken <error>" when it fails.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

const (
	listenPort   = 19400
	upstreamPort = 19401
)

func main() {
	mode := flag.String("mode", "", "agent | echo | hold")
	stateRoot := flag.String("state-root", "/var/lib/cdnca-l4-probe", "L4 runtime state root")
	binary := flag.String("openresty", "/usr/sbin/nginx", "OpenResty/nginx executable")
	status := flag.String("status", "/run/l4-probe-hold.status", "hold status file")
	flag.Parse()
	var err error
	switch *mode {
	case "agent":
		err = agent(*stateRoot, *binary)
	case "echo":
		err = echo()
	case "hold":
		err = hold(*status)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func agent(stateRoot, binary string) error {
	controller, err := l4runtime.NewOpenResty(binary, filepath.Join(stateRoot, "run", "nginx.pid"), 10*time.Second)
	if err != nil {
		return err
	}
	manager, err := l4runtime.NewManager(stateRoot, controller)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := manager.Apply(ctx, config()); err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	fmt.Println("agent ready")
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	<-signals
	fmt.Println("agent stopping; L4 is left to the next agent")
	return nil
}

func config() l4runtime.Config {
	return l4runtime.Config{
		SchemaVersion: l4runtime.SchemaVersionV1, VersionID: "l4-probe-v1",
		UpstreamPools: []l4runtime.UpstreamPool{{ID: "echo", Endpoints: []l4runtime.Endpoint{
			{Address: "127.0.0.1", Port: upstreamPort, Weight: 1, MaxFails: 1, FailTimeoutMS: 1_000},
		}}},
		Listeners: []l4runtime.Listener{{
			ID: "tcp-echo", Protocol: l4runtime.ProtocolTCP, Address: "127.0.0.1", Port: listenPort,
			UpstreamPoolID: "echo", ConnectTimeoutMS: 1_000, IdleTimeoutMS: 600_000, MaxConnectionsPerClient: 100,
		}},
	}
}

func echo() error {
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", upstreamPort))
	if err != nil {
		return err
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func hold(status string) error {
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err != nil {
		return writeStatus(status, "broken dial: "+err.Error())
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	for round := 1; ; round++ {
		message := fmt.Sprintf("round-%d\n", round)
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.WriteString(connection, message); err != nil {
			return writeStatus(status, "broken write: "+err.Error())
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != message {
			return writeStatus(status, fmt.Sprintf("broken read: %q %v", line, err))
		}
		if err := writeStatus(status, fmt.Sprintf("ok %d", round)); err != nil {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func writeStatus(path, value string) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(value+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
