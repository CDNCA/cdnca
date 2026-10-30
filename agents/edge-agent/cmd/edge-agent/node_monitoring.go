package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type nodeMonitoringSettings struct {
	Enabled     bool   `json:"enabled"`
	StateDir    string `json:"state_dir"`
	DefaultPort uint16 `json:"default_port"`
}

type localNodeProbe struct{}

func (localNodeProbe) Probe(ctx context.Context, port uint16, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	return connection.Close()
}

func (probe localNodeProbe) ProbeProtocol(ctx context.Context, protocol string, port uint16, timeout time.Duration) error {
	switch protocol {
	case "tcp":
		return probe.Probe(ctx, port, timeout)
	case "http":
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))+"/", nil)
		if err != nil {
			return err
		}
		response, err := (&http.Client{Timeout: timeout}).Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode >= http.StatusInternalServerError {
			return fmt.Errorf("http probe returned status %d", response.StatusCode)
		}
		return nil
	case "ping":
		return probePing(ctx, timeout)
	default:
		return fmt.Errorf("unsupported monitoring protocol %q", protocol)
	}
}

// pingNetworks: a raw ICMP socket needs CAP_NET_RAW, which the native root
// unit keeps (no capability bounding set) but the packaged cdnca-edge unit
// drops (CAP_NET_BIND_SERVICE only). The unprivileged ICMP datagram socket
// ("udp4", allowed by net.ipv4.ping_group_range, which systemd opens to all
// groups by default) works for both.
var pingNetworks = []string{"ip4:icmp", "udp4"}

func probePing(ctx context.Context, timeout time.Duration) error {
	var errs []error
	for _, network := range pingNetworks {
		err := probePingOn(ctx, network, timeout)
		if err == nil {
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", network, err))
		if !errors.Is(err, os.ErrPermission) && !errors.Is(err, syscall.EPROTONOSUPPORT) &&
			!errors.Is(err, syscall.EAFNOSUPPORT) && !errors.Is(err, syscall.EACCES) {
			break
		}
	}
	return errors.Join(errs...)
}

func probePingOn(ctx context.Context, network string, timeout time.Duration) error {
	connection, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	// A datagram socket's echo ID is rewritten by the kernel to its local
	// port, so replies are matched on sequence and payload there.
	raw := network == "ip4:icmp"
	identifier := int(time.Now().UnixNano() & 0xffff)
	payload := []byte("cdnca-node-monitoring")
	message := &icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: identifier, Seq: 1, Data: payload}}
	packet, err := message.Marshal(nil)
	if err != nil {
		return err
	}
	loopback := net.IPv4(127, 0, 0, 1)
	var destination net.Addr = &net.IPAddr{IP: loopback}
	if !raw {
		destination = &net.UDPAddr{IP: loopback}
	}
	if _, err := connection.WriteTo(packet, destination); err != nil {
		return err
	}
	buffer := make([]byte, 1500)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return err
		}
		var from net.IP
		switch address := peer.(type) {
		case *net.IPAddr:
			from = address.IP
		case *net.UDPAddr:
			from = address.IP
		}
		if !from.Equal(loopback) {
			continue
		}
		parsed, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), buffer[:count])
		if err != nil || parsed.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		body, ok := parsed.Body.(*icmp.Echo)
		if ok && body.Seq == 1 && (raw && body.ID == identifier || !raw && string(body.Data) == string(payload)) {
			return nil
		}
	}
}

func assembleNodeMonitoring(settings nodeMonitoringSettings, nodeID string) (*gatewayclient.NodeMonitoringBridge, *nodemonitoring.Runtime, error) {
	if !settings.Enabled {
		return nil, nil, nil
	}
	if settings.DefaultPort == 0 || !absoluteCleanPath(settings.StateDir) || settings.StateDir == string(filepath.Separator) {
		return nil, nil, fmt.Errorf("node_monitoring local settings are invalid")
	}
	bridge, err := gatewayclient.NewNodeMonitoringBridge(settings.StateDir, nodeID)
	if err != nil {
		return nil, nil, fmt.Errorf("configure node monitoring carrier: %w", err)
	}
	runtime, err := nodemonitoring.NewRuntime(nodemonitoring.Options{
		StateDir: filepath.Join(settings.StateDir, "runtime"), NodeID: nodeID,
		DefaultPort: settings.DefaultPort, Probe: localNodeProbe{}, Notifier: bridge,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("configure node monitoring runtime: %w", err)
	}
	if err := bridge.AttachRuntime(runtime); err != nil {
		return nil, nil, err
	}
	return bridge, runtime, nil
}
