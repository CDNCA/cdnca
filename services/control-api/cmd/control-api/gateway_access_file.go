package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/controlgrpc"
)

// withGatewayAccessFile mirrors every successful allow-list refresh into path
// (one address per line, sorted, deduplicated). install-control.sh's
// cdnca-gateway-access.path unit loads it into the nftables set that guards
// the remote ControlInternal, Redis and NATS ports (ADR 0013 §3.3, GW-09), so
// the host firewall and the listener filter share one source. control-api has
// no CAP_NET_ADMIN; it only writes the file. Empty path: list unchanged.
func withGatewayAccessFile(list controlgrpc.AllowedSourcesFunc, path string) controlgrpc.AllowedSourcesFunc {
	if path == "" {
		return list
	}
	return func(ctx context.Context) ([]net.IP, error) {
		ips, err := list(ctx)
		if err != nil {
			return nil, err
		}
		seen := make(map[string]bool, len(ips))
		lines := make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip == nil || seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			lines = append(lines, ip.String())
		}
		sort.Strings(lines)
		contents := strings.Join(lines, "\n")
		if contents != "" {
			contents += "\n"
		}
		if previous, readErr := os.ReadFile(path); readErr == nil && string(previous) == contents {
			return ips, nil
		}
		return ips, writeGatewayAccessFile(path, contents)
	}
}

func writeGatewayAccessFile(path, contents string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".allowed-ips-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.WriteString(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
