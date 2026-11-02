package nodesshinstall

import (
	"net"
	"net/netip"
	"strings"
)

// Detecting the controller's SSH egress when CDNCA_NODE_SSH_CONTROLLER_CIDRS
// is not set. In order:
//
//  1. the co-located Gateway's address (CDNCA_GATEWAY_LOCAL_ADDRESS) when it
//     is a public IP literal: install-control.sh writes the host's public IP
//     there (api.ipify.org, else the first public interface address), which
//     is what nodes see behind a cloud NAT too;
//  2. the public addresses on the controller's own interfaces.
//
// A domain is never resolved: the console and a WebSocket Gateway usually
// sit behind a CDN, whose addresses are not the controller's. A wrong guess
// cannot lock anyone out: the node keeps the restriction only once the
// controller confirmed it still reaches sshd, else it reverts within
// AccessRollbackWindow.

// DetectEgress returns the detected public egress addresses (empty: none).
// gatewayAddress is CDNCA_GATEWAY_LOCAL_ADDRESS (host:port, may be empty);
// interfaces lists the host's addresses (net.InterfaceAddrs).
func DetectEgress(gatewayAddress string, interfaces func() ([]net.Addr, error)) []string {
	if host, _, err := net.SplitHostPort(strings.TrimSpace(gatewayAddress)); err == nil {
		if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && publicEgress(address) {
			return []string{address.Unmap().String()}
		}
	}
	if interfaces == nil {
		return []string{}
	}
	addresses, err := interfaces()
	if err != nil {
		return []string{}
	}
	out := []string{}
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(value.String())
		if err != nil {
			continue
		}
		if address := prefix.Addr().Unmap(); publicEgress(address) && len(out) < maxControllerCIDRs {
			out = append(out, address.String())
		}
	}
	return out
}

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// publicEgress: a global unicast address that is not private (RFC 1918 / ULA),
// shared (CGNAT), loopback or link-local.
func publicEgress(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() && address.Zone() == "" && address.IsGlobalUnicast() && !address.IsPrivate() &&
		!carrierGradeNAT.Contains(address)
}
