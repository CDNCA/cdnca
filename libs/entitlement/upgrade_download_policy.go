package entitlement

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// UpgradeDownloadPolicy is how a node reaches the control plane's upgrade
// artifact cache: the host and port of download_url, the fixed addresses it
// dials and the root that verifies the endpoint ("system" = the root the node
// selected from its OS bundle at install time; otherwise one PEM certificate,
// the control plane's private root CA). It travels inside the control-signed
// upgrade execution, so a control plane that moved to another host, or
// between the plain and BaoTa layouts, updates its nodes on the next upgrade
// without reinstalling them (fix-btenv3). Same rules as install-node.sh
// split_upgrade_trust.
type UpgradeDownloadPolicy struct {
	Host      string   `json:"host"`
	Port      uint16   `json:"port"`
	Addresses []string `json:"addresses"`
	RootCA    string   `json:"root_ca"`
}

// UpgradeDownloadSystemRoot keeps the root the node already pinned.
const UpgradeDownloadSystemRoot = "system"

var (
	ErrInvalidUpgradeDownloadPolicy = errors.New("invalid upgrade download policy")

	upgradeDownloadRootPEM = regexp.MustCompile(`^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n$`)
	upgradeDownloadLabel   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Validate checks the policy on its own and against downloadURL: the URL
// must name exactly this host and port.
func (policy UpgradeDownloadPolicy) Validate(downloadURL string) error {
	if !validUpgradeDownloadHost(policy.Host) || policy.Port == 0 ||
		len(policy.Addresses) == 0 || len(policy.Addresses) > 16 ||
		(policy.RootCA != UpgradeDownloadSystemRoot && (len(policy.RootCA) > 16384 || !upgradeDownloadRootPEM.MatchString(policy.RootCA))) {
		return ErrInvalidUpgradeDownloadPolicy
	}
	seen := make(map[netip.Addr]bool, len(policy.Addresses))
	for _, raw := range policy.Addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.String() != raw || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() ||
			seen[address.Unmap()] {
			return ErrInvalidUpgradeDownloadPolicy
		}
		seen[address.Unmap()] = true
	}
	if literal, err := netip.ParseAddr(policy.Host); err == nil &&
		(len(policy.Addresses) != 1 || policy.Addresses[0] != literal.String()) {
		return ErrInvalidUpgradeDownloadPolicy
	}
	parsed, err := url.Parse(downloadURL)
	if err != nil || !strings.EqualFold(parsed.Hostname(), policy.Host) {
		return ErrInvalidUpgradeDownloadPolicy
	}
	port := uint64(443)
	if parsed.Port() != "" {
		if port, err = strconv.ParseUint(parsed.Port(), 10, 16); err != nil {
			return ErrInvalidUpgradeDownloadPolicy
		}
	}
	if uint16(port) != policy.Port {
		return ErrInvalidUpgradeDownloadPolicy
	}
	return nil
}

func validUpgradeDownloadHost(host string) bool {
	if host == "" || host != strings.ToLower(host) || len(host) > 253 || strings.Contains(host, "xn--") {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String() == host && address.Zone() == ""
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !upgradeDownloadLabel.MatchString(label) {
			return false
		}
	}
	return net.ParseIP(host) == nil
}
