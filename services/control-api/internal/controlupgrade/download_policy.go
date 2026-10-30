package controlupgrade

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

// DownloadPolicySource is the control plane's current upgrade download
// endpoint, signed into every execution (fix-btenv3): a control plane moved
// to another host or between the plain and BaoTa layouts updates the
// addresses, port and root its nodes dial on their next upgrade.
type DownloadPolicySource struct {
	// RootCAFile is the private root that verifies the download endpoint
	// (BaoTa direct port, IP control plane, operator certificate the system
	// store rejects); empty means the node keeps its system root.
	RootCAFile string
	// LookupHost resolves the download host; net.DefaultResolver when nil.
	LookupHost func(context.Context, string) ([]string, error)
}

// Policy returns the policy for downloadURL, or nil when it cannot be built
// (resolution or root CA failure): the node then keeps its installed policy,
// so a transient failure never blocks an upgrade.
func (source DownloadPolicySource) Policy(ctx context.Context, downloadURL string) *entitlement.UpgradeDownloadPolicy {
	policy, err := source.Resolve(ctx, downloadURL)
	if err != nil {
		return nil
	}
	return policy
}

// Resolve is Policy with the failure reason. The node install trust document
// (nativebackup.PublishNodeInstallTrust, fix-btenv4) uses it: a fresh install
// or a restore must not publish a document without a download policy.
func (source DownloadPolicySource) Resolve(ctx context.Context, downloadURL string) (*entitlement.UpgradeDownloadPolicy, error) {
	parsed, err := url.Parse(downloadURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return nil, errors.New("the upgrade artifact base URL is not an https URL")
	}
	host := parsed.Hostname()
	port := 443
	if parsed.Port() != "" {
		if port, err = strconv.Atoi(parsed.Port()); err != nil {
			return nil, errors.New("the upgrade artifact base URL has an invalid port")
		}
	}
	root := entitlement.UpgradeDownloadSystemRoot
	if source.RootCAFile != "" {
		content, err := os.ReadFile(source.RootCAFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read the root CA for node upgrade downloads: %w", err)
		}
		root = string(content)
	}
	var addresses []string
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []string{literal.String()}
	} else {
		lookup := source.LookupHost
		if lookup == nil {
			lookup = net.DefaultResolver.LookupHost
		}
		lookupContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		resolved, err := lookup(lookupContext, host)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %s for node upgrade downloads: %w", host, err)
		}
		// Same filter as install-control.sh publish_upgrade_trust.
		seen := map[netip.Addr]bool{}
		for _, raw := range resolved {
			address, err := netip.ParseAddr(raw)
			if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsLoopback() ||
				address.Is4In6() || address.IsMulticast() || seen[address] {
				continue
			}
			seen[address] = true
			addresses = append(addresses, address.String())
		}
		sort.Strings(addresses)
		if len(addresses) > 16 {
			addresses = addresses[:16]
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%s does not resolve to a non-loopback address for node upgrade downloads", host)
	}
	policy := &entitlement.UpgradeDownloadPolicy{Host: host, Port: uint16(port), Addresses: addresses, RootCA: root}
	if err := policy.Validate(downloadURL); err != nil {
		return nil, err
	}
	return policy, nil
}
