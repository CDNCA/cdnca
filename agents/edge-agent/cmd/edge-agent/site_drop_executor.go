package main

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
)

// siteDropXDP is the XDP filter's site drop (xdp.Manager).
type siteDropXDP interface {
	Running() bool
	SetSiteDrop(xdp.SiteDrop) error
}

// siteDropNFT is the nftables site drop in inet cdnca_ddos (ddos.Manager).
type siteDropNFT interface {
	SetSiteDropPorts(ctx context.Context, ports []uint16) error
}

// kernelSiteDropExecutor is the real SiteDropExecutor (esc-node §3):
//   - exclusive ports: nftables always (so a run time XDP fallback leaves no
//     gap), and XDP too in xdp mode (dropped at the NIC first);
//   - shared TLS ports: XDP by SNI in xdp mode (the plan has none otherwise);
//   - Hosts: OpenResty (444) through hosts.
//
// nft or hosts may be nil (no nft binary / no OpenResty host pusher yet): a
// plan needing them answers errSiteDropUnsupported.
type kernelSiteDropExecutor struct {
	xdp   siteDropXDP
	nft   siteDropNFT
	hosts siteDropHostPusher
}

// newKernelSiteDropExecutor is the daemon's executor: names always go to
// OpenResty over the dynamic routing control socket, so a plan with Hosts is
// enforced rather than answered errSiteDropUnsupported.
func newKernelSiteDropExecutor(filter siteDropXDP, nft siteDropNFT, controlSocket string) kernelSiteDropExecutor {
	return kernelSiteDropExecutor{xdp: filter, nft: nft, hosts: newControlSocketHostPusher(controlSocket)}
}

func (executor kernelSiteDropExecutor) Apply(ctx context.Context, plan siteDropPlan) error {
	if plan.empty() {
		return executor.Clear(ctx)
	}
	useXDP := plan.Mode == siteDropModeXDP
	// No receipt claims a drop the node does not do: exclusive ports need
	// nftables or XDP, names need OpenResty.
	if len(plan.Ports) != 0 && executor.nft == nil && !useXDP || len(plan.Hosts) != 0 && executor.hosts == nil {
		return errSiteDropUnsupported
	}
	if useXDP && (executor.xdp == nil || !executor.xdp.Running()) {
		// XDP fell back since the plan was derived: the next derivation
		// is nftables.
		return xdp.ErrNotRunning
	}
	var errs []error
	if executor.nft != nil {
		errs = append(errs, executor.nft.SetSiteDropPorts(ctx, plan.Ports))
	}
	if executor.xdp != nil && executor.xdp.Running() {
		drop := xdp.SiteDrop{}
		if useXDP {
			drop = xdp.SiteDrop{Ports: plan.Ports, SNIPorts: plan.SNIPorts, DropNames: plan.ServerNames,
				KeepNames: plan.KeepNames}
		}
		errs = append(errs, executor.xdp.SetSiteDrop(drop))
	}
	if executor.hosts != nil {
		if len(plan.Hosts) != 0 {
			errs = append(errs, executor.hosts.PushHosts(ctx, plan.Hosts))
		} else {
			errs = append(errs, executor.hosts.ClearHosts(ctx))
		}
	}
	return errors.Join(errs...)
}

func (executor kernelSiteDropExecutor) Clear(ctx context.Context) error {
	var errs []error
	if executor.nft != nil {
		errs = append(errs, executor.nft.SetSiteDropPorts(ctx, nil))
	}
	if executor.xdp != nil && executor.xdp.Running() {
		errs = append(errs, executor.xdp.SetSiteDrop(xdp.SiteDrop{}))
	}
	if executor.hosts != nil {
		errs = append(errs, executor.hosts.ClearHosts(ctx))
	}
	return errors.Join(errs...)
}
