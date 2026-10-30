package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/installationban"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// installationBanServing stops and resumes the node's dynamic routing
// runtime (ADR 0014 §6.2): the maintenance skeleton for every site server
// and no L4 forwards, then the previous configuration again.
type installationBanServing struct {
	runtime *dynroute.Runtime
	manager interface{ Reapply(context.Context) error }
}

func (serving installationBanServing) Stop(ctx context.Context, retryAfter time.Time) error {
	serving.runtime.SetMaintenance(&edgeskeleton.Maintenance{RetryAfter: installationban.RetryAfterHeader(retryAfter)})
	return serving.manager.Reapply(ctx)
}

func (serving installationBanServing) Resume(ctx context.Context) error {
	serving.runtime.SetMaintenance(nil)
	return serving.manager.Reapply(ctx)
}

// installationBanAgent adapts installationban.Runtime to the gateway client.
type installationBanAgent struct{ runtime *installationban.Runtime }

// Frozen lets the gateway client refuse new publications and upgrades while
// the node's service ticket is expired.
func (agent installationBanAgent) Frozen() bool { return agent.runtime.Frozen() }

func (agent installationBanAgent) ApplyInstallationBan(ctx context.Context, notice, ticket []byte) gatewayclient.InstallationBanResult {
	result := agent.runtime.Apply(ctx, notice, ticket)
	answer := gatewayclient.InstallationBanResult{Applied: result.Applied, Status: string(result.Status), Reason: result.Reason}
	if held := agent.runtime.Ticket(); held != nil {
		answer.TicketIssuedAt, answer.TicketNotAfter = time.Unix(held.IssuedAt, 0).UTC(), time.Unix(held.NotAfter, 0).UTC()
	}
	return answer
}

// assembleInstallationBanWithClock builds the node's installation ban runtime
// with the runtime's clock (tests/license-ban-e2e injects one). cdncaCE: the
// daemon does not assemble it (no license service issues service tickets).
func assembleInstallationBanWithClock(config fileConfig, runtime *dynroute.Runtime,
	manager *dynamicRoutingManager, trust *gatewayclient.TrustStore, now func() time.Time,
) (*installationban.Runtime, error) {
	if runtime == nil || manager == nil || config.Upgrade.InstallationID == "" {
		return nil, nil
	}
	ban, err := installationban.New(installationban.Config{
		Dir: filepath.Join(config.JournalDir, "installation-ban"), InstallationID: config.Upgrade.InstallationID,
		Keys:    func() map[string]ed25519.PublicKey { return trust.InstallationBanKeys() },
		Serving: installationBanServing{runtime: runtime, manager: manager}, Now: now, Logger: slog.Default(),
	})
	if err != nil {
		return nil, fmt.Errorf("configure installation ban: %w", err)
	}
	return ban, nil
}

// restoreInstallationBan restores the persisted state at start. A stop whose
// configuration was activated but whose bookkeeping failed (for example a
// referenced certificate version is not on the node yet) serves the
// maintenance configuration already: it is logged and the ticks retry it,
// instead of ending the agent and restarting it in a loop (acc-a DA-4).
func restoreInstallationBan(ctx context.Context, ban *installationban.Runtime) error {
	err := ban.Restore(ctx)
	if err != nil && gatewayclient.DynamicRoutingActivated(err) {
		slog.Warn("installation ban: restored, the activated configuration's maintenance failed; retried every minute",
			"error", err)
		return nil
	}
	return err
}

// runInstallationBanTicks re-evaluates the ticket every minute: a node that
// cannot renew within the offline tolerance stops by itself.
func runInstallationBanTicks(ctx context.Context, ban *installationban.Runtime) {
	runInstallationBanTicksEvery(ctx, ban, time.Minute)
}

func runInstallationBanTicksEvery(ctx context.Context, ban *installationban.Runtime, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if status, err := ban.Tick(ctx); err != nil {
				slog.Error("installation ban: could not enforce the node status", "status", status, "error", err)
			}
		}
	}
}
