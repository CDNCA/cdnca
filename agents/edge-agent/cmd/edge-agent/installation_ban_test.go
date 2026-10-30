package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/installationban"
)

type restoreServing struct {
	stopErr error
	stops   int
}

func (serving *restoreServing) Stop(context.Context, time.Time) error {
	serving.stops++
	return serving.stopErr
}

func (*restoreServing) Resume(context.Context) error { return nil }

// 验收 acc-a DA-4：节点停服（无票据）且 HTTPS 站点证书暂不可用时，Restore 里的
// Stop 返回"已激活、维护失败"，daemon 原先直接退出，systemd 反复拉起。
func TestRestoreInstallationBanToleratesActivatedMaintenanceFailure(t *testing.T) {
	serving := &restoreServing{stopErr: &dynroute.MaintenanceError{Generation: 7, Step: "retain",
		Err: errors.New("certificate version unavailable")}}
	ban, err := installationban.New(installationban.Config{Dir: t.TempDir(), InstallationID: "installation-1",
		Keys: func() map[string]ed25519.PublicKey { return nil }, Serving: serving})
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreInstallationBan(t.Context(), ban); err != nil {
		t.Fatalf("activated maintenance failure stopped the agent: %v", err)
	}
	// still retried by the next tick
	if _, err := ban.Tick(t.Context()); err == nil || serving.stops != 2 {
		t.Fatalf("tick err=%v stops=%d", err, serving.stops)
	}
	serving.stopErr = nil
	if _, err := ban.Tick(t.Context()); err != nil || serving.stops != 3 {
		t.Fatalf("recovered tick err=%v stops=%d", err, serving.stops)
	}
	if _, err := ban.Tick(t.Context()); err != nil || serving.stops != 3 {
		t.Fatalf("stopped again after success: stops=%d", serving.stops)
	}

	// Any other failure still ends the start.
	other := &restoreServing{stopErr: errors.New("openresty reload failed")}
	failing, err := installationban.New(installationban.Config{Dir: t.TempDir(), InstallationID: "installation-1",
		Keys: func() map[string]ed25519.PublicKey { return nil }, Serving: other})
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreInstallationBan(t.Context(), failing); err == nil {
		t.Fatal("a stop that did not activate was tolerated")
	}
}

// gatewayclient 经可选接口 Frozen() 识别冻结；适配器必须实现它，
// 否则冻结的节点仍会接受新发布与升级。新节点首票前即冻结。
func TestInstallationBanAgentReportsFrozen(t *testing.T) {
	var _ interface{ Frozen() bool } = installationBanAgent{}
	runtime, err := installationban.New(installationban.Config{Dir: t.TempDir(), InstallationID: "0190a000-0000-7000-8000-000000000001",
		Keys: func() map[string]ed25519.PublicKey { return nil }, Serving: &restoreServing{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Restore(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !(installationBanAgent{runtime: runtime}).Frozen() {
		t.Fatal("a node without a ticket must report frozen")
	}
}
