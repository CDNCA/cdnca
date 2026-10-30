package dynroute

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// E1 (PJ-E02/E03): what follows an activated generation.

type failingDDoS struct{ err error }

func (f failingDDoS) Apply(context.Context, *ddos.Spec) error { return f.err }

type failingRulePlans struct{ err error }

func (failingRulePlans) Root() string { return "" }
func (failingRulePlans) Prepare([]edgesite.Site, map[string][]byte, *edgeconfig.CRSRuleText,
	map[string]edgeconfig.CRSProfile) ([]edgeconfig.CRSTuningEntry, error) {
	return nil, nil
}
func (f failingRulePlans) Retain(map[string]bool) error { return f.err }

func TestMaintenanceFailuresAfterActivationAreMaintenanceErrors(t *testing.T) {
	sites := []edgesite.Site{testSite(testScopeA, testSiteA, 80)}
	system := testSystem(t, 1, edgeconfig.CCKernelBanOff)

	t.Run("save_state", func(t *testing.T) {
		runtime := newTestRuntime(t, 0)
		recorded := &recordedDDoS{}
		runtime.config.DDoS = recorded
		// state.json cannot be renamed into place: a directory occupies it.
		if err := os.MkdirAll(filepath.Join(runtime.statePath(), "occupied"), 0o700); err != nil {
			t.Fatal(err)
		}
		err := runtime.maintainActivated(context.Background(), 7, system, sites, nil, nil)
		var maintenance *MaintenanceError
		if !errors.As(err, &maintenance) || maintenance.Step != "save_state" || maintenance.Generation != 7 ||
			!maintenance.ActivatedMaintenanceFailure() {
			t.Fatalf("error %v", err)
		}
		// the DDoS table still follows the active generation
		if len(recorded.specs) != 1 || recorded.specs[0] == nil {
			t.Fatalf("specs %+v", recorded.specs)
		}
	})

	t.Run("retain", func(t *testing.T) {
		runtime := newTestRuntime(t, 0)
		runtime.config.RulePlans = failingRulePlans{err: errors.New("plans directory read-only")}
		err := runtime.maintainActivated(context.Background(), 3, system, sites, nil, nil)
		var maintenance *MaintenanceError
		if !errors.As(err, &maintenance) || maintenance.Generation != 3 || maintenance.Step != "retain_rule_plans" {
			t.Fatalf("error %v", err)
		}
		if _, statErr := os.Stat(runtime.statePath()); statErr != nil {
			t.Fatalf("state was not saved before retention: %v", statErr)
		}
		// the certificate pool cannot be read: the retention itself fails
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode 000 directory")
		}
		runtime.config.RulePlans = nil
		pool := filepath.Join(runtime.config.StateRoot, "tls-pool")
		if err := os.Chmod(pool, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(pool, 0o750) })
		err = runtime.maintainActivated(context.Background(), 4, system, sites, nil, nil)
		if !errors.As(err, &maintenance) || maintenance.Generation != 4 || maintenance.Step != "retain" {
			t.Fatalf("error %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		runtime := newTestRuntime(t, 0)
		if err := runtime.maintainActivated(context.Background(), 1, system, sites, nil, nil); err != nil {
			t.Fatal(err)
		}
	})
}

func TestApplyDDoSFailureIsKeptForTheReceipt(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	if _, ok := runtime.DDoSStatus(); ok {
		t.Fatal("status before any application")
	}
	sites := []edgesite.Site{testSite(testScopeA, testSiteA, 80)}
	runtime.config.DDoS = failingDDoS{err: errors.New("nft: Error: Could not process rule\nline 2")}
	runtime.applyDDoS(context.Background(), testSystem(t, 1, edgeconfig.CCKernelBanOff), sites, nil)
	status, ok := runtime.DDoSStatus()
	if !ok || status.State != DDoSFailed || status.Detail == "" || status.At.IsZero() {
		t.Fatalf("status %+v %v", status, ok)
	}
	// the next application succeeds: the failure clears
	runtime.config.DDoS = &recordedDDoS{}
	runtime.applyDDoS(context.Background(), testSystem(t, 1, edgeconfig.CCKernelBanOff), sites, nil)
	if status, _ := runtime.DDoSStatus(); status.State != DDoSApplied || status.Detail != "" {
		t.Fatalf("status %+v", status)
	}
	runtime.applyDDoS(context.Background(), nil, sites, nil)
	if status, _ := runtime.DDoSStatus(); status.State != DDoSOff {
		t.Fatalf("status %+v", status)
	}
}

// E1 遗留：回滚后的 generation 已生效，state.json 写不进去也是"已激活、维护失败"，不能当回滚失败。
func TestRollbackSaveFailureIsMaintenanceError(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	if err := runtime.saveRolledBack(4); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := os.Remove(runtime.statePath()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runtime.statePath(), "occupied"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := runtime.saveRolledBack(5)
	var maintenance *MaintenanceError
	if !errors.As(err, &maintenance) || maintenance.Step != "save_state" || maintenance.Generation != 5 ||
		!maintenance.ActivatedMaintenanceFailure() {
		t.Fatalf("error %v", err)
	}
}

