package firewallactioncontrol

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSettleReceipt(t *testing.T) {
	for name, test := range map[string]struct {
		carriers []receiptRollout
		want     receiptOutcome
	}{
		"no carrier waits":                {nil, receiptWait},
		"running waits":                   {[]receiptRollout{{running: 2}}, receiptWait},
		"one healthy applies":             {[]receiptRollout{{healthy: 1, failed: 3}}, receiptApplied},
		"healthy in a later release":      {[]receiptRollout{{failed: 1}, {healthy: 1}}, receiptApplied},
		"all failed rejects":              {[]receiptRollout{{failed: 2}}, receiptRejected},
		"failed while another runs":       {[]receiptRollout{{failed: 2}, {running: 1}}, receiptWait},
		"cancelled only waits":            {[]receiptRollout{{}}, receiptWait},
		"failed and running in one waits": {[]receiptRollout{{failed: 1, running: 1}}, receiptWait},
	} {
		if got := settleReceipt(test.carriers); got != test.want {
			t.Errorf("%s: settleReceipt() = %v, want %v", name, got, test.want)
		}
	}
}

func TestSnapshotFirewallActionBindings(t *testing.T) {
	siteID, policyID := uuid.New(), uuid.New()
	snapshot := `{"configuration_scope_id":"x","sites":[{"id":"` + siteID.String() + `","firewall_action":{"policy_id":"` +
		policyID.String() + `","policy_revision":3,"document_sha256":"ab","artifact_path":"firewall-action/` + siteID.String() +
		`.json"}},{"id":"` + uuid.NewString() + `"}]}`
	bindings := snapshotFirewallActionBindings([]byte(snapshot))
	if len(bindings) != 1 || !bindings[receiptBinding{siteID: siteID, policyID: policyID, revision: 3, digest: "ab"}] {
		t.Fatalf("bindings = %+v", bindings)
	}
	for _, other := range []string{"", "not json", `{"kind":"error_pages"}`, `{"sites":[{"id":"bad","firewall_action":{"policy_id":"bad"}}]}`} {
		if got := snapshotFirewallActionBindings([]byte(other)); len(got) != 0 {
			t.Errorf("snapshotFirewallActionBindings(%q) = %+v", other, got)
		}
	}
}

func TestCarriesDefault(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	inherited := receiptBinding{siteID: siteID, policyID: InheritedPolicyID(scopeID, siteID), revision: 2}
	own := receiptBinding{siteID: siteID, policyID: uuid.New(), revision: 2}
	if !carriesDefault(map[receiptBinding]bool{inherited: true}, scopeID, 2) {
		t.Fatal("inherited delivery of revision 2 not recognized")
	}
	if carriesDefault(map[receiptBinding]bool{inherited: true}, scopeID, 3) ||
		carriesDefault(map[receiptBinding]bool{own: true}, scopeID, 2) ||
		carriesDefault(map[receiptBinding]bool{inherited: true}, uuid.New(), 2) {
		t.Fatal("unrelated binding taken as the tenant default")
	}
}

func TestMigration607Contract(t *testing.T) {
	up, err := os.ReadFile("../../migrations/607_firewall_action_default_receipt.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/607_firewall_action_default_receipt.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"version=606", "606_firewall_action_enabled", "active_revision", "lkg_revision", "deployment_state",
		"DROP TRIGGER firewall_action_tenant_defaults_guard_605", "guard_firewall_action_tenant_default_607",
		"lkg_revision=active_revision",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("up migration missing %q", fragment)
		}
	}
	for _, fragment := range []string{"version=607", "deployment_state<>'pending'", "firewall_action_tenant_defaults_guard_605"} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("down migration missing %q", fragment)
		}
	}
}
