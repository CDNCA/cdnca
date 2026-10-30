package platformpolicy

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
)

func TestCCProtectionPatchUsesOpenRestySecurityContract(t *testing.T) {
	patch := ccProtectionPatch(CCProtection{
		CCEnable: true, BlockTime: 3600, WhiteTime: 21600,
		TmpWhiteTotalLimit: 400, TmpWhitePerLimit: 50, DefaultPageRule: "10003",
		AutoSwitch: CCAutoSwitch{Enable: true, QPS50x: 50, QPSTotal: 1000, Rule: "10003", Seconds: 300},
	})
	config, err := openrestysecurity.ApplyPatch(openrestysecurity.DefaultGlobalConfig(), patch, false)
	if err != nil {
		t.Fatalf("ApplyPatch() error = %v", err)
	}
	var enabled bool
	if err := json.Unmarshal(config["cc_enable"], &enabled); err != nil || !enabled {
		t.Fatalf("cc_enable = %s", config["cc_enable"])
	}
	var autoSwitch map[string]any
	if err := json.Unmarshal(config["auto_switch"], &autoSwitch); err != nil || autoSwitch["rule"] != "10003" {
		t.Fatalf("auto_switch = %s", config["auto_switch"])
	}
}
