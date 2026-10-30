package nodeserving

import "testing"

func TestDecideConfigSync(t *testing.T) {
	for name, test := range map[string]struct {
		input  ConfigSyncInput
		held   bool
		reason string
	}{
		"switch off releases":          {ConfigSyncInput{Held: true, Reason: ReasonSyncFailed, NodeActive: true, Failing: true}, false, ReasonSyncDisabled},
		"failing node is held":         {ConfigSyncInput{Enabled: true, NodeActive: true, Failing: true}, true, ReasonSyncFailed},
		"over half of a group refused": {ConfigSyncInput{Enabled: true, NodeActive: true, Failing: true, OverLimit: true}, false, ReasonSyncLimitGuard},
		"held while retry runs":        {ConfigSyncInput{Enabled: true, NodeActive: true, Running: true, Held: true, Reason: ReasonSyncFailed}, true, ReasonSyncFailed},
		"held while still failing":     {ConfigSyncInput{Enabled: true, NodeActive: true, Failing: true, Held: true, Reason: ReasonSyncFailed, OverLimit: true}, true, ReasonSyncFailed},
		"healthy again releases":       {ConfigSyncInput{Enabled: true, NodeActive: true, Held: true, Reason: ReasonSyncFailed}, false, ReasonSyncRecovered},
		"inactive node released":       {ConfigSyncInput{Enabled: true, Failing: true, Held: true, Reason: ReasonSyncFailed}, false, ReasonNodeInactive},
		"healthy stays released":       {ConfigSyncInput{Enabled: true, NodeActive: true, Reason: ReasonSyncRecovered}, false, ReasonSyncRecovered},
	} {
		decision := DecideConfigSync(test.input)
		if decision.Held != test.held || decision.Reason != test.reason {
			t.Errorf("%s: got held=%v reason=%s, want held=%v reason=%s", name, decision.Held, decision.Reason, test.held, test.reason)
		}
	}
}
