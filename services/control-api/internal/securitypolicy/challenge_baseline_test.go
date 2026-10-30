package securitypolicy

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/google/uuid"
)

// TestChallengeWithoutProofOfWorkFieldsIsRefused: the 1.0.33 challenge shape
// (no proof of work, page lifetime, pass binding or key rotation) is not a
// valid policy from the 1.0.35 baseline on; a challenge always carries them.
func TestChallengeWithoutProofOfWorkFieldsIsRefused(t *testing.T) {
	policy := expandedPolicy(t, seedCatalog(), "cc_rule:10001")
	if err := ValidatePublishablePolicy(policy); err != nil {
		t.Fatalf("catalog policy refused: %v", err)
	}
	stripped := policy
	stripped.Rules = cloneRules(policy.Rules)
	challenge := *stripped.Rules[0].ActionConfig.Challenge
	challenge.PowBits, challenge.DelaySeconds, challenge.ChallengeSeconds = 0, 0, 0
	challenge.BindIPv4Prefix, challenge.BindIPv6Prefix, challenge.KeyRotateSeconds = 0, 0, 0
	stripped.Rules[0].ActionConfig.Challenge = &challenge
	if err := ValidatePublishablePolicy(stripped); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("challenge without proof-of-work fields = %v, want ErrInvalidInput", err)
	}
	if _, err := CompileRuntimeSnapshot(stripped, uuid.New()); err == nil {
		t.Fatal("challenge without proof-of-work fields compiled")
	}
}

// TestCatalogChallengesAlwaysCarryProofOfWork: every catalog group expands to
// challenges with proof of work (redirect has none by design) and a page
// lifetime, and a policy with a challenge needs CC v3.
func TestCatalogChallengesAlwaysCarryProofOfWork(t *testing.T) {
	items := seedCatalog()
	challenges := 0
	for key, item := range items {
		if item.Kind != rulecatalog.KindCCRuleGroup || len(item.Body.CCRuleGroup.Entries) == 0 {
			continue
		}
		rules, err := ExpandCCRuleGroup(items, key)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		groupChallenges := 0
		for index := range rules {
			rules[index].ID = uuid.New()
			challenge := rules[index].ActionConfig.Challenge
			if challenge == nil {
				continue
			}
			groupChallenges++
			if challenge.ChallengeSeconds < 30 || (challenge.Type != "redirect") != (challenge.PowBits != 0) {
				t.Fatalf("%s rule %d: %+v", key, index, challenge)
			}
		}
		policy := Policy{ID: uuid.New(), ScopeID: uuid.New(), Kind: KindCC, Name: key, Enabled: true,
			DefaultAction: ActionAllow, Revision: 1, Rules: rules}
		if err := ValidatePublishablePolicy(policy); err != nil {
			t.Fatalf("%s refused: %v", key, err)
		}
		challenges += groupChallenges
		if got := PolicyCCAPIVersion(policy); groupChallenges > 0 && got < ccProofOfWorkAPIVersion {
			t.Fatalf("%s needs CC v%d, want at least v%d", key, got, ccProofOfWorkAPIVersion)
		}
	}
	if challenges == 0 {
		t.Fatal("no catalog challenge exercised")
	}
}
