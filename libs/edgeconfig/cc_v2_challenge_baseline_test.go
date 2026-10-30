package edgeconfig

import (
	"strings"
	"testing"
)

func challengeCCV2Policy(challenge CCV2Challenge, banSeconds uint32) CCV2Policy {
	policy := testCCV2Policy("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "11111111-1111-4111-8111-111111111111")
	policy.Rules[0].Flow = CCV2FlowStop
	policy.Rules[0].Action = CCV2Action{Kind: CCV2ActionChallenge, BanSeconds: banSeconds, Challenge: &challenge}
	return policy
}

// A challenge always carries proof of work (redirect: none), page lifetime,
// pass binding and key rotation, needs CC v3 and encodes every field. The
// 1.0.33 shape without them is invalid from the 1.0.35 baseline on.
func TestCCV2ChallengeRequiresProofOfWorkFields(t *testing.T) {
	full := challengeCCV2Policy(CCV2Challenge{Mode: "js", FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 3600,
		PowBits: 16, ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}, 60)
	encoded, err := CanonicalCCV2Policy(full)
	if err != nil || !strings.Contains(string(encoded), `"pow_bits":16,"challenge_seconds":120`) ||
		!CCV2PolicyNeedsProofOfWork(full) || CCV2PolicyAPIVersion(full) != 3 {
		t.Fatalf("challenge = %s, %v", encoded, err)
	}
	redirect := challengeCCV2Policy(CCV2Challenge{Mode: "redirect", FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 3600,
		ChallengeSeconds: 120, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}, 60)
	if encoded, err := CanonicalCCV2Policy(redirect); err != nil || !strings.Contains(string(encoded), `"pow_bits":0`) ||
		CCV2PolicyAPIVersion(redirect) != 3 {
		t.Fatalf("redirect = %s, %v", encoded, err)
	}
	for name, challenge := range map[string]CCV2Challenge{
		"1.0.33 js":       {Mode: "js", FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 21600},
		"1.0.33 delay":    {Mode: "delay", DelaySeconds: 5, FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 21600},
		"1.0.33 redirect": {Mode: "redirect", FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 21600},
	} {
		if _, err := CanonicalCCV2Policy(challengeCCV2Policy(challenge, 360)); err == nil {
			t.Fatalf("%s challenge accepted", name)
		}
	}
}
