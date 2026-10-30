package identity

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestLoginSecurityCanonicalIPsAndRejectsUnsafeInput(t *testing.T) {
	got, err := normalizeLoginSecurity("email", []string{"2001:0db8::1", "::ffff:192.0.2.1", "192.0.2.1", "198.51.100.9/24"})
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.1", "198.51.100.0/24", "2001:db8::1"}) {
		t.Fatalf("canonical allowlist=%v err=%v", got, err)
	}
	for name, input := range map[string][]string{
		"bad cidr": {"192.0.2.0/33"}, "port": {"192.0.2.1:443"}, "zone": {"fe80::1%en0"},
		"blank": {""}, "whitespace": {" 192.0.2.1"}, "too many": strings.Split(strings.Repeat("192.0.2.1,", 32)+"192.0.2.2", ","),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeLoginSecurity("none", input); !errors.Is(err, ErrInvalidUserInput) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if _, err := normalizeLoginSecurity("totp", []string{}); !errors.Is(err, ErrInvalidUserInput) {
		t.Fatal(err)
	}
}

func TestLoginSecurityCannotUsePasswordlessBypassOrUnknownIP(t *testing.T) {
	policy := ManagedUserLoginSecurity{UserID: uuid.New(), TenantScopeID: uuid.New(), LoginVerification: "email", LoginAllowlist: []string{"192.0.2.1"}}
	if err := checkLoginSecurity(policy, "192.0.2.1", false, nil); !errors.Is(err, ErrLoginChallengeInvalid) {
		t.Fatalf("passwordless bypass: %v", err)
	}
	for _, source := range []string{"", "invalid", "192.0.2.2"} {
		if err := checkLoginSecurity(policy, source, true, nil); !errors.Is(err, ErrLoginSourceDenied) {
			t.Fatalf("source=%q err=%v", source, err)
		}
	}
	var required *LoginVerificationRequired
	if err := checkLoginSecurity(policy, "192.0.2.1", true, nil); !errors.As(err, &required) || required.Channel != "email" || required.ScopeID != policy.TenantScopeID {
		t.Fatalf("required=%v err=%v", required, err)
	}
	if err := checkLoginSecurity(policy, "::ffff:192.0.2.1", true, &LoginChallengeProof{ChallengeID: uuid.New(), OTP: "123456"}); err != nil {
		t.Fatal(err)
	}
	policy.LoginVerification, policy.LoginAllowlist = "none", []string{"203.0.113.0/24"}
	if err := checkLoginSecurity(policy, "203.0.113.77", true, nil); err != nil {
		t.Fatalf("cidr allowlist: %v", err)
	}
	if err := checkLoginSecurity(policy, "203.0.114.1", true, nil); !errors.Is(err, ErrLoginSourceDenied) {
		t.Fatalf("outside cidr: %v", err)
	}
	policy.LoginAllowlist = []string{}
	if err := checkLoginSecurity(policy, "", true, nil); err != nil {
		t.Fatalf("legacy default: %v", err)
	}
}
