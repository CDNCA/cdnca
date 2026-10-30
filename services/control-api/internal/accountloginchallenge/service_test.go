package accountloginchallenge

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

var loginChallengeTestKey = bytes.Repeat([]byte{0x41}, 32)

func TestNormalizeLoginChallengeBindsCanonicalIdentifierAndSource(t *testing.T) {
	t.Parallel()

	input := CreateInput{
		ScopeID: uuid.New(), Identifier: " OWNER@EXAMPLE.COM ", Channel: notification.ChannelEmail,
		Source: "2001:db8::1", IdempotencyKey: "login-create-1", RequestID: "login-request-1",
	}
	normalized, err := normalizeCreate(input, loginChallengeTestKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Identifier != "owner@example.com" || normalized.Source != "2001:db8::1" ||
		normalized.IdentifierDigest == ([32]byte{}) || normalized.SourceDigest == ([32]byte{}) {
		t.Fatalf("normalized input = %+v", normalized)
	}
	changed := input
	changed.Identifier = "other@example.com"
	second, err := normalizeCreate(changed, loginChallengeTestKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if second.IdentifierDigest == normalized.IdentifierDigest {
		t.Fatal("identifier was not bound into the challenge digest")
	}
}

func TestNormalizeLoginChallengeRejectsUnsafeBindings(t *testing.T) {
	t.Parallel()

	valid := CreateInput{
		ScopeID: uuid.New(), Identifier: "owner@example.com", Channel: notification.ChannelEmail,
		Source: "192.0.2.8", IdempotencyKey: "login-create-1", RequestID: "login-request-1",
	}
	for name, mutate := range map[string]func(*CreateInput){
		"scope":         func(input *CreateInput) { input.ScopeID = uuid.Nil },
		"identifier":    func(input *CreateInput) { input.Identifier = "invalid" },
		"channel":       func(input *CreateInput) { input.Channel = notification.Channel("push") },
		"mapped source": func(input *CreateInput) { input.Source = "::ffff:192.0.2.8" },
		"idempotency":   func(input *CreateInput) { input.IdempotencyKey = "contains space" },
		"request":       func(input *CreateInput) { input.RequestID = "contains space" },
		"human token":   func(input *CreateInput) { input.HumanToken = string(bytes.Repeat([]byte{'x'}, 4097)) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input := valid
			mutate(&input)
			if _, err := normalizeCreate(input, loginChallengeTestKey, ""); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalize error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestLoginMethodPolicyKeepsEmailAndSMSIndependent(t *testing.T) {
	t.Parallel()

	policy := systemusersettings.PublicSettings{
		EmailCodeLoginEnabled: true, EmailAntiAbuseMode: "none",
		SMSCodeLoginEnabled: false, SMSAntiAbuseMode: "native",
	}
	if mode, enabled := loginMethodPolicy(policy, notification.ChannelEmail); mode != "none" || !enabled {
		t.Fatalf("email policy = (%q,%t)", mode, enabled)
	}
	if mode, enabled := loginMethodPolicy(policy, notification.ChannelSMS); mode != "native" || enabled {
		t.Fatalf("sms policy = (%q,%t)", mode, enabled)
	}
	if mode, enabled := loginMethodPolicy(policy, notification.Channel("push")); mode != "native" || enabled {
		t.Fatalf("unsupported policy = (%q,%t)", mode, enabled)
	}
}

func TestPublicMethodsExposeCaptchaWidgetOnlyForExternalModes(t *testing.T) {
	t.Parallel()

	policy := systemusersettings.PublicSettings{EmailCodeLoginEnabled: true, EmailAntiAbuseMode: "none",
		SMSAntiAbuseMode: "native", CaptchaProvider: "tencent", CaptchaAppID: "190000001"}
	if methods := publicMethods(policy); methods.CaptchaProvider != "" || methods.CaptchaAppID != "" {
		t.Fatalf("captcha widget leaked for built-in modes: %#v", methods)
	}
	policy.SMSAntiAbuseMode = "tencent"
	if methods := publicMethods(policy); methods.CaptchaProvider != "tencent" || methods.CaptchaAppID != "190000001" ||
		methods.SMSAntiAbuseMode != "tencent" || !methods.EmailEnabled {
		t.Fatalf("external captcha methods = %#v", methods)
	}
}

func TestNativeAntiAbuseUsesBuiltInRateLimitsWithoutExternalToken(t *testing.T) {
	t.Parallel()

	if externalHumanMode("none") || externalHumanMode("native") ||
		!externalHumanMode("tencent") || !externalHumanMode("geetest_v4") {
		t.Fatal("external human verification mode classification changed")
	}
}

func TestRandomOTPIsAlwaysSixDigits(t *testing.T) {
	t.Parallel()

	otp, err := randomOTP(bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if otp != "000000" || !otpPattern.MatchString(otp) {
		t.Fatalf("otp = %q", otp)
	}
}

type registrationPolicy struct{ enabled bool }

func (policy registrationPolicy) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return systemusersettings.PublicSettings{RegistrationEnabled: policy.enabled, EmailAntiAbuseMode: "native", SMSAntiAbuseMode: "native"}, nil
}

// vis-1: the sign-in page shows the sign-up link only when the registration
// switch is on and the registration endpoints are mounted.
func TestMethodsAdvertiseRegistrationOnlyWhenSwitchOnAndMounted(t *testing.T) {
	t.Parallel()

	scope := uuid.New()
	for _, item := range []struct {
		enabled, mounted, want bool
	}{{false, true, false}, {true, false, false}, {false, false, false}, {true, true, true}} {
		service := &Service{policy: registrationPolicy{enabled: item.enabled}, registrationMounted: item.mounted}
		methods, err := service.Methods(context.Background(), scope)
		if err != nil || methods.RegistrationEnabled != item.want {
			t.Fatalf("enabled=%t mounted=%t: methods=%#v err=%v", item.enabled, item.mounted, methods, err)
		}
	}
}
