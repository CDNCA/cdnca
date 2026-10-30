package systemusersettings

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

func TestDefaultSettingsAreValid(t *testing.T) {
	if !validSettings(DefaultSettings()) {
		t.Fatal("default settings must satisfy the service contract")
	}
}

func TestSettingsNotificationDefinitionsNormalizeOnlySupportedPlaceholders(t *testing.T) {
	definitions, err := settingsNotificationDefinitions(DefaultSettings(), 7)
	if err != nil {
		t.Fatalf("build notification definitions: %v", err)
	}
	if len(definitions) != 4 {
		t.Fatalf("definition count = %d, want 4", len(definitions))
	}
	for _, definition := range definitions {
		if definition.Ref.Version != 7 || strings.Contains(definition.Subject+definition.Body, "{{username}}") ||
			strings.Contains(definition.Subject+definition.Body, "{{captcha}}") ||
			strings.Contains(definition.Subject+definition.Body, "${captcha}") {
			t.Fatalf("definition was not normalized: %#v", definition)
		}
		catalog := notification.NewCatalog()
		if err := catalog.Register(definition); err != nil {
			t.Fatalf("definition is not renderable: %v", err)
		}
	}
}

func TestSettingsNotificationDefinitionsRejectUnknownAndSensitivePlaceholders(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Settings)
	}{
		{name: "unknown mustache", mutate: func(value *Settings) { value.VerificationBody = "验证码 {{unknown}} {{captcha}}" }},
		{name: "unknown dollar", mutate: func(value *Settings) { value.VerificationSMSBody = "${unknown} ${captcha}" }},
		{name: "dotted password", mutate: func(value *Settings) { value.PasswordResetBody = "{{ .password }} {{username}}" }},
		{name: "dollar password", mutate: func(value *Settings) { value.PasswordResetBody = "${password} {{username}}" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := DefaultSettings()
			test.mutate(&value)
			if validSettings(value) {
				if _, err := settingsNotificationDefinitions(value, 1); !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("definition error = %v, want ErrInvalidInput", err)
				}
				return
			}
			if test.name == "unknown mustache" || test.name == "unknown dollar" {
				t.Fatal("unknown placeholder should reach strict notification validation")
			}
		})
	}
}

func TestSettingsNotificationDefinitionsRequireCaptchaButAllowPlainLifecycleCopy(t *testing.T) {
	value := DefaultSettings()
	value.RegistrationSuccessBody = "<p>账户已创建。</p>"
	value.PasswordResetBody = "<p>请使用安全链接继续。</p>"
	definitions, err := settingsNotificationDefinitions(value, 2)
	if err != nil {
		t.Fatalf("plain lifecycle copy rejected: %v", err)
	}
	if len(definitions[0].Variables) != 0 || len(definitions[1].Variables) != 0 {
		t.Fatalf("plain lifecycle variables=(%v,%v)", definitions[0].Variables, definitions[1].Variables)
	}
	value.VerificationBody = "<p>请输入短信或邮件中的验证码。</p>"
	value.VerificationSubject = "用户验证码"
	if _, err := settingsNotificationDefinitions(value, 3); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing email captcha error=%v", err)
	}
}

func TestSettingsRejectPlaintextPasswordsAndSecretValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Settings)
	}{
		{"registration password template", func(value *Settings) { value.RegistrationSuccessBody = "Password: {{PASSWORD}}" }},
		{"reset password template", func(value *Settings) { value.PasswordResetBody = "{{password}}" }},
		{"captcha secret id", func(value *Settings) { value.CaptchaSecretIDReference = "plaintext-secret" }},
		{"captcha secret key", func(value *Settings) { value.CaptchaSecretKeyReference = "secret-key" }},
		{"captcha app secret", func(value *Settings) { value.CaptchaAppSecretReference = "app-secret" }},
		{"empty SMS verification body", func(value *Settings) { value.VerificationSMSBody = "" }},
		{"enterprise secret id", func(value *Settings) { value.EnterpriseSecretIDReference = "secret-id" }},
		{"enterprise secret key", func(value *Settings) { value.EnterpriseSecretKeyReference = "secret-key" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := DefaultSettings()
			test.mutate(&value)
			if validSettings(value) {
				t.Fatal("unsafe setting was accepted")
			}
		})
	}
	for _, emptyReference := range []string{"vault://", "kms-envelope://"} {
		value := DefaultSettings()
		value.CaptchaSecretIDReference = emptyReference
		if validSettings(value) {
			t.Fatalf("empty secret reference %q was accepted", emptyReference)
		}
	}

	value := DefaultSettings()
	value.CaptchaSecretIDReference = "vault://captcha/secret-id"
	value.CaptchaSecretKeyReference = "kms-envelope://captcha/secret-key"
	value.CaptchaAppSecretReference = "vault://captcha/app-secret"
	value.EnterpriseSecretIDReference = "kms-envelope://identity/secret-id"
	value.EnterpriseSecretKeyReference = "vault://identity/secret-key"
	if !validSettings(value) {
		t.Fatal("approved secret references must be accepted")
	}
}

func TestSettingsEnforceDependentFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Settings)
	}{
		{"email verification requires email", func(value *Settings) { value.EmailVerificationRequired = true }},
		{"phone verification requires phone", func(value *Settings) { value.PhoneVerificationRequired = true }},
		{"captcha threshold cannot exceed failure limit", func(value *Settings) { value.LoginCaptchaThresholdPerHour = value.LoginFailureLimitPerHour + 1 }},
		{"tencent anti abuse requires references", func(value *Settings) { value.EmailAntiAbuseMode = "tencent" }},
		{"geetest anti abuse requires references", func(value *Settings) { value.SMSAntiAbuseMode = "geetest_v4"; value.CaptchaProvider = "geetest_v4" }},
		{"enterprise verification requires references", func(value *Settings) { value.EnterpriseVerificationEnabled = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := DefaultSettings()
			test.mutate(&value)
			if validSettings(value) {
				t.Fatal("invalid dependent-field combination was accepted")
			}
		})
	}
}

func TestSettingsAcceptConfiguredExternalVerification(t *testing.T) {
	value := DefaultSettings()
	value.EmailAntiAbuseMode = "tencent"
	value.CaptchaSecretIDReference = "vault://captcha/secret-id"
	value.CaptchaSecretKeyReference = "vault://captcha/secret-key"
	value.CaptchaAppID = "captcha-app"
	value.CaptchaAppSecretReference = "vault://captcha/app-secret"
	value.EnterpriseVerificationEnabled = true
	value.EnterpriseSecretIDReference = "vault://enterprise/secret-id"
	value.EnterpriseSecretKeyReference = "vault://enterprise/secret-key"
	if !validSettings(value) {
		t.Fatal("fully configured external verification was rejected")
	}
}

func TestSettingsRequireEnabledDefaultRechargeMethod(t *testing.T) {
	for _, method := range []string{"wechat", "alipay", "bank_transfer"} {
		t.Run(method, func(t *testing.T) {
			value := DefaultSettings()
			value.DefaultRechargeMethod = method
			if validSettings(value) {
				t.Fatal("disabled recharge method was accepted as default")
			}
			switch method {
			case "wechat":
				value.WeChatPaymentEnabled = true
			case "alipay":
				value.AlipayPaymentEnabled = true
			case "bank_transfer":
				value.BankTransferEnabled = true
			}
			if !validSettings(value) {
				t.Fatal("enabled recharge method was rejected as default")
			}
		})
	}
}
