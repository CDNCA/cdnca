package systemusersettings

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// fix-fielderr-be2: a refused user setting names value.<field> of the save body.
func TestSettingsFieldError(t *testing.T) {
	for name, check := range map[string]struct {
		change        func(*Settings)
		field, reason string
	}{
		"session ttl":      {func(v *Settings) { v.SessionTTLSeconds = 10 }, "value.session_ttl_seconds", fielderr.OutOfRange},
		"login domains":    {func(v *Settings) { v.UserLoginDomains = strings.Repeat("a", 4097) }, "value.user_login_domains", fielderr.TooLong},
		"subject required": {func(v *Settings) { v.PasswordResetSubject = "" }, "value.password_reset_subject", fielderr.Required},
		"password token":   {func(v *Settings) { v.RegistrationSuccessBody = "hi {{.password}}" }, "value.registration_success_body", fielderr.Invalid},
		"channel":          {func(v *Settings) { v.VerificationTemplateChannel = "fax" }, "value.verification_template_channel", fielderr.Invalid},
		"terms body":       {func(v *Settings) { v.TermsBody = "a\rb" }, "value.terms_body", fielderr.InvalidFormat},
		"email verify":     {func(v *Settings) { v.EmailVerificationRequired = true; v.EmailRequired = false }, "value.email_verification_required", fielderr.Invalid},
		"phone verify":     {func(v *Settings) { v.PhoneVerificationRequired = true; v.PhoneRequired = false }, "value.phone_verification_required", fielderr.Invalid},
		"failure limit":    {func(v *Settings) { v.LoginFailureLimitPerHour = 0 }, "value.login_failure_limit_per_hour", fielderr.OutOfRange},
		"captcha limit":    {func(v *Settings) { v.LoginCaptchaThresholdPerHour = v.LoginFailureLimitPerHour + 1 }, "value.login_captcha_threshold_per_hour", fielderr.OutOfRange},
		"reference":        {func(v *Settings) { v.CaptchaSecretKeyReference = "plain-secret" }, "value.captcha_secret_key_reference", fielderr.InvalidFormat},
		"anti abuse":       {func(v *Settings) { v.EmailAntiAbuseMode = "tencent" }, "value.email_anti_abuse_mode", fielderr.Invalid},
		"enterprise":       {func(v *Settings) { v.EnterpriseVerificationEnabled = true }, "value.enterprise_secret_id_reference", fielderr.Required},
		"recharge method":  {func(v *Settings) { v.DefaultRechargeMethod = "wechat"; v.WeChatPaymentEnabled = false }, "value.default_recharge_method", fielderr.Invalid},
		"country code":     {func(v *Settings) { v.DefaultPhoneCountryCode = "" }, "value.default_phone_country_code", fielderr.Required},
		"country invalid":  {func(v *Settings) { v.DefaultPhoneCountryCode = "0x" }, "value.default_phone_country_code", fielderr.Invalid},
	} {
		value := DefaultSettings()
		check.change(&value)
		err := settingsFieldError(value)
		located, ok := fielderr.As(err)
		if !errors.Is(err, ErrInvalidInput) || !ok || located.Field != check.field || located.Reason != check.reason {
			t.Errorf("%s: %v, want %s/%s", name, err, check.field, check.reason)
		}
		if validSettings(value) {
			t.Errorf("%s: validSettings accepted a refused value", name)
		}
	}
	if err := settingsFieldError(DefaultSettings()); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
}

// The verification templates must carry the captcha placeholder; the refusal
// names the template that lacks it.
func TestNotificationDefinitionsFieldError(t *testing.T) {
	value := DefaultSettings()
	value.VerificationSubject, value.VerificationBody = "验证", "请验证"
	if located, ok := fielderr.As(notificationDefinitionsErr(value)); !ok || located.Field != "value.verification_body" || located.Reason != fielderr.Invalid {
		t.Fatalf("email captcha: %+v", located)
	}
	value = DefaultSettings()
	value.VerificationSMSBody = "请验证"
	if located, ok := fielderr.As(notificationDefinitionsErr(value)); !ok || located.Field != "value.verification_sms_body" || located.Reason != fielderr.Invalid {
		t.Fatalf("sms captcha: %+v", located)
	}
}

func notificationDefinitionsErr(value Settings) error {
	_, err := settingsNotificationDefinitions(value, 1)
	if !errors.Is(err, ErrInvalidInput) {
		return errors.New("not ErrInvalidInput")
	}
	return err
}
