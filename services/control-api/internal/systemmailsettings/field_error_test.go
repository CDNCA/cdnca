package systemmailsettings

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// fix-fielderr-be2: a refused mail/SMS setting names the field of the save
// body (value.<field>, sms_access_key_secret, mail_secret).
func TestSaveNamesRefusedField(t *testing.T) {
	aliyunSMS := func(v *Settings) {
		v.SMSProvider, v.SMSAccessKeyID, v.SMSSignatureName = SMSProviderAliyun, "LTAI-id", "CDNCA"
	}
	for name, check := range map[string]struct {
		request       SaveRequest
		field, reason string
	}{
		"smtp address":    {SaveRequest{Value: with(func(v *Settings) { v.SMTPAddress = "a\nb" })}, "value.smtp_address", fielderr.InvalidFormat},
		"smtp port":       {SaveRequest{Value: with(func(v *Settings) { v.SMTPPort = 0 })}, "value.smtp_port", fielderr.OutOfRange},
		"smtp user":       {SaveRequest{Value: with(func(v *Settings) { v.SMTPUser = strings.Repeat("u", 257) })}, "value.smtp_user", fielderr.TooLong},
		"smtp password":   {SaveRequest{Value: with(func(v *Settings) { v.SMTPPasswordReference = "plain" })}, "value.smtp_password_reference", fielderr.InvalidFormat},
		"sms provider":    {SaveRequest{Value: with(func(v *Settings) { v.SMSProvider = "tencent" })}, "value.sms_provider", fielderr.Invalid},
		"sms key id":      {SaveRequest{Value: with(func(v *Settings) { aliyunSMS(v); v.SMSAccessKeyID = "" }), SMSAccessKeySecret: "s"}, "value.sms_access_key_id", fielderr.Required},
		"sms signature":   {SaveRequest{Value: with(func(v *Settings) { aliyunSMS(v); v.SMSSignatureName = "" }), SMSAccessKeySecret: "s"}, "value.sms_signature_name", fielderr.Required},
		"sms secret":      {SaveRequest{Value: with(aliyunSMS), SMSAccessKeySecret: "s\n"}, "sms_access_key_secret", fielderr.InvalidFormat},
		"sms template":    {SaveRequest{Value: with(func(v *Settings) { aliyunSMS(v); v.SMSTemplateMap = "{" }), SMSAccessKeySecret: "s"}, "value.sms_template_map", fielderr.InvalidFormat},
		"template no sms": {SaveRequest{Value: with(func(v *Settings) { v.SMSTemplateMap = "{}" })}, "value.sms_template_map", fielderr.Invalid},
		"mail provider":   {SaveRequest{Value: with(func(v *Settings) { v.MailProvider = "ses" })}, "value.mail_provider", fielderr.Invalid},
		"mail region":     {SaveRequest{Value: func() Settings { v := officialMail(MailProviderAliyun); v.MailRegion = "mars-1"; return v }(), MailSecret: "s"}, "value.mail_region", fielderr.Invalid},
		"mail from":       {SaveRequest{Value: func() Settings { v := officialMail(MailProviderSendGrid); v.MailFrom = "A <a@example.com>"; return v }(), MailSecret: "SG.k"}, "value.mail_from", fielderr.InvalidFormat},
		"mail from empty": {SaveRequest{Value: func() Settings { v := officialMail(MailProviderSendGrid); v.MailFrom = ""; return v }(), MailSecret: "SG.k"}, "value.mail_from", fielderr.Required},
		"aliyun key id":   {SaveRequest{Value: func() Settings { v := officialMail(MailProviderAliyun); v.MailAccessKeyID = ""; return v }(), MailSecret: "s"}, "value.mail_access_key_id", fielderr.Required},
		"extra key id":    {SaveRequest{Value: func() Settings { v := officialMail(MailProviderSendGrid); v.MailAccessKeyID = "x"; return v }(), MailSecret: "SG.k"}, "value.mail_access_key_id", fielderr.Invalid},
		"mail secret":     {SaveRequest{Value: officialMail(MailProviderSendGrid), MailSecret: "SG.k\nBcc"}, "mail_secret", fielderr.InvalidFormat},
		"secret for smtp": {SaveRequest{Value: DefaultSettings(), MailSecret: "SG.k"}, "mail_secret", fielderr.Invalid},
	} {
		err := saveWithoutStore(t, check.request)
		located, ok := fielderr.As(err)
		if !errors.Is(err, ErrInvalidInput) || !ok || located.Field != check.field || located.Reason != check.reason {
			t.Errorf("%s: %v, want %s/%s", name, err, check.field, check.reason)
		}
	}
}

func with(change func(*Settings)) Settings {
	value := DefaultSettings()
	change(&value)
	return value
}
