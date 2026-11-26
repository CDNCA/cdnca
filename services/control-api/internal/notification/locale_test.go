package notification

import "testing"

func TestLocalizedTemplateIDs(t *testing.T) {
	for _, tc := range []struct{ id, locale, want string }{
		{"certificate.expired.zh-cn", LocaleEnUS, "certificate.expired.en-us"},
		{"ticket_created", LocaleEnUS, "ticket_created.en-us"},
		{"certificate.expired.zh-cn", LocaleZhCN, "certificate.expired.zh-cn"},
		{"certificate.expired.zh-cn", LocaleZhTW, "certificate.expired.zh-cn"},
		{"certificate.expired.zh-cn", "", "certificate.expired.zh-cn"},
		{"ticket_created.en-us", LocaleEnUS, "ticket_created.en-us"},
	} {
		if got := LocalizedTemplateID(tc.id, tc.locale); got != tc.want {
			t.Errorf("LocalizedTemplateID(%q, %q) = %q, want %q", tc.id, tc.locale, got, tc.want)
		}
	}
	for _, tc := range []struct{ id, want string }{
		{"certificate.expired.en-us", "certificate.expired.zh-cn"},
		{"ticket_created.en-us", "ticket_created"},
		{"account_login_verification.en-us", "account_login_verification"},
		{"certificate.expired.zh-cn", "certificate.expired.zh-cn"},
		{"operator_custom", "operator_custom"},
	} {
		if got := BaseTemplateID(tc.id); got != tc.want {
			t.Errorf("BaseTemplateID(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestLocaleFromAcceptLanguage(t *testing.T) {
	for header, want := range map[string]string{
		"en-US": LocaleEnUS, "en": LocaleEnUS, "EN-gb,zh;q=0.8": LocaleEnUS, "en;q=0.9": LocaleEnUS,
		"zh-CN": "", "zh-TW,en;q=0.9": "", "": "", "fr-FR": "", "eng": "",
	} {
		if got := LocaleFromAcceptLanguage(header); got != want {
			t.Errorf("LocaleFromAcceptLanguage(%q) = %q, want %q", header, got, want)
		}
	}
	for locale, want := range map[string]bool{LocaleZhCN: true, LocaleZhTW: true, LocaleEnUS: true, "en": false, "": false} {
		if ValidLocale(locale) != want {
			t.Errorf("ValidLocale(%q) = %v", locale, !want)
		}
	}
}

// TestLocalizedContexts: only a channel whose template is the
// English translation gets the English text of a LocalizedValue; plain values
// and Chinese channels keep the Chinese text.
func TestLocalizedContexts(t *testing.T) {
	context := TemplateContext{"reason": LocalizedValue("余额不足", "Insufficient balance"), "name": PublicValue("edge-1"),
		"note": LocalizedValue("不限", "")}
	got := localizedContexts(map[Channel]TemplateContext{ChannelSMS: context, ChannelEmail: context}, map[Channel]TemplateRef{
		ChannelSMS: {ID: "node.offline.en-us"}, ChannelEmail: {ID: "node.offline.zh-cn"},
	})
	if got[ChannelSMS]["reason"].value != "Insufficient balance" || got[ChannelSMS]["name"].value != "edge-1" ||
		got[ChannelSMS]["note"].value != "不限" {
		t.Fatalf("english channel = %+v", got[ChannelSMS])
	}
	if got[ChannelEmail]["reason"].value != "余额不足" || context["reason"].value != "余额不足" {
		t.Fatalf("chinese channel = %+v, request = %+v", got[ChannelEmail], context)
	}
}

// TestSMSTemplateParamsKeepChineseCopy: an English SMS keeps the
// Chinese copies for a native provider that sends the Chinese template.
func TestSMSTemplateParamsKeepChineseCopy(t *testing.T) {
	context := TemplateContext{"reason": LocalizedValue("余额不足", "Insufficient balance"), "name": PublicValue("edge-1")}
	english := smsTemplateParams(context, TemplateRef{ID: "node.offline.en-us"})
	if len(english) != 3 || english["reason"] != "Insufficient balance" || english[ChineseParamPrefix+"reason"] != "余额不足" ||
		english["name"] != "edge-1" {
		t.Fatalf("english params = %v", english)
	}
	if chinese := ChineseTemplateParams(english); len(chinese) != 2 || chinese["reason"] != "余额不足" || chinese["name"] != "edge-1" {
		t.Fatalf("chinese params = %v", chinese)
	}
	if got := smsTemplateParams(context, TemplateRef{ID: "node.offline.zh-cn"}); len(got) != 2 || got["reason"] != "余额不足" {
		t.Fatalf("chinese template params = %v", got)
	}
}
