package systemusersettings

import (
	"encoding/json"
	"regexp"
	"testing"
)

// no row and a document saved before username_required was
// read keep asking for a username (the earlier behaviour); a saved value wins.
func TestDecodeSettingsUsernameRequiredDefault(t *testing.T) {
	if !DefaultSettings().UsernameRequired {
		t.Fatal("no settings row must keep requiring a username")
	}
	encoded, err := json.Marshal(DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name  string
		value any
		want  bool
	}{{"absent", nil, true}, {"saved off", false, false}, {"saved on", true, true}} {
		delete(fields, "username_required")
		if item.value != nil {
			fields["username_required"] = item.value
		}
		raw, _ := json.Marshal(fields)
		value, err := decodeSettings(raw)
		if err != nil || value.UsernameRequired != item.want {
			t.Fatalf("%s: username_required=%v err=%v", item.name, value.UsernameRequired, err)
		}
	}
}

// the version follows the title and body and nothing else.
func TestTermsVersion(t *testing.T) {
	version := TermsVersion("用户协议", "正文")
	if !regexp.MustCompile(`^terms-[0-9a-f]{12}$`).MatchString(version) || TermsVersion("用户协议", "正文") != version {
		t.Fatalf("version=%q", version)
	}
	for _, other := range []string{TermsVersion("用户协议", "正文。"), TermsVersion("用户协议 ", "正文"), TermsVersion("用户协议正", "文")} {
		if other == version {
			t.Fatalf("a changed terms text kept version %q", version)
		}
	}
}

// the terms are published once the body is not blank and not
// the old default placeholder pair; a new install has none, and an empty body
// is a valid document.
func TestTermsPublished(t *testing.T) {
	for _, item := range []struct {
		name, title, body string
		want              bool
	}{
		{"old default pair", "用户协议、法律声明和隐私政策", "这里填写协议内容", false},
		{"empty body", "用户协议、法律声明和隐私政策", "", false},
		{"blank body", "注册协议", " \n\t", false},
		{"custom body", "用户协议、法律声明和隐私政策", "第一条 本站协议", true},
		{"custom title, old body", "注册协议", "这里填写协议内容", true},
		{"custom", "注册协议", "第一条 本站协议", true},
	} {
		if got := TermsPublished(item.title, item.body); got != item.want {
			t.Errorf("%s: published=%v want %v", item.name, got, item.want)
		}
	}
	defaults := DefaultSettings()
	if defaults.TermsBody != "" || TermsPublished(defaults.TermsTitle, defaults.TermsBody) {
		t.Fatalf("a new install has terms: %q", defaults.TermsBody)
	}
	if err := settingsFieldError(defaults); err != nil {
		t.Fatalf("empty terms body refused: %v", err)
	}
	encoded, _ := json.Marshal(defaults)
	if _, err := decodeSettings(encoded); err != nil {
		t.Fatalf("stored empty terms body unreadable: %v", err)
	}
}

// the settings page reads the old default pair as an empty body
// (a read-time view, the document is unchanged); other terms read as stored.
func TestAdminTermsView(t *testing.T) {
	legacy := DefaultSettings()
	legacy.TermsTitle, legacy.TermsBody = "用户协议、法律声明和隐私政策", "这里填写协议内容"
	if view := adminTermsView(legacy); view.TermsTitle != legacy.TermsTitle || view.TermsBody != "" || legacy.TermsBody != "这里填写协议内容" {
		t.Fatalf("legacy view: %q %q", view.TermsTitle, view.TermsBody)
	}
	custom := DefaultSettings()
	custom.TermsTitle, custom.TermsBody = "用户协议、法律声明和隐私政策", "第一条 本站协议"
	if view := adminTermsView(custom); view.TermsBody != custom.TermsBody {
		t.Fatalf("custom view: %q", view.TermsBody)
	}
}

// unpublished (empty body), terms A and terms B have three
// different versions; the site's own terms page is no part of any of them.
func TestTermsVersionAcrossPublishing(t *testing.T) {
	title := DefaultSettings().TermsTitle
	versions := map[string]string{
		"unpublished": TermsVersion(title, ""), "A": TermsVersion(title, "第一条 A"), "B": TermsVersion(title, "第一条 B"),
	}
	seen := map[string]string{}
	for name, version := range versions {
		if other, ok := seen[version]; ok {
			t.Fatalf("%s and %s share version %s", name, other, version)
		}
		seen[version] = name
	}
}

// an old installation holding the default placeholder pair keeps
// its terms version when the settings page saves the body back as "" (the
// admin view reads the placeholder as empty) with an unrelated change; a
// blank body is the same unpublished version too.
func TestTermsVersionLegacyPlaceholderEqualsEmpty(t *testing.T) {
	legacy := TermsVersion(legacyDefaultTermsTitle, legacyDefaultTermsBody)
	if empty := TermsVersion(legacyDefaultTermsTitle, ""); empty != legacy {
		t.Fatalf("legacy placeholder %s, saved empty %s", legacy, empty)
	}
	if blank := TermsVersion(legacyDefaultTermsTitle, "  \n"); blank != legacy {
		t.Fatalf("legacy placeholder %s, blank %s", legacy, blank)
	}
	if published := TermsVersion(legacyDefaultTermsTitle, "第一条 正文"); published == legacy {
		t.Fatal("publishing the terms must change the version")
	}
	// the placeholder under another title is the site's own text: published, its own version
	if TermsVersion("注册协议", legacyDefaultTermsBody) == TermsVersion("注册协议", "") {
		t.Fatal("the placeholder text under a custom title is published content")
	}
}
