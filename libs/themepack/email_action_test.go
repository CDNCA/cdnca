package themepack

import (
	"strings"
	"testing"
)

const legacyEmailTemplate = `<!doctype html><html><head><title>{{subject}}</title></head><body><main class="cf-page">` +
	`<h1 class="cf-title">{{subject}}</h1>{{#lines}}<p class="cf-line">{{.}}</p>{{/lines}}` +
	`{{#footer_text}}<p class="cf-footer">{{footer_text}}</p>{{/footer_text}}</main></body></html>`

const recoveryURL = "https://ctrl.example.test/reset-password#token=abc&recovery_context=def"

func withEmailTemplate(t *testing.T, email string) []byte {
	return customPackage(t, func(document map[string]any) { templates(document)["email"] = email })
}

// the built-in themes link the action address, escaped once, with the
// fragment and parameter order untouched; without an action there is no link.
func TestBuiltinEmailLinksAction(t *testing.T) {
	for _, entry := range BuiltinCatalog() {
		rendered, err := Render(entry.Raw)
		if err != nil {
			t.Fatalf("%s: %v", entry.ID, err)
		}
		page, err := rendered.RenderEmailAction("找回密码", []string{"见 https://evil.example.test/"}, EmailAction{URL: recoveryURL, Label: "设置新密码"})
		if err != nil {
			t.Fatalf("%s: %v", entry.ID, err)
		}
		text := string(page)
		if strings.Count(text, "<a ") != 1 ||
			!strings.Contains(text, `<a href="https://ctrl.example.test/reset-password#token=abc&amp;recovery_context=def">设置新密码</a>`) ||
			!strings.Contains(text, `<p class="cf-line">见 https://evil.example.test/</p>`) {
			t.Fatalf("%s email = %s", entry.ID, text)
		}
		plain, err := rendered.RenderEmail("通知", []string{"正文"})
		if err != nil || strings.Contains(string(plain), "<a") || strings.Contains(string(plain), "href") {
			t.Fatalf("%s email without action = %s (%v)", entry.ID, plain, err)
		}
	}
}

// A package whose email template predates action_url (any installed theme)
// still renders; the address becomes the last text line, not a link.
func TestLegacyEmailTemplateAppendsActionText(t *testing.T) {
	rendered, err := Render(withEmailTemplate(t, legacyEmailTemplate))
	if err != nil {
		t.Fatal(err)
	}
	if rendered.emailLinks {
		t.Fatal("legacy template reported as linking the action")
	}
	page, err := rendered.RenderEmailAction("找回密码", []string{"正文"}, EmailAction{URL: recoveryURL, Label: "设置新密码"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	if strings.Contains(text, "<a") || !strings.Contains(text,
		`<p class="cf-line">正文</p><p class="cf-line"></p><p class="cf-line">https://ctrl.example.test/reset-password#token=abc&amp;recovery_context=def</p>`) {
		t.Fatalf("legacy email = %s", text)
	}
	if page, err := rendered.RenderEmail("通知", []string{"正文"}); err != nil || strings.Count(string(page), `class="cf-line"`) != 1 {
		t.Fatalf("legacy email without action = %s (%v)", page, err)
	}
}

// The only href a package may carry is the email template's
// href="{{action_url}}"; the page may then link to that address only.
func TestEmailActionHrefIsTheOnlyLink(t *testing.T) {
	linked := `<!doctype html><html><head><title>{{subject}}</title></head><body>{{#lines}}<p>{{.}}</p>{{/lines}}` +
		`{{#action_url}}<p><a class="cf-line" href="{{action_url}}">{{action_label}}</a></p>{{/action_url}}</body></html>`
	if _, err := Render(withEmailTemplate(t, linked)); err != nil {
		t.Fatalf("linked template refused: %v", err)
	}
	refused := map[string]string{
		"literal href":          strings.Replace(linked, `href="{{action_url}}"`, `href="https://evil.example.test/"`, 1),
		"relative href":         strings.Replace(linked, `href="{{action_url}}"`, `href="/x"`, 1),
		"href with suffix":      strings.Replace(linked, `href="{{action_url}}"`, `href="{{action_url}}x"`, 1),
		"label as href":         strings.Replace(linked, `href="{{action_url}}"`, `href="{{action_label}}"`, 1),
		"uppercase href":        strings.Replace(linked, `href="{{action_url}}"`, `HREF="{{action_url}}"`, 1),
		"href on another tag":   strings.Replace(linked, `<a class="cf-line" href="{{action_url}}">{{action_label}}</a>`, `<span href="{{action_url}}">x</span>`, 1),
		"link without action":   strings.Replace(strings.Replace(linked, `{{#action_url}}`, ``, 1), `{{/action_url}}`, ``, 1),
		"extra attribute":       strings.Replace(linked, `<a class`, `<a target="_blank" class`, 1),
		"undeclared link class": strings.Replace(linked, `<a class="cf-line"`, `<a class="nope"`, 1),
	}
	for name, email := range refused {
		if _, err := Render(withEmailTemplate(t, email)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	errorPage := customPackage(t, func(document map[string]any) {
		templates(document)["error_page"] = strings.Replace(templates(document)["error_page"].(string), "</body>", `<a href="{{action_url}}">x</a></body>`, 1)
	})
	if code := validationCode(t, func() error { _, err := Render(errorPage); return err }()); code != "external_reference" {
		t.Fatalf("error page href code = %s", code)
	}
	// The renderer accepts a link only to the address it was given.
	rendered, err := Render(withEmailTemplate(t, linked))
	if err != nil {
		t.Fatal(err)
	}
	page, err := rendered.RenderEmailAction("s", nil, EmailAction{URL: recoveryURL, Label: "设置新密码"})
	if err != nil {
		t.Fatal(err)
	}
	if validateThemedHTML(page, recoveryURL) != nil || validateThemedHTML(page, "https://other.example.test/") == nil || ValidateThemedHTML(page) == nil {
		t.Fatal("themed page link check")
	}
}

func TestEmailActionRejectsUnsafeAddress(t *testing.T) {
	rendered := DefaultRendered()
	for _, action := range []EmailAction{
		{URL: "http://ctrl.example.test/reset", Label: "设置新密码"},
		{URL: "javascript:alert(1)", Label: "设置新密码"},
		{URL: "https:///reset", Label: "设置新密码"},
		{URL: "https://user:pass@ctrl.example.test/reset", Label: "设置新密码"},
		{URL: "https://ctrl.example.test/a b", Label: "设置新密码"},
		{URL: "https://ctrl.example.test/a\nb", Label: "设置新密码"},
		{URL: recoveryURL},
		{Label: "设置新密码"},
	} {
		if _, err := rendered.RenderEmailAction("s", []string{"x"}, action); err == nil {
			t.Errorf("action %+v accepted", action)
		}
	}
}
