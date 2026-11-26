package main

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/google/uuid"
	xhtml "golang.org/x/net/html"
)

type defaultThemeLayout struct{}

func (defaultThemeLayout) Render(_ context.Context, _ uuid.UUID, subject, body string, action theme.EmailAction) ([]byte, bool) {
	page, err := theme.DefaultRendered().RenderEmailAction(subject, strings.Split(body, "\n"), action)
	return page, err == nil
}

// PA-17: with a theme layout the message is multipart/alternative — the
// plain text unchanged plus the themed HTML; without one, text only.
func TestSMTPMessageCarriesThemedHTMLAlternative(t *testing.T) {
	message := notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
		Subject: "余额提醒", Body: "账户余额不足 <10 元>\n请及时充值", IdempotencyKey: "notification-v1-theme", AttemptNumber: 1,
	}
	html, ok := defaultThemeLayout{}.Render(t.Context(), uuid.Nil, message.Subject, message.Body, smtpEmailAction(message))
	if !ok {
		t.Fatal("default theme email did not render")
	}
	raw := buildSMTPMessage("noreply@example.test", "mail.example.test", message, html)
	if again := buildSMTPMessage("noreply@example.test", "mail.example.test", message, html); again[strings.Index(again, "Message-ID"):] != raw[strings.Index(raw, "Message-ID"):] {
		t.Fatal("multipart body is not stable across retries")
	}
	parsed, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" || parsed.Header.Get("X-CDNCA-Idempotency-Key") != "notification-v1-theme" {
		t.Fatalf("headers = %v (%v)", parsed.Header, err)
	}
	reader := multipart.NewReader(parsed.Body, params["boundary"])
	var types []string
	var htmlPart string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(part)
		types = append(types, part.Header.Get("Content-Type"))
		if strings.HasPrefix(part.Header.Get("Content-Type"), "text/html") {
			htmlPart = string(body)
		} else if !strings.Contains(string(body), "账户余额不足 <10 元>") {
			t.Fatalf("plain part = %q", body)
		}
	}
	if len(types) != 2 || !strings.Contains(htmlPart, "账户余额不足 &lt;10 元&gt;") || !strings.Contains(htmlPart, "<style>") ||
		strings.Contains(htmlPart, "url(") {
		t.Fatalf("parts = %v html = %s", types, htmlPart)
	}

	plain := buildSMTPMessage("noreply@example.test", "mail.example.test", message, nil)
	if !strings.Contains(plain, "Content-Type: text/plain; charset=UTF-8\r\n") || strings.Contains(plain, "multipart") {
		t.Fatalf("plain message = %q", plain)
	}
}

// smtpParts parses a built message and returns its decoded text/plain and
// text/html parts.
func smtpParts(t *testing.T, raw string) (plain, html string) {
	t.Helper()
	parsed, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	reader := multipart.NewReader(parsed.Body, params["boundary"])
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return plain, html
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(part.Header.Get("Content-Type"), "text/html") {
			html = string(body)
		} else {
			plain = string(body)
		}
	}
}

type htmlLink struct{ href, text string }

// htmlLinks parses page and returns every <a>: its decoded href and text.
func htmlLinks(t *testing.T, page string) []htmlLink {
	t.Helper()
	document, err := xhtml.Parse(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	var links []htmlLink
	var text func(*xhtml.Node) string
	text = func(node *xhtml.Node) string {
		if node.Type == xhtml.TextNode {
			return node.Data
		}
		var output strings.Builder
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			output.WriteString(text(child))
		}
		return output.String()
	}
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		if node.Type == xhtml.ElementNode && node.Data == "a" {
			link := htmlLink{text: text(node)}
			for _, attribute := range node.Attr {
				if attribute.Key == "href" {
					link.href = attribute.Val
				}
			}
			links = append(links, link)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	return links
}

// 找回密码邮件的 HTML 版里，重置地址是可点击链接（href 与 ActionURL
// 逐字节相同，含 fragment 与参数次序），文字为「设置新密码」；纯文本版仍是完整地址。
func TestSMTPHTMLAlternativeLinksActionURL(t *testing.T) {
	actionURL := "https://ctrl.example.test/dashboard/reset-password#token=abc-_9&recovery_context=def.ghi"
	message := notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
		Subject: "找回密码", Body: "请在有效期内打开以下链接设置新密码：\n参考 https://evil.example.test/x 不应成为链接",
		IdempotencyKey: "recovery-v1-link", AttemptNumber: 1, ActionURL: actionURL, TemplateID: "account_recovery_email",
	}
	html, ok := defaultThemeLayout{}.Render(t.Context(), uuid.Nil, message.Subject, message.Body, smtpEmailAction(message))
	if !ok {
		t.Fatal("default theme email did not render")
	}
	plain, htmlPart := smtpParts(t, buildSMTPMessage("noreply@example.test", "mail.example.test", message, html))
	links := htmlLinks(t, htmlPart)
	if len(links) != 1 || links[0].href != actionURL || links[0].text != "设置新密码" {
		t.Fatalf("links = %+v html = %s", links, htmlPart)
	}
	if !strings.Contains(htmlPart, "参考 https://evil.example.test/x 不应成为链接") {
		t.Fatalf("body line not kept as text: %s", htmlPart)
	}
	if !strings.HasSuffix(strings.TrimRight(plain, "\r\n"), "\r\n\r\n"+actionURL) {
		t.Fatalf("plain part = %q", plain)
	}

	invitation := message
	invitation.TemplateID = identity.TenantMemberInvitationTemplate
	html, ok = defaultThemeLayout{}.Render(t.Context(), uuid.Nil, invitation.Subject, invitation.Body, smtpEmailAction(invitation))
	if links := htmlLinks(t, string(html)); !ok || len(links) != 1 || links[0].href != actionURL || links[0].text != "接受邀请" {
		t.Fatalf("invitation links = %+v (%v)", links, ok)
	}
}

// 无操作链接的普通通知：HTML 里没有任何 <a>。
func TestSMTPHTMLAlternativeWithoutActionHasNoLink(t *testing.T) {
	message := notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
		Subject: "余额提醒", Body: "余额不足，详见 https://ctrl.example.test/billing", IdempotencyKey: "notification-v1-nolink", AttemptNumber: 1,
	}
	if action := smtpEmailAction(message); action != (theme.EmailAction{}) {
		t.Fatalf("action = %+v", action)
	}
	html, ok := defaultThemeLayout{}.Render(t.Context(), uuid.Nil, message.Subject, message.Body, smtpEmailAction(message))
	if !ok {
		t.Fatal("default theme email did not render")
	}
	_, htmlPart := smtpParts(t, buildSMTPMessage("noreply@example.test", "mail.example.test", message, html))
	if links := htmlLinks(t, htmlPart); len(links) != 0 || strings.Contains(htmlPart, "href") {
		t.Fatalf("links = %+v html = %s", links, htmlPart)
	}
}

// 已安装的旧主题（邮件模板不认识 action_url）：照常渲染，地址作为末行纯文本可复制。
func TestSMTPHTMLAlternativeLegacyThemeShowsActionURL(t *testing.T) {
	var pkg map[string]any
	if err := json.Unmarshal(theme.BuiltinCatalog()[0].Raw, &pkg); err != nil {
		t.Fatal(err)
	}
	pkg["templates"].(map[string]any)["email"] = `<!doctype html><html><head><title>{{subject}}</title></head><body><main class="cf-page">` +
		`<h1 class="cf-title">{{subject}}</h1>{{#lines}}<p class="cf-line">{{.}}</p>{{/lines}}` +
		`{{#footer_text}}<p class="cf-footer">{{footer_text}}</p>{{/footer_text}}</main></body></html>`
	raw, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := theme.Render(raw)
	if err != nil {
		t.Fatalf("legacy theme no longer renders: %v", err)
	}
	actionURL := "https://ctrl.example.test/dashboard/reset-password#token=abc&recovery_context=def"
	page, err := legacy.RenderEmailAction("找回密码", []string{"请打开以下链接设置新密码："}, theme.EmailAction{URL: actionURL, Label: "设置新密码"})
	if err != nil {
		t.Fatal(err)
	}
	if links := htmlLinks(t, string(page)); len(links) != 0 ||
		!strings.Contains(string(page), `<p class="cf-line">https://ctrl.example.test/dashboard/reset-password#token=abc&amp;recovery_context=def</p>`) {
		t.Fatalf("legacy page = %s", page)
	}
}

func TestSMTPEmailActionLabelFollowsTemplateLanguage(t *testing.T) {
	for templateID, want := range map[string]string{
		"account_recovery_email":                           "设置新密码",
		"account_recovery_email.en-us":                     "Set a new password",
		identity.TenantMemberInvitationTemplate:            "接受邀请",
		identity.TenantMemberInvitationTemplate + ".en-us": "Accept invitation",
	} {
		action := smtpEmailAction(notificationruntime.ProviderMessage{TemplateID: templateID, ActionURL: "https://console.example.com/reset"})
		if action.Label != want {
			t.Errorf("%s label = %q, want %q", templateID, action.Label, want)
		}
	}
}
