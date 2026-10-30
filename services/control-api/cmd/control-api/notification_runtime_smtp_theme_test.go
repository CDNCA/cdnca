package main

import (
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/google/uuid"
)

type defaultThemeLayout struct{}

func (defaultThemeLayout) Render(_ context.Context, _ uuid.UUID, subject, body string) ([]byte, bool) {
	page, err := theme.DefaultRendered().RenderEmail(subject, strings.Split(body, "\n"))
	return page, err == nil
}

// PA-17: with a theme layout the message is multipart/alternative — the
// plain text unchanged plus the themed HTML; without one, text only.
func TestSMTPMessageCarriesThemedHTMLAlternative(t *testing.T) {
	message := notificationruntime.ProviderMessage{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
		Subject: "余额提醒", Body: "账户余额不足 <10 元>\n请及时充值", IdempotencyKey: "notification-v1-theme", AttemptNumber: 1,
	}
	html, ok := defaultThemeLayout{}.Render(t.Context(), uuid.Nil, message.Subject, message.Body)
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
