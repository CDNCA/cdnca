//go:build integration

package notification

import (
	"context"
	"testing"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

// TestNotificationRecipientLocaleSelectsTemplate: the same event renders the Chinese template for a
// member without a language or with Chinese, the .en-us translation for an English member, and falls back to
// Chinese when the translation of that version is missing or declares other variables.
func TestNotificationRecipientLocaleSelectsTemplate(t *testing.T) {
	fixture := newNotificationFixture(t)
	ctx := context.Background()
	fixture.enableSMS(t)
	english := TemplateRef{ID: fixture.sms.ID + ".en-us", Version: 1, Channel: ChannelSMS}
	if err := fixture.store.SaveTemplate(ctx, TemplateDefinition{
		Ref: english, Body: "Node {{.name}} is offline", Variables: []string{"name"},
	}); err != nil {
		t.Fatal(err)
	}
	versionTwo := TemplateRef{ID: fixture.sms.ID, Version: 2, Channel: ChannelSMS}
	if err := fixture.store.SaveTemplate(ctx, TemplateDefinition{
		Ref: versionTwo, Body: "版本二：{{.name}}", Variables: []string{"name"},
	}); err != nil {
		t.Fatal(err)
	}
	versionThree := TemplateRef{ID: fixture.sms.ID, Version: 3, Channel: ChannelSMS}
	if err := fixture.store.SaveTemplate(ctx, TemplateDefinition{
		Ref: versionThree, Body: "版本三：{{.name}}", Variables: []string{"name"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SaveTemplate(ctx, TemplateDefinition{
		Ref:  TemplateRef{ID: english.ID, Version: 3, Channel: ChannelSMS},
		Body: "Version three: {{.node}}", Variables: []string{"node"},
	}); err != nil {
		t.Fatal(err)
	}
	setLocale := func(locale any) {
		t.Helper()
		if _, err := fixture.pool.Exec(ctx, `UPDATE users SET locale=$2 WHERE id=$1`, fixture.userID, locale); err != nil {
			t.Fatal(err)
		}
	}
	enqueue := func(eventID string, ref TemplateRef) (string, string) {
		t.Helper()
		request := fixture.request(fixture.scopeA, eventID, DeliveryTenantSubscribed)
		request.Templates[ChannelSMS] = ref
		result, err := fixture.store.Enqueue(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Deliveries) != 1 {
			t.Fatalf("deliveries = %+v", result.Deliveries)
		}
		var templateID, body string
		if err := fixture.pool.QueryRow(ctx, `SELECT template_id, body FROM notification_outbox WHERE id=$1`,
			result.Deliveries[0].OutboxID).Scan(&templateID, &body); err != nil {
			t.Fatal(err)
		}
		return templateID, body
	}
	for _, tc := range []struct {
		name, event string
		locale      any
		ref         TemplateRef
		wantID      string
		wantBody    string
	}{
		{"unset", "locale-unset", nil, fixture.sms, fixture.sms.ID, "节点 edge-1 已离线"},
		{"chinese", "locale-zh", "zh-CN", fixture.sms, fixture.sms.ID, "节点 edge-1 已离线"},
		{"traditional", "locale-zh-tw", "zh-TW", fixture.sms, fixture.sms.ID, "节点 edge-1 已离线"},
		{"english", "locale-en", "en-US", fixture.sms, english.ID, "Node edge-1 is offline"},
		{"english missing version", "locale-en-v2", "en-US", versionTwo, fixture.sms.ID, "版本二：edge-1"},
		{"english other variables", "locale-en-v3", "en-US", versionThree, fixture.sms.ID, "版本三：edge-1"},
	} {
		setLocale(tc.locale)
		if id, body := enqueue(tc.event, tc.ref); id != tc.wantID || body != tc.wantBody {
			t.Errorf("%s: outbox %s %q, want %s %q", tc.name, id, body, tc.wantID, tc.wantBody)
		}
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE users SET locale='fr-FR' WHERE id=$1`, fixture.userID); err == nil {
		t.Error("users.locale accepted fr-FR")
	}
}

// TestAnonymousDispatchRequestLocaleSelectsTemplate: sign-in,
// registration and recovery messages follow the requester's language and
// fall back to Chinese without a translation.
func TestAnonymousDispatchRequestLocaleSelectsTemplate(t *testing.T) {
	pool := headMigratedNotificationPool(t)
	ctx := t.Context()
	_, scopeID, _ := seedAnonymousDispatchIdentity(t, pool, "locale")
	store, err := NewStoreWithClock(pool, audit.New(pool), (&lockedClock{now: anonymousDispatchTestTime}).Now)
	if err != nil {
		t.Fatal(err)
	}
	translated := TemplateRef{ID: "account_recovery_locale", Version: 1, Channel: ChannelSMS}
	untranslated := TemplateRef{ID: "account_recovery_locale_zh", Version: 1, Channel: ChannelSMS}
	for _, definition := range []TemplateDefinition{
		{Ref: translated, Body: "重置地址：{{.recovery_url}}", Variables: []string{"recovery_url"}},
		{Ref: TemplateRef{ID: translated.ID + ".en-us", Version: 1, Channel: ChannelSMS},
			Body: "Reset link: {{.recovery_url}}", Variables: []string{"recovery_url"}},
		{Ref: untranslated, Body: "仅中文：{{.recovery_url}}", Variables: []string{"recovery_url"}},
	} {
		if err := store.SaveTemplate(ctx, definition); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetChannelSwitches(ctx, ChannelSwitches{SMS: true}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		event, locale string
		ref           TemplateRef
		wantID        string
		wantBody      string
	}{
		{"anonymous-locale-default", "", translated, translated.ID, "重置地址：{{.recovery_url}}"},
		{"anonymous-locale-en", LocaleEnUS, translated, translated.ID + ".en-us", "Reset link: {{.recovery_url}}"},
		{"anonymous-locale-en-missing", LocaleEnUS, untranslated, untranslated.ID, "仅中文：{{.recovery_url}}"},
	} {
		result, err := enqueueAnonymousDispatch(ctx, pool, store, DispatchEnqueueRequest{
			ScopeID: scopeID, SourceEventID: tc.event, AnonymousDispatchReference: uuid.New(),
			Templates: map[Channel]TemplateRef{ChannelSMS: tc.ref}, AuditRequestID: "audit-" + tc.event,
			Locale: tc.locale,
		})
		if err != nil || len(result.Deliveries) != 1 {
			t.Fatalf("%s: result %+v, err %v", tc.event, result, err)
		}
		var templateID, body string
		if err := pool.QueryRow(ctx, `SELECT template_id, body FROM notification_outbox WHERE id=$1`,
			result.Deliveries[0].OutboxID).Scan(&templateID, &body); err != nil {
			t.Fatal(err)
		}
		if templateID != tc.wantID || body != tc.wantBody {
			t.Errorf("%s: outbox %s %q, want %s %q", tc.event, templateID, body, tc.wantID, tc.wantBody)
		}
	}
}

// TestNotificationEnglishRecipientGetsEnglishValues: values Go
// code generates in both languages reach an English member's English message
// (body and SMS template parameters, which keep the Chinese copy for a native
// provider without an English template code) without Chinese text in the
// body; a Chinese member,
// and an English member whose template has no translation, keep Chinese.
func TestNotificationEnglishRecipientGetsEnglishValues(t *testing.T) {
	fixture := newNotificationFixture(t)
	ctx := context.Background()
	fixture.enableSMS(t)
	if err := fixture.store.SaveTemplate(ctx, TemplateDefinition{
		Ref:  TemplateRef{ID: fixture.sms.ID + ".en-us", Version: 1, Channel: ChannelSMS},
		Body: "Node {{.name}} is offline", Variables: []string{"name"},
	}); err != nil {
		t.Fatal(err)
	}
	untranslated := TemplateRef{ID: fixture.sms.ID, Version: 2, Channel: ChannelSMS}
	if err := fixture.store.SaveTemplate(ctx, TemplateDefinition{
		Ref: untranslated, Body: "版本二：{{.name}}", Variables: []string{"name"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		event, locale string
		ref           TemplateRef
		wantBody      string
		wantParams    string
	}{
		{"values-en", "en-US", fixture.sms, "Node Primary origin is offline", `{"name": "Primary origin", "zh-cn:name": "主源"}`},
		{"values-zh", "zh-CN", fixture.sms, "节点 主源 已离线", `{"name": "主源"}`},
		{"values-en-untranslated", "en-US", untranslated, "版本二：主源", `{"name": "主源"}`},
	} {
		if _, err := fixture.pool.Exec(ctx, `UPDATE users SET locale=$2 WHERE id=$1`, fixture.userID, tc.locale); err != nil {
			t.Fatal(err)
		}
		request := fixture.request(fixture.scopeA, tc.event, DeliveryTenantSubscribed)
		request.Templates[ChannelSMS] = tc.ref
		request.Contexts[ChannelSMS] = TemplateContext{"name": LocalizedValue("主源", "Primary origin")}
		result, err := fixture.store.Enqueue(ctx, request)
		if err != nil || len(result.Deliveries) != 1 {
			t.Fatalf("%s: result %+v, err %v", tc.event, result, err)
		}
		var body, params string
		if err := fixture.pool.QueryRow(ctx, `SELECT body, template_params::text FROM notification_outbox WHERE id=$1`,
			result.Deliveries[0].OutboxID).Scan(&body, &params); err != nil {
			t.Fatal(err)
		}
		if body != tc.wantBody || params != tc.wantParams {
			t.Errorf("%s: outbox %q %s, want %q %s", tc.event, body, params, tc.wantBody, tc.wantParams)
		}
		if tc.locale == "en-US" && tc.ref == fixture.sms {
			for _, r := range body {
				if unicode.Is(unicode.Han, r) {
					t.Errorf("%s: English message has Chinese text: %q", tc.event, body)
					break
				}
			}
		}
	}
}
