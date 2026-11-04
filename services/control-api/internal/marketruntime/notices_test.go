package marketruntime

import (
	"regexp"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/notice"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/migrations"
)

// fix-nm03: every market notice kind has a template context, the upstream
// pause compensation notice carries its amount fields, and the renewal stop
// and resume notices use the v2 templates (migration 558) that explain
// upstream_paused.
func TestNoticeKindsHaveTemplates(t *testing.T) {
	for _, kind := range notice.Kinds {
		if _, ok := noticeVariables[kind]; !ok {
			t.Errorf("%s has no template variables", kind)
		}
	}
	n := notice.Notice{Kind: notice.KindRenewalCompensated, Values: map[string]string{
		notice.ValueOffer: "o", notice.ValueAction: "extended", notice.ValueObserved: "1800", notice.ValueAt: "2026-10-28T00:00:00Z"}}
	ctx, err := NoticeContext(n)
	if err != nil {
		t.Fatal(err)
	}
	_, observed := ctx["observed"]
	_, at := ctx["at"]
	_, currency := ctx["currency"]
	if len(ctx) != 6 || !observed || !at || !currency {
		t.Errorf("compensation context: %v", ctx)
	}
	for kind, want := range map[string]uint64{
		notice.KindRenewalStopped: 2, notice.KindRenewalResumed: 2, notice.KindRenewalCompensated: 1, notice.KindFeedbackOpened: 1,
	} {
		if got := noticeTemplateVersionOf(kind); got != want {
			t.Errorf("%s template version %d, want %d", kind, got, want)
		}
	}
}

// Migrations 622 / 625: the terms changed notice uses
// the v3 template naming what changed and, for a seller's delisting, when the
// subscription ends; a market that does not send category or at renders "-".
func TestTermsChangedNoticeCarriesCategory(t *testing.T) {
	if got := noticeTemplateVersionOf(notice.KindTermsChanged); got != 3 {
		t.Fatalf("terms changed template version %d, want 3", got)
	}
	for values, want := range map[string]string{"sla_worse": "sla_worse", "": "-"} {
		n := notice.Notice{Kind: notice.KindTermsChanged, Values: map[string]string{
			notice.ValueOffer: "o", notice.ValueAction: "close"}}
		if values != "" {
			n.Values[notice.ValueCategory] = values
		}
		ctx, err := NoticeContext(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(ctx) != 5 || ctx["category"] != notification.PublicValue(want) || ctx["at"] != notification.PublicValue("-") {
			t.Errorf("category %q: context %v", values, ctx)
		}
	}
}

// Migration 625: the v3 templates compile under the notification
// catalogue's rules and say "delisted, no renewal after at" for offer_delisted,
// the v2 wording otherwise.
func TestTermsChangedV3TemplatesRender(t *testing.T) {
	raw, err := migrations.FS.ReadFile("625_market_offer_delisted_notice.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\('market\.terms\.changed\.zh-cn', 3, '(sms|email)', '([^']*)', '([^']*)', ARRAY\[([^\]]*)\]`).
		FindAllStringSubmatch(string(raw), -1)
	if len(rows) != 2 {
		t.Fatalf("want sms and email v3 rows, got %d", len(rows))
	}
	catalog := notification.NewCatalog()
	for _, row := range rows {
		var vars []string
		for _, v := range strings.Split(row[4], ",") {
			vars = append(vars, strings.Trim(v, "' "))
		}
		ref := notification.TemplateRef{ID: "market.terms.changed.zh-cn", Version: 3, Channel: notification.Channel(row[1])}
		if err := catalog.Register(notification.TemplateDefinition{Ref: ref, Subject: row[2], Body: row[3], Variables: vars}); err != nil {
			t.Fatalf("%s: %v", row[1], err)
		}
	}
	for category, want := range map[string]string{"offer_delisted": "到期后不再续费", "price_up": "条款已变更"} {
		ctx, err := NoticeContext(notice.Notice{Kind: notice.KindTermsChanged, Values: map[string]string{notice.ValueOffer: "HK BGP",
			notice.ValueAction: "close", notice.ValueCategory: category, notice.ValueAt: "2026-11-05T00:00:00Z"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, channel := range []notification.Channel{notification.ChannelSMS, notification.ChannelEmail} {
			msg, err := catalog.Render(notification.TemplateRef{ID: "market.terms.changed.zh-cn", Version: 3, Channel: channel}, ctx)
			if err != nil {
				t.Fatalf("%s %s: %v", category, channel, err)
			}
			text := msg.Subject + msg.Body
			if !strings.Contains(text, want) || !strings.Contains(text, "HK BGP") ||
				(category == "offer_delisted") != strings.Contains(text, "2026-11-05T00:00:00Z") {
				t.Errorf("%s %s: %q", category, channel, text)
			}
		}
	}
}
