package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

// The bodies match migration 303's notification_templates rows.
func TestSecondaryVerificationNoticeRendersTheSeededTemplates(t *testing.T) {
	catalog := notification.NewCatalog()
	for _, definition := range []notification.TemplateDefinition{
		{Ref: notification.TemplateRef{ID: secondaryVerificationTemplate, Version: 1, Channel: notification.ChannelEmail},
			Subject:   "二次实名认证通知",
			Body:      "<p>您好，{{.username}}。平台要求您使用首次实名认证的身份证完成二次实名认证，截止时间：{{.deadline}}。逾期未完成可能导致网站被锁定。</p>",
			Variables: []string{"username", "deadline"}},
		{Ref: notification.TemplateRef{ID: secondaryVerificationTemplate, Version: 1, Channel: notification.ChannelSMS},
			Body:      "您好，平台要求您使用首次实名认证的身份证完成二次实名认证，截止时间：{{.deadline}}。",
			Variables: []string{"deadline"}},
	} {
		if err := catalog.Register(definition); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)
	for name, notice := range map[string]SecondaryVerificationNotice{
		"with deadline": {ScopeID: uuid.New(), UserID: uuid.New(), Username: "jason", Deadline: &deadline, RequestedAt: time.Now(), RequestID: "req-1"},
		"no deadline":   {ScopeID: uuid.New(), UserID: uuid.New(), Username: "jason", RequestedAt: time.Now(), RequestID: "req-2"},
	} {
		request := SecondaryVerificationEnqueueRequest(notice)
		if request.Policy != notification.DeliverySystemRequired || request.EventType != "identity.secondary_verification" {
			t.Fatalf("%s: request=%#v", name, request)
		}
		want := "不限"
		if notice.Deadline != nil {
			want = "2026-11-01 12:00:00"
		}
		for channel, ref := range request.Templates {
			rendered, err := catalog.Render(ref, request.Contexts[channel])
			if err != nil {
				t.Fatalf("%s %s: %v", name, channel, err)
			}
			if !strings.Contains(rendered.Body, want) {
				t.Fatalf("%s %s body=%q", name, channel, rendered.Body)
			}
		}
	}
}
