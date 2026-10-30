package notificationcontrol

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

func TestNewStoreRejectsIncompleteDependencies(t *testing.T) {
	if store, err := NewStoreWithDependencies(nil, nil, nil); store != nil || !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewStoreWithDependencies() = (%v, %v)", store, err)
	}
}

func TestSupportedNotificationEventTypes(t *testing.T) {
	for _, eventType := range []string{
		EventTypeAnnouncementPublished,
		"package.monitor.cc_rule_auto_switch",
		"security.attack.detected",
		"ticket.created",
		"ticket.replied",
		"ticket.status_changed",
		"ticket.staff.created",
		"ticket.staff.replied",
	} {
		if !SupportedEventType(eventType) {
			t.Fatalf("%s must be supported", eventType)
		}
	}
	// Community edition: no package monitor, auto-renew or payment events.
	for _, eventType := range []string{"", "announcement.created", "Announcement.Published",
		"package.monitor.traffic.triggered", "package.auto_renew.failed", "payment.reconcile.mismatch"} {
		if SupportedEventType(eventType) {
			t.Fatalf("unexpected supported event type %q", eventType)
		}
	}
	// Subscriptions are listed and written per catalog entry: a repeated
	// event type would be offered twice.
	seen := map[string]bool{}
	for _, eventType := range supportedEventTypes {
		if seen[eventType] {
			t.Fatalf("event type %q listed twice", eventType)
		}
		seen[eventType] = true
	}
}

func TestAnnouncementPublishedTemplateRejectsBranchAndTransformGrammar(t *testing.T) {
	valid := notification.TemplateDefinition{
		Ref:     notification.TemplateRef{ID: announcementPublishedTemplateID, Version: 1, Channel: notification.ChannelEmail},
		Subject: "[公告] {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"},
	}
	if err := validateAnnouncementPublishedTemplate(valid); err != nil {
		t.Fatalf("valid fixed template = %v", err)
	}

	tests := []struct {
		name    string
		subject string
		body    string
	}{
		{
			name:    "conditional can select body for a different legal title",
			subject: `{{if eq .title "trigger"}}{{.body}}{{else}}{{.title}}{{end}}`,
			body:    "{{.body}}",
		},
		{name: "urlquery transform can expand a legal body", subject: "{{.title}}", body: "{{urlquery .body}}"},
		{name: "printf function is outside fixed substitutions", subject: `{{printf "%s" .title}}`, body: "{{.body}}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition := valid
			definition.Subject = test.subject
			definition.Body = test.body
			if err := validateAnnouncementPublishedTemplate(definition); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAnnouncementPublishedSMSTemplateUsesChannelBounds(t *testing.T) {
	valid := notification.TemplateDefinition{
		Ref: notification.TemplateRef{
			ID: announcementPublishedTemplateID, Version: 1, Channel: notification.ChannelSMS,
		},
		Body: "{{.title}}\n{{.body}}", Variables: []string{"title", "body"},
	}
	if err := validateAnnouncementPublishedTemplate(valid); err != nil {
		t.Fatalf("valid SMS template = %v", err)
	}

	for name, mutate := range map[string]func(*notification.TemplateDefinition){
		"email subject":    func(value *notification.TemplateDefinition) { value.Subject = "not allowed" },
		"missing variable": func(value *notification.TemplateDefinition) { value.Variables = []string{"body"} },
	} {
		t.Run(name, func(t *testing.T) {
			definition := valid
			mutate(&definition)
			if err := validateAnnouncementPublishedTemplate(definition); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}
