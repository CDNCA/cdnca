package notificationcontrol

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

func assertLocated(t *testing.T, err error, field, reason string) {
	t.Helper()
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	located, ok := fielderr.As(err)
	if !ok || located.Field != field || located.Reason != reason {
		t.Fatalf("located = %+v (%v), want %s/%s", located, err, field, reason)
	}
}

// fix-fielderr-be5: a refused delivery policy names the body field
// (window_mode, timezone, window_start/end, events, events[n].<field>).
func TestDeliveryPolicyRefusalsLocateField(t *testing.T) {
	for name, check := range map[string]struct {
		mutate        func(*UpdateDeliveryPolicyRequest)
		field, reason string
	}{
		"mode":              {func(r *UpdateDeliveryPolicyRequest) { r.WindowMode = "night" }, "window_mode", fielderr.Invalid},
		"timezone empty":    {func(r *UpdateDeliveryPolicyRequest) { r.Timezone = "" }, "timezone", fielderr.Required},
		"timezone long":     {func(r *UpdateDeliveryPolicyRequest) { r.Timezone = fmt.Sprintf("%065d", 0) }, "timezone", fielderr.TooLong},
		"timezone local":    {func(r *UpdateDeliveryPolicyRequest) { r.Timezone = "Local" }, "timezone", fielderr.Invalid},
		"timezone unknown":  {func(r *UpdateDeliveryPolicyRequest) { r.Timezone = "Mars/Base" }, "timezone", fielderr.Invalid},
		"custom start":      {func(r *UpdateDeliveryPolicyRequest) { r.WindowMode, r.WindowStart = "custom", "25:00" }, "window_start", fielderr.InvalidFormat},
		"custom end":        {func(r *UpdateDeliveryPolicyRequest) { r.WindowMode, r.WindowEnd = "custom", "8" }, "window_end", fielderr.InvalidFormat},
		"all day start":     {func(r *UpdateDeliveryPolicyRequest) { r.WindowStart = "08:00" }, "window_start", fielderr.Invalid},
		"all day end":       {func(r *UpdateDeliveryPolicyRequest) { r.WindowEnd = "22:00" }, "window_end", fielderr.Invalid},
		"no events":         {func(r *UpdateDeliveryPolicyRequest) { r.Events = nil }, "events", fielderr.Required},
		"event type":        {func(r *UpdateDeliveryPolicyRequest) { r.Events[1].EventType = "Bad" }, "events[1].event_type", fielderr.InvalidFormat},
		"event duplicate":   {func(r *UpdateDeliveryPolicyRequest) { r.Events[2].EventType = r.Events[0].EventType }, "events[2].event_type", fielderr.Duplicate},
		"repeat low":        {func(r *UpdateDeliveryPolicyRequest) { r.Events[1].RepeatCount = 0 }, "events[1].repeat_count", fielderr.OutOfRange},
		"repeat high":       {func(r *UpdateDeliveryPolicyRequest) { r.Events[0].RepeatCount = 11 }, "events[0].repeat_count", fielderr.OutOfRange},
		"interval":          {func(r *UpdateDeliveryPolicyRequest) { r.Events[2].IntervalHours = 169 }, "events[2].interval_hours", fielderr.OutOfRange},
		"unsupported on":    {func(r *UpdateDeliveryPolicyRequest) { r.Events[1].Supported, r.Events[1].Enabled = false, true }, "events[1].enabled", fielderr.Invalid},
		"unsupported email": {func(r *UpdateDeliveryPolicyRequest) { r.Events[1].Supported, r.Events[1].EmailEnabled = false, true }, "events[1].email_enabled", fielderr.Invalid},
	} {
		t.Run(name, func(t *testing.T) {
			request := deliveryPolicyRequestWithEvents(3)
			check.mutate(&request)
			assertLocated(t, validateDeliveryPolicyRequest(request), check.field, check.reason)
		})
	}
	tooMany := deliveryPolicyRequestWithEvents(maxDeliveryPolicyEvents + 1)
	assertLocated(t, validateDeliveryPolicyRequest(tooMany), "events", fielderr.TooLong)
}

// fix-fielderr-be5: the fixed announcement template and a catalog refusal of a
// template write name subject / body / variables.
func TestTemplateWriteRefusalsLocateField(t *testing.T) {
	valid := notification.TemplateDefinition{
		Ref:     notification.TemplateRef{ID: announcementPublishedTemplateID, Version: 1, Channel: notification.ChannelEmail},
		Subject: "[公告] {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"},
	}
	for name, check := range map[string]struct {
		mutate        func(*notification.TemplateDefinition)
		field, reason string
	}{
		"variables":   {func(d *notification.TemplateDefinition) { d.Variables = []string{"title"} }, "variables", fielderr.Invalid},
		"sms subject": {func(d *notification.TemplateDefinition) { d.Ref.Channel, d.Subject = notification.ChannelSMS, "x" }, "subject", fielderr.Invalid},
		"subject":     {func(d *notification.TemplateDefinition) { d.Subject = "{{urlquery .title}}" }, "subject", fielderr.Invalid},
		"body":        {func(d *notification.TemplateDefinition) { d.Body = "{{.body}}{{.body}}" }, "body", fielderr.TooLong},
	} {
		t.Run(name, func(t *testing.T) {
			definition := valid
			check.mutate(&definition)
			assertLocated(t, validateAnnouncementPublishedTemplate(definition), check.field, check.reason)
		})
	}

	catalogErr := notification.NewCatalog().Register(notification.TemplateDefinition{
		Ref: notification.TemplateRef{ID: "site_ready", Version: 1, Channel: notification.ChannelEmail}, Subject: "", Body: "b",
	})
	assertLocated(t, templateRefusal(catalogErr), "subject", fielderr.Required)
	if err := templateRefusal(notification.ErrTemplateExists); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unlocated refusal = %v", err)
	} else if _, ok := fielderr.As(err); ok {
		t.Fatalf("unlocated refusal has a field: %v", err)
	}
}
