package notification

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCatalogRendersVersionedSMSAndEmailTemplates(t *testing.T) {
	catalog := NewCatalog()
	definitions := []TemplateDefinition{
		{
			Ref:       TemplateRef{ID: "quota_warning", Version: 1, Channel: ChannelSMS},
			Body:      "{{.display_name}}，流量已使用 {{.percent}}%。",
			Variables: []string{"display_name", "percent"},
		},
		{
			Ref:       TemplateRef{ID: "quota_warning", Version: 2, Channel: ChannelSMS},
			Body:      "{{.display_name}}，当前用量 {{.percent}}%。",
			Variables: []string{"display_name", "percent"},
		},
		{
			Ref:       TemplateRef{ID: "quota_warning", Version: 3, Channel: ChannelEmail},
			Subject:   "用量提醒：{{.site_name}}",
			Body:      "{{.display_name}}，站点 {{.site_name}} 已使用 {{.percent}}%。",
			Variables: []string{"display_name", "percent", "site_name"},
		},
	}
	for _, definition := range definitions {
		if err := catalog.Register(definition); err != nil {
			t.Fatalf("register %+v: %v", definition.Ref, err)
		}
	}

	context := TemplateContext{
		"display_name": PublicValue("张三"),
		"percent":      PublicValue("80"),
	}
	first, err := catalog.Render(definitions[0].Ref, context)
	if err != nil {
		t.Fatal(err)
	}
	second, err := catalog.Render(definitions[1].Ref, context)
	if err != nil {
		t.Fatal(err)
	}
	if first.Body != "张三，流量已使用 80%。" || second.Body != "张三，当前用量 80%。" {
		t.Fatalf("versioned bodies = %q / %q", first.Body, second.Body)
	}

	email, err := catalog.Render(definitions[2].Ref, TemplateContext{
		"display_name": PublicValue("张三"),
		"percent":      PublicValue("80"),
		"site_name":    PublicValue("example.test"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if email.Subject != "用量提醒：example.test" ||
		email.Body != "张三，站点 example.test 已使用 80%。" {
		t.Fatalf("email = %+v", email)
	}
	if err := catalog.Register(definitions[0]); !errors.Is(err, ErrTemplateExists) {
		t.Fatalf("duplicate registration error = %v", err)
	}
}

func TestNextNotificationWindowHonorsCustomAndCrossMidnightWindows(t *testing.T) {
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	policy := DeliveryRuntimePolicy{WindowMode: "custom", WindowStart: 8 * 60, WindowEnd: 22 * 60, Timezone: "Asia/Shanghai"}
	if got := nextNotificationWindow(time.Date(2026, 8, 16, 7, 30, 0, 0, location), policy); !got.Equal(time.Date(2026, 8, 16, 8, 0, 0, 0, location)) {
		t.Fatalf("before window = %s", got)
	}
	if got := nextNotificationWindow(time.Date(2026, 8, 16, 23, 30, 0, 0, location), policy); !got.Equal(time.Date(2026, 8, 17, 8, 0, 0, 0, location)) {
		t.Fatalf("after window = %s", got)
	}
	policy.WindowStart, policy.WindowEnd = 22*60, 6*60
	if got := nextNotificationWindow(time.Date(2026, 8, 16, 12, 0, 0, 0, location), policy); !got.Equal(time.Date(2026, 8, 16, 22, 0, 0, 0, location)) {
		t.Fatalf("cross-midday = %s", got)
	}
	if got := nextNotificationWindow(time.Date(2026, 8, 16, 23, 0, 0, 0, location), policy); !got.Equal(time.Date(2026, 8, 16, 23, 0, 0, 0, location)) {
		t.Fatalf("cross-night = %s", got)
	}
}

func TestCatalogZeroValueCanRegisterAndRender(t *testing.T) {
	var catalog Catalog
	ref := TemplateRef{ID: "zero_value", Version: 1, Channel: ChannelSMS}
	if err := catalog.Register(TemplateDefinition{Ref: ref, Body: "ready"}); err != nil {
		t.Fatal(err)
	}
	message, err := catalog.Render(ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	if message.Body != "ready" {
		t.Fatalf("body = %q", message.Body)
	}
}

func TestTemplateSourceLimitsUseUTF8Bytes(t *testing.T) {
	tests := []struct {
		name       string
		definition TemplateDefinition
		want       error
	}{
		{
			name: "sms source at byte limit",
			definition: TemplateDefinition{
				Ref:  TemplateRef{ID: "sms_source_at_limit", Version: 1, Channel: ChannelSMS},
				Body: strings.Repeat("a", MaxSMSBodySourceBytes),
			},
		},
		{
			name: "sms source over byte limit",
			definition: TemplateDefinition{
				Ref:  TemplateRef{ID: "sms_source_over_limit", Version: 1, Channel: ChannelSMS},
				Body: strings.Repeat("界", MaxSMSBodySourceBytes/len("界")+1),
			},
			want: ErrTemplateLimit,
		},
		{
			name: "email subject source at byte limit",
			definition: TemplateDefinition{
				Ref:     TemplateRef{ID: "email_subject_at_source_limit", Version: 1, Channel: ChannelEmail},
				Subject: strings.Repeat("a", MaxEmailSubjectSourceBytes), Body: "body",
			},
		},
		{
			name: "email subject source over byte limit",
			definition: TemplateDefinition{
				Ref:     TemplateRef{ID: "email_subject_over_limit", Version: 1, Channel: ChannelEmail},
				Subject: strings.Repeat("a", MaxEmailSubjectSourceBytes+1), Body: "body",
			},
			want: ErrTemplateLimit,
		},
		{
			name: "email body source at byte limit",
			definition: TemplateDefinition{
				Ref:     TemplateRef{ID: "email_body_at_source_limit", Version: 1, Channel: ChannelEmail},
				Subject: "subject", Body: strings.Repeat("a", MaxEmailBodySourceBytes),
			},
		},
		{
			name: "email body source over byte limit",
			definition: TemplateDefinition{
				Ref:     TemplateRef{ID: "email_body_over_limit", Version: 1, Channel: ChannelEmail},
				Subject: "subject", Body: strings.Repeat("a", MaxEmailBodySourceBytes+1),
			},
			want: ErrTemplateLimit,
		},
		{
			name: "invalid utf8 source",
			definition: TemplateDefinition{
				Ref: TemplateRef{ID: "invalid_utf8", Version: 1, Channel: ChannelSMS}, Body: string([]byte{0xff}),
			},
			want: ErrTemplateLimit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := NewCatalog().Register(test.definition)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	variables := make([]string, MaxTemplateVariables+1)
	body := make([]string, len(variables))
	for index := range variables {
		variables[index] = fmt.Sprintf("value_%d", index)
		body[index] = "{{." + variables[index] + "}}"
	}
	if err := NewCatalog().Register(TemplateDefinition{
		Ref:     TemplateRef{ID: "too_many_variables", Version: 1, Channel: ChannelEmail},
		Subject: "subject", Body: strings.Join(body, ""), Variables: variables,
	}); !errors.Is(err, ErrTemplateLimit) {
		t.Fatalf("variable count error = %v", err)
	}
}

func TestContextLimitsRejectBeforeRenderingWithoutLeaking(t *testing.T) {
	catalog := NewCatalog()
	ref := TemplateRef{ID: "context_limits", Version: 1, Channel: ChannelEmail}
	if err := catalog.Register(TemplateDefinition{
		Ref: ref, Subject: "subject", Body: "{{.value}}", Variables: []string{"value"},
	}); err != nil {
		t.Fatal(err)
	}
	atLimit := strings.Repeat("a", MaxVariableValueBytes)
	if _, err := catalog.Render(ref, TemplateContext{"value": PublicValue(atLimit)}); err != nil {
		t.Fatalf("value at limit: %v", err)
	}
	overLimit := "sensitive-prefix-" + strings.Repeat("a", MaxVariableValueBytes)
	_, err := catalog.Render(ref, TemplateContext{"value": PublicValue(overLimit)})
	if !errors.Is(err, ErrContextLimit) {
		t.Fatalf("value over limit error = %v", err)
	}
	if strings.Contains(err.Error(), overLimit) {
		t.Fatalf("context value leaked in error: %v", err)
	}
	_, err = catalog.Render(ref, TemplateContext{"value": PublicValue(string([]byte{0xff}))})
	if !errors.Is(err, ErrContextLimit) {
		t.Fatalf("invalid UTF-8 context error = %v", err)
	}

	expected := make(map[string]struct{}, MaxTemplateVariables)
	context := make(TemplateContext, MaxTemplateVariables)
	for index := 0; index < MaxTemplateVariables; index++ {
		name := fmt.Sprintf("value_%d", index)
		expected[name] = struct{}{}
		context[name] = PublicValue(strings.Repeat("x", MaxVariableValueBytes))
	}
	if _, err := checkedContext(expected, context, ContextValidationPolicy{}); !errors.Is(err, ErrContextLimit) {
		t.Fatalf("total context error = %v", err)
	}
}

func TestAnnouncementPublishedEmailAllowsFullBodyWithoutRelaxingGenericOrSMSContextLimits(t *testing.T) {
	body := strings.Repeat("x", MaxEmailBodyBytes)
	emailContext := AnnouncementPublishedEmailContext("维护公告", body)

	catalog := NewCatalog()
	emailRef := TemplateRef{ID: "announcement_published", Version: 1, Channel: ChannelEmail}
	if err := catalog.Register(TemplateDefinition{
		Ref: emailRef, Subject: "[公告] {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"},
	}); err != nil {
		t.Fatal(err)
	}
	policy, err := AnnouncementPublishedEmailContextValidationPolicy(emailRef)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(catalog, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Plan(PlanRequest{
		Identity: EventIdentity{
			TenantID: "tenant", RecipientID: "recipient", EventID: "announcement-1", EventType: "announcement.published",
		},
		Policy: DeliverySystemRequired, Switches: ChannelSwitches{Email: true},
		Templates:                 map[Channel]TemplateRef{ChannelEmail: emailRef},
		Contexts:                  map[Channel]TemplateContext{ChannelEmail: emailContext},
		ContextValidationPolicies: map[Channel]ContextValidationPolicy{ChannelEmail: policy},
	})
	if err != nil {
		t.Fatalf("maximum announcement email body: %v", err)
	}
	if len(plan.Deliveries) != 1 || plan.Deliveries[0].Subject != "[公告] 维护公告" || plan.Deliveries[0].Body != body {
		t.Fatalf("maximum announcement plan = %+v", plan.Deliveries)
	}
	if _, err := catalog.Render(emailRef, emailContext); !errors.Is(err, ErrContextLimit) {
		t.Fatalf("untrusted announcement context error = %v", err)
	}

	genericRef := TemplateRef{ID: "generic_large_context", Version: 1, Channel: ChannelEmail}
	if err := catalog.Register(TemplateDefinition{
		Ref: genericRef, Subject: "{{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Render(genericRef, emailContext); !errors.Is(err, ErrContextLimit) {
		t.Fatalf("generic email context error = %v", err)
	}
	genericContext := TemplateContext{
		"title": PublicValue("维护公告"),
		"body":  PublicValue(body),
	}
	if err := validateContextResources(genericContext); !errors.Is(err, ErrContextLimit) {
		t.Fatalf("generic title/body preflight error = %v", err)
	}

	wrongVersionRef := TemplateRef{ID: "announcement_published", Version: 2, Channel: ChannelEmail}
	if err := catalog.Register(TemplateDefinition{
		Ref: wrongVersionRef, Subject: "[公告] {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Plan(PlanRequest{
		Identity: EventIdentity{
			TenantID: "tenant", RecipientID: "recipient", EventID: "announcement-2", EventType: "announcement.published",
		},
		Policy: DeliverySystemRequired, Switches: ChannelSwitches{Email: true},
		Templates:                 map[Channel]TemplateRef{ChannelEmail: wrongVersionRef},
		Contexts:                  map[Channel]TemplateContext{ChannelEmail: emailContext},
		ContextValidationPolicies: map[Channel]ContextValidationPolicy{ChannelEmail: policy},
	}); !errors.Is(err, ErrContextLimit) {
		t.Fatalf("wrong announcement template identity error = %v", err)
	}

	smsRef := TemplateRef{ID: "announcement_published", Version: 1, Channel: ChannelSMS}
	if err := catalog.Register(TemplateDefinition{
		Ref: smsRef, Body: "{{.title}}\n{{.body}}", Variables: []string{"title", "body"},
	}); err != nil {
		t.Fatal(err)
	}
	smsContext := TemplateContext{"title": PublicValue("维护公告"), "body": PublicValue(body)}
	if _, err := catalog.Render(smsRef, smsContext); !errors.Is(err, ErrContextLimit) {
		t.Fatalf("announcement SMS context error = %v", err)
	}
}

func TestAnnouncementPublishedEmailContextCannotSelfAuthorizeLargeBody(t *testing.T) {
	ref := TemplateRef{ID: "announcement_published", Version: 7, Channel: ChannelEmail}
	catalog := NewCatalog()
	if err := catalog.Register(TemplateDefinition{
		Ref: ref, Subject: "[公告] {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"},
	}); err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", MaxEmailBodyBytes)
	forged := AnnouncementPublishedEmailContext("维护公告", body)
	forged["_cdnca_announcement_email_template"] = PublicValue(
		"v1:announcement_published:7:email",
	)
	if _, err := catalog.Render(ref, forged); !errors.Is(err, ErrContextLimit) {
		t.Fatalf("self-authorized announcement context error = %v", err)
	}
}

func TestAnnouncementContextPolicyCannotAuthorizeWrongEventChannelOrUnknownPolicy(t *testing.T) {
	emailRef := TemplateRef{ID: "announcement_published", Version: 9, Channel: ChannelEmail}
	policy, err := AnnouncementPublishedEmailContextValidationPolicy(emailRef)
	if err != nil {
		t.Fatal(err)
	}
	context := map[Channel]TemplateContext{
		ChannelEmail: AnnouncementPublishedEmailContext("维护公告", strings.Repeat("x", MaxEmailBodyBytes)),
	}
	templates := map[Channel]TemplateRef{ChannelEmail: emailRef}
	for name, test := range map[string]struct {
		eventType string
		policies  map[Channel]ContextValidationPolicy
	}{
		"generic event": {
			eventType: "generic.event", policies: map[Channel]ContextValidationPolicy{ChannelEmail: policy},
		},
		"SMS channel": {
			eventType: "announcement.published", policies: map[Channel]ContextValidationPolicy{ChannelSMS: policy},
		},
		"unknown policy": {
			eventType: "announcement.published", policies: map[Channel]ContextValidationPolicy{ChannelEmail: {
				kind: contextValidationPolicyKind(99), template: emailRef,
			}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateContextValidationPolicies(test.eventType, templates, context, test.policies); !errors.Is(err, ErrContextLimit) {
				t.Fatalf("policy validation error = %v", err)
			}
		})
	}
	if _, err := AnnouncementPublishedEmailContextValidationPolicy(TemplateRef{
		ID: "announcement_published", Version: 9, Channel: ChannelSMS,
	}); !errors.Is(err, ErrContextLimit) {
		t.Fatalf("SMS policy constructor error = %v", err)
	}

	storeRequest := EnqueueRequest{
		ScopeID:       uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		RecipientID:   uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		SourceEventID: "announcement:policy:v1", EventType: "announcement.published",
		Policy: DeliverySystemRequired, Templates: templates, Contexts: context,
		ContextValidationPolicies: map[Channel]ContextValidationPolicy{ChannelEmail: policy},
		AuditRequestID:            "announcement-policy-request",
	}
	if err := validateEnqueueRequest(storeRequest); err != nil {
		t.Fatalf("store valid announcement policy = %v", err)
	}
	storeRequest.EventType = "generic.event"
	if err := validateEnqueueRequest(storeRequest); !errors.Is(err, ErrInvalidEnqueue) {
		t.Fatalf("store wrong event policy = %v", err)
	}
	storeRequest.EventType = "announcement.published"
	storeRequest.Templates = map[Channel]TemplateRef{ChannelEmail: {
		ID: "announcement_published", Version: emailRef.Version + 1, Channel: ChannelEmail,
	}}
	if err := validateEnqueueRequest(storeRequest); !errors.Is(err, ErrInvalidEnqueue) {
		t.Fatalf("store wrong template policy = %v", err)
	}
}

func TestEnqueueDigestExcludesContextValidationPolicy(t *testing.T) {
	ref := TemplateRef{ID: "announcement_published", Version: 3, Channel: ChannelEmail}
	request := EnqueueRequest{
		ScopeID:       uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		RecipientID:   uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		SourceEventID: "announcement:small:v1", EventType: "announcement.published",
		Policy:    DeliveryTenantSubscribed,
		Templates: map[Channel]TemplateRef{ChannelEmail: ref},
		Contexts: map[Channel]TemplateContext{ChannelEmail: {
			"title": PublicValue("small"), "body": PublicValue("body"),
		}},
	}
	want := "8b4f9d89fc9677aefeb250ebbb6ff486f4ce41331fa55c0fe5f550c5b591e9ec"
	if got := fmt.Sprintf("%x", enqueueRequestDigest(request)); got != want {
		t.Fatalf("small context digest = %s, want %s", got, want)
	}
	policy, err := AnnouncementPublishedEmailContextValidationPolicy(ref)
	if err != nil {
		t.Fatal(err)
	}
	request.ContextValidationPolicies = map[Channel]ContextValidationPolicy{ChannelEmail: policy}
	if got := fmt.Sprintf("%x", enqueueRequestDigest(request)); got != want {
		t.Fatalf("policy changed replay digest = %s, want %s", got, want)
	}
}

func TestRenderedOutputLimitsUseSMSBytesEmailSubjectRunesAndEmailBodyBytes(t *testing.T) {
	tests := []struct {
		name       string
		definition TemplateDefinition
		context    TemplateContext
		want       error
	}{
		{
			name: "sms bytes at limit",
			definition: TemplateDefinition{
				Ref:  TemplateRef{ID: "sms_output_at_limit", Version: 1, Channel: ChannelSMS},
				Body: "{{.value}}", Variables: []string{"value"},
			},
			context: TemplateContext{"value": PublicValue(strings.Repeat("a", MaxSMSBodyBytes))},
		},
		{
			name: "sms multibyte over byte limit",
			definition: TemplateDefinition{
				Ref:  TemplateRef{ID: "sms_output_over_limit", Version: 1, Channel: ChannelSMS},
				Body: "{{.value}}", Variables: []string{"value"},
			},
			context: TemplateContext{"value": PublicValue(strings.Repeat("界", MaxSMSBodyBytes/len("界")+1))},
			want:    ErrRenderLimit,
		},
		{
			name: "email subject runes at limit",
			definition: TemplateDefinition{
				Ref:     TemplateRef{ID: "email_subject_at_limit", Version: 1, Channel: ChannelEmail},
				Subject: "{{.value}}", Body: "body", Variables: []string{"value"},
			},
			context: TemplateContext{"value": PublicValue(strings.Repeat("界", MaxEmailSubjectRunes))},
		},
		{
			name: "email subject runes over limit",
			definition: TemplateDefinition{
				Ref:     TemplateRef{ID: "email_subject_over_output", Version: 1, Channel: ChannelEmail},
				Subject: "{{.value}}", Body: "body", Variables: []string{"value"},
			},
			context: TemplateContext{"value": PublicValue(strings.Repeat("界", MaxEmailSubjectRunes+1))},
			want:    ErrRenderLimit,
		},
		{
			name: "email body bytes at limit",
			definition: TemplateDefinition{
				Ref:     TemplateRef{ID: "email_body_at_output", Version: 1, Channel: ChannelEmail},
				Subject: "subject", Body: strings.Repeat("{{.value}}", MaxEmailBodyBytes/MaxVariableValueBytes),
				Variables: []string{"value"},
			},
			context: TemplateContext{"value": PublicValue(strings.Repeat("a", MaxVariableValueBytes))},
		},
		{
			name: "email body bytes over limit",
			definition: TemplateDefinition{
				Ref:     TemplateRef{ID: "email_body_over_output", Version: 1, Channel: ChannelEmail},
				Subject: "subject", Body: strings.Repeat("{{.value}}", MaxEmailBodyBytes/MaxVariableValueBytes+1),
				Variables: []string{"value"},
			},
			context: TemplateContext{"value": PublicValue(strings.Repeat("a", MaxVariableValueBytes))},
			want:    ErrRenderLimit,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := NewCatalog()
			if err := catalog.Register(test.definition); err != nil {
				t.Fatal(err)
			}
			_, err := catalog.Render(test.definition.Ref, test.context)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCatalogRejectsEveryMissingAndExtraVariableCombination(t *testing.T) {
	catalog := NewCatalog()
	ref := TemplateRef{ID: "combination", Version: 1, Channel: ChannelEmail}
	if err := catalog.Register(TemplateDefinition{
		Ref:       ref,
		Subject:   "{{.first}} {{.second}}",
		Body:      "{{.third}}",
		Variables: []string{"first", "second", "third"},
	}); err != nil {
		t.Fatal(err)
	}

	names := []string{"first", "second", "third"}
	for mask := 0; mask < 1<<len(names); mask++ {
		context := make(TemplateContext)
		for index, name := range names {
			if mask&(1<<index) != 0 {
				context[name] = PublicValue(name)
			}
		}
		_, err := catalog.Render(ref, context)
		if mask == (1<<len(names))-1 {
			if err != nil {
				t.Fatalf("complete variable mask %03b: %v", mask, err)
			}
		} else if !errors.Is(err, ErrVariableMismatch) {
			t.Fatalf("missing variable mask %03b error = %v", mask, err)
		}

		context["unexpected"] = PublicValue("must be rejected")
		if _, err := catalog.Render(ref, context); !errors.Is(err, ErrVariableMismatch) {
			t.Fatalf("extra variable mask %03b error = %v", mask, err)
		}
	}
}

func TestCatalogRejectsUnsafeDefinitionsAndSensitiveContextWithoutLeaking(t *testing.T) {
	unsafeDefinitions := []TemplateDefinition{
		{
			Ref:       TemplateRef{ID: "undeclared", Version: 1, Channel: ChannelSMS},
			Body:      "{{.display_name}} {{.percent}}",
			Variables: []string{"display_name"},
		},
		{
			Ref:       TemplateRef{ID: "dynamic", Version: 1, Channel: ChannelSMS},
			Body:      "{{index . \"display_name\"}}",
			Variables: []string{"display_name"},
		},
		{
			Ref:       TemplateRef{ID: "whole_context", Version: 1, Channel: ChannelSMS},
			Body:      "{{printf \"%v\" .}}",
			Variables: nil,
		},
		{
			Ref:       TemplateRef{ID: "secret_name", Version: 1, Channel: ChannelSMS},
			Body:      "{{.api_token}}",
			Variables: []string{"api_token"},
		},
	}
	for _, definition := range unsafeDefinitions {
		if err := NewCatalog().Register(definition); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("definition %q error = %v", definition.Ref.ID, err)
		}
	}

	// A declared variable may go unused (an SMS template shares its email
	// sibling's declaration, fix-r4); the context must still match it exactly.
	unused := NewCatalog()
	unusedRef := TemplateRef{ID: "unused", Version: 1, Channel: ChannelSMS}
	if err := unused.Register(TemplateDefinition{
		Ref: unusedRef, Body: "{{.display_name}}", Variables: []string{"display_name", "percent"},
	}); err != nil {
		t.Fatalf("declared but unused variable: %v", err)
	}
	if _, err := unused.Render(unusedRef, TemplateContext{"display_name": PublicValue("a")}); !errors.Is(err, ErrVariableMismatch) {
		t.Fatalf("context without a declared variable = %v", err)
	}
	if message, err := unused.Render(unusedRef, TemplateContext{
		"display_name": PublicValue("a"), "percent": PublicValue("1"),
	}); err != nil || message.Body != "a" {
		t.Fatalf("declared context = %+v %v", message, err)
	}

	catalog := NewCatalog()
	ref := TemplateRef{ID: "sensitive_context", Version: 1, Channel: ChannelSMS}
	if err := catalog.Register(TemplateDefinition{
		Ref: ref, Body: "{{.display_name}}", Variables: []string{"display_name"},
	}); err != nil {
		t.Fatal(err)
	}
	secret := "never-include-this-secret"
	_, err := catalog.Render(ref, TemplateContext{"display_name": SensitiveValue(secret)})
	if !errors.Is(err, ErrSensitiveContext) {
		t.Fatalf("sensitive context error = %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%v", err), secret) {
		t.Fatalf("sensitive value leaked in error: %v", err)
	}
}

func TestDecideChannelsHonorsIndependentSwitchesSubscriptionsAndRequiredPolicy(t *testing.T) {
	tests := []struct {
		name         string
		policy       DeliveryPolicy
		switches     ChannelSwitches
		subscription Subscription
		want         []Channel
	}{
		{
			name: "tenant receives both", policy: DeliveryTenantSubscribed,
			switches: ChannelSwitches{SMS: true, Email: true}, subscription: Subscription{SMS: true, Email: true},
			want: []Channel{ChannelSMS, ChannelEmail},
		},
		{
			name: "sms globally off", policy: DeliveryTenantSubscribed,
			switches: ChannelSwitches{Email: true}, subscription: Subscription{SMS: true, Email: true},
			want: []Channel{ChannelEmail},
		},
		{
			name: "email globally off", policy: DeliveryTenantSubscribed,
			switches: ChannelSwitches{SMS: true}, subscription: Subscription{SMS: true, Email: true},
			want: []Channel{ChannelSMS},
		},
		{
			name: "both globally off", policy: DeliverySystemRequired,
			switches: ChannelSwitches{}, subscription: Subscription{SMS: true, Email: true},
			want: nil,
		},
		{
			name: "tenant subscriptions off", policy: DeliveryTenantSubscribed,
			switches: ChannelSwitches{SMS: true, Email: true}, subscription: Subscription{},
			want: nil,
		},
		{
			name: "required bypasses tenant subscriptions", policy: DeliverySystemRequired,
			switches: ChannelSwitches{SMS: true, Email: true}, subscription: Subscription{},
			want: []Channel{ChannelSMS, ChannelEmail},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecideChannels(test.policy, test.switches, test.subscription)
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(got) != fmt.Sprint(test.want) {
				t.Fatalf("channels = %v, want %v", got, test.want)
			}
		})
	}
	if _, err := DecideChannels(DeliveryPolicy("unknown"), ChannelSwitches{}, Subscription{}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown policy error = %v", err)
	}
}

func TestEnginePlansStableDeduplicationKeysWithFixedClock(t *testing.T) {
	catalog := NewCatalog()
	smsRef := TemplateRef{ID: "node_offline", Version: 2, Channel: ChannelSMS}
	emailRef := TemplateRef{ID: "node_offline", Version: 4, Channel: ChannelEmail}
	if err := catalog.Register(TemplateDefinition{
		Ref: smsRef, Body: "节点 {{.node_name}} 已离线", Variables: []string{"node_name"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Register(TemplateDefinition{
		Ref: emailRef, Subject: "节点离线", Body: "节点 {{.node_name}} 已离线", Variables: []string{"node_name"},
	}); err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 7, 22, 13, 14, 15, 0, time.FixedZone("CST", 8*60*60))
	engine, err := NewEngine(catalog, func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	request := PlanRequest{
		Identity: EventIdentity{
			TenantID: "tenant-7", RecipientID: "user-9", EventID: "event-11", EventType: "node.offline",
		},
		Policy:       DeliverySystemRequired,
		Switches:     ChannelSwitches{SMS: true, Email: true},
		Subscription: Subscription{},
		Templates: map[Channel]TemplateRef{
			ChannelSMS: smsRef, ChannelEmail: emailRef,
		},
		Contexts: map[Channel]TemplateContext{
			ChannelSMS:   {"node_name": PublicValue("edge-1")},
			ChannelEmail: {"node_name": PublicValue("edge-1")},
		},
	}
	first, err := engine.Plan(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Plan(request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.CreatedAt.Equal(fixed.UTC()) || !second.CreatedAt.Equal(fixed.UTC()) {
		t.Fatalf("created times = %v / %v", first.CreatedAt, second.CreatedAt)
	}
	if len(first.Deliveries) != 2 || len(second.Deliveries) != 2 {
		t.Fatalf("delivery counts = %d / %d", len(first.Deliveries), len(second.Deliveries))
	}
	if first.Deliveries[0].DedupKey != second.Deliveries[0].DedupKey ||
		first.Deliveries[1].DedupKey != second.Deliveries[1].DedupKey {
		t.Fatal("duplicate event produced different deduplication keys")
	}
	if first.Deliveries[0].DedupKey == first.Deliveries[1].DedupKey {
		t.Fatal("different channels shared a deduplication key")
	}
	changed := request
	changed.Identity.EventID = "event-12"
	third, err := engine.Plan(changed)
	if err != nil {
		t.Fatal(err)
	}
	if first.Deliveries[0].DedupKey == third.Deliveries[0].DedupKey {
		t.Fatal("different events shared a deduplication key")
	}
}

func TestEngineDoesNotRequireTemplatesForDisabledChannels(t *testing.T) {
	catalog := NewCatalog()
	engine, err := NewEngine(catalog, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Plan(PlanRequest{
		Identity: EventIdentity{TenantID: "tenant", RecipientID: "user", EventID: "event", EventType: "maintenance"},
		Policy:   DeliverySystemRequired, Switches: ChannelSwitches{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Deliveries) != 0 {
		t.Fatalf("deliveries = %+v", plan.Deliveries)
	}
}

func TestRetryPolicyClassifiesPermanentTemporaryAndExhaustedFailures(t *testing.T) {
	fixed := time.Date(2026, 7, 22, 5, 0, 0, 0, time.UTC)
	policy, err := NewRetryPolicy(4, time.Second, 3*time.Second, func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}

	permanent, err := policy.Decide(1, Failure{Class: FailurePermanent, Code: "recipient_invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if permanent.Action != RetryStopped || permanent.Delay != 0 || !permanent.RetryAt.IsZero() {
		t.Fatalf("permanent decision = %+v", permanent)
	}

	wants := []struct {
		attempt int
		action  RetryAction
		delay   time.Duration
	}{
		{attempt: 1, action: RetryScheduled, delay: time.Second},
		{attempt: 2, action: RetryScheduled, delay: 2 * time.Second},
		{attempt: 3, action: RetryScheduled, delay: 3 * time.Second},
		{attempt: 4, action: RetryExhausted},
		{attempt: 20, action: RetryExhausted},
	}
	for _, want := range wants {
		decision, err := policy.Decide(want.attempt, Failure{Class: FailureTemporary, Code: "provider_unavailable"})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Action != want.action || decision.Delay != want.delay {
			t.Errorf("attempt %d decision = %+v", want.attempt, decision)
		}
		if want.action == RetryScheduled && !decision.RetryAt.Equal(fixed.Add(want.delay)) {
			t.Errorf("attempt %d retry time = %v", want.attempt, decision.RetryAt)
		}
		if want.action != RetryScheduled && !decision.RetryAt.IsZero() {
			t.Errorf("attempt %d unexpectedly scheduled at %v", want.attempt, decision.RetryAt)
		}
	}

	invalid := []Failure{
		{Class: FailureClass("unknown"), Code: "provider_unavailable"},
		{Class: FailureTemporary, Code: "raw upstream error: secret=abc"},
	}
	for _, failure := range invalid {
		if _, err := policy.Decide(1, failure); !errors.Is(err, ErrInvalidFailure) {
			t.Errorf("failure %+v error = %v", failure, err)
		}
	}
}

func TestRetryPolicyHonorsBoundedProviderRetryAfter(t *testing.T) {
	fixed := time.Date(2026, 7, 23, 9, 0, 0, 0, time.UTC)
	policy, err := NewRetryPolicy(4, time.Second, 30*time.Second, func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}

	decision, err := policy.Decide(1, Failure{
		Class: FailureTemporary, Code: "provider_rate_limited", RetryAfter: 12 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Delay != 12*time.Second || !decision.RetryAt.Equal(fixed.Add(12*time.Second)) {
		t.Fatalf("provider retry decision = %+v", decision)
	}

	decision, err = policy.Decide(1, Failure{
		Class: FailureTemporary, Code: "provider_rate_limited", RetryAfter: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Delay != 30*time.Second || !decision.RetryAt.Equal(fixed.Add(30*time.Second)) {
		t.Fatalf("bounded provider retry decision = %+v", decision)
	}

	invalid := []Failure{
		{Class: FailurePermanent, Code: "recipient_invalid", RetryAfter: time.Second},
		{Class: FailureTemporary, Code: "provider_unavailable", RetryAfter: -time.Second},
	}
	for _, failure := range invalid {
		if _, err := policy.Decide(1, failure); !errors.Is(err, ErrInvalidFailure) {
			t.Errorf("failure %+v error = %v", failure, err)
		}
	}
}

func TestWorkerConfigRequiresBoundedLeaseSafetyMargin(t *testing.T) {
	config := DefaultWorkerConfig()
	if !validWorkerConfig(config) {
		t.Fatal("default worker config is invalid")
	}
	config.LeaseSafetyMargin = 0
	if validWorkerConfig(config) {
		t.Fatal("zero lease safety margin was accepted")
	}
	config.LeaseSafetyMargin = config.LeaseDuration
	if validWorkerConfig(config) {
		t.Fatal("lease-wide safety margin was accepted")
	}
}

func TestCatalogAndEngineAreRaceSafe(t *testing.T) {
	catalog := NewCatalog()
	baseRef := TemplateRef{ID: "concurrent", Version: 1, Channel: ChannelSMS}
	if err := catalog.Register(TemplateDefinition{
		Ref: baseRef, Body: "{{.name}}", Variables: []string{"name"},
	}); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(catalog, func() time.Time { return time.Unix(1_700_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}

	const workers = 32
	start := make(chan struct{})
	errorsFound := make(chan error, workers*2)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			ref := TemplateRef{ID: "concurrent", Version: uint64(worker + 2), Channel: ChannelSMS}
			if err := catalog.Register(TemplateDefinition{
				Ref: ref, Body: "{{.name}}", Variables: []string{"name"},
			}); err != nil {
				errorsFound <- err
			}
			plan, err := engine.Plan(PlanRequest{
				Identity: EventIdentity{
					TenantID: "tenant", RecipientID: "user", EventID: fmt.Sprintf("event-%d", worker), EventType: "test.event",
				},
				Policy:   DeliveryTenantSubscribed,
				Switches: ChannelSwitches{SMS: true}, Subscription: Subscription{SMS: true},
				Templates: map[Channel]TemplateRef{ChannelSMS: baseRef},
				Contexts:  map[Channel]TemplateContext{ChannelSMS: {"name": PublicValue("safe")}},
			})
			if err != nil {
				errorsFound <- err
				return
			}
			if len(plan.Deliveries) != 1 || plan.Deliveries[0].Body != "safe" {
				errorsFound <- fmt.Errorf("unexpected concurrent plan: %+v", plan)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}
