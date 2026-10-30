package accountrecovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

func TestDigestDomainsAreSeparated(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	value := "same-value"
	token := keyedDigest(key, tokenDigestDomain, value)
	subject := keyedDigest(key, subjectDigestDomain, value)
	source := keyedDigest(key, sourceDigestDomain, value)
	password := keyedDigest(key, passwordDigestDomain, value)
	email := keyedDigest(key, contactDigestDomain("email"), value)
	phone := keyedDigest(key, contactDigestDomain("sms"), value)
	for name, digest := range map[string][32]byte{
		"subject":  subject,
		"source":   source,
		"password": password,
		"email":    email,
		"phone":    phone,
	} {
		if digest == token {
			t.Fatalf("%s digest reused token domain", name)
		}
	}
}

func TestWindowStartUsesInjectedClock(t *testing.T) {
	now := time.Date(2026, 7, 22, 10, 7, 31, 987654321, time.FixedZone("CST", 8*60*60))
	got := rateWindowStart(now, 15*time.Minute)
	want := time.Date(2026, 7, 22, 2, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("rateWindowStart() = %s, want %s", got, want)
	}
}

// Non-ASCII passwords break libs/passwordpolicy.
func TestValidateResetEnvelopeRejectsNonASCIIPassword(t *testing.T) {
	password := strings.Repeat("\U0001F600", 3)
	if len(password) != 12 || utf8.RuneCountInString(password) != 3 {
		t.Fatalf("test password bytes/runes = %d/%d", len(password), utf8.RuneCountInString(password))
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, tokenBytes))
	input := ResetInput{
		TenantID: uuid.New(), ScopeID: uuid.New(), Token: token,
		NewPassword: password, ConfirmPassword: password, IdempotencyKey: "utf8-byte-policy",
		Context: RequestContext{RequestID: "utf8-request", TraceID: "utf8-trace", SourceIP: "198.51.100.50"},
	}
	if _, _, err := validateResetEnvelope(input); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("three four-byte characters error = %v, want password policy", err)
	}
}

func TestResolveDispatchTemplatesOverridesPublishedEmailAndKeepsSMSFallback(t *testing.T) {
	emailFallback := notification.TemplateRef{ID: "recovery_email", Version: 1, Channel: notification.ChannelEmail}
	smsFallback := notification.TemplateRef{ID: "recovery_sms", Version: 1, Channel: notification.ChannelSMS}
	emailPublished := notification.TemplateRef{
		ID: "platform_user_account_recovery", Version: 4, Channel: notification.ChannelEmail,
	}
	service := &Service{
		templates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelEmail: emailFallback,
			notification.ChannelSMS:   smsFallback,
		},
		templateResolver: recoveryTemplateResolver{email: emailPublished},
	}
	resolved, err := service.resolveDispatchTemplates(t.Context(), uuid.New())
	if err != nil || resolved[notification.ChannelEmail] != emailPublished ||
		resolved[notification.ChannelSMS] != smsFallback {
		t.Fatalf("resolved templates=(%#v,%v)", resolved, err)
	}
	if service.templates[notification.ChannelEmail] != emailFallback {
		t.Fatal("fallback template map was mutated")
	}

	service.templateResolver = recoveryTemplateResolver{err: errors.New("settings unavailable")}
	resolved, err = service.resolveDispatchTemplates(t.Context(), uuid.New())
	if err != nil || resolved[notification.ChannelEmail] != emailFallback ||
		resolved[notification.ChannelSMS] != smsFallback {
		t.Fatalf("resolver fallback=(%#v,%v)", resolved, err)
	}
}

func TestRenderAccountRecoveryTemplateSubstitutesUsernameWithoutTouchingActionURL(t *testing.T) {
	subject, body := renderAccountRecoveryTemplate(
		"找回密码：{{.username}}", "<p>您好，{{.username}}。</p>", "member-1",
	)
	if subject != "找回密码：member-1" || body != "<p>您好，member-1。</p>" || strings.Contains(subject+body, "{{") {
		t.Fatalf("rendered recovery template=(%q,%q)", subject, body)
	}
}

type recoveryTemplateResolver struct {
	email notification.TemplateRef
	err   error
}

func (resolver recoveryTemplateResolver) GetAccountRecoveryTemplate(
	_ context.Context,
	_ uuid.UUID,
	channel notification.Channel,
) (notification.TemplateRef, bool, error) {
	if resolver.err != nil {
		return notification.TemplateRef{}, false, resolver.err
	}
	if channel == notification.ChannelEmail && resolver.email != (notification.TemplateRef{}) {
		return resolver.email, true, nil
	}
	return notification.TemplateRef{}, false, nil
}
