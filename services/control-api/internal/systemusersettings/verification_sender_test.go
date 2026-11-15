package systemusersettings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// A verification is in effect while it is required and its
// notification channel switch is on. Turning it on with the switch on and no
// sender is refused (sign-up would refuse everyone); with the switch off it
// saves and is not in effect (GetPublic reports it off); with a sender it is
// saved, and a verification already on is kept when the sender goes away.
func TestPostgresVerificationRequiresSender(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	email, sms := false, false
	service.WithVerificationSenders(func(context.Context) (bool, bool) { return email, sms })
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}

	// the defaults need no sender
	saved, err := service.Save(t.Context(), actor, SaveRequest{Value: DefaultSettings(), IdempotencyKey: "sender-default", RequestID: "sender-default"})
	if err != nil || saved.Value.EmailVerificationRequired || saved.Value.PhoneVerificationRequired {
		t.Fatalf("default save=(%+v,%v)", saved.Value, err)
	}
	switches := func(email, sms bool) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), `UPDATE notification_channel_settings SET email_enabled=$1,sms_enabled=$2 WHERE singleton`, email, sms); err != nil {
			t.Fatal(err)
		}
	}
	value := DefaultSettings()
	value.EmailRequired, value.EmailVerificationRequired = true, true
	// channel switch off: saved, not in effect
	switches(false, false)
	off, err := service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: saved.Revision, Value: value,
		IdempotencyKey: "sender-switch-off", RequestID: "sender-switch-off"})
	if err != nil || !off.Value.EmailVerificationRequired {
		t.Fatalf("switch off save=(%+v,%v)", off.Value, err)
	}
	if public, err := service.GetPublic(t.Context(), scopeID); err != nil || public.EmailVerificationRequired {
		t.Fatalf("switch off: verification in effect %+v %v", public, err)
	}
	saved, err = service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: off.Revision, Value: DefaultSettings(),
		IdempotencyKey: "sender-reset", RequestID: "sender-reset"})
	if err != nil {
		t.Fatal(err)
	}
	switches(true, true)
	_, err = service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: saved.Revision, Value: value,
		IdempotencyKey: "sender-email-off", RequestID: "sender-email-off"})
	located, ok := fielderr.As(err)
	if !errors.Is(err, ErrVerificationSenderUnavailable) || !ok || located.Field != "value.email_verification_required" {
		t.Fatalf("email verification without a sender = %v (%+v)", err, located)
	}
	phone := DefaultSettings()
	phone.PhoneRequired, phone.PhoneVerificationRequired = true, true
	_, err = service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: saved.Revision, Value: phone,
		IdempotencyKey: "sender-sms-off", RequestID: "sender-sms-off"})
	if located, ok := fielderr.As(err); !errors.Is(err, ErrVerificationSenderUnavailable) || !ok || located.Field != "value.phone_verification_required" {
		t.Fatalf("phone verification without a sender = %v", err)
	}

	email = true
	on, err := service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: saved.Revision, Value: value,
		IdempotencyKey: "sender-email-on", RequestID: "sender-email-on"})
	if err != nil || !on.Value.EmailVerificationRequired {
		t.Fatalf("email verification with a sender=(%+v,%v)", on.Value, err)
	}
	if public, err := service.GetPublic(t.Context(), scopeID); err != nil || !public.EmailVerificationRequired {
		t.Fatalf("both on: verification not in effect %+v %v", public, err)
	}
	// the sender goes away: other edits still save, the verification stays on
	email = false
	value.SessionTTLSeconds = 3600
	kept, err := service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: on.Revision, Value: value,
		IdempotencyKey: "sender-email-kept", RequestID: "sender-email-kept"})
	if err != nil || !kept.Value.EmailVerificationRequired {
		t.Fatalf("kept verification=(%+v,%v)", kept.Value, err)
	}
}
