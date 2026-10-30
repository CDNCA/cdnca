package accountloginchallenge

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FX38: consuming a password-login SMS challenge normalizes a bare phone with
// the same platform default code that Create used, read in the login tx.
func TestConsumePhoneCountryCodeMatchesCreate(t *testing.T) {
	original := publicSettingsTx
	t.Cleanup(func() { publicSettingsTx = original })
	publicSettingsTx = func(context.Context, pgx.Tx, uuid.UUID) (systemusersettings.PublicSettings, error) {
		return systemusersettings.PublicSettings{DefaultPhoneCountryCode: "1"}, nil
	}
	code, err := consumePhoneCountryCode(t.Context(), nil, uuid.New(), notification.ChannelSMS, "415 555 0100")
	if err != nil || code != "1" {
		t.Fatalf("code = %q, %v", code, err)
	}
	if code, err := consumePhoneCountryCode(t.Context(), nil, uuid.New(), notification.ChannelEmail, "a@example.com"); err != nil || code != "" {
		t.Fatalf("email code = %q, %v", code, err)
	}
}

// FX38: an SMS login identifier typed without "+86" matches the stored E.164 phone.
func TestNormalizeLoginChallengeUsesE164Phone(t *testing.T) {
	normalized, err := normalizeCreate(CreateInput{ScopeID: uuid.New(), Identifier: "138 0013 8000",
		Channel: notification.ChannelSMS, Source: "2001:db8::1", IdempotencyKey: "login-create-1",
		RequestID: "login-request-1"}, loginChallengeTestKey, "")
	if err != nil || normalized.Identifier != "+8613800138000" {
		t.Fatalf("identifier = %q, %v", normalized.Identifier, err)
	}
}
