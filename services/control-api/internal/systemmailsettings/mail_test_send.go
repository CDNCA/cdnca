package systemmailsettings

import (
	"context"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/mail"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/jackc/pgx/v5"
)

const operationTest = "system_mail_settings.test"

// TestRequest sends one test mail through Value.MailProvider as entered on
// the page (not saved): an official provider uses MailSecret, or the stored
// credential when it belongs to that provider.
type TestRequest struct {
	Value      Settings
	MailSecret string
	To         string
	RequestID  string
}

// TestTarget is what the process sender gets. Secret is cleared after Send.
type TestTarget struct {
	Value  Settings
	Secret []byte
	To     string
}

// TestSender sends the test mail and returns the provider message id or a
// *mail.Error (or another error: reported as provider_unavailable).
type TestSender func(context.Context, TestTarget) (string, error)

// TestResult is always returned once a send was attempted.
type TestResult struct {
	OK        bool   `json:"ok"`
	Provider  string `json:"provider"`
	MessageID string `json:"message_id,omitempty"`
	Code      string `json:"code,omitempty"`
}

// Test requires system_configuration.manage and audits the attempt (provider,
// recipient, outcome; never the credential).
func (s *Service) Test(ctx context.Context, actor Actor, request TestRequest, send TestSender) (TestResult, error) {
	if err := validActor(actor); err != nil {
		return TestResult{}, err
	}
	if send == nil || !validMetadata(request.RequestID) || !validSettings(request.Value) || !mail.ValidAddress(request.To) ||
		!validMailProvider(request.Value, request.MailSecret) || request.MailSecret != "" && s.cipher == nil {
		return TestResult{}, ErrInvalidInput
	}
	target := TestTarget{Value: request.Value, To: request.To}
	official := MailProviderKind(request.Value.MailProvider) == MailKindOfficial
	if official && request.MailSecret != "" {
		target.Secret = []byte(request.MailSecret)
	}
	defer func() { clear(target.Secret) }()
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, "system_configuration.manage"); err != nil {
			return err
		}
		// a test sends through the provider, so even the saved one needs
		// its module (stored "" never equals an official provider)
		if err := s.checkMailModule(ctx, tx, request.Value.MailProvider, ""); err != nil {
			return err
		}
		if !official || target.Secret != nil {
			return nil
		}
		var keyID, provider *string
		var ciphertext []byte
		err := tx.QueryRow(ctx, `SELECT mail_secret_key_id,mail_secret_ciphertext,mail_secret_provider
			FROM platform_system_mail_settings WHERE platform_scope_id=$1`, actor.ScopeID).Scan(&keyID, &ciphertext, &provider)
		if err == pgx.ErrNoRows || err == nil && (keyID == nil || provider == nil || *provider != request.Value.MailProvider) {
			return ErrInvalidInput
		}
		if err != nil {
			return err
		}
		target.Secret, err = openMailSecret(s.cipher, actor.ScopeID.String(), *provider, *keyID, ciphertext)
		return err
	})
	if err != nil {
		return TestResult{}, fmt.Errorf("test platform system mail settings: %w", err)
	}
	result := TestResult{Provider: MailProviderKind(request.Value.MailProvider)}
	if result.Provider != MailKindSMTP {
		result.Provider = request.Value.MailProvider
	}
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	messageID, sendErr := send(sendCtx, target)
	cancel()
	switch failure := mail.ErrorOf(sendErr); {
	case sendErr == nil:
		result.OK, result.MessageID = true, messageID
	case failure != nil:
		result.Code = failure.Code
	default:
		result.Code = mail.CodeUnavailable
	}
	outcome := "success"
	if !result.OK {
		outcome = "failure"
	}
	if err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: operationTest, ResourceType: "platform_system_mail_settings", ResourceID: actor.ScopeID.String(),
			RequestID: request.RequestID, Result: outcome, Payload: map[string]any{"mail_provider": request.Value.MailProvider,
				"to": request.To, "code": result.Code}})
	}); err != nil {
		return TestResult{}, fmt.Errorf("audit platform system mail test: %w", err)
	}
	return result, nil
}
