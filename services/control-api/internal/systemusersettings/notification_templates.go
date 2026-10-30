package systemusersettings

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	registrationSuccessTemplateID      = "platform_user_registration_success"
	accountRecoveryTemplateID          = "platform_user_account_recovery"
	registrationVerificationTemplateID = "platform_user_registration_verification"
)

var (
	usernamePlaceholder = regexp.MustCompile(`\{\{\s*\.?username\s*\}\}`)
	captchaPlaceholder  = regexp.MustCompile(`\{\{\s*\.?captcha\s*\}\}|\$\{captcha\}`)
)

func settingsNotificationDefinitions(value Settings, version uint64) ([]notification.TemplateDefinition, error) {
	registrationSubject := normalizeNotificationTemplate(value.RegistrationSuccessSubject, usernamePlaceholder, "username")
	registrationBody := normalizeNotificationTemplate(value.RegistrationSuccessBody, usernamePlaceholder, "username")
	recoverySubject := normalizeNotificationTemplate(value.PasswordResetSubject, usernamePlaceholder, "username")
	recoveryBody := normalizeNotificationTemplate(value.PasswordResetBody, usernamePlaceholder, "username")
	verificationSubject := normalizeNotificationTemplate(value.VerificationSubject, captchaPlaceholder, "captcha")
	verificationBody := normalizeNotificationTemplate(value.VerificationBody, captchaPlaceholder, "captcha")
	verificationSMSBody := normalizeNotificationTemplate(value.VerificationSMSBody, captchaPlaceholder, "captcha")
	if !strings.Contains(verificationSubject+verificationBody, "{{.captcha}}") {
		return nil, fielderr.New(ErrInvalidInput, "value.verification_body", fielderr.Invalid)
	}
	if !strings.Contains(verificationSMSBody, "{{.captcha}}") {
		return nil, fielderr.New(ErrInvalidInput, "value.verification_sms_body", fielderr.Invalid)
	}
	definitions := []notification.TemplateDefinition{
		{
			Ref: notification.TemplateRef{
				ID: registrationSuccessTemplateID, Version: version, Channel: notification.ChannelEmail,
			},
			Subject:   registrationSubject,
			Body:      registrationBody,
			Variables: notificationTemplateVariables(registrationSubject+registrationBody, "username"),
		},
		{
			Ref: notification.TemplateRef{
				ID: accountRecoveryTemplateID, Version: version, Channel: notification.ChannelEmail,
			},
			Subject:   recoverySubject,
			Body:      recoveryBody,
			Variables: notificationTemplateVariables(recoverySubject+recoveryBody, "username"),
		},
		{
			Ref: notification.TemplateRef{
				ID: registrationVerificationTemplateID, Version: version, Channel: notification.ChannelEmail,
			},
			Subject:   verificationSubject,
			Body:      verificationBody,
			Variables: []string{"captcha"},
		},
		{
			Ref: notification.TemplateRef{
				ID: registrationVerificationTemplateID, Version: version, Channel: notification.ChannelSMS,
			},
			Body:      verificationSMSBody,
			Variables: []string{"captcha"},
		},
	}
	// value.<field> of each definition's subject and body, in definitions order.
	fields := [][2]string{
		{"registration_success_subject", "registration_success_body"}, {"password_reset_subject", "password_reset_body"},
		{"verification_subject", "verification_body"}, {"verification_sms_body", "verification_sms_body"},
	}
	catalog := notification.NewCatalog()
	for index, definition := range definitions {
		if strings.Contains(definition.Subject, "${") {
			return nil, fielderr.New(ErrInvalidInput, "value."+fields[index][0], fielderr.Invalid)
		}
		if strings.Contains(definition.Body, "${") {
			return nil, fielderr.New(ErrInvalidInput, "value."+fields[index][1], fielderr.Invalid)
		}
		if err := catalog.Register(definition); err != nil {
			return nil, fielderr.New(ErrInvalidInput, "value."+fields[index][1], fielderr.Invalid)
		}
	}
	return definitions, nil
}

func notificationTemplateVariables(source, variable string) []string {
	if strings.Contains(source, "{{."+variable+"}}") {
		return []string{variable}
	}
	return nil
}

func normalizeNotificationTemplate(source string, placeholder *regexp.Regexp, variable string) string {
	return placeholder.ReplaceAllString(source, "{{."+variable+"}}")
}

func insertSettingsNotificationTemplates(
	ctx context.Context,
	tx pgx.Tx,
	definitions []notification.TemplateDefinition,
	createdAt time.Time,
) error {
	for _, definition := range definitions {
		result, err := tx.Exec(ctx, `INSERT INTO notification_templates (
			template_id,version,channel,subject,body,variables,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			definition.Ref.ID, definition.Ref.Version, definition.Ref.Channel,
			definition.Subject, definition.Body, definition.Variables, createdAt)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrUnavailable
		}
	}
	return nil
}

func (s *Service) GetRegistrationVerificationTemplate(
	ctx context.Context,
	scopeID uuid.UUID,
	channel notification.Channel,
) (notification.TemplateRef, bool, error) {
	if channel != notification.ChannelEmail && channel != notification.ChannelSMS {
		return notification.TemplateRef{}, false, ErrInvalidInput
	}
	return s.getPublishedNotificationTemplate(ctx, scopeID, registrationVerificationTemplateID, channel)
}

func (s *Service) GetRegistrationSuccessTemplate(
	ctx context.Context,
	scopeID uuid.UUID,
) (notification.TemplateRef, []string, bool, error) {
	ref, found, err := s.getPublishedNotificationTemplate(ctx, scopeID, registrationSuccessTemplateID, notification.ChannelEmail)
	if err != nil || !found {
		return ref, nil, found, err
	}
	var variables []string
	if err := s.pool.QueryRow(ctx, `SELECT variables FROM notification_templates
		WHERE template_id=$1 AND version=$2 AND channel=$3`, ref.ID, ref.Version, ref.Channel).Scan(&variables); err != nil {
		return notification.TemplateRef{}, nil, false, fmt.Errorf("get registration success template variables: %w", err)
	}
	return ref, variables, true, nil
}

func (s *Service) GetRegistrationSuccessTemplateTx(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
) (notification.TemplateRef, []string, bool, error) {
	if s == nil || tx == nil || ctx == nil || scopeID == uuid.Nil {
		return notification.TemplateRef{}, nil, false, ErrInvalidStore
	}
	platformScopeID, err := resolvePlatformScope(ctx, tx, scopeID)
	if err != nil {
		return notification.TemplateRef{}, nil, false, err
	}
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM platform_system_user_settings
		WHERE platform_scope_id=$1`, platformScopeID).Scan(&revision); err == pgx.ErrNoRows {
		return notification.TemplateRef{}, nil, false, nil
	} else if err != nil {
		return notification.TemplateRef{}, nil, false, err
	}
	if revision < 1 {
		return notification.TemplateRef{}, nil, false, ErrUnavailable
	}
	ref := notification.TemplateRef{
		ID: registrationSuccessTemplateID, Version: uint64(revision), Channel: notification.ChannelEmail,
	}
	var variables []string
	if err := tx.QueryRow(ctx, `SELECT variables FROM notification_templates
		WHERE template_id=$1 AND version=$2 AND channel=$3`, ref.ID, ref.Version, ref.Channel).Scan(&variables); err == pgx.ErrNoRows {
		return ref, nil, false, nil
	} else if err != nil {
		return notification.TemplateRef{}, nil, false, err
	}
	return ref, variables, true, nil
}

func (s *Service) GetAccountRecoveryTemplate(
	ctx context.Context,
	scopeID uuid.UUID,
	channel notification.Channel,
) (notification.TemplateRef, bool, error) {
	if channel == notification.ChannelSMS {
		return notification.TemplateRef{}, false, nil
	}
	if channel != notification.ChannelEmail {
		return notification.TemplateRef{}, false, ErrInvalidInput
	}
	return s.getPublishedNotificationTemplate(ctx, scopeID, accountRecoveryTemplateID, channel)
}

func (s *Service) getPublishedNotificationTemplate(
	ctx context.Context,
	scopeID uuid.UUID,
	templateID string,
	channel notification.Channel,
) (notification.TemplateRef, bool, error) {
	if s == nil || s.pool == nil || ctx == nil || scopeID == uuid.Nil || strings.TrimSpace(templateID) != templateID {
		return notification.TemplateRef{}, false, ErrInvalidStore
	}
	var ref notification.TemplateRef
	found := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		platformScopeID, err := resolvePlatformScope(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM platform_system_user_settings
			WHERE platform_scope_id=$1`, platformScopeID).Scan(&revision); err == pgx.ErrNoRows {
			return nil
		} else if err != nil {
			return err
		}
		if revision < 1 {
			return ErrUnavailable
		}
		ref = notification.TemplateRef{ID: templateID, Version: uint64(revision), Channel: channel}
		if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM notification_templates
			WHERE template_id=$1 AND version=$2 AND channel=$3
		)`, ref.ID, ref.Version, ref.Channel).Scan(&found); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return notification.TemplateRef{}, false, fmt.Errorf("get platform system user notification template: %w", err)
	}
	return ref, found, nil
}

func resolvePlatformScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (uuid.UUID, error) {
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1`, scopeID).Scan(&kind, &tenantID); err != nil {
		return uuid.Nil, err
	}
	if kind == "platform" && tenantID == nil {
		return scopeID, nil
	}
	if kind != "tenant" || tenantID == nil {
		return uuid.Nil, ErrPermissionDenied
	}
	var platformScopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes
		WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platformScopeID); err != nil {
		if err == pgx.ErrNoRows {
			return uuid.Nil, ErrPermissionDenied
		}
		return uuid.Nil, err
	}
	return platformScopeID, nil
}
