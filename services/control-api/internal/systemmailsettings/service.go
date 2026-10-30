package systemmailsettings

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/mail"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const operationUpdate = "system_mail_settings.update"

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Service struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	now     Clock
	cipher  SecretCipher
	modules ModuleGate
}

const smsSecretDomain = "cdnca-system-mail-sms-secret/v1\x00"

// WithSecretCipher enables storing a native SMS provider credential.
func (s *Service) WithSecretCipher(cipher SecretCipher) *Service {
	s.cipher = cipher
	return s
}

// WithModuleGate gates choosing an official mail service on its module
// (module.mail.<provider>, RevokeKeepExisting): a provider the lease does not
// grant cannot be newly chosen or tested; a saved one stays saved.
func (s *Service) WithModuleGate(gate ModuleGate) *Service {
	s.modules = gate
	return s
}

// checkMailModule: nil unless provider is an official service other than
// stored whose module the lease does not grant.
func (s *Service) checkMailModule(ctx context.Context, tx pgx.Tx, provider, stored string) error {
	if s.modules == nil || MailProviderKind(provider) != MailKindOfficial || provider == stored {
		return nil
	}
	granted, err := s.modules(ctx, tx, mail.ModuleCode(provider))
	if err != nil {
		return ErrUnavailable
	}
	if !granted {
		return ErrModuleNotLicensed
	}
	return nil
}

func NewService(pool *pgxpool.Pool, auditor AuditAppender, now Clock) (*Service, error) {
	if pool == nil || auditor == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Service{pool: pool, auditor: auditor, now: now}, nil
}

func (s *Service) Get(ctx context.Context, actor Actor) (Document, error) {
	if err := validActor(actor); err != nil {
		return Document{}, err
	}
	var result Document
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, "system_configuration.read"); err != nil {
			return err
		}
		var revision int64
		var raw []byte
		var updatedAt time.Time
		var fingerprint, mailProvider, mailFingerprint *string
		err := tx.QueryRow(ctx, `SELECT revision,settings,updated_at,sms_secret_fingerprint,mail_secret_provider,mail_secret_fingerprint
			FROM platform_system_mail_settings WHERE platform_scope_id=$1`, actor.ScopeID).
			Scan(&revision, &raw, &updatedAt, &fingerprint, &mailProvider, &mailFingerprint)
		if err == pgx.ErrNoRows {
			result = Document{Schema: schema, Value: DefaultSettings()}
			return nil
		}
		if err != nil {
			return err
		}
		var value Settings
		if json.Unmarshal(raw, &value) != nil || !validSettings(value) {
			return ErrUnavailable
		}
		result = Document{Schema: schema, Revision: revision, UpdatedAt: updatedAt.UTC(), Value: value}
		if fingerprint != nil {
			result.SMSSecretConfigured, result.SMSSecretFingerprint = true, *fingerprint
		}
		result.setMailSecret(mailProvider, mailFingerprint)
		return nil
	})
	if err != nil {
		return Document{}, fmt.Errorf("get platform system mail settings: %w", err)
	}
	return result, nil
}

func (s *Service) Save(ctx context.Context, actor Actor, request SaveRequest) (Document, error) {
	if err := validActor(actor); err != nil {
		return Document{}, err
	}
	if request.ExpectedRevision < 0 || request.ExpectedRevision >= 1<<63-1 ||
		!validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
		return Document{}, ErrInvalidInput
	}
	for _, refusal := range []error{settingsFieldError(request.Value), smsProviderFieldError(request.Value, request.SMSAccessKeySecret),
		mailProviderFieldError(request.Value, request.MailSecret)} {
		if refusal != nil {
			return Document{}, refusal
		}
	}
	if (request.SMSAccessKeySecret != "" || request.MailSecret != "") && s.cipher == nil {
		return Document{}, ErrInvalidInput
	}
	digest, err := requestDigest(request)
	if err != nil {
		return Document{}, err
	}
	var result Document
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, "system_configuration.manage"); err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		var existingDigest, existingResponse []byte
		err := tx.QueryRow(ctx, `SELECT request_digest,response_body
			FROM platform_system_mail_settings_write_requests
			WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
			actor.UserID, operationUpdate, request.IdempotencyKey).Scan(&existingDigest, &existingResponse)
		if err == nil {
			if !bytesEqual(existingDigest, digest[:]) || len(existingResponse) == 0 {
				return ErrIdempotencyConflict
			}
			if json.Unmarshal(existingResponse, &result) != nil {
				return ErrUnavailable
			}
			result.Replayed = true
			return nil
		}
		if err != pgx.ErrNoRows {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_system_mail_settings_write_requests
			(id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,created_at)
			VALUES($1,$2,$3,$3,$4,$5,$6,$7)`, uuid.New(), actor.UserID, actor.ScopeID,
			operationUpdate, request.IdempotencyKey, digest[:], now); err != nil {
			return err
		}
		var currentRevision int64
		var currentRaw []byte
		var keyID, fingerprint *string
		var ciphertext []byte
		var mailKeyID, mailFingerprint, mailProvider *string
		var mailCiphertext []byte
		err = tx.QueryRow(ctx, `SELECT revision,settings,sms_secret_key_id,sms_secret_ciphertext,sms_secret_fingerprint,
			       mail_secret_key_id,mail_secret_ciphertext,mail_secret_fingerprint,mail_secret_provider
			FROM platform_system_mail_settings
			WHERE platform_scope_id=$1 FOR UPDATE`, actor.ScopeID).Scan(&currentRevision, &currentRaw, &keyID, &ciphertext, &fingerprint,
			&mailKeyID, &mailCiphertext, &mailFingerprint, &mailProvider)
		exists := err == nil
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if !exists {
			currentRevision = 0
		}
		if currentRevision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		var current Settings
		if exists && json.Unmarshal(currentRaw, &current) != nil {
			return ErrUnavailable
		}
		if err := s.checkMailModule(ctx, tx, request.Value.MailProvider, current.MailProvider); err != nil {
			return err
		}
		encoded, err := json.Marshal(request.Value)
		if err != nil {
			return ErrInvalidInput
		}
		switch {
		case !NativeSMSProvider(request.Value.SMSProvider):
			keyID, ciphertext, fingerprint = nil, nil, nil
		case request.SMSAccessKeySecret != "":
			sealedKey, sealed, sealErr := sealSMSSecret(s.cipher, actor.ScopeID, request.SMSAccessKeySecret)
			if sealErr != nil {
				return sealErr
			}
			value := smsSecretFingerprint(request.SMSAccessKeySecret)
			keyID, ciphertext, fingerprint = &sealedKey, sealed, &value
		case keyID == nil:
			// A native provider cannot be saved without its credential.
			return fielderr.New(ErrInvalidInput, "sms_access_key_secret", fielderr.Required)
		}
		storedMailProvider := ""
		if mailProvider != nil {
			storedMailProvider = *mailProvider
		}
		keepMail, mailOK := mailSecretDecision(storedMailProvider, request.Value.MailProvider, request.MailSecret != "")
		if !mailOK {
			// An official mail service cannot be chosen without its own credential.
			return fielderr.New(ErrInvalidInput, "mail_secret", fielderr.Required)
		}
		if !keepMail {
			sealedKey, sealed, sealErr := sealMailSecret(s.cipher, actor.ScopeID.String(), request.Value.MailProvider, request.MailSecret)
			if sealErr != nil {
				return sealErr
			}
			provider, value := request.Value.MailProvider, mailSecretFingerprint(request.MailSecret)
			mailKeyID, mailCiphertext, mailFingerprint, mailProvider = &sealedKey, sealed, &value, &provider
		}
		nextRevision := currentRevision + 1
		if exists {
			_, err = tx.Exec(ctx, `UPDATE platform_system_mail_settings
				SET revision=$2,settings=$3,updated_by_user_id=$4,updated_at=$5,
				    sms_secret_key_id=$6,sms_secret_ciphertext=$7,sms_secret_fingerprint=$8,
				    mail_secret_key_id=$9,mail_secret_ciphertext=$10,mail_secret_fingerprint=$11,mail_secret_provider=$12
				WHERE platform_scope_id=$1`, actor.ScopeID, nextRevision, string(encoded), actor.UserID, now,
				keyID, ciphertext, fingerprint, mailKeyID, mailCiphertext, mailFingerprint, mailProvider)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO platform_system_mail_settings
				(platform_scope_id,revision,settings,updated_by_user_id,updated_at,
				 sms_secret_key_id,sms_secret_ciphertext,sms_secret_fingerprint,
				 mail_secret_key_id,mail_secret_ciphertext,mail_secret_fingerprint,mail_secret_provider)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, actor.ScopeID, nextRevision, string(encoded), actor.UserID, now,
				keyID, ciphertext, fingerprint, mailKeyID, mailCiphertext, mailFingerprint, mailProvider)
		}
		if err != nil {
			return err
		}
		result = Document{Schema: schema, Revision: nextRevision, UpdatedAt: now, Value: request.Value}
		if fingerprint != nil {
			result.SMSSecretConfigured, result.SMSSecretFingerprint = true, *fingerprint
		}
		result.setMailSecret(mailProvider, mailFingerprint)
		mailSecret := "unchanged"
		if !keepMail {
			mailSecret = "replaced"
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: operationUpdate, ResourceType: "platform_system_mail_settings", ResourceID: actor.ScopeID.String(),
			RequestID: request.RequestID, Result: "success", Payload: map[string]any{"revision": nextRevision,
				"mail_provider": request.Value.MailProvider, "mail_secret": mailSecret}}); err != nil {
			return err
		}
		response, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE platform_system_mail_settings_write_requests
			SET response_body=$4,completed_at=$5
			WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
			actor.UserID, operationUpdate, request.IdempotencyKey, string(response), now)
		return err
	})
	if err != nil {
		return Document{}, fmt.Errorf("save platform system mail settings: %w", err)
	}
	return result, nil
}

func (document *Document) setMailSecret(provider, fingerprint *string) {
	if provider != nil && fingerprint != nil {
		document.MailSecretConfigured, document.MailSecretProvider, document.MailSecretFingerprint = true, *provider, *fingerprint
	}
}

func validActor(actor Actor) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	return nil
}

func validMetadata(value string) bool { return metadataPattern.MatchString(value) }

func validSettings(value Settings) bool { return settingsFieldError(value) == nil }

// settingsFieldError is ErrInvalidInput naming the first refused SMTP/SMS
// field (value.<field>, fix-fielderr-be2); nil when they are well formed.
func settingsFieldError(value Settings) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, "value."+name, reason) }
	for _, item := range []struct {
		name, value string
		max         int
		reference   bool
	}{
		{"smtp_address", value.SMTPAddress, 512, false}, {"smtp_user", value.SMTPUser, 256, false},
		{"smtp_password_reference", value.SMTPPasswordReference, 1024, true}, {"sms_provider", value.SMSProvider, 64, false},
		{"sms_access_key_id", value.SMSAccessKeyID, 256, false}, {"sms_access_key_reference", value.SMSAccessKeyReference, 1024, true},
		{"sms_signature_name", value.SMSSignatureName, 256, false},
	} {
		switch {
		case !utf8.ValidString(item.value) || strings.ContainsAny(item.value, "\x00\r") ||
			(item.name == "smtp_address" || item.name == "smtp_user") && strings.ContainsRune(item.value, '\n'):
			return field(item.name, fielderr.InvalidFormat)
		case !validText(item.value, 0, item.max):
			return field(item.name, fielderr.TooLong)
		case item.reference && !validReference(item.value):
			return field(item.name, fielderr.InvalidFormat)
		}
	}
	if value.SMTPPort < 1 || value.SMTPPort > 65535 {
		return field("smtp_port", fielderr.OutOfRange)
	}
	return nil
}

func validReference(value string) bool {
	return validText(value, 0, 1024) && (value == "" || (strings.HasPrefix(value, "vault://") && len(value) > len("vault://")) || (strings.HasPrefix(value, "kms-envelope://") && len(value) > len("kms-envelope://")))
}

func validText(value string, min, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= min && utf8.RuneCountInString(value) <= max && !strings.ContainsAny(value, "\x00\r")
}

func requestDigest(request SaveRequest) ([32]byte, error) {
	// The credential enters the digest only as a hash, never in plaintext.
	var secretDigest, mailDigest string
	if request.SMSAccessKeySecret != "" {
		sum := sha256.Sum256([]byte(smsSecretDomain + request.SMSAccessKeySecret))
		secretDigest = hex.EncodeToString(sum[:])
	}
	if request.MailSecret != "" {
		sum := sha256.Sum256([]byte(mailSecretDomain + request.MailSecret))
		mailDigest = hex.EncodeToString(sum[:])
	}
	encoded, err := json.Marshal(struct {
		ExpectedRevision int64    `json:"expected_revision"`
		Value            Settings `json:"value"`
		SecretDigest     string   `json:"secret_digest,omitempty"`
		MailDigest       string   `json:"mail_secret_digest,omitempty"`
	}{request.ExpectedRevision, request.Value, secretDigest, mailDigest})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func bytesEqual(left, right []byte) bool {
	return len(left) == len(right) && string(left) == string(right)
}

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('platform-system-mail-settings-authorization:' || $1::text || ':' || $2::text,0))`, actor.ScopeID, actor.UserID); err != nil {
		return err
	}
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR UPDATE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil || kind != "platform" || tenantID != nil {
		return ErrPermissionDenied
	}
	var accountStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`, actor.UserID).Scan(&accountStatus); err != nil || accountStatus != "active" {
		return ErrPermissionDenied
	}
	var membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`, actor.ScopeID, actor.UserID).Scan(&membershipStatus); err != nil || membershipStatus != "active" {
		return ErrPermissionDenied
	}
	var roleID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT assignment.role_id FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions grant_row ON grant_row.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND grant_row.permission_name=$3
		ORDER BY assignment.role_id LIMIT 1 FOR UPDATE OF assignment,role,grant_row`, actor.ScopeID, actor.UserID, permission).Scan(&roleID); err != nil {
		return ErrPermissionDenied
	}
	return nil
}

func validSMSProvider(value Settings, secret string) bool {
	return smsProviderFieldError(value, secret) == nil
}

// smsProviderFieldError: https_json keeps its secret outside PostgreSQL (vault
// reference); aliyun/submail store an encrypted credential and a template map.
func smsProviderFieldError(value Settings, secret string) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, name, reason) }
	switch value.SMSProvider {
	case "", SMSProviderHTTPSJSON:
		if value.SMSTemplateMap != "" {
			return field("value.sms_template_map", fielderr.Invalid)
		}
		if secret != "" {
			return field("sms_access_key_secret", fielderr.Invalid)
		}
		return nil
	case SMSProviderAliyun, SMSProviderSubmail:
		switch {
		case value.SMSAccessKeyReference != "":
			return field("value.sms_access_key_reference", fielderr.Invalid)
		case value.SMSAccessKeyID == "":
			return field("value.sms_access_key_id", fielderr.Required)
		case value.SMSProvider == SMSProviderAliyun && value.SMSSignatureName == "":
			return field("value.sms_signature_name", fielderr.Required)
		case len(secret) > 512:
			return field("sms_access_key_secret", fielderr.TooLong)
		case strings.ContainsAny(secret, "\r\n\x00") || strings.TrimSpace(secret) != secret:
			return field("sms_access_key_secret", fielderr.InvalidFormat)
		}
		if _, err := ParseSMSTemplateMap(value.SMSTemplateMap); err != nil {
			return field("value.sms_template_map", fielderr.InvalidFormat)
		}
		return nil
	default:
		return field("value.sms_provider", fielderr.Invalid)
	}
}

// ParseSMSTemplateMap validates and decodes Settings.SMSTemplateMap.
func ParseSMSTemplateMap(raw string) (map[string]SMSTemplate, error) {
	result := map[string]SMSTemplate{}
	if raw == "" {
		return result, nil
	}
	if len(raw) > 16384 {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || decoder.More() || len(result) > 64 {
		return nil, ErrInvalidInput
	}
	for id, template := range result {
		if !metadataPattern.MatchString(id) || !validMapText(template.Code) || len(template.Variables) > 32 {
			return nil, ErrInvalidInput
		}
		for ours, theirs := range template.Variables {
			if !validMapText(ours) || !validMapText(theirs) {
				return nil, ErrInvalidInput
			}
		}
	}
	return result, nil
}

func validMapText(value string) bool {
	return value != "" && len(value) <= 64 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func smsSecretFingerprint(secret string) string {
	sum := sha256.Sum256([]byte(smsSecretDomain + secret))
	return hex.EncodeToString(sum[:8])
}

// sealSMSSecret binds the envelope to the platform scope so a ciphertext cannot
// be replayed into another row.
func sealSMSSecret(cipher SecretCipher, scopeID uuid.UUID, secret string) (string, []byte, error) {
	plaintext := []byte(smsSecretDomain + scopeID.String() + "\x00" + secret)
	defer clear(plaintext)
	keyID, ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		return "", nil, ErrUnavailable
	}
	return keyID, ciphertext, nil
}

func openSMSSecret(cipher SecretCipher, scopeID uuid.UUID, keyID string, ciphertext []byte) ([]byte, error) {
	if cipher == nil {
		return nil, ErrUnavailable
	}
	plaintext, err := cipher.Decrypt(keyID, ciphertext)
	if err != nil {
		return nil, ErrUnavailable
	}
	prefix := []byte(smsSecretDomain + scopeID.String() + "\x00")
	if !bytes.HasPrefix(plaintext, prefix) {
		clear(plaintext)
		return nil, ErrUnavailable
	}
	secret := append([]byte(nil), plaintext[len(prefix):]...)
	clear(plaintext)
	return secret, nil
}
