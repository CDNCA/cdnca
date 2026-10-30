package systemsettings

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const operationUpdate = "system_settings.update"

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Service struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	now     Clock
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
		err := tx.QueryRow(ctx, `SELECT revision,settings,updated_at
			FROM platform_system_settings WHERE platform_scope_id=$1`, actor.ScopeID).
			Scan(&revision, &raw, &updatedAt)
		if err == pgx.ErrNoRows {
			result = Document{Schema: schema, Revision: 0, Value: DefaultSettings()}
			return nil
		}
		if err != nil {
			return err
		}
		var value Settings
		if err := json.Unmarshal(raw, &value); err != nil || !validSettings(value) {
			return ErrUnavailable
		}
		result = Document{Schema: schema, Revision: revision, UpdatedAt: updatedAt.UTC(), Value: value}
		return nil
	})
	if err != nil {
		return Document{}, fmt.Errorf("get platform system settings: %w", err)
	}
	return result, nil
}

// Public 读取平台（唯一 platform 作用域）的公开设置子集，供登录页/外壳品牌、用户端购买页与全站 JS 使用。
// 这里不做 RBAC：品牌字段可匿名读，其余字段由调用方确认会话有效后才下发。
func (s *Service) Public(ctx context.Context) (PublicSettings, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT settings.settings
		FROM platform_system_settings settings JOIN access_scopes scope ON scope.id=settings.platform_scope_id
		WHERE scope.kind='platform' AND scope.tenant_id IS NULL
		ORDER BY scope.created_at, scope.id LIMIT 1`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return PublicSettings{}, nil
	}
	if err != nil {
		return PublicSettings{}, fmt.Errorf("read public platform system settings: %w", err)
	}
	var value Settings
	if err := json.Unmarshal(raw, &value); err != nil || !validSettings(value) {
		return PublicSettings{}, ErrUnavailable
	}
	return PublicSettings{
		PublicBranding: PublicBranding{SystemName: value.SystemName, UserTitle: value.UserTitle, AdminTitle: value.AdminTitle},
		PurchaseNotice: value.PurchaseNotice, GlobalJS: value.GlobalJS,
	}, nil
}

func (s *Service) Save(ctx context.Context, actor Actor, request SaveRequest) (Document, error) {
	if err := validActor(actor); err != nil {
		return Document{}, err
	}
	if request.ExpectedRevision < 0 || request.ExpectedRevision >= 1<<63-1 ||
		!validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
		return Document{}, ErrInvalidInput
	}
	if err := settingsFieldError(request.Value); err != nil {
		return Document{}, err
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
		if now.Year() < 1 || now.Year() > 9999 {
			return ErrInvalidInput
		}
		var existingDigest []byte
		var existingResponse []byte
		err := tx.QueryRow(ctx, `SELECT request_digest,response_body
			FROM platform_system_settings_write_requests
			WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3
			FOR UPDATE`, actor.UserID, operationUpdate, request.IdempotencyKey).
			Scan(&existingDigest, &existingResponse)
		if err == nil {
			if string(existingDigest) != string(digest[:]) {
				return ErrIdempotencyConflict
			}
			if len(existingResponse) == 0 {
				return ErrIdempotencyConflict
			}
			if err := json.Unmarshal(existingResponse, &result); err != nil {
				return ErrUnavailable
			}
			result.Replayed = true
			return nil
		}
		if err != pgx.ErrNoRows {
			return err
		}
		requestID := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO platform_system_settings_write_requests(
			id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,created_at
		) VALUES($1,$2,$3,$3,$4,$5,$6,$7)`, requestID, actor.UserID, actor.ScopeID,
			operationUpdate, request.IdempotencyKey, digest[:], now); err != nil {
			return err
		}
		var currentRevision int64
		var currentRaw []byte
		err = tx.QueryRow(ctx, `SELECT revision,settings FROM platform_system_settings
			WHERE platform_scope_id=$1 FOR UPDATE`, actor.ScopeID).Scan(&currentRevision, &currentRaw)
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
		encoded, err := json.Marshal(request.Value)
		if err != nil {
			return ErrInvalidInput
		}
		nextRevision := currentRevision + 1
		if exists {
			_, err = tx.Exec(ctx, `UPDATE platform_system_settings
				SET revision=$2,settings=$3,updated_by_user_id=$4,updated_at=$5
				WHERE platform_scope_id=$1`, actor.ScopeID, nextRevision, encoded, actor.UserID, now)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO platform_system_settings(
				platform_scope_id,revision,settings,updated_by_user_id,updated_at
			) VALUES($1,$2,$3,$4,$5)`, actor.ScopeID, nextRevision, encoded, actor.UserID, now)
		}
		if err != nil {
			return err
		}
		result = Document{Schema: schema, Revision: nextRevision, UpdatedAt: now, Value: request.Value}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operationUpdate,
			ResourceType: "platform_system_settings", ResourceID: actor.ScopeID.String(),
			RequestID: request.RequestID, Result: "success", Payload: map[string]any{
				"revision": nextRevision,
			},
		}); err != nil {
			return err
		}
		response, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE platform_system_settings_write_requests
			SET response_body=$4,completed_at=$5
			WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
			actor.UserID, operationUpdate, request.IdempotencyKey, response, now)
		return err
	})
	if err != nil {
		return Document{}, fmt.Errorf("save platform system settings: %w", err)
	}
	return result, nil
}

func validActor(actor Actor) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	return nil
}

func validMetadata(value string) bool { return metadataPattern.MatchString(value) }

func validSettings(value Settings) bool { return settingsFieldError(value) == nil }

// settingsFieldError is ErrInvalidInput naming the first refused field of the
// save body (value.<field>, fix-fielderr-be); nil when the settings are valid.
func settingsFieldError(value Settings) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, "value."+name, reason) }
	for _, item := range []struct {
		name     string
		value    string
		min, max int
	}{
		{"system_name", value.SystemName, 1, 128}, {"user_title", value.UserTitle, 1, 256},
		{"admin_title", value.AdminTitle, 1, 256}, {"footer_links", value.FooterLinks, 0, 16 << 10},
		{"footer_text", value.FooterText, 0, 1024}, {"global_js", value.GlobalJS, 0, 256 << 10},
		{"bound_domains", value.BoundDomains, 0, 8192}, {"favicon", value.Favicon, 0, 2048},
		{"logo", value.Logo, 0, 2048}, {"login_ad", value.LoginAd, 0, 2048},
		{"purchase_notice", value.PurchaseNotice, 0, 65536}, {"maintenance_message", value.MaintenanceMessage, 0, 1024},
	} {
		if !validText(item.value, item.min, item.max) {
			return field(item.name, textReason(item.value, item.min, item.max))
		}
	}
	if !validReference(value.Certificate) {
		return field("certificate", fielderr.InvalidFormat)
	}
	if !validReference(value.PrivateKey) {
		return field("private_key", fielderr.InvalidFormat)
	}
	if len(value.GlobalJSReportHosts) > maxGlobalJSReportHosts {
		return field("global_js_report_hosts", fielderr.TooLong)
	}
	seen := make(map[string]struct{}, len(value.GlobalJSReportHosts))
	for index, host := range value.GlobalJSReportHosts {
		name := "global_js_report_hosts[" + strconv.Itoa(index) + "]"
		if len(host) > 253 || !reportHostPattern.MatchString(host) {
			return field(name, fielderr.InvalidFormat)
		}
		if _, duplicate := seen[host]; duplicate {
			return field(name, fielderr.Duplicate)
		}
		seen[host] = struct{}{}
	}
	return nil
}

func textReason(value string, min, max int) string {
	count := utf8.RuneCountInString(value)
	switch {
	case !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r"):
		return fielderr.InvalidFormat
	case count == 0 && min > 0:
		return fielderr.Required
	case count < min:
		return fielderr.TooShort
	}
	return fielderr.TooLong
}

const maxGlobalJSReportHosts = 20

// reportHostPattern: a lowercase DNS name with at least two labels and an
// alphabetic TLD; no scheme, port, path, wildcard, IP literal or trailing dot.
var reportHostPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// CSPReportHostSources renders the hosts as CSP source expressions.
func CSPReportHostSources(value Settings) string {
	sources := make([]string, len(value.GlobalJSReportHosts))
	for index, host := range value.GlobalJSReportHosts {
		sources[index] = "https://" + host
	}
	return strings.Join(sources, " ")
}

// CSPReportHosts returns the platform's report hosts as CSP sources for the
// web container (read before index.html is served, so without a session).
func (s *Service) CSPReportHosts(ctx context.Context) (string, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT settings.settings
		FROM platform_system_settings settings JOIN access_scopes scope ON scope.id=settings.platform_scope_id
		WHERE scope.kind='platform' AND scope.tenant_id IS NULL
		ORDER BY scope.created_at, scope.id LIMIT 1`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read platform CSP report hosts: %w", err)
	}
	var value Settings
	if err := json.Unmarshal(raw, &value); err != nil || !validSettings(value) {
		return "", ErrUnavailable
	}
	return CSPReportHostSources(value), nil
}

func validText(value string, min, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= min &&
		utf8.RuneCountInString(value) <= max && !strings.ContainsAny(value, "\x00\r")
}

func validReference(value string) bool {
	return validText(value, 0, 1024) && (value == "" ||
		(strings.HasPrefix(value, "vault://") && len(value) > len("vault://")) ||
		(strings.HasPrefix(value, "kms-envelope://") && len(value) > len("kms-envelope://")))
}

func requestDigest(request SaveRequest) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		ExpectedRevision int64    `json:"expected_revision"`
		Value            Settings `json:"value"`
	}{request.ExpectedRevision, request.Value})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'platform-system-settings-authorization:' || $1::text || ':' || $2::text,0))`, actor.ScopeID, actor.UserID); err != nil {
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
