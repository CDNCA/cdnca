package systemothersettings

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const operationUpdate = "system_other_settings.update"

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Service struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	now     Clock
}

type RowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func NewService(pool *pgxpool.Pool, auditor AuditAppender, now Clock) (*Service, error) {
	if pool == nil || auditor == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Service{pool: pool, auditor: auditor, now: now}, nil
}

// L4DrainMaxMS is the drain_max_ms edge publications carry for L4 v2 streams:
// nil when the setting is the default (the agent applies 24 h itself, and
// releases stay byte-identical for agents that predate the field).
func L4DrainMaxMS(ctx context.Context, query RowQuerier) (*int, error) {
	if query == nil {
		return nil, ErrInvalidStore
	}
	var raw []byte
	err := query.QueryRow(ctx, `SELECT settings FROM platform_system_other_settings
		WHERE platform_scope_id=(SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL)`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read L4 drain limit: %w", err)
	}
	value, err := decodeSettings(raw)
	if err != nil || !validSettings(value) {
		return nil, ErrUnavailable
	}
	if value.L4DrainMaxSeconds == nil || *value.L4DrainMaxSeconds == DefaultL4DrainMaxSeconds {
		return nil, nil
	}
	milliseconds := *value.L4DrainMaxSeconds * 1000
	return &milliseconds, nil
}

// APIKeyEnabled returns the platform-wide API key status. A missing settings
// row predates this setting and therefore keeps the established enabled state.
func APIKeyEnabled(ctx context.Context, query RowQuerier) (bool, error) {
	if query == nil {
		return false, ErrInvalidStore
	}
	var raw []byte
	err := query.QueryRow(ctx, `SELECT settings FROM platform_system_other_settings
		WHERE platform_scope_id=(SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL)`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read platform API key status: %w", err)
	}
	value, err := decodeSettings(raw)
	if err != nil || !validSettings(value) {
		return false, ErrUnavailable
	}
	return value.APIKeyEnabled, nil
}

// DisableFailedSyncNodes reports the platform switch that holds nodes whose
// configuration sync failed out of customer DNS (NF04). Off when unset.
func DisableFailedSyncNodes(ctx context.Context, query RowQuerier) (bool, error) {
	if query == nil {
		return false, ErrInvalidStore
	}
	var raw []byte
	err := query.QueryRow(ctx, `SELECT settings FROM platform_system_other_settings
		WHERE platform_scope_id=(SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL)`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read failed sync node setting: %w", err)
	}
	value, err := decodeSettings(raw)
	if err != nil || !validSettings(value) {
		return false, ErrUnavailable
	}
	return value.DisableFailedSyncNodes, nil
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
		err := tx.QueryRow(ctx, `SELECT revision,settings,updated_at FROM platform_system_other_settings WHERE platform_scope_id=$1`, actor.ScopeID).Scan(&revision, &raw, &updatedAt)
		if err == pgx.ErrNoRows {
			result = Document{Schema: schema, Value: DefaultSettings()}
			return nil
		}
		if err != nil {
			return err
		}
		value, err := decodeSettings(raw)
		if err != nil || !validSettings(value) {
			return ErrUnavailable
		}
		result = Document{Schema: schema, Revision: revision, UpdatedAt: updatedAt.UTC(), Value: value}
		return nil
	})
	if err != nil {
		return Document{}, fmt.Errorf("get platform system other settings: %w", err)
	}
	return result, nil
}

func (s *Service) Save(ctx context.Context, actor Actor, request SaveRequest) (Document, error) {
	if err := validActor(actor); err != nil {
		return Document{}, err
	}
	if request.ExpectedRevision < 0 || request.ExpectedRevision >= 1<<63-1 || !validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) {
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
		var existingDigest, existingResponse []byte
		err := tx.QueryRow(ctx, `SELECT request_digest,response_body FROM platform_system_other_settings_write_requests WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`, actor.UserID, operationUpdate, request.IdempotencyKey).Scan(&existingDigest, &existingResponse)
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
		if _, err := tx.Exec(ctx, `INSERT INTO platform_system_other_settings_write_requests(id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,$3,$4,$5,$6,$7)`, uuid.New(), actor.UserID, actor.ScopeID, operationUpdate, request.IdempotencyKey, digest[:], now); err != nil {
			return err
		}
		var currentRevision int64
		var currentRaw []byte
		err = tx.QueryRow(ctx, `SELECT revision,settings FROM platform_system_other_settings WHERE platform_scope_id=$1 FOR UPDATE`, actor.ScopeID).Scan(&currentRevision, &currentRaw)
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
		if request.Value.L4DrainMaxSeconds == nil || request.Value.DomainOwnershipPolicy == nil ||
			request.Value.CertificateExpiryNoticeDays == nil || request.Value.RuleIntelContribution == nil {
			// Clients that predate a field keep its stored value.
			stored := DefaultSettings()
			if exists {
				if stored, err = decodeSettings(currentRaw); err != nil || !validSettings(stored) {
					return ErrUnavailable
				}
			}
			if request.Value.L4DrainMaxSeconds == nil {
				request.Value.L4DrainMaxSeconds = stored.L4DrainMaxSeconds
			}
			if request.Value.DomainOwnershipPolicy == nil {
				request.Value.DomainOwnershipPolicy = stored.DomainOwnershipPolicy
			}
			if request.Value.CertificateExpiryNoticeDays == nil {
				request.Value.CertificateExpiryNoticeDays = stored.CertificateExpiryNoticeDays
			}
			if request.Value.RuleIntelContribution == nil {
				request.Value.RuleIntelContribution = stored.RuleIntelContribution
			}
		}
		encoded, err := json.Marshal(request.Value)
		if err != nil {
			return ErrInvalidInput
		}
		nextRevision := currentRevision + 1
		if exists {
			// "dns_config" belongs to 节点管理 > DNS配置 (dnsacme) and is kept.
			_, err = tx.Exec(ctx, `UPDATE platform_system_other_settings SET revision=$2,settings=$3::jsonb || jsonb_strip_nulls(jsonb_build_object('dns_config',settings->'dns_config')),updated_by_user_id=$4,updated_at=$5 WHERE platform_scope_id=$1`, actor.ScopeID, nextRevision, string(encoded), actor.UserID, now)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO platform_system_other_settings(platform_scope_id,revision,settings,updated_by_user_id,updated_at) VALUES($1,$2,$3,$4,$5)`, actor.ScopeID, nextRevision, string(encoded), actor.UserID, now)
		}
		if err != nil {
			return err
		}
		result = Document{Schema: schema, Revision: nextRevision, UpdatedAt: now, Value: request.Value}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operationUpdate, ResourceType: "platform_system_other_settings", ResourceID: actor.ScopeID.String(), RequestID: request.RequestID, Result: "success", Payload: map[string]any{"revision": nextRevision}}); err != nil {
			return err
		}
		response, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE platform_system_other_settings_write_requests SET response_body=$4,completed_at=$5 WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`, actor.UserID, operationUpdate, request.IdempotencyKey, string(response), now)
		return err
	})
	if err != nil {
		return Document{}, fmt.Errorf("save platform system other settings: %w", err)
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

// validNoticeDays: 1..8 days, descending, each 1..60 (certnotify.ValidNoticeDays).
func validNoticeDays(days []int) bool {
	if len(days) < 1 || len(days) > 8 {
		return false
	}
	for index, day := range days {
		if day < 1 || day > 60 || index > 0 && days[index-1] <= day {
			return false
		}
	}
	return true
}

// CertificateExpiryNoticeDays is the platform's certificate expiry notice
// days (the default when unset).
func CertificateExpiryNoticeDays(ctx context.Context, query RowQuerier) ([]int, error) {
	if query == nil {
		return nil, ErrInvalidStore
	}
	var raw []byte
	err := query.QueryRow(ctx, `SELECT settings FROM platform_system_other_settings
		WHERE platform_scope_id=(SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL)`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return append([]int(nil), DefaultCertificateExpiryNoticeDays...), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read certificate expiry notice days: %w", err)
	}
	value, err := decodeSettings(raw)
	if err != nil || !validSettings(value) || value.CertificateExpiryNoticeDays == nil {
		return nil, ErrUnavailable
	}
	return value.CertificateExpiryNoticeDays, nil
}
// RuleIntelContribution reports the platform switch "向官方贡献规则情报"
// (ADR 0011 §4.3): on when unset or when no settings row exists.
func RuleIntelContribution(ctx context.Context, query RowQuerier) (bool, error) {
	if query == nil {
		return false, ErrInvalidStore
	}
	var raw []byte
	err := query.QueryRow(ctx, `SELECT settings FROM platform_system_other_settings
		WHERE platform_scope_id=(SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL)`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read rule intel contribution setting: %w", err)
	}
	value, err := decodeSettings(raw)
	if err != nil || !validSettings(value) {
		return false, ErrUnavailable
	}
	return value.RuleIntelContribution == nil || *value.RuleIntelContribution, nil
}

func validSettings(value Settings) bool { return settingsFieldError(value) == nil }

// settingsFieldError is ErrInvalidInput naming the first refused field of the
// save body (value.<field>, fix-fielderr-be2); nil when the settings are valid.
func settingsFieldError(value Settings) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, "value."+name, reason) }
	for _, item := range []struct {
		name, value string
		max         int
		lineBreaks  bool
	}{
		{"source_ip_header", value.SourceIPHeader, 256, true}, {"dns_protection", value.DNSProtection, 2048, false},
		{"http_proxy", value.HTTPProxy, 2048, true},
	} {
		switch {
		case !utf8.ValidString(item.value) || strings.ContainsRune(item.value, '\x00') || item.lineBreaks && strings.ContainsAny(item.value, "\r\n"):
			return field(item.name, fielderr.InvalidFormat)
		case !validText(item.value, 0, item.max):
			return field(item.name, fielderr.TooLong)
		}
	}
	switch {
	case value.RecordRepairMode != "off" && value.RecordRepairMode != "repair" && value.RecordRepairMode != "repair_delete_extra":
		return field("record_repair_mode", fielderr.Invalid)
	case value.SyncBatch < 1 || value.SyncBatch > 10000:
		return field("sync_batch", fielderr.OutOfRange)
	case value.SyncScope != "region" && value.SyncScope != "line_group":
		return field("sync_scope", fielderr.Invalid)
	case value.ResourceRank < 1 || value.ResourceRank > 1000:
		return field("resource_rank", fielderr.OutOfRange)
	case !(value.TCPFactor >= 0.01 && value.TCPFactor <= 100):
		return field("tcp_factor", fielderr.OutOfRange)
	case value.L4DrainMaxSeconds != nil && (*value.L4DrainMaxSeconds < 0 || *value.L4DrainMaxSeconds > MaxL4DrainMaxSeconds):
		return field("l4_drain_max_seconds", fielderr.OutOfRange)
	case value.DomainOwnershipPolicy != nil && *value.DomainOwnershipPolicy != "off" &&
		*value.DomainOwnershipPolicy != "wildcard_only" && *value.DomainOwnershipPolicy != "all":
		return field("domain_ownership_policy", fielderr.Invalid)
	case value.CertificateExpiryNoticeDays != nil && !validNoticeDays(value.CertificateExpiryNoticeDays):
		return field("certificate_expiry_notice_days", fielderr.Invalid)
	}
	return nil
}

// decodeSettings keeps rows written before the baseline fields were added
// readable while ensuring every response uses the current versioned shape.
func decodeSettings(raw []byte) (Settings, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return Settings{}, err
	}
	defaults := DefaultSettings()
	if rawValue, ok := object["dns_protection"]; ok {
		var legacy bool
		if err := json.Unmarshal(rawValue, &legacy); err == nil {
			encoded, err := json.Marshal("")
			if err != nil {
				return Settings{}, err
			}
			object["dns_protection"] = encoded
		}
	}
	// Every missing field takes its default: rows written before a field was
	// added, and the row 节点管理 > DNS配置 creates for its "dns_config" key.
	encodedDefaults, err := json.Marshal(defaults)
	if err != nil {
		return Settings{}, err
	}
	var defaultObject map[string]json.RawMessage
	if err := json.Unmarshal(encodedDefaults, &defaultObject); err != nil {
		return Settings{}, err
	}
	for key, value := range defaultObject {
		if _, ok := object[key]; !ok {
			object[key] = value
		}
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return Settings{}, err
	}
	var value Settings
	if err := json.Unmarshal(encoded, &value); err != nil {
		return Settings{}, err
	}
	return value, nil
}
func validText(value string, min, max int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) >= min && utf8.RuneCountInString(value) <= max && !strings.ContainsRune(value, '\x00')
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
func bytesEqual(left, right []byte) bool {
	return len(left) == len(right) && string(left) == string(right)
}
func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('platform-system-other-settings-authorization:' || $1::text || ':' || $2::text,0))`, actor.ScopeID, actor.UserID); err != nil {
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
	if err := tx.QueryRow(ctx, `SELECT assignment.role_id FROM role_assignments assignment JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id JOIN role_permissions grant_row ON grant_row.role_id=role.id WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND grant_row.permission_name=$3 ORDER BY assignment.role_id LIMIT 1 FOR UPDATE OF assignment,role,grant_row`, actor.ScopeID, actor.UserID, permission).Scan(&roleID); err != nil {
		return ErrPermissionDenied
	}
	return nil
}
