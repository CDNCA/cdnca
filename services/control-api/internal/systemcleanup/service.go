package systemcleanup

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const operationUpdate = "system_cleanup_settings.update"

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
		err := tx.QueryRow(ctx, `SELECT revision,settings,updated_at FROM platform_system_cleanup_settings WHERE platform_scope_id=$1`, actor.ScopeID).Scan(&revision, &raw, &updatedAt)
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
		value.AuditRetentionDays = WithAuditDefaults(value.AuditRetentionDays)
		result = Document{Schema: schema, Revision: revision, UpdatedAt: updatedAt.UTC(), Value: value}
		return nil
	})
	if err != nil {
		return Document{}, fmt.Errorf("get platform system cleanup settings: %w", err)
	}
	return result, nil
}

func (s *Service) Save(ctx context.Context, actor Actor, request SaveRequest) (Document, error) {
	if err := validActor(actor); err != nil {
		return Document{}, err
	}
	if request.ExpectedRevision < 0 || request.ExpectedRevision >= 1<<63-1 || !validMetadata(request.IdempotencyKey) || !validMetadata(request.RequestID) || !validSettings(request.Value) {
		return Document{}, ErrInvalidInput
	}
	request.Value.AuditRetentionDays = WithAuditDefaults(request.Value.AuditRetentionDays)
	digest := requestDigest(request)
	var result Document
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, "system_configuration.manage"); err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		var existingDigest, existingResponse []byte
		err := tx.QueryRow(ctx, `SELECT request_digest,response_body FROM platform_system_cleanup_settings_write_requests WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`, actor.UserID, operationUpdate, request.IdempotencyKey).Scan(&existingDigest, &existingResponse)
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
		if _, err := tx.Exec(ctx, `INSERT INTO platform_system_cleanup_settings_write_requests(id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,$3,$4,$5,$6,$7)`, uuid.New(), actor.UserID, actor.ScopeID, operationUpdate, request.IdempotencyKey, digest[:], now); err != nil {
			return err
		}
		var currentRevision int64
		var currentRaw []byte
		err = tx.QueryRow(ctx, `SELECT revision,settings FROM platform_system_cleanup_settings WHERE platform_scope_id=$1 FOR UPDATE`, actor.ScopeID).Scan(&currentRevision, &currentRaw)
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
		previous := DefaultSettings()
		if exists && json.Unmarshal(currentRaw, &previous) == nil {
			previous.AuditRetentionDays = WithAuditDefaults(previous.AuditRetentionDays)
		}
		encoded, err := json.Marshal(request.Value)
		if err != nil {
			return ErrInvalidInput
		}
		nextRevision := currentRevision + 1
		if exists {
			_, err = tx.Exec(ctx, `UPDATE platform_system_cleanup_settings SET revision=$2,settings=$3,updated_by_user_id=$4,updated_at=$5 WHERE platform_scope_id=$1`, actor.ScopeID, nextRevision, encoded, actor.UserID, now)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO platform_system_cleanup_settings(platform_scope_id,revision,settings,updated_by_user_id,updated_at) VALUES($1,$2,$3,$4,$5)`, actor.ScopeID, nextRevision, encoded, actor.UserID, now)
		}
		if err != nil {
			return err
		}
		result = Document{Schema: schema, Revision: nextRevision, UpdatedAt: now, Value: request.Value}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operationUpdate, ResourceType: "platform_system_cleanup_settings", ResourceID: actor.ScopeID.String(), RequestID: request.RequestID, Result: "success", Payload: map[string]any{"revision": nextRevision},
			Changes: settingsChanges(previous, request.Value)}); err != nil {
			return err
		}
		response, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE platform_system_cleanup_settings_write_requests SET response_body=$4,completed_at=$5 WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`, actor.UserID, operationUpdate, request.IdempotencyKey, response, now)
		return err
	})
	if err != nil {
		return Document{}, fmt.Errorf("save platform system cleanup settings: %w", err)
	}
	return result, nil
}

// settingsChanges lists every changed setting as field -> before/after;
// audit retention is reported per category ("audit_retention_days.<category>").
func settingsChanges(before, after Settings) []audit.Change {
	flatten := func(value Settings) map[string]any {
		out := map[string]any{}
		raw, _ := json.Marshal(value)
		_ = json.Unmarshal(raw, &out)
		delete(out, "audit_retention_days")
		for category, days := range value.AuditRetentionDays {
			out["audit_retention_days."+category] = float64(days)
		}
		return out
	}
	old, next := flatten(before), flatten(after)
	keys := make([]string, 0, len(next))
	for key := range next {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var changes []audit.Change
	for _, key := range keys {
		if old[key] != next[key] {
			changes = append(changes, audit.Change{Field: key, Before: old[key], After: next[key]})
		}
	}
	return changes
}

func validActor(actor Actor) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	return nil
}
func validMetadata(value string) bool { return metadataPattern.MatchString(value) }
func validSettings(value Settings) bool {
	return validDays(value.CleanupCacheDays) && ValidAuditRetention(value.AuditRetentionDays) && validDays(value.AccessLogsDays) && validDays(value.NodeMetricsDays) && validDays(value.BandwidthHistoryDays) && validDays(value.BlacklistHistoryDays) && validDays(value.NodeTrafficHistoryDays)
}
func validDays(value int) bool { return value >= 0 && value <= 3650 }
func requestDigest(request SaveRequest) [32]byte {
	encoded, _ := json.Marshal(struct {
		ExpectedRevision int64    `json:"expected_revision"`
		Value            Settings `json:"value"`
	}{request.ExpectedRevision, request.Value})
	return sha256.Sum256(encoded)
}
func bytesEqual(left, right []byte) bool {
	return len(left) == len(right) && string(left) == string(right)
}

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('platform-system-cleanup-settings-authorization:' || $1::text || ':' || $2::text,0))`, actor.ScopeID, actor.UserID); err != nil {
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
