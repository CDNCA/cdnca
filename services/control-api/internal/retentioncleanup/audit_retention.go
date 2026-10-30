package retentioncleanup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemcleanup"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuditRetentionKey is the platform_system_cleanup_settings key holding
// {"<category>": days} (unified-log). Missing categories use the catalog
// default; 0 keeps forever.
const AuditRetentionKey = "audit_retention_days"

// MaxRetentionDays bounds every retention setting.
const MaxRetentionDays = 3650

var ErrInvalidRetention = errors.New("invalid audit retention setting")

type queryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// DefaultAuditRetention returns the catalog default days per category.
func DefaultAuditRetention() map[string]int { return systemcleanup.DefaultAuditRetention() }

// ValidateAuditRetention checks category names and the 0..MaxRetentionDays range.
func ValidateAuditRetention(days map[string]int) error {
	for category, value := range days {
		if !audit.ValidCategory(audit.Category(category)) {
			return fmt.Errorf("%w: unknown category %q", ErrInvalidRetention, category)
		}
		if value < 0 || value > MaxRetentionDays {
			return fmt.Errorf("%w: %s must be 0..%d days", ErrInvalidRetention, category, MaxRetentionDays)
		}
	}
	return nil
}

// LoadAuditRetention returns the effective days per category.
func LoadAuditRetention(ctx context.Context, db queryer) (map[string]int, error) {
	out := DefaultAuditRetention()
	var raw []byte
	err := db.QueryRow(ctx, `SELECT settings->$1 FROM platform_system_cleanup_settings
		WHERE settings ? $1 ORDER BY updated_at DESC LIMIT 1`, AuditRetentionKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) || len(raw) == 0 {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load audit retention: %w", err)
	}
	var stored map[string]int
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("decode audit retention: %w", err)
	}
	if err := ValidateAuditRetention(stored); err != nil {
		return nil, err
	}
	for category, value := range stored {
		out[category] = value
	}
	return out, nil
}

// SaveAuditRetention merges days into the platform cleanup settings row.
// Tests use it to seed settings; the console saves through systemcleanup.Service, which audits the change.
func SaveAuditRetention(ctx context.Context, db interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}, platformScopeID uuid.UUID, days map[string]int) error {
	if err := ValidateAuditRetention(days); err != nil {
		return err
	}
	encoded, err := json.Marshal(days)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO platform_system_cleanup_settings(platform_scope_id,revision,settings,updated_at)
			VALUES($1,1,jsonb_build_object($2::text,$3::jsonb),now())
			ON CONFLICT (platform_scope_id) DO UPDATE SET revision=platform_system_cleanup_settings.revision+1,
				settings=platform_system_cleanup_settings.settings || jsonb_build_object($2::text,
					COALESCE(platform_system_cleanup_settings.settings->$2,'{}'::jsonb) || $3::jsonb),
				updated_at=now()`, platformScopeID, AuditRetentionKey, string(encoded))
		return err
	})
}

// auditCutoffs turns days into per-category cutoffs (nil = keep forever) and
// the advance cutoff: the newest cutoff, i.e. the shortest retention.
func auditCutoffs(days map[string]int, now time.Time) (categories []string, cutoffs []*time.Time, advance *time.Time) {
	for _, info := range audit.Categories() {
		category := string(info.Category)
		categories = append(categories, category)
		value := days[category]
		if value <= 0 {
			cutoffs = append(cutoffs, nil)
			continue
		}
		cutoff := now.Add(-time.Duration(value) * 24 * time.Hour)
		cutoffs = append(cutoffs, &cutoff)
		if advance == nil || cutoff.After(*advance) {
			copied := cutoff
			advance = &copied
		}
	}
	return categories, cutoffs, advance
}
