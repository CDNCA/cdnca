package securityban

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TemporaryBans is analyticslog.Client.
type TemporaryBans interface {
	ListTemporaryBans(ctx context.Context, after, through time.Time, limit uint16) ([]analyticslog.TemporaryBanEvent, error)
}

const (
	// SyncLag leaves recent ingestion alone (a batch inserted now may carry
	// an ingested_at a little in the past).
	SyncLag = 30 * time.Second
	// SyncCatchUp: a cursor-less (first) run starts this far back.
	SyncCatchUp = time.Hour
	syncBatch   = 1000
)

// Syncer folds the nodes' automatic WAF / CC bans (security_events
// temporary_ban) into security_ban_entries.
type Syncer struct {
	pool    *pgxpool.Pool
	events  TemporaryBans
	now     func() time.Time
	changed func()
	// alerts announces folded WAF bans (EnableWAFBanAlerts).
	alerts AlertEnqueuer
}

func NewSyncer(pool *pgxpool.Pool, events TemporaryBans, now func() time.Time) (*Syncer, error) {
	if pool == nil || events == nil || now == nil {
		return nil, errors.New("security ban sync configuration is incomplete")
	}
	return &Syncer{pool: pool, events: events, now: now}, nil
}

// OnChange registers a callback run after a pass that changed the list.
func (syncer *Syncer) OnChange(callback func()) { syncer.changed = callback }

type SyncResult struct {
	Read, Added, Extended, Skipped int
}

// RunOnce reads every event ingested after the cursor (up to now-SyncLag)
// and advances the cursor batch by batch.
func (syncer *Syncer) RunOnce(ctx context.Context) (SyncResult, error) {
	var result SyncResult
	now := syncer.now().UTC()
	through := now.Add(-SyncLag).Truncate(time.Millisecond)
	var cursorMS int64
	err := syncer.pool.QueryRow(ctx, `SELECT ingested_until_ms FROM security_ban_sync_cursor WHERE singleton`).Scan(&cursorMS)
	if errors.Is(err, pgx.ErrNoRows) {
		cursorMS = through.Add(-SyncCatchUp).UnixMilli()
	} else if err != nil {
		return result, fmt.Errorf("read security ban sync cursor: %w", err)
	}
	after := time.UnixMilli(cursorMS).UTC()
	for after.Before(through) {
		events, err := syncer.events.ListTemporaryBans(ctx, after, through, syncBatch)
		if err != nil {
			return result, fmt.Errorf("read temporary bans: %w", err)
		}
		// A full batch may end inside a millisecond with more events: stop
		// before its last millisecond (re-read next pass; folding is
		// idempotent by source_event_id) unless the batch is one millisecond.
		next, batch := through, events
		if len(events) == syncBatch {
			last := events[len(events)-1].IngestedAt
			next = last
			if cut := last.Add(-time.Millisecond); cut.After(after) {
				next = cut
				for len(batch) > 0 && batch[len(batch)-1].IngestedAt.After(cut) {
					batch = batch[:len(batch)-1]
				}
			}
		}
		if err := pgx.BeginFunc(ctx, syncer.pool, func(tx pgx.Tx) error {
			for _, event := range batch {
				outcome, seconds, err := fold(ctx, tx, event, now)
				if err != nil {
					return err
				}
				if outcome != foldSkipped {
					syncer.alertWAFBan(ctx, tx, event, seconds)
				}
				result.Read++
				switch outcome {
				case foldAdded:
					result.Added++
				case foldExtended:
					result.Extended++
				default:
					result.Skipped++
				}
			}
			_, err := tx.Exec(ctx, `INSERT INTO security_ban_sync_cursor(singleton,ingested_until_ms,updated_at) VALUES(true,$1,$2)
				ON CONFLICT(singleton) DO UPDATE SET ingested_until_ms=EXCLUDED.ingested_until_ms,updated_at=EXCLUDED.updated_at`,
				next.UnixMilli(), now)
			return err
		}); err != nil {
			return result, fmt.Errorf("fold temporary bans: %w", err)
		}
		after = next
	}
	if result.Added+result.Extended > 0 && syncer.changed != nil {
		syncer.changed()
	}
	return result, nil
}

// Run syncs every interval until ctx ends; failures are logged and retried.
func (syncer *Syncer) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if result, err := syncer.RunOnce(ctx); err != nil {
			if ctx.Err() == nil {
				slog.Warn("security ban sync failed", "error", err)
			}
		} else if result.Added+result.Extended > 0 {
			slog.Info("security ban sync", "added", result.Added, "extended", result.Extended, "skipped", result.Skipped)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type foldOutcome int

const (
	foldSkipped foldOutcome = iota
	foldAdded
	foldExtended
)

// fold records one automatic ban: a new row, or the extension of the
// client's active row on the site. Skipped: already folded, the site is not
// the reported tenant's (or is gone), the client is not a single address or
// the ban is not of the client (detector count_key: a CC rule's ban of what
// it counts by), a release of the client happened after the
// ban started, or the ban is over.
// seconds is the folded ban's duration.
func fold(ctx context.Context, tx pgx.Tx, event analyticslog.TemporaryBanEvent, now time.Time) (foldOutcome, int, error) {
	siteID, err := uuid.Parse(event.SiteID)
	if err != nil {
		return foldSkipped, 0, nil
	}
	client, ok := canonicalClient(event.ClientIP)
	if !ok || !client.IsSingleIP() || event.Detector == "count_key" {
		return foldSkipped, 0, nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_ban_entries WHERE source_event_id=$1)`,
		event.EventID).Scan(&exists); err != nil || exists {
		return foldSkipped, 0, err
	}
	var scopeID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT site.scope_id FROM sites site JOIN access_scopes scope ON scope.id=site.scope_id
		AND scope.kind='tenant' WHERE site.id=$1 AND scope.tenant_id::text=$2 AND site.deleted_at IS NULL`,
		siteID, event.TenantID).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		slog.Warn("security ban event dropped: site not in the reported tenant", "site_id", event.SiteID, "tenant_id", event.TenantID)
		return foldSkipped, 0, nil
	} else if err != nil {
		return foldSkipped, 0, err
	}
	seconds, err := banSeconds(ctx, tx, scopeID, siteID, event)
	if err != nil {
		return foldSkipped, 0, err
	}
	start := event.OccurredAt.UTC().Truncate(time.Microsecond)
	until := start.Add(time.Duration(seconds) * time.Second)
	if !until.After(now) {
		return foldSkipped, 0, nil
	}
	if err := lockClient(ctx, tx, siteID, client); err != nil {
		return foldSkipped, 0, err
	}
	var released bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_ban_entries WHERE site_id=$1 AND client_ip=$2
		AND released_at >= $3)`, siteID, client, start).Scan(&released); err != nil || released {
		return foldSkipped, 0, err
	}
	activeID, activeUntil, active, err := activeEntryID(ctx, tx, siteID, client, now)
	if err != nil {
		return foldSkipped, 0, err
	}
	if active {
		if !until.After(activeUntil) {
			return foldSkipped, 0, nil
		}
		_, err := tx.Exec(ctx, `UPDATE security_ban_entries SET banned_until=least($2, banned_at + interval '30 days')
			WHERE id=$1`, activeID, until)
		return foldExtended, seconds, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return foldSkipped, 0, err
	}
	ruleID := event.RuleID
	if ruleID == "-" || !ruleIDPattern.MatchString(ruleID) {
		ruleID = ""
	}
	_, err = tx.Exec(ctx, `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,rule_id,
		banned_at,banned_until,source_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		id, scopeID, siteID, client, event.EventType, ruleID, start, until, event.EventID)
	return foldAdded, seconds, err
}

// banSeconds is the ban's duration the node banned with: the rule's own in the policy version the site's
// binding publishes (the CC auto switch rules included), else in the site's published
// rule pack mounts; a WAF block / challenge rule bans through auto block (the policy's, else the auto defense
// overlay's built-in OverlayAutoBlockSeconds). DefaultBanSeconds when neither names the rule.
func banSeconds(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, event analyticslog.TemporaryBanEvent) (int, error) {
	var document []byte
	err := tx.QueryRow(ctx, `SELECT version.document FROM security_policy_site_bindings binding
		JOIN security_policy_versions version ON version.policy_id=binding.policy_id
		 AND version.revision=binding.active_policy_version
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2 AND binding.policy_kind=$3`,
		scopeID, siteID, event.EventType).Scan(&document)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	var policy securitypolicy.Policy
	if err == nil && json.Unmarshal(document, &policy) == nil {
		if seconds, ok := policyBanSeconds(policy, event.EventType, event.RuleID); ok {
			return clampSeconds(seconds), nil
		}
	}
	seconds, err := mountedBanSeconds(ctx, tx, siteID, event)
	if err != nil {
		return 0, err
	}
	return clampSeconds(seconds), nil
}

// policyBanSeconds: the duration of ruleID's ban in policy; ok false when the policy does not name the rule (a
// WAF policy with its own auto block always answers: an unnamed rule's ban is its auto block).
func policyBanSeconds(policy securitypolicy.Policy, kind, ruleID string) (int, bool) {
	rules := policy.Rules
	if settings := policy.CCSettings; settings != nil && settings.AutoSwitch != nil {
		rules = append(slices.Clone(rules), settings.AutoSwitch.Rules...)
		for _, set := range settings.AutoSwitch.RuleSets {
			rules = append(rules, set.Rules...)
		}
	}
	autoBlock := 0
	if settings := policy.WAFSettings; settings != nil && settings.AutoBlock != nil {
		autoBlock = settings.AutoBlock.BlockSeconds
	}
	for _, rule := range rules {
		if rule.ID.String() != ruleID {
			continue
		}
		config := rule.ActionConfig
		switch {
		case config.WAFBan != nil && rule.Action == securitypolicy.ActionBan:
			return config.WAFBan.BanSeconds, true
		case config.RateLimit != nil && config.RateLimit.ResponseAction == "temporary_ban":
			return config.RateLimit.BanSeconds, true
		case config.Challenge != nil && config.Challenge.BanSeconds > 0:
			return config.Challenge.BanSeconds, true
		case kind == "waf" && autoBlock > 0:
			return autoBlock, true
		case kind == "waf":
			return OverlayAutoBlockSeconds, true
		}
		return 0, false
	}
	if kind == "waf" && autoBlock > 0 {
		return autoBlock, true
	}
	return 0, false
}

// mountedBanSeconds: the ban seconds of the site's published rule pack rule the event names (0 = none: no
// mounts, sealed or missing pack, another engine).
func mountedBanSeconds(ctx context.Context, tx pgx.Tx, siteID uuid.UUID, event analyticslog.TemporaryBanEvent) (int, error) {
	var document []byte
	err := tx.QueryRow(ctx, `SELECT security FROM site_security_mounts WHERE site_id=$1`, siteID).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	var security rulepack.Security
	if json.Unmarshal(document, &security) != nil {
		return 0, nil
	}
	for _, mount := range security.Mounts {
		if (event.EventType == "cc") != (mount.Engine == rulepack.EngineCCV2) ||
			(event.EventType == "waf" && mount.Engine != rulepack.EngineWAFV2) {
			continue
		}
		var content []byte
		err := tx.QueryRow(ctx, `SELECT content FROM rule_pack_artifacts WHERE pack_id=$1 AND version=$2 AND sha256=$3`,
			mount.PackID, mount.Version, mount.SHA256).Scan(&content)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (content == nil || rulepack.IsSealed(content)) {
			continue
		} else if err != nil {
			return 0, err
		}
		pack, err := rulepack.Load(content, mount.SHA256)
		if err != nil {
			continue
		}
		rules, err := rulepack.MountRules(mount, pack)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if rule.NodeID == event.RuleID {
				return packRuleBanSeconds(rule), nil
			}
		}
	}
	return 0, nil
}

// packRuleBanSeconds: a pack CC rule's ban, a pack WAF ban rule's; a pack WAF block / challenge rule bans only
// through the overlay auto block (a pack segment has no auto block of its own).
func packRuleBanSeconds(rule rulepack.NodeRule) int {
	switch {
	case rule.CC != nil:
		return int(rule.CC.Action.BanSeconds)
	case rule.WAF != nil && rule.WAF.Action == edgeconfig.WAFBan && rule.WAF.ActionConfig != nil:
		return rule.WAF.ActionConfig.BanSeconds
	case rule.WAF != nil:
		return OverlayAutoBlockSeconds
	}
	return 0
}

func clampSeconds(seconds int) int {
	if seconds < 1 {
		return DefaultBanSeconds
	}
	return min(seconds, MaxManualSeconds)
}
