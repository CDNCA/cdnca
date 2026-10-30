package wafsubscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidInput     = errors.New("invalid WAF rule subscription input")
	ErrNotFound         = errors.New("WAF rule subscription not found")
	ErrPermissionDenied = errors.New("WAF rule subscriptions are managed by platform operators")
	// ErrNotReady: the subscription has no good snapshot yet.
	ErrNotReady = errors.New("WAF rule subscription has not been fetched yet")
)

const (
	DefaultIntervalMinutes = 360
	minIntervalMinutes     = 5
	maxIntervalMinutes     = 10080
	retryAfterFailure      = 5 * time.Minute
	syncTimeout            = 90 * time.Second
	dueBatch               = 16
	pollEvery              = time.Minute
	maxErrorRunes          = 1000
)

// Subscription is a subscription-fed WAF rule library and its last good
// snapshot. Revision counts snapshots whose rules changed (0 = never
// fetched); subscriber packs carry it as their major version. Subscribers
// counts the tenants keeping a pack of it, PendingSites the published sites
// whose mount is older than their tenant's current pack version.
type Subscription struct {
	ID              uuid.UUID       `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	SourceURL       string          `json:"source_url"`
	IntervalMinutes int             `json:"interval_minutes"`
	Enabled         bool            `json:"enabled"`
	Revision        int64           `json:"revision"`
	FeedVersion     string          `json:"feed_version"`
	FeedGeneratedAt string          `json:"feed_generated_at"`
	RuleCount       int             `json:"rule_count"`
	LastAttemptAt   *time.Time      `json:"last_attempt_at"`
	LastSuccessAt   *time.Time      `json:"last_success_at"`
	LastError       string          `json:"last_error"`
	NextFetchAt     time.Time       `json:"next_fetch_at"`
	Subscribers     int             `json:"subscribers"`
	PendingSites    int             `json:"pending_sites"`
	UpdatedAt       time.Time       `json:"updated_at"`
	Deleted         bool            `json:"-"`
	Rules           []rulepack.Rule `json:"-"`
	rulesSHA256     []byte
}

// Input is what an operator configures.
type Input struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	SourceURL       string `json:"source_url"`
	IntervalMinutes int    `json:"interval_minutes"`
	Enabled         bool   `json:"enabled"`
}

// Actor is the caller: a platform operator manages subscriptions, a tenant
// member subscribes its tenant. SourceIP and RequestID go into the audit.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
	RequestID string
	SourceIP  string
}

// Operator is the platform principal managing subscriptions.
type Operator = Actor

type documentFetcher interface {
	fetch(ctx context.Context, url string) ([]byte, error)
}

type Service struct {
	pool    *pgxpool.Pool
	fetcher documentFetcher
	auditor *audit.Log
	now     func() time.Time
	logger  *slog.Logger
}

func NewService(pool *pgxpool.Pool, now func() time.Time, logger *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{pool: pool, fetcher: NewFetcher(), auditor: audit.NewWithClock(pool, now), now: now, logger: logger}
}

func (input *Input) normalize() error {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.SourceURL = strings.TrimSpace(input.SourceURL)
	if input.IntervalMinutes == 0 {
		input.IntervalMinutes = DefaultIntervalMinutes
	}
	if n := utf8.RuneCountInString(input.Name); n < 1 || n > 128 || !utf8.ValidString(input.Description) ||
		utf8.RuneCountInString(input.Description) > 500 ||
		input.IntervalMinutes < minIntervalMinutes || input.IntervalMinutes > maxIntervalMinutes {
		return ErrInvalidInput
	}
	if err := ValidateURL(input.SourceURL); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return nil
}

func (actor Actor) checkOperator() error {
	if actor.ScopeKind != "platform" || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil {
		return ErrPermissionDenied
	}
	return nil
}

func (actor Actor) checkTenant() error {
	if actor.ScopeKind != "tenant" || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil {
		return ErrPermissionDenied
	}
	return nil
}

// pendingMounts are the published site mounts of a subscriber pack whose
// version is not the pack's current one.
const pendingMounts = `FROM waf_rule_subscription_packs member
	JOIN rule_packs pack ON pack.pack_id=member.pack_id
	JOIN rule_pack_site_mount_artifacts mount ON mount.pack_id=member.pack_id AND mount.version IS DISTINCT FROM pack.current_version
	JOIN sites site ON site.id=mount.site_id AND site.deleted_at IS NULL`

const subscriptionColumns = `s.id,s.name,s.description,s.source_url,s.interval_minutes,s.enabled,s.revision,
	s.feed_version,s.feed_generated_at,s.rule_count,s.last_attempt_at,s.last_success_at,s.last_error,
	s.next_fetch_at,s.updated_at,s.deleted_at IS NOT NULL,s.rules,s.rules_sha256,
	(SELECT count(*) FROM waf_rule_subscription_packs member WHERE member.subscription_id=s.id),
	(SELECT count(DISTINCT mount.site_id) ` + pendingMounts + ` WHERE member.subscription_id=s.id)`

func scanSubscription(row pgx.Row) (Subscription, error) {
	var item Subscription
	var rules []byte
	err := row.Scan(&item.ID, &item.Name, &item.Description, &item.SourceURL, &item.IntervalMinutes, &item.Enabled,
		&item.Revision, &item.FeedVersion, &item.FeedGeneratedAt, &item.RuleCount, &item.LastAttemptAt,
		&item.LastSuccessAt, &item.LastError, &item.NextFetchAt, &item.UpdatedAt, &item.Deleted, &rules, &item.rulesSHA256,
		&item.Subscribers, &item.PendingSites)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, ErrNotFound
	}
	if err != nil {
		return Subscription{}, err
	}
	if err := json.Unmarshal(rules, &item.Rules); err != nil {
		return Subscription{}, fmt.Errorf("decode subscription rules: %w", err)
	}
	return item, nil
}

// List returns the libraries; includeDeleted keeps deleted ones.
func (s *Service) List(ctx context.Context, includeDeleted bool) ([]Subscription, error) {
	query := `SELECT ` + subscriptionColumns + ` FROM waf_rule_subscriptions s`
	if !includeDeleted {
		query += ` WHERE s.deleted_at IS NULL`
	}
	rows, err := s.pool.Query(ctx, query+` ORDER BY s.name, s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Subscription, 0)
	for rows.Next() {
		item, err := scanSubscription(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// Get returns one library, deleted or not.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Subscription, error) {
	return scanSubscription(s.pool.QueryRow(ctx, `SELECT `+subscriptionColumns+` FROM waf_rule_subscriptions s WHERE s.id=$1`, id))
}
func (s *Service) Create(ctx context.Context, operator Operator, input Input) (Subscription, error) {
	if err := operator.checkOperator(); err != nil {
		return Subscription{}, err
	}
	if err := input.normalize(); err != nil {
		return Subscription{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Subscription{}, err
	}
	now := s.now().UTC()
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO waf_rule_subscriptions(id,name,description,source_url,interval_minutes,
			enabled,next_fetch_at,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,$7,$7)`, id, input.Name, input.Description, input.SourceURL,
			input.IntervalMinutes, input.Enabled, now, operator.UserID); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, &operator, operator.ScopeID, id, "rule.subscription.create", "success",
			map[string]any{"name": input.Name, "changes": inputChanges(nil, input)})
	})
	if err != nil {
		return Subscription{}, err
	}
	return s.Get(ctx, id)
}

func (s *Service) Update(ctx context.Context, operator Operator, id uuid.UUID, input Input) (Subscription, error) {
	if err := operator.checkOperator(); err != nil {
		return Subscription{}, err
	}
	if err := input.normalize(); err != nil {
		return Subscription{}, err
	}
	now := s.now().UTC()
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var before Input
		err := tx.QueryRow(ctx, `SELECT name,description,source_url,interval_minutes,enabled FROM waf_rule_subscriptions
			WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&before.Name, &before.Description, &before.SourceURL,
			&before.IntervalMinutes, &before.Enabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		// A changed URL or interval is fetched on the next poll.
		if _, err := tx.Exec(ctx, `UPDATE waf_rule_subscriptions SET name=$2,description=$3,
			next_fetch_at=CASE WHEN source_url<>$4 OR interval_minutes<>$5 THEN $7 ELSE next_fetch_at END,
			source_url=$4,interval_minutes=$5,enabled=$6,updated_by_user_id=$8,updated_at=$7
			WHERE id=$1`, id, input.Name, input.Description, input.SourceURL,
			input.IntervalMinutes, input.Enabled, now, operator.UserID); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, &operator, operator.ScopeID, id, "rule.subscription.update", "success",
			map[string]any{"name": input.Name, "changes": inputChanges(&before, input)})
	})
	if err != nil {
		return Subscription{}, err
	}
	return s.Get(ctx, id)
}

// Delete hides the library and stops fetching. Subscriber packs stay (they
// may be enabled and mounted); tenants unsubscribe or delete them.
func (s *Service) Delete(ctx context.Context, operator Operator, id uuid.UUID) error {
	if err := operator.checkOperator(); err != nil {
		return err
	}
	now := s.now().UTC()
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var name string
		err := tx.QueryRow(ctx, `UPDATE waf_rule_subscriptions SET deleted_at=$2,enabled=false,updated_at=$2,
			updated_by_user_id=$3 WHERE id=$1 AND deleted_at IS NULL RETURNING name`, id, now, operator.UserID).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, &operator, operator.ScopeID, id, "rule.subscription.delete", "success",
			map[string]any{"name": name, "changes": map[string]any{"deleted": map[string]any{"from": false, "to": true}}})
	})
}

// inputChanges is the before -> after of the configured fields (all of them
// on create). The URL is recorded without its query, which may carry a
// token.
func inputChanges(before *Input, after Input) map[string]any {
	changes := map[string]any{}
	field := func(name string, from, to any) {
		if before == nil {
			changes[name] = map[string]any{"from": nil, "to": to}
		} else if from != to {
			changes[name] = map[string]any{"from": from, "to": to}
		}
	}
	var old Input
	if before != nil {
		old = *before
	}
	field("name", old.Name, after.Name)
	field("description", old.Description, after.Description)
	field("source_url", RedactURL(old.SourceURL), RedactURL(after.SourceURL))
	field("interval_minutes", old.IntervalMinutes, after.IntervalMinutes)
	field("enabled", old.Enabled, after.Enabled)
	if before != nil && old.SourceURL != after.SourceURL && RedactURL(old.SourceURL) == RedactURL(after.SourceURL) {
		changes["source_url"] = map[string]any{"from": RedactURL(old.SourceURL), "to": RedactURL(after.SourceURL),
			"query_changed": true}
	}
	return changes
}

// RedactURL keeps scheme, host and path; a query becomes "?…".
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "…"
	}
	redacted := parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath()
	if parsed.RawQuery != "" {
		redacted += "?…"
	}
	return redacted
}

// Sync fetches the library now ("立即更新订阅"), whether or not it is
// enabled for periodic updates.
func (s *Service) Sync(ctx context.Context, operator Operator, id uuid.UUID) (Subscription, error) {
	if err := operator.checkOperator(); err != nil {
		return Subscription{}, err
	}
	item, err := s.Get(ctx, id)
	if err != nil {
		return Subscription{}, err
	}
	if item.Deleted {
		return Subscription{}, ErrNotFound
	}
	if _, err := s.pool.Exec(ctx, `UPDATE waf_rule_subscriptions SET last_attempt_at=$2 WHERE id=$1`, id, s.now().UTC()); err != nil {
		return Subscription{}, err
	}
	s.syncOne(ctx, item, &operator)
	return s.Get(ctx, id)
}

// RunDue fetches the enabled libraries whose next fetch is due. Claiming
// moves next_fetch_at first, so concurrent control-api instances skip rows
// another one is fetching.
func (s *Service) RunDue(ctx context.Context) (int, error) {
	now := s.now().UTC()
	rows, err := s.pool.Query(ctx, `UPDATE waf_rule_subscriptions s SET last_attempt_at=$1,
		next_fetch_at=$1 + make_interval(mins => s.interval_minutes)
		WHERE s.id IN (SELECT id FROM waf_rule_subscriptions WHERE enabled AND deleted_at IS NULL AND next_fetch_at<=$1
			ORDER BY next_fetch_at LIMIT $2 FOR UPDATE SKIP LOCKED)
		RETURNING `+subscriptionColumns, now, dueBatch)
	if err != nil {
		return 0, err
	}
	claimed := make([]Subscription, 0)
	for rows.Next() {
		item, err := scanSubscription(rows)
		if err != nil {
			rows.Close()
			return 0, err
		}
		claimed = append(claimed, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, item := range claimed {
		s.syncOne(ctx, item, nil)
	}
	return len(claimed), nil
}

// Run polls RunDue until ctx ends. Failures are recorded per library and
// logged; they never stop the server.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	for {
		if _, err := s.RunDue(ctx); err != nil && ctx.Err() == nil {
			s.logger.Warn("WAF rule subscription poll failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// syncOutcome is what one fetch did, for rule.subscription.sync.
type syncOutcome struct {
	after   *Subscription
	created []string
	reason  string
	message string
}

// syncOne fetches and compiles item. A success stores the snapshot (the
// revision moves only when the compiled rules change) and brings every
// subscriber pack to it (a new pack version, never enabled or published);
// a failure keeps the last good snapshot and records the error. actor is
// nil for a scheduled fetch.
func (s *Service) syncOne(ctx context.Context, item Subscription, actor *Actor) {
	fetchCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	feed, err := s.fetchFeed(fetchCtx, item.SourceURL)
	now := s.now().UTC()
	// The outcome is recorded even when the caller's deadline ended the fetch.
	ctx, cancelRecord := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancelRecord()
	outcome := syncOutcome{}
	defer func() { s.auditSync(ctx, actor, item, outcome) }()
	if err != nil {
		outcome.reason, outcome.message = "fetch_failed", err.Error()
		var compileError *CompileError
		if errors.Is(err, ErrInvalidDocument) || errors.As(err, &compileError) {
			outcome.reason = "invalid_document"
		}
		s.recordFailure(ctx, item.ID, now, err.Error())
		return
	}
	stored, err := s.recordSuccess(ctx, item.ID, feed, now)
	if err != nil {
		outcome.reason, outcome.message = "store_failed", err.Error()
		s.recordFailure(ctx, item.ID, now, "store snapshot: "+err.Error())
		return
	}
	outcome.after = &stored
	created, err := s.propagate(ctx, stored, actor, now)
	outcome.created = created
	if err != nil {
		outcome.reason, outcome.message = "pack_version_failed", err.Error()
		s.recordFailure(ctx, item.ID, now, "update subscriber packs: "+err.Error())
	}
}

func (s *Service) fetchFeed(ctx context.Context, url string) (Feed, error) {
	raw, err := s.fetcher.fetch(ctx, url)
	if err != nil {
		return Feed{}, err
	}
	return Compile(raw)
}

func (s *Service) recordSuccess(ctx context.Context, id uuid.UUID, feed Feed, now time.Time) (Subscription, error) {
	rules, err := json.Marshal(feed.Rules)
	if err != nil {
		return Subscription{}, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE waf_rule_subscriptions SET
		revision=CASE WHEN rules_sha256 IS DISTINCT FROM $2 THEN revision+1 ELSE revision END,
		rules=$3,rule_count=$4,rules_sha256=$2,feed_version=$5,feed_generated_at=$6,
		last_success_at=$7,last_error='' WHERE id=$1 AND deleted_at IS NULL`,
		id, feed.SHA256[:], rules, len(feed.Rules), feed.Version, feed.GeneratedAt, now)
	if err != nil {
		return Subscription{}, err
	}
	if tag.RowsAffected() != 1 {
		return Subscription{}, ErrNotFound
	}
	return s.Get(ctx, id)
}

func (s *Service) recordFailure(ctx context.Context, id uuid.UUID, now time.Time, message string) {
	// Retry a failed fetch sooner than the interval, never later.
	if _, err := s.pool.Exec(ctx, `UPDATE waf_rule_subscriptions SET last_error=$2,
		next_fetch_at=LEAST(next_fetch_at,$3) WHERE id=$1`, id, truncateRunes(message, maxErrorRunes),
		now.Add(retryAfterFailure)); err != nil {
		s.logger.Warn("record WAF rule subscription failure", "subscription_id", id, "err", err)
	}
}

func truncateRunes(message string, limit int) string {
	if runes := []rune(message); len(runes) > limit {
		return string(runes[:limit])
	}
	return message
}

// propagate brings every subscriber pack to item's snapshot, each tenant in
// its own transaction (one failing tenant does not hold back the others).
// It runs after every good fetch, so a pack missed by an earlier failure
// catches up on the next one.
func (s *Service) propagate(ctx context.Context, item Subscription, actor *Actor, now time.Time) ([]string, error) {
	if item.Revision < 1 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT tenant_scope_id, subscribed_by_user_id FROM waf_rule_subscription_packs
		WHERE subscription_id=$1 ORDER BY tenant_scope_id`, item.ID)
	if err != nil {
		return nil, err
	}
	type member struct{ tenant, subscriber uuid.UUID }
	members := make([]member, 0)
	for rows.Next() {
		var row member
		if err := rows.Scan(&row.tenant, &row.subscriber); err != nil {
			rows.Close()
			return nil, err
		}
		members = append(members, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	created := make([]string, 0)
	var failures []error
	for _, row := range members {
		var added *rulepackcontrol.AddedVersion
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			var err error
			added, err = ensureVersion(ctx, tx, item, row.tenant, row.subscriber, actor, now)
			return err
		})
		if err != nil {
			failures = append(failures, fmt.Errorf("tenant %s: %w", row.tenant, err))
			continue
		}
		if added != nil {
			created = append(created, added.PackID+"@"+added.Version)
		}
	}
	if len(failures) > 0 {
		return created, fmt.Errorf("%d of %d subscriber packs: %w", len(failures), len(members), errors.Join(failures...))
	}
	return created, nil
}

// ensureVersion adds the version of tenant's pack that carries item's
// snapshot, unless the newest subscription version already does (nil). The
// version is <revision>.0.0, or the next minor when the same revision's pack
// text changed (rename, description).
func ensureVersion(ctx context.Context, tx pgx.Tx, item Subscription, tenant, createdBy uuid.UUID, actor *Actor,
	now time.Time) (*rulepackcontrol.AddedVersion, error) {
	packID := PackID(tenant, item.ID)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM rule_packs WHERE pack_id=$1 FOR UPDATE`, packID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT version, sha256 FROM rule_pack_artifacts WHERE pack_id=$1 AND source='subscription'`, packID)
	if err != nil {
		return nil, err
	}
	var latest Revision
	var latestSHA string
	found := false
	for rows.Next() {
		var version, sha string
		if err := rows.Scan(&version, &sha); err != nil {
			rows.Close()
			return nil, err
		}
		if parsed, ok := parseRevision(version); ok && (!found || latest.less(parsed)) {
			latest, latestSHA, found = parsed, sha, true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	next := Revision{Major: item.Revision}
	if found && latest.Major > item.Revision {
		return nil, fmt.Errorf("pack %s has version %s, newer than subscription revision %d", packID, latest, item.Revision)
	}
	if found && latest.Major == item.Revision {
		same, err := rulepack.CompilePack(Pack(tenant, item.ID, item.Name, item.Description, latest, item.Rules))
		if err != nil {
			return nil, err
		}
		if same.SHA256 == latestSHA {
			return nil, nil
		}
		next.Minor = latest.Minor + 1
	}
	compiled, err := rulepack.CompilePack(Pack(tenant, item.ID, item.Name, item.Description, next, item.Rules))
	if err != nil {
		return nil, err
	}
	var packActor *rulepackcontrol.Actor
	if actor != nil {
		packActor = &rulepackcontrol.Actor{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind,
			SourceIP: actor.SourceIP, RequestID: actor.RequestID}
	}
	added, err := rulepackcontrol.AddVersion(ctx, tx, now, rulepackcontrol.NewVersion{Compiled: compiled, Source: "subscription",
		CreatedBy: createdBy, Actor: packActor, Audit: map[string]any{"subscription_id": item.ID.String(),
			"subscription_revision": item.Revision}})
	if err != nil {
		return nil, err
	}
	return &added, nil
}

// Subscribe gives the actor's tenant its pack of the subscription (version
// <revision>.0.0, downloaded, not enabled) and keeps it updated. A tenant
// already subscribed gets its pack unchanged.
func (s *Service) Subscribe(ctx context.Context, actor Actor, id uuid.UUID) (TenantSubscription, error) {
	if err := actor.checkTenant(); err != nil {
		return TenantSubscription{}, err
	}
	now := s.now().UTC()
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// FOR SHARE orders this against a fetch storing a new snapshot: a
		// later fetch sees the membership, an earlier one is read here.
		item, err := scanSubscription(tx.QueryRow(ctx, `SELECT `+subscriptionColumns+` FROM waf_rule_subscriptions s
			WHERE s.id=$1 FOR SHARE OF s`, id))
		if err != nil {
			return err
		}
		if item.Deleted {
			return ErrNotFound
		}
		if item.Revision < 1 {
			return ErrNotReady
		}
		var subscribed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM waf_rule_subscription_packs WHERE subscription_id=$1
			AND tenant_scope_id=$2)`, id, actor.ScopeID).Scan(&subscribed); err != nil {
			return err
		}
		if subscribed {
			return nil
		}
		// A pack left from an earlier subscription is brought up to date.
		added, err := ensureVersion(ctx, tx, item, actor.ScopeID, actor.UserID, &actor, now)
		if err != nil {
			return err
		}
		packID := PackID(actor.ScopeID, id)
		if _, err := tx.Exec(ctx, `INSERT INTO waf_rule_subscription_packs(subscription_id,tenant_scope_id,pack_id,
			subscribed_by_user_id,subscribed_at) VALUES($1,$2,$3,$4,$5)`, id, actor.ScopeID, packID, actor.UserID, now); err != nil {
			return err
		}
		payload := map[string]any{"name": item.Name, "pack_id": packID,
			"changes": map[string]any{"subscribed": map[string]any{"from": false, "to": true}}}
		if added != nil {
			payload["pack_version"] = added.Version
		}
		return s.appendAudit(ctx, tx, &actor, actor.ScopeID, id, "rule.subscription.subscribe", "success", payload)
	})
	if err != nil {
		return TenantSubscription{}, err
	}
	items, err := s.TenantList(ctx, actor, &id)
	if err != nil {
		return TenantSubscription{}, err
	}
	if len(items) != 1 {
		return TenantSubscription{}, ErrNotFound
	}
	return items[0], nil
}

// Unsubscribe stops updating the actor's tenant pack. The pack and its
// versions stay: it may be enabled and mounted, and it is deleted (when no
// level enables it and no site mounts it) on the rule pack page.
func (s *Service) Unsubscribe(ctx context.Context, actor Actor, id uuid.UUID) error {
	if err := actor.checkTenant(); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var name string
		if err := tx.QueryRow(ctx, `SELECT name FROM waf_rule_subscriptions WHERE id=$1`, id).Scan(&name); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		var packID string
		err := tx.QueryRow(ctx, `DELETE FROM waf_rule_subscription_packs WHERE subscription_id=$1 AND tenant_scope_id=$2
			RETURNING pack_id`, id, actor.ScopeID).Scan(&packID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, &actor, actor.ScopeID, id, "rule.subscription.unsubscribe", "success",
			map[string]any{"name": name, "pack_id": packID,
				"changes": map[string]any{"subscribed": map[string]any{"from": true, "to": false}}})
	})
}

// PendingSite is a published site whose mount of a subscriber pack is not
// the pack's current version ("待发布"): the new version runs there only
// once the site is published again.
type PendingSite struct {
	SiteID           uuid.UUID `json:"site_id"`
	Domain           string    `json:"domain"`
	PublishedVersion string    `json:"published_version"`
}

// SubscriberPack is one tenant's pack of a subscription.
type SubscriberPack struct {
	SubscriptionID uuid.UUID     `json:"subscription_id"`
	TenantScopeID  uuid.UUID     `json:"tenant_scope_id"`
	TenantName     string        `json:"tenant_name"`
	PackID         string        `json:"pack_id"`
	CurrentVersion string        `json:"current_version"`
	LatestVersion  string        `json:"latest_version"`
	UpdatePolicy   string        `json:"update_policy"`
	SubscribedAt   time.Time     `json:"subscribed_at"`
	PendingSites   []PendingSite `json:"pending_sites"`
}

// SubscriberPacks lists subscriber packs: every tenant's for a platform
// actor (optionally of one subscription), the own tenant's otherwise.
func (s *Service) SubscriberPacks(ctx context.Context, actor Actor, subscriptionID *uuid.UUID) ([]SubscriberPack, error) {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" && actor.ScopeKind != "tenant" {
		return nil, ErrPermissionDenied
	}
	rows, err := s.pool.Query(ctx, `SELECT member.subscription_id, member.tenant_scope_id, coalesce(tenant.display_name,''),
			member.pack_id, coalesce(pack.current_version,''), pack.update_policy, member.subscribed_at,
			coalesce((SELECT array_agg(artifact.version) FROM rule_pack_artifacts artifact
			  WHERE artifact.pack_id=member.pack_id AND artifact.source='subscription'), '{}')
		FROM waf_rule_subscription_packs member
		JOIN rule_packs pack ON pack.pack_id=member.pack_id
		JOIN access_scopes scope ON scope.id=member.tenant_scope_id
		LEFT JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE ($1::text='platform' OR member.tenant_scope_id=$2) AND ($3::uuid IS NULL OR member.subscription_id=$3)
		ORDER BY member.subscription_id, tenant.display_name, member.tenant_scope_id`, actor.ScopeKind, actor.ScopeID, subscriptionID)
	if err != nil {
		return nil, err
	}
	packs := make([]SubscriberPack, 0)
	index := map[string]int{}
	for rows.Next() {
		var pack SubscriberPack
		var versions []string
		if err := rows.Scan(&pack.SubscriptionID, &pack.TenantScopeID, &pack.TenantName, &pack.PackID, &pack.CurrentVersion,
			&pack.UpdatePolicy, &pack.SubscribedAt, &versions); err != nil {
			rows.Close()
			return nil, err
		}
		pack.LatestVersion = latestVersion(versions)
		pack.PendingSites = []PendingSite{}
		index[pack.PackID] = len(packs)
		packs = append(packs, pack)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(packs) == 0 {
		return packs, nil
	}
	ids := make([]string, 0, len(packs))
	for _, pack := range packs {
		ids = append(ids, pack.PackID)
	}
	sites, err := s.pool.Query(ctx, `SELECT member.pack_id, site.id, site.domain, mount.version `+pendingMounts+`
		WHERE member.pack_id = ANY($1) ORDER BY site.domain, site.id`, ids)
	if err != nil {
		return nil, err
	}
	defer sites.Close()
	for sites.Next() {
		var packID string
		var site PendingSite
		if err := sites.Scan(&packID, &site.SiteID, &site.Domain, &site.PublishedVersion); err != nil {
			return nil, err
		}
		packs[index[packID]].PendingSites = append(packs[index[packID]].PendingSites, site)
	}
	return packs, sites.Err()
}

func latestVersion(versions []string) string {
	var latest Revision
	found := false
	for _, version := range versions {
		if parsed, ok := parseRevision(version); ok && (!found || latest.less(parsed)) {
			latest, found = parsed, true
		}
	}
	if !found {
		return ""
	}
	return latest.String()
}

// TenantSubscription is a subscription as a tenant sees it: no URL or
// fetch errors (operator data), whether the tenant subscribes and its pack.
type TenantSubscription struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Revision    int64           `json:"revision"`
	FeedVersion string          `json:"feed_version"`
	RuleCount   int             `json:"rule_count"`
	SyncedAt    *time.Time      `json:"synced_at"`
	Deleted     bool            `json:"deleted"`
	Subscribed  bool            `json:"subscribed"`
	Pack        *SubscriberPack `json:"pack"`
}

// TenantList lists the fetched, not deleted subscriptions and every
// subscription the tenant keeps a pack of (deleted ones included, so it can
// unsubscribe). only narrows it to one subscription.
func (s *Service) TenantList(ctx context.Context, actor Actor, only *uuid.UUID) ([]TenantSubscription, error) {
	if err := actor.checkTenant(); err != nil {
		return nil, err
	}
	all, err := s.List(ctx, true)
	if err != nil {
		return nil, err
	}
	packs, err := s.SubscriberPacks(ctx, actor, only)
	if err != nil {
		return nil, err
	}
	bySubscription := map[uuid.UUID]SubscriberPack{}
	for _, pack := range packs {
		bySubscription[pack.SubscriptionID] = pack
	}
	items := make([]TenantSubscription, 0)
	for _, item := range all {
		pack, subscribed := bySubscription[item.ID]
		if only != nil && item.ID != *only || !subscribed && (item.Deleted || item.Revision < 1) {
			continue
		}
		entry := TenantSubscription{ID: item.ID, Name: item.Name, Description: item.Description, Revision: item.Revision,
			FeedVersion: item.FeedVersion, RuleCount: item.RuleCount, SyncedAt: item.LastSuccessAt, Deleted: item.Deleted,
			Subscribed: subscribed}
		if subscribed {
			entry.Pack = &pack
		}
		items = append(items, entry)
	}
	return items, nil
}

func (s *Service) appendAudit(ctx context.Context, tx pgx.Tx, actor *Actor, scopeID, id uuid.UUID, action, result string,
	payload map[string]any) error {
	event := audit.Event{ScopeID: scopeID, Action: action, ResourceType: "waf_rule_subscription", ResourceID: id.String(),
		RequestID: "waf-subscription-" + uuid.NewString(), Result: result, Payload: payload}
	payload["actor"], payload["ip"] = "system", ""
	if actor != nil {
		userID := actor.UserID
		event.ActorUserID = &userID
		payload["actor"], payload["ip"] = "user", actor.SourceIP
		if actor.RequestID != "" {
			event.RequestID = actor.RequestID
		}
	}
	return s.auditor.Append(ctx, tx, event)
}

// auditSync writes rule.subscription.sync: always for a manual sync, for a
// scheduled one only when something changed (a new revision or pack
// version, or a different error) so a failing feed polled every few minutes
// does not flood the log.
func (s *Service) auditSync(ctx context.Context, actor *Actor, before Subscription, outcome syncOutcome) {
	after := before
	if outcome.after != nil {
		after = *outcome.after
	}
	errorChanged := outcome.message != "" && truncateRunes(outcome.message, maxErrorRunes) != before.LastError
	if actor == nil && after.Revision == before.Revision && len(outcome.created) == 0 && !errorChanged &&
		!(outcome.reason == "" && before.LastError != "") {
		return
	}
	changes := map[string]any{}
	if after.Revision != before.Revision {
		changes["revision"] = map[string]any{"from": before.Revision, "to": after.Revision}
	}
	if after.FeedVersion != before.FeedVersion {
		changes["feed_version"] = map[string]any{"from": before.FeedVersion, "to": after.FeedVersion}
	}
	if after.RuleCount != before.RuleCount {
		changes["rule_count"] = map[string]any{"from": before.RuleCount, "to": after.RuleCount}
	}
	if len(outcome.created) > 0 {
		changes["pack_versions"] = map[string]any{"added": outcome.created}
	}
	trigger := "scheduled"
	if actor != nil {
		trigger = "manual"
	}
	payload := map[string]any{"name": before.Name, "trigger": trigger, "changes": changes}
	result := "success"
	if outcome.reason != "" {
		result = "failure"
		payload["reason"] = outcome.reason
		payload["error"] = truncateRunes(outcome.message, 300)
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID := uuid.Nil
		if actor != nil {
			scopeID = actor.ScopeID
		} else if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY id LIMIT 1`).
			Scan(&scopeID); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, scopeID, before.ID, "rule.subscription.sync", result, payload)
	})
	if err != nil {
		s.logger.Warn("audit WAF rule subscription sync", "subscription_id", before.ID, "err", err)
	}
}

// PendingPublication is a site whose bound platform WAF library copy (a
// protected "@system/<id>" policy of a platform library) has a newer
// version than the one the site runs. WAF rule subscriptions no longer feed
// such copies (their pending sites are SubscriberPack.PendingSites).
// Publishing stays an operator action through the security activation
// chain; LastTargetNodeIDs are the nodes of the site's last activation.
type PendingPublication struct {
	SiteID            uuid.UUID   `json:"site_id"`
	Domain            string      `json:"domain"`
	PolicyID          uuid.UUID   `json:"policy_id"`
	ActiveVersion     int64       `json:"active_version"`
	LatestVersion     int64       `json:"latest_version"`
	UpdatedAt         time.Time   `json:"updated_at"`
	Publishing        bool        `json:"publishing"`
	LastTargetNodeIDs []uuid.UUID `json:"last_target_node_ids"`
}

// PendingPublications lists the actor's (a tenant's, or every tenant's for
// a platform actor) sites waiting for a platform library update.
func (s *Service) PendingPublications(ctx context.Context, actor securitypolicy.Actor) ([]PendingPublication, error) {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "tenant" && actor.ScopeKind != "platform" {
		return nil, ErrInvalidInput
	}
	rows, err := s.pool.Query(ctx, `SELECT binding.site_id,site.domain,policy.id,binding.active_policy_version,policy.revision,policy.updated_at,
			EXISTS(SELECT 1 FROM security_policy_activation_candidates open
			  WHERE open.tenant_scope_id=binding.tenant_scope_id AND open.binding_id=binding.id
			    AND open.candidate_status IN ('claimed','canary','expanding','healthy')),
			COALESCE((SELECT last.canary_node_ids || last.expand_node_ids FROM security_policy_activation_candidates last
			  WHERE last.tenant_scope_id=binding.tenant_scope_id AND last.binding_id=binding.id
			  ORDER BY last.created_at DESC, last.id DESC LIMIT 1), '{}')
		FROM security_policy_site_bindings binding
		JOIN security_policies policy ON policy.scope_id=binding.tenant_scope_id AND policy.id=binding.policy_id
		JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id AND site.deleted_at IS NULL
		WHERE binding.policy_kind='waf' AND policy.kind='waf' AND policy.deleted_at IS NULL AND policy.name LIKE '@system/%'
		  AND binding.active_policy_version IS NOT NULL AND binding.active_policy_version < policy.revision
		  AND ($1::text='platform' OR binding.tenant_scope_id=$2)
		ORDER BY site.domain, binding.site_id`, actor.ScopeKind, actor.ScopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PendingPublication, 0)
	for rows.Next() {
		var item PendingPublication
		if err := rows.Scan(&item.SiteID, &item.Domain, &item.PolicyID, &item.ActiveVersion, &item.LatestVersion, &item.UpdatedAt,
			&item.Publishing, &item.LastTargetNodeIDs); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
