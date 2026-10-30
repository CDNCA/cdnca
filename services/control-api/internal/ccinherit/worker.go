// Package ccinherit keeps CC policies whose site settings follow the global
// CC config (securitypolicy.CCSettings mode "system": blacklist / whitelist
// time, auto switch) in step with it. A change of a tenant's global config
// (openresty_security_publication_outbox, scope global), of the platform's
// auto switch layers (its global / region / node configs and nodes,
// fix-fwregion) or of the system
// rule catalog re-resolves those policies: a changed policy gets a new
// revision (as its owner) and every site that runs its latest revision is
// activated again (as whoever published the site's current release).
package ccinherit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidConfiguration = errors.New("invalid CC settings inheritance configuration")

type PolicyStore interface {
	CCSystemDefaults(context.Context, uuid.UUID) (securitypolicy.CCSystemDefaults, error)
	SystemCatalog(context.Context) ([]rulecatalog.Item, error)
}

type PolicyUpdater interface {
	Get(context.Context, securitypolicy.Actor, uuid.UUID) (securitypolicy.Policy, error)
	Update(context.Context, securitypolicy.Actor, securitypolicy.UpdateRequest) (securitypolicy.WriteResult, error)
}

type ActivationStarter interface {
	Start(context.Context, securitypolicy.Actor, securityactivation.StartInput) (securityactivation.StartResult, error)
}

type Worker struct {
	pool        *pgxpool.Pool
	store       PolicyStore
	policies    PolicyUpdater
	activations ActivationStarter
	interval    time.Duration
	now         func() time.Time
	logger      *slog.Logger

	outboxSeen  time.Time
	catalogSeen time.Time
	// platformSeen: the platform scope's firewall configs and nodes
	// (auto switch layers, fix-fwregion).
	platformSeen time.Time
	swept       bool
	// retry holds scopes whose last pass failed (an owner without the custom
	// CC feature, a revision race): retried each pass on their own.
	retry map[uuid.UUID]struct{}
}

func NewWorker(pool *pgxpool.Pool, store PolicyStore, policies PolicyUpdater, activations ActivationStarter,
	interval time.Duration, now func() time.Time, logger *slog.Logger) (*Worker, error) {
	if pool == nil || store == nil || policies == nil || activations == nil || interval <= 0 || now == nil {
		return nil, ErrInvalidConfiguration
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{pool: pool, store: store, policies: policies, activations: activations, interval: interval,
		now: now, logger: logger, retry: map[uuid.UUID]struct{}{}}, nil
}

func (worker *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(worker.interval)
	defer ticker.Stop()
	for {
		if err := worker.Reconcile(ctx); err != nil && ctx.Err() == nil {
			worker.logger.Warn("CC settings inheritance pass failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Reconcile re-resolves every scope whose global CC config changed since
// the previous pass (all scopes on the first pass and after a catalog
// change). Failures of one policy or site are logged and retried next pass.
func (worker *Worker) Reconcile(ctx context.Context) error {
	var catalogAt time.Time
	if err := worker.pool.QueryRow(ctx, `SELECT COALESCE(max(updated_at),'epoch') FROM security_system_rules`).
		Scan(&catalogAt); err != nil {
		return fmt.Errorf("read rule catalog watermark: %w", err)
	}
	var outboxAt, platformAt time.Time
	if err := worker.pool.QueryRow(ctx, `SELECT COALESCE(max(created_at),'epoch') FROM openresty_security_publication_outbox
		WHERE scope_type='global'`).Scan(&outboxAt); err != nil {
		return fmt.Errorf("read global CC config watermark: %w", err)
	}
	// fix-fwregion: the platform's global, region and node configs (防火墙配置)
	// are every tenant's auto switch layers; so is a platform node joining,
	// leaving or changing region.
	if err := worker.pool.QueryRow(ctx, `SELECT GREATEST(
		  (SELECT COALESCE(max(outbox.created_at),'epoch') FROM openresty_security_publication_outbox outbox
		    JOIN access_scopes scope ON scope.id=outbox.tenant_scope_id AND scope.kind='platform'),
		  (SELECT COALESCE(max(node.updated_at),'epoch') FROM nodes node
		    JOIN access_scopes scope ON scope.id=node.scope_id AND scope.kind='platform'))`).Scan(&platformAt); err != nil {
		return fmt.Errorf("read platform auto switch layers watermark: %w", err)
	}
	all := !worker.swept || catalogAt.After(worker.catalogSeen) || platformAt.After(worker.platformSeen)
	scopes, err := worker.changedScopes(ctx, all)
	if err != nil {
		return err
	}
	pending := map[uuid.UUID]struct{}{}
	for _, scopeID := range scopes {
		pending[scopeID] = struct{}{}
	}
	for scopeID := range worker.retry {
		if _, listed := pending[scopeID]; !listed {
			scopes = append(scopes, scopeID)
		}
	}
	retry := map[uuid.UUID]struct{}{}
	for _, scopeID := range scopes {
		if err := worker.reconcileScope(ctx, scopeID); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			retry[scopeID] = struct{}{}
			worker.logger.Warn("CC settings inheritance failed for scope", "scope_id", scopeID, "error", err)
		}
	}
	worker.retry = retry
	worker.swept, worker.catalogSeen, worker.outboxSeen, worker.platformSeen = true, catalogAt, outboxAt, platformAt
	return nil
}

func (worker *Worker) changedScopes(ctx context.Context, all bool) ([]uuid.UUID, error) {
	query := `SELECT DISTINCT policy.scope_id FROM security_policies policy
		WHERE policy.kind='cc' AND policy.deleted_at IS NULL AND (
		  policy.cc_settings->'ban_seconds'->>'mode'='system' OR policy.cc_settings->'pass_seconds'->>'mode'='system' OR
		  policy.cc_settings->'auto_switch'->>'mode'='system')`
	args := []any{}
	if !all {
		query += ` AND EXISTS (SELECT 1 FROM openresty_security_publication_outbox outbox
			WHERE outbox.tenant_scope_id=policy.scope_id AND outbox.scope_type='global' AND outbox.created_at>$1)`
		args = append(args, worker.outboxSeen)
	}
	rows, err := worker.pool.Query(ctx, query+` ORDER BY policy.scope_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("list scopes following the global CC config: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

type inheritingPolicy struct {
	id       uuid.UUID
	ownerID  uuid.UUID
	revision int64
}

func (worker *Worker) reconcileScope(ctx context.Context, scopeID uuid.UUID) error {
	rows, err := worker.pool.Query(ctx, `SELECT id,owner_user_id,revision FROM security_policies
		WHERE scope_id=$1 AND kind='cc' AND deleted_at IS NULL AND (
		  cc_settings->'ban_seconds'->>'mode'='system' OR cc_settings->'pass_seconds'->>'mode'='system' OR
		  cc_settings->'auto_switch'->>'mode'='system') ORDER BY id`, scopeID)
	if err != nil {
		return err
	}
	policies, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (inheritingPolicy, error) {
		var value inheritingPolicy
		return value, row.Scan(&value.id, &value.ownerID, &value.revision)
	})
	if err != nil || len(policies) == 0 {
		return err
	}
	defaults, err := worker.store.CCSystemDefaults(ctx, scopeID)
	if err != nil {
		return err
	}
	var catalog []rulecatalog.Item
	if securitypolicy.AutoSwitchNeedsCatalog(defaults) {
		if catalog, err = worker.store.SystemCatalog(ctx); err != nil {
			return err
		}
	}
	var failure error
	for _, item := range policies {
		if err := worker.reconcilePolicy(ctx, scopeID, item, defaults, catalog); err != nil {
			failure = errors.Join(failure, fmt.Errorf("policy %s: %w", item.id, err))
		}
	}
	return failure
}

func (worker *Worker) reconcilePolicy(ctx context.Context, scopeID uuid.UUID, item inheritingPolicy,
	defaults securitypolicy.CCSystemDefaults, catalog []rulecatalog.Item) error {
	owner := securitypolicy.Actor{UserID: item.ownerID, ScopeID: scopeID, ScopeKind: "tenant"}
	current, err := worker.policies.Get(ctx, owner, item.id)
	if err != nil {
		return err
	}
	resolved := cloneSettings(current.CCSettings)
	securitypolicy.ResolveCCSettings(resolved, defaults, catalog)
	canonical, err := securitypolicy.CanonicalCCSettings(current.ID, resolved)
	if err != nil {
		return fmt.Errorf("re-resolved settings are invalid: %w", err)
	}
	stored, err := securitypolicy.CanonicalCCSettings(current.ID, current.CCSettings)
	if err != nil {
		return fmt.Errorf("stored settings are invalid: %w", err)
	}
	if reflect.DeepEqual(canonical, stored) {
		return nil
	}
	key := fmt.Sprintf("cc-inherit.%s.%d", current.ID, current.Revision)
	written, err := worker.policies.Update(ctx, owner, securitypolicy.UpdateRequest{ID: current.ID,
		ExpectedRevision: current.Revision, IdempotencyKey: key, RequestID: uuid.NewSHA1(current.ID, []byte(key)).String(),
		Fields: securitypolicy.PolicyFields{Kind: current.Kind, Name: current.Name, Description: current.Description,
			Enabled: current.Enabled, DefaultAction: current.DefaultAction, Rules: current.Rules, CCSettings: resolved}})
	if err != nil {
		return fmt.Errorf("write re-resolved settings: %w", err)
	}
	worker.logger.Info("CC policy settings follow the global CC config", "scope_id", scopeID,
		"policy_id", current.ID, "revision", written.Policy.Revision)
	return worker.reactivate(ctx, scopeID, current.ID, current.Revision, written.Policy.Revision)
}

type activeBinding struct {
	siteID          uuid.UUID
	bindingRevision int64
	lastBundleID    uuid.UUID
	actor           securitypolicy.Actor
}

// reactivate starts an activation of revision on every site whose active
// revision was previous (a site pinned to an older revision, or with an
// activation in flight, keeps it: activating would publish more than the
// inherited settings).
func (worker *Worker) reactivate(ctx context.Context, scopeID, policyID uuid.UUID, previous, revision int64) error {
	rows, err := worker.pool.Query(ctx, `SELECT binding.site_id,binding.revision,binding.last_bundle_id,
		publication.actor_user_id,publication.actor_scope_id,actor_scope.kind
		FROM security_policy_site_bindings binding
		JOIN security_policy_publications publication
		  ON publication.tenant_scope_id=binding.tenant_scope_id AND publication.id=binding.last_bundle_id
		JOIN access_scopes actor_scope ON actor_scope.id=publication.actor_scope_id
		WHERE binding.tenant_scope_id=$1 AND binding.policy_id=$2 AND binding.active_policy_version=$3
		  AND binding.last_bundle_id IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM security_policy_activation_candidates open
		    WHERE open.tenant_scope_id=binding.tenant_scope_id AND open.binding_id=binding.id
		      AND open.candidate_status IN ('claimed','canary','expanding','healthy'))
		ORDER BY binding.site_id`, scopeID, policyID, previous)
	if err != nil {
		return err
	}
	bindings, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (activeBinding, error) {
		var value activeBinding
		return value, row.Scan(&value.siteID, &value.bindingRevision, &value.lastBundleID,
			&value.actor.UserID, &value.actor.ScopeID, &value.actor.ScopeKind)
	})
	if err != nil {
		return err
	}
	var failure error
	for _, binding := range bindings {
		nodes, err := worker.publicationNodes(ctx, scopeID, binding.lastBundleID)
		if err != nil || len(nodes) == 0 {
			failure = errors.Join(failure, fmt.Errorf("site %s targets: %v", binding.siteID, err))
			continue
		}
		key := fmt.Sprintf("cc-inherit.%s.%s.%d", policyID, binding.siteID, revision)
		_, err = worker.activations.Start(ctx, binding.actor, securityactivation.StartInput{
			TenantScopeID: scopeID, SiteID: binding.siteID, PolicyID: policyID, PolicyVersion: revision,
			ExpectedBindingRevision: binding.bindingRevision, ExpectedActivePolicyVersion: previous,
			TargetNodeIDs: nodes, CanarySize: 1, IdempotencyKey: key,
			RequestID: uuid.NewSHA1(policyID, []byte(key)).String(), ExpiresAt: worker.now().Add(10 * time.Minute),
		})
		var refusal *edgepublish.TargetCapabilityError
		switch {
		case err == nil:
		case errors.As(err, &refusal):
			// Recorded as a capability wait; published once the nodes upgrade.
			worker.logger.Info("CC inherited settings wait for node capability", "site_id", binding.siteID, "error", err)
		default:
			failure = errors.Join(failure, fmt.Errorf("activate site %s: %w", binding.siteID, err))
		}
	}
	return failure
}

func (worker *Worker) publicationNodes(ctx context.Context, scopeID, publicationID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := worker.pool.Query(ctx, `SELECT node_id FROM security_policy_publication_targets
		WHERE tenant_scope_id=$1 AND publication_id=$2 ORDER BY node_id`, scopeID, publicationID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func cloneSettings(settings *securitypolicy.CCSettings) *securitypolicy.CCSettings {
	if settings == nil {
		return nil
	}
	value := *settings
	if settings.BanSeconds != nil {
		ban := *settings.BanSeconds
		value.BanSeconds = &ban
	}
	if settings.PassSeconds != nil {
		pass := *settings.PassSeconds
		value.PassSeconds = &pass
	}
	if settings.AutoSwitch != nil {
		auto := *settings.AutoSwitch
		auto.RuleGroups = append([]string{}, settings.AutoSwitch.RuleGroups...)
		auto.Rules = append([]securitypolicy.Rule{}, settings.AutoSwitch.Rules...)
		auto.Overrides = append([]securitypolicy.CCAutoSwitchOverride(nil), settings.AutoSwitch.Overrides...)
		auto.RuleSets = append([]securitypolicy.CCAutoSwitchRuleSet(nil), settings.AutoSwitch.RuleSets...)
		value.AutoSwitch = &auto
	}
	return &value
}
