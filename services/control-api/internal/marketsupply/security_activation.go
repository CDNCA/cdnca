package marketsupply

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A leaf site's access list and rate limit become one local ACL and one CC
// policy of its tenant, named after the site. Commit only writes the policy:
// it takes effect through a per-node activation, which can start only once
// the nodes run the tenant's configuration that carries the site. The
// reconciler starts it then, woken by a node configuration becoming current
// and by a periodic tick; a policy still not active after
// securityActivationWait is reported failed.
const (
	securityActivationWait = 30 * time.Minute
	securityReconcileEvery = time.Minute
	// securityStartBucket groups Start calls so concurrent reconcilers send
	// the same idempotency key and replay one candidate.
	securityStartBucket = 5 * time.Minute
)

// SecurityPolicies is the subset of securitypolicy.Service the leaf drives.
type SecurityPolicies interface {
	Create(ctx context.Context, actor securitypolicy.Actor, request securitypolicy.CreateRequest) (securitypolicy.WriteResult, error)
	Update(ctx context.Context, actor securitypolicy.Actor, request securitypolicy.UpdateRequest) (securitypolicy.WriteResult, error)
	Get(ctx context.Context, actor securitypolicy.Actor, id uuid.UUID) (securitypolicy.Policy, error)
	SetQuickBlock(ctx context.Context, actor securitypolicy.Actor, request securitypolicy.QuickBlockRequest) (securitypolicy.WriteResult, error)
}

// SecurityActivations is the subset of securityactivation.Store the leaf drives.
type SecurityActivations interface {
	Start(ctx context.Context, actor securitypolicy.Actor, input securityactivation.StartInput) (securityactivation.StartResult, error)
	Status(ctx context.Context, actor securitypolicy.Actor, siteID uuid.UUID, policyKind string) (securityactivation.StatusResult, error)
}

// WithSecurity lets market sites carry access lists and rate limits; without
// it those blocks are refused with unsupported_access / unsupported_rate_limit.
func (s *Service) WithSecurity(policies SecurityPolicies, activations SecurityActivations) *Service {
	s.policies, s.activations = policies, activations
	return s
}

func leafPolicyName(kind string, siteID uuid.UUID) string {
	return "market " + kind + " " + siteID.String()
}

func tenantActor(tenant tenantRef) securitypolicy.Actor {
	return securitypolicy.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
}

// applySecurity writes the site's ACL and CC policies as the tenant owner. A
// block the subscriber does not send is not managed; an unchanged block
// writes nothing, so a retried commit adds no revision.
func (s *Service) applySecurity(ctx context.Context, tenant tenantRef, leafSiteID uuid.UUID, req siteconf.CommitRequest) error {
	var wanted []securitypolicy.PolicyFields
	if access, err := req.Config.DecodeAccess(); err != nil {
		return err
	} else if access != nil {
		fields, unsupported, err := accessFields(access)
		if err != nil || unsupported != "" {
			return errors.Join(siteconf.ErrInvalid, err)
		}
		wanted = append(wanted, fields)
	}
	if limit, err := req.Config.DecodeRateLimit(); err != nil {
		return err
	} else if limit != nil {
		fields, err := rateLimitFields(limit)
		if err != nil {
			return err
		}
		wanted = append(wanted, fields)
	}
	if cc, err := decodeSiteCC(req.Config); err != nil {
		return errors.Join(siteconf.ErrInvalid, err)
	} else if cc != nil {
		fields, err := ccFields(cc)
		if err != nil {
			return errors.Join(siteconf.ErrInvalid, err)
		}
		wanted = append(wanted, fields)
	}
	var quickBlock *securitypolicy.QuickBlock
	if waf, err := decodeSiteWAF(req.Config); err != nil {
		return err
	} else if waf != nil {
		fields, err := wafFields(waf)
		if err != nil {
			return errors.Join(siteconf.ErrInvalid, err)
		}
		key := "market-sec-" + req.SiteID.String() + "-waf"
		mapped, err := s.applyIPLists(ctx, tenant, waf, key)
		if err != nil {
			return err
		}
		if err := s.applyCRSApps(ctx, tenant, leafSiteID, waf, key); err != nil {
			return err
		}
		wanted, quickBlock = append(wanted, withLeafIPLists(fields, mapped)), waf.QuickBlock
	}
	if len(wanted) == 0 {
		return nil
	}
	if s.policies == nil {
		return errors.New("market supply: security policies are not configured")
	}
	actor := tenantActor(tenant)
	for _, fields := range wanted {
		fields.Name = leafPolicyName(fields.Kind, leafSiteID)
		id, err := s.leafPolicyID(ctx, tenant, fields.Name, fields.Kind)
		if err != nil {
			return err
		}
		key := "market-sec-" + req.SiteID.String() + "-" + fields.Kind
		if id == uuid.Nil {
			created, err := s.policies.Create(ctx, actor, securitypolicy.CreateRequest{TargetScopeID: tenant.scopeID,
				OwnerUserID: tenant.userID, Fields: fields, IdempotencyKey: key + "-create", RequestID: key})
			if err != nil {
				return err
			}
			if fields.Kind == securitypolicy.KindWAF {
				if err := s.applyQuickBlock(ctx, actor, created.Policy, quickBlock, key); err != nil {
					return err
				}
			}
			continue
		}
		current, err := s.policies.Get(ctx, actor, id)
		if err != nil {
			return err
		}
		if !samePolicyFields(current, fields) {
			updated, err := s.policies.Update(ctx, actor, securitypolicy.UpdateRequest{ID: id,
				ExpectedRevision: current.Revision, Fields: fields,
				IdempotencyKey: key + "-r" + itoa(current.Revision), RequestID: key})
			if err != nil {
				return err
			}
			current = updated.Policy
		}
		if fields.Kind == securitypolicy.KindWAF {
			if err := s.applyQuickBlock(ctx, actor, current, quickBlock, key); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyQuickBlock sets the WAF policy's quick block switches (the store
// expands them into its system-managed rules) when they differ.
func (s *Service) applyQuickBlock(ctx context.Context, actor securitypolicy.Actor, current securitypolicy.Policy,
	block *securitypolicy.QuickBlock, key string) error {
	wanted := securitypolicy.QuickBlock{}
	if block != nil {
		wanted = *block
	}
	if err := securitypolicy.NormalizeQuickBlock(&wanted); err != nil {
		return err
	}
	stored := securitypolicy.QuickBlock{}
	if current.QuickBlock != nil {
		stored = *current.QuickBlock
	}
	if sameJSON(stored, wanted) || current.QuickBlock == nil && !wanted.Active() {
		return nil
	}
	_, err := s.policies.SetQuickBlock(ctx, actor, securitypolicy.QuickBlockRequest{ID: current.ID,
		ExpectedRevision: current.Revision, QuickBlock: wanted,
		IdempotencyKey: key + "-qb-r" + itoa(current.Revision), RequestID: key})
	return err
}

func (s *Service) leafPolicyID(ctx context.Context, tenant tenantRef, name, kind string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `SELECT id FROM security_policies
		WHERE scope_id=$1 AND name=$2 AND kind=$3 AND deleted_at IS NULL`, tenant.scopeID, name, kind).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// samePolicyFields compares what the subscriber controls; rule IDs are
// assigned by the store and never sent.
func samePolicyFields(current securitypolicy.Policy, fields securitypolicy.PolicyFields) bool {
	// Quick block rules are the store's (applyQuickBlock), never sent.
	rules := slices.DeleteFunc(slices.Clone(current.Rules), func(rule securitypolicy.Rule) bool {
		return securitypolicy.IsQuickBlockRuleID(rule.ID)
	})
	for index := range rules {
		rules[index].ID = uuid.Nil
	}
	// Auto switch rule IDs are derived by the store from the policy ID.
	var settings *securitypolicy.CCSettings
	if current.CCSettings != nil {
		value := *current.CCSettings
		if value.AutoSwitch != nil {
			autoSwitch := *value.AutoSwitch
			autoSwitch.Rules = slices.Clone(autoSwitch.Rules)
			for index := range autoSwitch.Rules {
				autoSwitch.Rules[index].ID = uuid.Nil
			}
			value.AutoSwitch = &autoSwitch
		}
		settings = &value
	}
	return sameJSON(securitypolicy.PolicyFields{Kind: current.Kind, Name: current.Name, Description: current.Description,
		Enabled: current.Enabled, DefaultAction: current.DefaultAction, Rules: rules, CCSettings: settings,
		WAFSettings: current.WAFSettings}, fields)
}

// leafPolicy is one leaf site's ACL, CC or WAF policy as the reconciler sees it.
type leafPolicy struct {
	tenant        tenantRef
	siteID        uuid.UUID
	kind          string
	id            uuid.UUID
	version       int64
	updatedAt     time.Time
	deliveryNodes []uuid.UUID
	currentNodes  []uuid.UUID
}

// SecurityState reports one leaf policy's activation in OpStatus.
type SecurityState struct {
	Kind    string `json:"kind"`
	Version int64  `json:"version"`
	State   string `json:"state"` // active, activating, waiting_nodes, failed
	Reason  string `json:"reason,omitempty"`
}

const (
	securityActive       = "active"
	securityActivating   = "activating"
	securityWaitingNodes = "waiting_nodes"
	securityFailed       = "failed"
)

// loadLeafPolicies lists leaf policies, of one tenant scope or of all market
// tenants, with the nodes they must reach: the tenant's delivery nodes and
// those of them already running a current configuration of the tenant.
func (s *Service) loadLeafPolicies(ctx context.Context, scopeID *uuid.UUID, siteID *uuid.UUID) ([]leafPolicy, error) {
	rows, err := s.pool.Query(ctx, `SELECT policy.scope_id, account.id, policy.id, policy.kind, policy.name,
			policy.revision, policy.updated_at,
			COALESCE((SELECT fact.node_ids FROM edge_automatic_publication_policy_facts fact
			  WHERE fact.target_scope_id=policy.scope_id AND fact.mode='automatic'
			  ORDER BY fact.revision DESC LIMIT 1), '{}'),
			COALESCE((SELECT array_agg(state.node_id ORDER BY state.node_id) FROM node_config_state state
			  JOIN nodes node ON node.id=state.node_id AND node.admin_state='active'
			  WHERE state.configuration_scope_id=policy.scope_id AND state.current_config_version_id IS NOT NULL
			    AND NOT state.reconciliation_required), '{}')
		FROM security_policies policy
		JOIN memberships membership ON membership.scope_id=policy.scope_id
		JOIN users account ON account.id=membership.user_id AND account.username LIKE $3
		WHERE policy.deleted_at IS NULL AND policy.kind IN ('acl','cc','waf') AND policy.name LIKE 'market % %'
		  AND ($1::uuid IS NULL OR policy.scope_id=$1)
		  AND ($2::uuid IS NULL OR policy.name LIKE '% ' || $2::text)
		ORDER BY policy.scope_id, policy.name`, scopeID, siteID, tenantPrefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []leafPolicy
	for rows.Next() {
		var p leafPolicy
		var name string
		if err := rows.Scan(&p.tenant.scopeID, &p.tenant.userID, &p.id, &p.kind, &name, &p.version, &p.updatedAt,
			&p.deliveryNodes, &p.currentNodes); err != nil {
			return nil, err
		}
		parts := strings.Fields(name)
		site, err := uuid.Parse(parts[len(parts)-1])
		if err != nil || len(parts) != 3 || parts[1] != p.kind {
			continue
		}
		p.siteID = site
		out = append(out, p)
	}
	return out, rows.Err()
}

// targets are the delivery nodes now running the tenant's configuration, or
// nil while any of them still lacks it.
func (p leafPolicy) targets() []uuid.UUID {
	if len(p.deliveryNodes) == 0 {
		return nil
	}
	for _, node := range p.deliveryNodes {
		if !slices.Contains(p.currentNodes, node) {
			return nil
		}
	}
	return p.deliveryNodes
}

// state derives a policy's activation state from its binding and latest
// candidate; nothing about it is stored by the leaf.
func (p leafPolicy) state(status securityactivation.StatusResult, now time.Time) SecurityState {
	out := SecurityState{Kind: p.kind, Version: p.version}
	if status.Binding != nil && status.Binding.ActivePolicyVersion == p.version {
		out.State = securityActive
		return out
	}
	if candidate := status.LatestCandidate; candidate != nil && candidate.LastClaimedPolicyVersion == p.version {
		switch candidate.Status {
		case securityactivation.StatusFailed, securityactivation.StatusCancelled, securityactivation.StatusExpired:
			out.State, out.Reason = securityFailed, "activation_"+string(candidate.Status)
		default:
			out.State = securityActivating
		}
		return out
	}
	if now.Sub(p.updatedAt) > securityActivationWait {
		out.State, out.Reason = securityFailed, "nodes_not_current"
		if len(p.deliveryNodes) == 0 {
			out.Reason = "no_delivery_nodes"
		}
		return out
	}
	out.State = securityWaitingNodes
	return out
}

// ReconcileSecurity starts the activation of every leaf policy, of one
// tenant scope or of all, whose nodes now run the tenant's configuration.
// Start is idempotent per policy version and time bucket, so a reconciler
// racing another, or retrying, replays the same candidate.
func (s *Service) ReconcileSecurity(ctx context.Context, scopeID *uuid.UUID) (started int, err error) {
	if s.activations == nil {
		return 0, nil
	}
	policies, err := s.loadLeafPolicies(ctx, scopeID, nil)
	if err != nil {
		return 0, err
	}
	now := s.now().UTC()
	var errs []error
	for _, p := range policies {
		actor := tenantActor(p.tenant)
		status, err := s.activations.Status(ctx, actor, p.siteID, p.kind)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var activeVersion, bindingRevision int64
		if status.Binding != nil {
			activeVersion, bindingRevision = status.Binding.ActivePolicyVersion, status.Binding.BindingRevision
		}
		if p.state(status, now).State != securityWaitingNodes {
			continue
		}
		targets := p.targets()
		if targets == nil {
			continue
		}
		bucket := now.Truncate(securityStartBucket)
		expiresAt := bucket.Add(15 * time.Minute)
		if deadline := p.updatedAt.Add(securityActivationWait); expiresAt.After(deadline) {
			expiresAt = deadline
		}
		if !expiresAt.After(now.Add(time.Minute)) {
			continue
		}
		key := "market-activate-" + p.id.String() + "-v" + itoa(p.version) + "-" + itoa(bucket.Unix())
		if _, err := s.activations.Start(ctx, actor, securityactivation.StartInput{
			TenantScopeID: p.tenant.scopeID, SiteID: p.siteID, PolicyID: p.id, PolicyVersion: p.version,
			ExpectedBindingRevision: bindingRevision, ExpectedActivePolicyVersion: activeVersion,
			TargetNodeIDs: targets, CanarySize: 1, IdempotencyKey: key, RequestID: key,
			CorrelationID: p.id.String(), ExpiresAt: expiresAt,
		}); err != nil {
			errs = append(errs, err)
			continue
		}
		started++
	}
	return started, errors.Join(errs...)
}

// securityStatus reports the site's leaf policies for OpStatus.
func (s *Service) securityStatus(ctx context.Context, tenant tenantRef, siteID uuid.UUID) ([]SecurityState, error) {
	if s.activations == nil {
		return nil, nil
	}
	policies, err := s.loadLeafPolicies(ctx, &tenant.scopeID, &siteID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	out := make([]SecurityState, 0, len(policies))
	for _, p := range policies {
		if p.siteID != siteID {
			continue
		}
		status, err := s.activations.Status(ctx, tenantActor(p.tenant), siteID, p.kind)
		if err != nil {
			return nil, err
		}
		out = append(out, p.state(status, now))
	}
	return out, nil
}

// RunSecurityReconciler reconciles on every node configuration that becomes
// current (channel, see edgestatus.NodeConfigCurrentChannel) and once per
// securityReconcileEvery, until ctx ends. A notification only wakes the loop;
// the tick covers one that was missed.
func (s *Service) RunSecurityReconciler(ctx context.Context, channel string, logf func(string, ...any)) error {
	wake := make(chan struct{}, 1)
	go s.listenNodeConfig(ctx, channel, wake, logf)
	ticker := time.NewTicker(securityReconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-wake:
		}
		if _, err := s.ReconcileSecurity(ctx, nil); err != nil && ctx.Err() == nil {
			logf("market security reconcile failed", "err", err)
		}
	}
}

func (s *Service) listenNodeConfig(ctx context.Context, channel string, wake chan<- struct{}, logf func(string, ...any)) {
	for ctx.Err() == nil {
		conn, err := s.pool.Acquire(ctx)
		if err == nil {
			_, err = conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize())
			for err == nil {
				if _, err = conn.Conn().WaitForNotification(ctx); err == nil {
					select {
					case wake <- struct{}{}:
					default: // a reconcile is already queued
					}
				}
			}
			conn.Release()
		}
		if ctx.Err() != nil {
			return
		}
		logf("market security listener reconnecting", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func itoa(value int64) string { return strconv.FormatInt(value, 10) }

func sameJSON(a, b any) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	return errLeft == nil && errRight == nil && string(left) == string(right)
}
