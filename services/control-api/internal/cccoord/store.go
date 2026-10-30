package cccoord

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitycoordmetrics"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	clock   func() time.Time
	config  Config
	metrics *securitycoordmetrics.Registry
}

func NewStore(pool *pgxpool.Pool, clock func() time.Time, config Config) (*Store, error) {
	return NewStoreWithMetrics(pool, clock, config, nil)
}

func NewStoreWithMetrics(pool *pgxpool.Pool, clock func() time.Time, config Config,
	metrics *securitycoordmetrics.Registry,
) (*Store, error) {
	if pool == nil || clock == nil || config.validate() != nil {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, clock: clock, config: config, metrics: metrics}, nil
}

func (store *Store) Observe(ctx context.Context, envelope Envelope) (ObserveResult, error) {
	if store == nil || store.pool == nil || ctx == nil || envelope.SchemaVersion != 1 ||
		envelope.Type != "security.cccoord.v1" || !identityPattern.MatchString(envelope.MessageID) ||
		envelope.ProducedAt.IsZero() || envelope.TenantScopeID == uuid.Nil || envelope.SiteID == uuid.Nil ||
		envelope.NodeID == uuid.Nil || envelope.ConfigVersionID == uuid.Nil || len(envelope.Events) == 0 {
		return ObserveResult{}, ErrInvalidInput
	}
	var result ObserveResult
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		settings, err := loadSettings(ctx, tx, envelope.TenantScopeID, envelope.SiteID)
		if err != nil {
			return err
		}
		if len(envelope.Events) > settings.MaxFactsPerMessage || !containsNode(settings.TargetNodeIDs, envelope.NodeID) {
			return ErrScopeMismatch
		}
		activeVersion, err := loadActivePolicyVersion(ctx, tx, settings)
		if err != nil {
			return err
		}
		now := store.clock().UTC().Truncate(time.Microsecond)
		for _, raw := range envelope.Events {
			fact := raw
			if fact.MessageID == "" {
				fact.MessageID = envelope.MessageID
			}
			fact.TenantScopeID, fact.SiteID, fact.NodeID = envelope.TenantScopeID, envelope.SiteID, envelope.NodeID
			fact.ConfigVersionID = envelope.ConfigVersionID
			fact, err = normalizeFact(fact)
			if err != nil || fact.MessageID != envelope.MessageID || fact.OccurredAt.After(envelope.ProducedAt.Add(time.Minute)) ||
				fact.OccurredAt.Before(envelope.ProducedAt.Add(-store.config.FactTTL)) {
				return ErrInvalidInput
			}
			inserted, factID, err := insertFact(ctx, tx, settings, fact, now)
			if err != nil {
				return err
			}
			if !inserted {
				result.Duplicates++
				continue
			}
			result.Accepted++
			if !automaticEligible(fact.RequestClass) {
				continue
			}
			queued, rejected, err := store.observeStandardFact(ctx, tx, settings, fact, factID, activeVersion, now)
			if err != nil {
				return err
			}
			if queued {
				result.Queued++
			}
			if rejected {
				result.Rejected++
			}
		}
		return nil
	})
	return result, err
}

func loadSettings(ctx context.Context, tx pgx.Tx, tenantScopeID, siteID uuid.UUID) (Settings, error) {
	var settings Settings
	err := tx.QueryRow(ctx, `SELECT id,tenant_scope_id,site_id,source_cc_policy_id,source_cc_policy_version,
		actor_scope_id,actor_user_id,revision,hit_threshold,node_threshold,window_seconds,block_seconds,
		release_hold_seconds,fact_ttl_seconds,max_facts_per_message,max_active_states,max_claims,max_attempts,enabled
		FROM cc_coordination_settings WHERE tenant_scope_id=$1 AND site_id=$2 AND enabled
		ORDER BY revision DESC LIMIT 1 FOR SHARE`, tenantScopeID, siteID).Scan(
		&settings.ID, &settings.TenantScopeID, &settings.SiteID, &settings.SourceCCPolicyID,
		&settings.SourcePolicyVersion, &settings.ActorScopeID, &settings.ActorUserID, &settings.Revision,
		&settings.HitThreshold, &settings.NodeThreshold, &settings.WindowSeconds, &settings.BlockSeconds,
		&settings.ReleaseHoldSecond, &settings.FactTTLSeconds, &settings.MaxFactsPerMessage,
		&settings.MaxActiveStates, &settings.MaxClaims, &settings.MaxAttempts, &settings.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, ErrScopeMismatch
	}
	if err != nil {
		return Settings{}, fmt.Errorf("load CC coordination settings: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT node_id FROM cc_coordination_setting_targets
		WHERE tenant_scope_id=$1 AND settings_id=$2 AND settings_revision=$3 ORDER BY node_id`,
		settings.TenantScopeID, settings.ID, settings.Revision)
	if err != nil {
		return Settings{}, fmt.Errorf("load CC coordination targets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return Settings{}, err
		}
		settings.TargetNodeIDs = append(settings.TargetNodeIDs, nodeID)
	}
	if err := rows.Err(); err != nil {
		return Settings{}, err
	}
	if _, err := normalizeSettings(settings); err != nil {
		return Settings{}, ErrScopeMismatch
	}
	return settings, nil
}

func loadActivePolicyVersion(ctx context.Context, tx pgx.Tx, settings Settings) (int64, error) {
	var version int64
	err := tx.QueryRow(ctx, `SELECT COALESCE(active_policy_version,0)
		FROM security_policy_site_bindings
		WHERE tenant_scope_id=$1 AND site_id=$2 AND policy_id=$3 AND policy_kind='cc' FOR SHARE`,
		settings.TenantScopeID, settings.SiteID, settings.SourceCCPolicyID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) || version < settings.SourcePolicyVersion {
		return 0, ErrScopeMismatch
	}
	if err != nil {
		return 0, fmt.Errorf("load active CC policy binding: %w", err)
	}
	return version, nil
}

func insertFact(ctx context.Context, tx pgx.Tx, settings Settings, fact Fact, now time.Time) (bool, uuid.UUID, error) {
	factID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(settings.TenantScopeID.String()+"\x00"+fact.EventID))
	var inserted uuid.UUID
	err := tx.QueryRow(ctx, `INSERT INTO cc_coordination_facts(
		id,tenant_scope_id,settings_id,settings_revision,site_id,node_id,message_id,event_id,
		config_version_id,rule_id,host,path,method,listen_port,protocol,request_class,client_cidr,
		action,status_code,occurred_at,expires_at,received_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
		ON CONFLICT (tenant_scope_id,event_id) DO NOTHING RETURNING id`,
		factID, settings.TenantScopeID, settings.ID, settings.Revision, settings.SiteID, fact.NodeID,
		fact.MessageID, fact.EventID, fact.ConfigVersionID, fact.RuleID, fact.Host, fact.Path, fact.Method,
		fact.ListenerPort, fact.Protocol, fact.RequestClass, fact.ClientCIDR, fact.Action, fact.StatusCode,
		fact.OccurredAt, fact.OccurredAt.Add(time.Duration(settings.FactTTLSeconds)*time.Second), now).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, factID, nil
	}
	if err != nil {
		return false, uuid.Nil, fmt.Errorf("insert CC coordination fact: %w", err)
	}
	return true, inserted, nil
}

func (store *Store) observeStandardFact(
	ctx context.Context,
	tx pgx.Tx,
	settings Settings,
	fact Fact,
	factID uuid.UUID,
	activeVersion int64,
	now time.Time,
) (bool, bool, error) {
	digest := aggregateDigest(settings.SourceCCPolicyID, fact)
	windowStart := fact.OccurredAt.Add(-time.Duration(settings.WindowSeconds) * time.Second)
	var hits int64
	var nodes int
	if err := tx.QueryRow(ctx, `SELECT count(*),count(DISTINCT node_id) FROM cc_coordination_facts
		WHERE tenant_scope_id=$1 AND site_id=$2 AND rule_id=$3 AND host=$4 AND path=$5 AND method=$6
		  AND listen_port=$7 AND protocol=$8 AND request_class='standard' AND client_cidr=$9
		  AND occurred_at>=$10 AND occurred_at<=$11 AND expires_at>$12`,
		settings.TenantScopeID, settings.SiteID, fact.RuleID, fact.Host, fact.Path, fact.Method,
		fact.ListenerPort, fact.Protocol, fact.ClientCIDR, windowStart, fact.OccurredAt, now).Scan(&hits, &nodes); err != nil {
		return false, false, fmt.Errorf("aggregate CC coordination facts: %w", err)
	}
	if hits < int64(settings.HitThreshold) || nodes < int(settings.NodeThreshold) {
		return false, false, nil
	}

	state, found, err := loadState(ctx, tx, settings.TenantScopeID, settings.SiteID, digest)
	if err != nil {
		return false, false, err
	}
	if found && state.State != StateReleased && state.State != StateFailed && state.ExpiresAt.After(now) {
		_, err = tx.Exec(ctx, `UPDATE cc_coordination_states SET hit_count=GREATEST(hit_count,$2),
			node_count=GREATEST(node_count,$3),last_fact_id=$4,updated_at=$5 WHERE id=$1`,
			state.ID, hits, nodes, factID, now)
		return false, false, err
	}
	if found && state.ReleaseHoldTill.After(now) {
		return false, false, nil
	}
	var activeStates int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM cc_coordination_states
		WHERE tenant_scope_id=$1 AND site_id=$2 AND expires_at>$3 AND state NOT IN ('released','failed')`,
		settings.TenantScopeID, settings.SiteID, now).Scan(&activeStates); err != nil {
		return false, false, err
	}
	if activeStates >= settings.MaxActiveStates {
		return false, true, nil
	}

	generation := int64(1)
	stateID := uuid.NewSHA1(uuid.NameSpaceOID, append([]byte("cccoord-state\x00"), digest[:]...))
	if found {
		generation = state.Generation + 1
		stateID = state.ID
	}
	action := Action{
		ID:            uuid.NewSHA1(stateID, []byte("block\x00"+strconv.FormatInt(generation, 10))),
		TenantScopeID: settings.TenantScopeID, SiteID: settings.SiteID, StateID: stateID,
		SourcePolicyID: settings.SourceCCPolicyID, RuleID: fact.RuleID, ClientCIDR: fact.ClientCIDR,
		Host: fact.Host, Path: fact.Path, Method: fact.Method, ListenerPort: fact.ListenerPort,
		Protocol: fact.Protocol, RequestClass: fact.RequestClass, Operation: ActionBlock,
		ReasonCode: ReasonThresholdReached, Generation: generation, ExpectedVersion: activeVersion,
		TargetNodeIDs: settings.TargetNodeIDs,
		ExpiresAt:     now.Add(time.Duration(settings.BlockSeconds) * time.Second),
		ActorScopeID:  settings.ActorScopeID, ActorUserID: settings.ActorUserID,
	}
	payload, decisionDigest, err := actionPayload(action)
	if err != nil {
		return false, false, err
	}
	if !found {
		_, err = tx.Exec(ctx, `INSERT INTO cc_coordination_states(
			id,tenant_scope_id,settings_id,settings_revision,site_id,source_cc_policy_id,aggregate_digest,
			rule_id,host,path,method,listen_port,protocol,request_class,client_cidr,generation,state,reason_code,
			hit_count,node_count,current_policy_version,lkg_policy_version,decision_digest,last_fact_id,
			window_started_at,expires_at,release_hold_until,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'standard',$14,$15,'block_pending',$16,
			$17,$18,$19,$19,$20,$21,$22,$23,$24,$25)`,
			stateID, settings.TenantScopeID, settings.ID, settings.Revision, settings.SiteID,
			settings.SourceCCPolicyID, digest[:], fact.RuleID, fact.Host, fact.Path, fact.Method,
			fact.ListenerPort, fact.Protocol, fact.ClientCIDR, generation, ReasonThresholdReached,
			hits, nodes, activeVersion, decisionDigest[:], factID, windowStart, action.ExpiresAt,
			now.Add(time.Duration(settings.ReleaseHoldSecond)*time.Second), now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE cc_coordination_states SET generation=$2,state='block_pending',
			reason_code=$3,hit_count=$4,node_count=$5,current_policy_version=$6,lkg_policy_version=$6,
			decision_digest=$7,last_fact_id=$8,window_started_at=$9,expires_at=$10,
			release_hold_until=$11,updated_at=$12 WHERE id=$1 AND generation=$13`,
			stateID, generation, ReasonThresholdReached, hits, nodes, activeVersion, decisionDigest[:], factID,
			windowStart, action.ExpiresAt, now.Add(time.Duration(settings.ReleaseHoldSecond)*time.Second), now,
			state.Generation)
	}
	if err != nil {
		return false, false, fmt.Errorf("persist CC coordination decision: %w", err)
	}
	if err := insertAction(ctx, tx, action, payload, decisionDigest, settings.MaxAttempts, now); err != nil {
		return false, false, err
	}
	return true, false, nil
}

func loadState(ctx context.Context, tx pgx.Tx, tenantScopeID, siteID uuid.UUID, digest [sha256.Size]byte) (State, bool, error) {
	var state State
	err := tx.QueryRow(ctx, `SELECT id,tenant_scope_id,site_id,source_cc_policy_id,rule_id,client_cidr::text,
		host,path,method,listen_port,protocol,request_class,generation,state,reason_code,hit_count,node_count,
		COALESCE(current_policy_version,0),COALESCE(lkg_policy_version,0),expires_at,release_hold_until,updated_at
		FROM cc_coordination_states WHERE tenant_scope_id=$1 AND site_id=$2 AND aggregate_digest=$3 FOR UPDATE`,
		tenantScopeID, siteID, digest[:]).Scan(&state.ID, &state.TenantScopeID, &state.SiteID,
		&state.SourcePolicyID, &state.RuleID, &state.ClientCIDR, &state.Host, &state.Path, &state.Method,
		&state.ListenerPort, &state.Protocol, &state.RequestClass, &state.Generation, &state.State,
		&state.ReasonCode, &state.HitCount, &state.NodeCount, &state.CurrentPolicyVersion,
		&state.LKGPolicyVersion, &state.ExpiresAt, &state.ReleaseHoldTill, &state.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, fmt.Errorf("load CC coordination state: %w", err)
	}
	return state, true, nil
}

func insertAction(ctx context.Context, tx pgx.Tx, action Action, payload []byte, digest [sha256.Size]byte, maxAttempts int, now time.Time) error {
	key := "cccoord." + hex.EncodeToString(digest[:])
	_, err := tx.Exec(ctx, `INSERT INTO cc_coordination_actions(
		id,tenant_scope_id,site_id,state_id,generation,sequence,operation,reason_code,idempotency_key,
		expected_active_policy_version,decision_payload,decision_digest,status,attempts,max_attempts,
		available_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,$11,'pending',0,$12,$13,$13,$13)
		ON CONFLICT (tenant_scope_id,idempotency_key) DO NOTHING`,
		action.ID, action.TenantScopeID, action.SiteID, action.StateID, action.Generation, action.Operation,
		action.ReasonCode, key, action.ExpectedVersion, payload, digest[:], maxAttempts, now)
	if err != nil {
		return fmt.Errorf("insert CC coordination action: %w", err)
	}
	return nil
}

func (store *Store) Claim(ctx context.Context, owner string, limit int) ([]Action, error) {
	if store == nil || store.pool == nil || ctx == nil || !identityPattern.MatchString(owner) || limit < 1 || limit > store.config.MaxClaims {
		return nil, ErrInvalidInput
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	claimed := make([]Action, 0, limit)
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE cc_coordination_actions SET status='retryable',lease_token=NULL,
			lease_owner=NULL,lease_expires_at=NULL,available_at=$1,updated_at=$1,result_reason_code='publish_retryable'
			WHERE status='claimed' AND lease_expires_at<=$1`, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT action.id FROM cc_coordination_actions action
			WHERE action.status IN ('pending','retryable') AND action.available_at<=$1 AND action.attempts<action.max_attempts
			  AND NOT EXISTS (SELECT 1 FROM cc_coordination_actions earlier
			      WHERE earlier.tenant_scope_id=action.tenant_scope_id AND earlier.site_id=action.site_id
			        AND earlier.sequence<action.sequence AND earlier.status NOT IN ('succeeded','exhausted','cancelled'))
			ORDER BY action.tenant_scope_id,action.available_at,action.sequence,action.id
			FOR UPDATE SKIP LOCKED LIMIT $2`, now, limit)
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			token := uuid.New()
			var action Action
			err := tx.QueryRow(ctx, `UPDATE cc_coordination_actions SET status='claimed',attempts=attempts+1,
				lease_token=$2,lease_owner=$3,lease_expires_at=$4,updated_at=$1,result_reason_code=NULL
				WHERE id=$5 RETURNING id,tenant_scope_id,site_id,state_id,generation,operation,reason_code,
				expected_active_policy_version,attempts,lease_token`,
				now, token, owner, now.Add(store.config.ClaimLease), id).Scan(&action.ID, &action.TenantScopeID,
				&action.SiteID, &action.StateID, &action.Generation, &action.Operation, &action.ReasonCode,
				&action.ExpectedVersion, &action.Attempts, &action.ClaimToken)
			if err != nil {
				return err
			}
			if err := loadActionAuthority(ctx, tx, &action); err != nil {
				return err
			}
			claimed = append(claimed, action)
		}
		return nil
	})
	return claimed, err
}

func loadActionAuthority(ctx context.Context, tx pgx.Tx, action *Action) error {
	if err := tx.QueryRow(ctx, `SELECT state.source_cc_policy_id,state.rule_id,state.client_cidr::text,
		state.host,state.path,state.method,state.listen_port,state.protocol,state.request_class,state.expires_at,
		settings.actor_scope_id,settings.actor_user_id
		FROM cc_coordination_states state JOIN cc_coordination_settings settings
		  ON settings.id=state.settings_id AND settings.revision=state.settings_revision
		WHERE state.id=$1 AND state.tenant_scope_id=$2`, action.StateID, action.TenantScopeID).Scan(
		&action.SourcePolicyID, &action.RuleID, &action.ClientCIDR, &action.Host, &action.Path,
		&action.Method, &action.ListenerPort, &action.Protocol, &action.RequestClass, &action.ExpiresAt,
		&action.ActorScopeID, &action.ActorUserID); err != nil {
		return fmt.Errorf("load claimed CC action authority: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT target.node_id FROM cc_coordination_states state
		JOIN cc_coordination_setting_targets target ON target.settings_id=state.settings_id
		 AND target.settings_revision=state.settings_revision WHERE state.id=$1 ORDER BY target.node_id`, action.StateID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			return err
		}
		action.TargetNodeIDs = append(action.TargetNodeIDs, nodeID)
	}
	return rows.Err()
}

func (store *Store) Retry(ctx context.Context, action Action, cause error) error {
	if action.ID == uuid.Nil || action.ClaimToken == uuid.Nil {
		return ErrInvalidInput
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	code := "publish_retryable"
	terminal := action.Attempts >= store.config.MaxAttempts
	status := "retryable"
	available := now.Add(retryDelay(action.Attempts))
	if terminal {
		status, code, available = "exhausted", "publish_exhausted", now
	}
	result, err := store.pool.Exec(ctx, `UPDATE cc_coordination_actions SET status=$3,lease_token=NULL,
		lease_owner=NULL,lease_expires_at=NULL,available_at=$4,result_reason_code=$5,
		completed_at=CASE WHEN $3='exhausted' THEN $2 ELSE NULL END,updated_at=$2
		WHERE id=$1 AND status='claimed' AND lease_token=$6`, action.ID, now, status, available, code, action.ClaimToken)
	if err != nil {
		return fmt.Errorf("retry CC coordination action: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrGenerationConflict
	}
	_ = cause
	return nil
}

func (store *Store) SettlePublished(ctx context.Context, action Action, publication PublicationResult) error {
	if action.ID == uuid.Nil || action.ClaimToken == uuid.Nil || publication.PublicationID == uuid.Nil || publication.PolicyVersion <= action.ExpectedVersion {
		return ErrInvalidInput
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	result, err := store.pool.Exec(ctx, `UPDATE cc_coordination_actions SET status='succeeded',
		lease_token=NULL,lease_owner=NULL,lease_expires_at=NULL,publication_id=$3,published_policy_version=$4,
		result_reason_code='published',completed_at=$2,updated_at=$2
		WHERE id=$1 AND status='claimed' AND lease_token=$5`,
		action.ID, now, publication.PublicationID, publication.PolicyVersion, action.ClaimToken)
	if err != nil {
		return fmt.Errorf("settle CC coordination publication: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrGenerationConflict
	}
	return nil
}

func (store *Store) PendingActivations(ctx context.Context, limit int) ([]Activation, error) {
	if limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	rows, err := store.pool.Query(ctx, `SELECT action.id,action.tenant_scope_id,action.site_id,action.state_id,
		action.generation,action.operation,action.publication_id,action.published_policy_version,
		state.source_cc_policy_id,state.current_policy_version,state.lkg_policy_version,
		settings.actor_scope_id,settings.actor_user_id
		FROM cc_coordination_actions action JOIN cc_coordination_states state ON state.id=action.state_id
		JOIN cc_coordination_settings settings ON settings.id=state.settings_id AND settings.revision=state.settings_revision
		WHERE action.status='succeeded' AND state.state IN ('block_pending','release_pending')
		ORDER BY action.completed_at,action.id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []Activation
	for rows.Next() {
		var value Activation
		if err := rows.Scan(&value.ActionID, &value.TenantScopeID, &value.SiteID, &value.StateID,
			&value.Generation, &value.Operation, &value.PublicationID, &value.PolicyVersion,
			&value.PolicyID, &value.CurrentPolicyVersion, &value.LKGPolicyVersion,
			&value.ActorScopeID, &value.ActorUserID); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (store *Store) SettleActivation(ctx context.Context, activation Activation, state ActivationState) error {
	if activation.StateID == uuid.Nil || activation.Generation < 1 ||
		(state != ActivationPending && state != ActivationActive && state != ActivationFailed) {
		return ErrInvalidInput
	}
	if state == ActivationPending {
		return nil
	}
	now := store.clock().UTC().Truncate(time.Microsecond)
	if state == ActivationFailed {
		result, err := store.pool.Exec(ctx, `UPDATE cc_coordination_states SET state='failed',
			reason_code=$3,updated_at=$4 WHERE id=$1 AND generation=$2 AND state IN ('block_pending','release_pending')`,
			activation.StateID, activation.Generation, ReasonLocalFallback, now)
		if err != nil || result.RowsAffected() != 1 {
			return ErrGenerationConflict
		}
		return nil
	}
	finalState := StateBlocked
	if activation.Operation == ActionRelease {
		finalState = StateReleased
	}
	result, err := store.pool.Exec(ctx, `UPDATE cc_coordination_states SET state=$3,
		lkg_policy_version=COALESCE(current_policy_version,lkg_policy_version),current_policy_version=$4,
		updated_at=$5 WHERE id=$1 AND generation=$2 AND state IN ('block_pending','release_pending')`,
		activation.StateID, activation.Generation, finalState, activation.PolicyVersion, now)
	if err != nil || result.RowsAffected() != 1 {
		return ErrGenerationConflict
	}
	if activation.Operation == ActionRelease {
		_, err = store.pool.Exec(ctx, `UPDATE cc_coordination_releases SET status='applied',
			result_reason_code='released',completed_at=$2 WHERE state_id=$1 AND status='pending'`, activation.StateID, now)
	}
	return err
}

func (store *Store) Release(ctx context.Context, actor securitypolicy.Actor, input ReleaseInput) (result ReleaseResult, resultErr error) {
	defer func() {
		if store == nil || store.metrics == nil {
			return
		}
		reason := securitycoordmetrics.ReasonFalsePositiveConfirmed
		if resultErr != nil {
			reason = ccMetricReason(resultErr)
		}
		store.metrics.RecordCCRelease(securitycoordmetrics.CCRelease{Replayed: result.Replayed, Reason: reason})
	}()
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil ||
		(actor.ScopeKind != "tenant" && actor.ScopeKind != "platform") ||
		(actor.ScopeKind == "tenant" && input.TenantScopeID != actor.ScopeID) ||
		input.TenantScopeID == uuid.Nil || input.SiteID == uuid.Nil || input.RuleID == uuid.Nil ||
		!validHost(input.Host) || !validPath(input.Path) || !validMethod(input.Method) || input.ListenerPort == 0 ||
		(input.Protocol != "http" && input.Protocol != "https") ||
		input.ExpectedGeneration < 1 || !identityPattern.MatchString(input.IdempotencyKey) ||
		!identityPattern.MatchString(input.RequestID) {
		return ReleaseResult{}, ErrInvalidInput
	}
	prefix, err := netip.ParsePrefix(input.ClientCIDR)
	if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
		return ReleaseResult{}, ErrInvalidInput
	}
	digest := sha256.Sum256([]byte(input.TenantScopeID.String() + "\x00" + input.SiteID.String() + "\x00" +
		input.RuleID.String() + "\x00" + prefix.String() + "\x00" + input.Host + "\x00" + input.Path + "\x00" +
		input.Method + "\x00" + strconv.Itoa(int(input.ListenerPort)) + "\x00" + input.Protocol + "\x00" +
		strconv.FormatInt(input.ExpectedGeneration, 10)))
	err = pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		var state State
		err := tx.QueryRow(ctx, `SELECT id,tenant_scope_id,site_id,source_cc_policy_id,rule_id,client_cidr::text,
			host,path,method,listen_port,protocol,request_class,generation,state,reason_code,hit_count,node_count,
			COALESCE(current_policy_version,0),COALESCE(lkg_policy_version,0),expires_at,release_hold_until,updated_at
			FROM cc_coordination_states WHERE tenant_scope_id=$1 AND site_id=$2 AND rule_id=$3 AND client_cidr=$4
			  AND host=$5 AND path=$6 AND method=$7 AND listen_port=$8 AND protocol=$9
			FOR UPDATE`, input.TenantScopeID, input.SiteID, input.RuleID, prefix.String(), input.Host, input.Path,
			input.Method, input.ListenerPort, input.Protocol).Scan(
			&state.ID, &state.TenantScopeID, &state.SiteID, &state.SourcePolicyID, &state.RuleID,
			&state.ClientCIDR, &state.Host, &state.Path, &state.Method, &state.ListenerPort, &state.Protocol,
			&state.RequestClass, &state.Generation, &state.State, &state.ReasonCode, &state.HitCount,
			&state.NodeCount, &state.CurrentPolicyVersion, &state.LKGPolicyVersion, &state.ExpiresAt,
			&state.ReleaseHoldTill, &state.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrScopeMismatch
		}
		if err != nil {
			return err
		}
		if state.Generation != input.ExpectedGeneration || state.State != StateBlocked {
			return ErrGenerationConflict
		}
		var existingDigest []byte
		var status string
		err = tx.QueryRow(ctx, `SELECT request_digest,status FROM cc_coordination_releases
			WHERE tenant_scope_id=$1 AND idempotency_key=$2`, input.TenantScopeID, input.IdempotencyKey).Scan(&existingDigest, &status)
		if err == nil {
			if !bytes.Equal(existingDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			result = ReleaseResult{State: state, Replayed: true}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		now := store.clock().UTC().Truncate(time.Microsecond)
		releaseID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(input.TenantScopeID.String()+"\x00"+input.IdempotencyKey))
		if _, err := tx.Exec(ctx, `INSERT INTO cc_coordination_releases(
			id,tenant_scope_id,site_id,state_id,expected_generation,idempotency_key,request_id,
			actor_scope_id,actor_user_id,reason_code,request_digest,status,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$2,$8,'false_positive_confirmed',$9,'pending',$10)`,
			releaseID, input.TenantScopeID, input.SiteID, state.ID, state.Generation,
			input.IdempotencyKey, input.RequestID, actor.UserID, digest[:], now); err != nil {
			return err
		}
		action := Action{
			ID:            uuid.NewSHA1(state.ID, []byte("release\x00"+strconv.FormatInt(state.Generation+1, 10))),
			TenantScopeID: state.TenantScopeID, SiteID: state.SiteID, StateID: state.ID,
			SourcePolicyID: state.SourcePolicyID, RuleID: state.RuleID, ClientCIDR: state.ClientCIDR,
			Host: state.Host, Path: state.Path, Method: state.Method, ListenerPort: state.ListenerPort,
			Protocol: state.Protocol, RequestClass: state.RequestClass, Operation: ActionRelease,
			ReasonCode: ReasonFalsePositiveConfirmed, Generation: state.Generation + 1,
			ExpectedVersion: state.CurrentPolicyVersion, ExpiresAt: state.ExpiresAt,
			ActorScopeID: actor.ScopeID, ActorUserID: actor.UserID,
		}
		payload, decision, err := actionPayload(action)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE cc_coordination_states SET generation=$2,state='release_pending',
			reason_code=$3,decision_digest=$4,updated_at=$5 WHERE id=$1 AND generation=$6`,
			state.ID, action.Generation, ReasonFalsePositiveConfirmed, decision[:], now, state.Generation); err != nil {
			return err
		}
		var maxAttempts int
		if err := tx.QueryRow(ctx, `SELECT max_attempts FROM cc_coordination_settings settings
			JOIN cc_coordination_states state ON state.settings_id=settings.id AND state.settings_revision=settings.revision
			WHERE state.id=$1`, state.ID).Scan(&maxAttempts); err != nil {
			return err
		}
		if err := insertAction(ctx, tx, action, payload, decision, maxAttempts, now); err != nil {
			return err
		}
		state.Generation, state.State, state.ReasonCode = action.Generation, StateReleasePending, ReasonFalsePositiveConfirmed
		state.UpdatedAt = now
		result = ReleaseResult{State: state}
		return nil
	})
	return result, err
}

func ccMetricReason(err error) securitycoordmetrics.Reason {
	switch {
	case errors.Is(err, ErrCapacity):
		return securitycoordmetrics.ReasonCapacityRejected
	case errors.Is(err, ErrScopeMismatch):
		return securitycoordmetrics.ReasonScopeRejected
	case errors.Is(err, ErrInvalidInput):
		return securitycoordmetrics.ReasonInvalidInput
	case errors.Is(err, ErrIdempotencyConflict), errors.Is(err, ErrGenerationConflict):
		return securitycoordmetrics.ReasonConflict
	default:
		return securitycoordmetrics.ReasonDependencyUnavailable
	}
}

func (store *Store) PolicyVersion(ctx context.Context, policyID uuid.UUID, revision int64) (securitypolicy.Policy, error) {
	if policyID == uuid.Nil || revision < 1 {
		return securitypolicy.Policy{}, ErrInvalidInput
	}
	var document []byte
	if err := store.pool.QueryRow(ctx, `SELECT document FROM security_policy_versions
		WHERE policy_id=$1 AND revision=$2`, policyID, revision).Scan(&document); err != nil {
		return securitypolicy.Policy{}, err
	}
	var policy securitypolicy.Policy
	if err := json.Unmarshal(document, &policy); err != nil || policy.ID != policyID || policy.Revision != revision || policy.Kind != securitypolicy.KindCC {
		return securitypolicy.Policy{}, ErrScopeMismatch
	}
	return policy, nil
}

// ListStates lists active states, newest first. A nil tenantScopeID (the
// platform view) spans every tenant and a nil siteID every site; the caller
// authorizes the scope. limit bounds the read.
func (store *Store) ListStates(ctx context.Context, tenantScopeID, siteID uuid.UUID, limit int) ([]State, error) {
	if store == nil || store.pool == nil || ctx == nil || limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	var scopeFilter, siteFilter *uuid.UUID
	if tenantScopeID != uuid.Nil {
		scopeFilter = &tenantScopeID
	}
	if siteID != uuid.Nil {
		siteFilter = &siteID
	}
	rows, err := store.pool.Query(ctx, `SELECT `+stateColumns+`
		FROM cc_coordination_states state JOIN access_scopes scope ON scope.id=state.tenant_scope_id
		WHERE ($1::uuid IS NULL OR state.tenant_scope_id=$1) AND ($2::uuid IS NULL OR state.site_id=$2)
		  AND state.state IN ('block_pending','blocked','release_pending','failed')
		ORDER BY state.updated_at DESC,state.id DESC LIMIT $3`, scopeFilter, siteFilter, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := make([]State, 0, limit)
	for rows.Next() {
		state, err := scanState(rows)
		if err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func (store *Store) GetState(ctx context.Context, tenantScopeID, siteID, stateID uuid.UUID) (State, error) {
	if store == nil || store.pool == nil || ctx == nil || tenantScopeID == uuid.Nil || siteID == uuid.Nil || stateID == uuid.Nil {
		return State{}, ErrInvalidInput
	}
	state, err := scanState(store.pool.QueryRow(ctx, `SELECT `+stateColumns+`
		FROM cc_coordination_states state JOIN access_scopes scope ON scope.id=state.tenant_scope_id
		WHERE state.id=$1 AND state.tenant_scope_id=$2 AND state.site_id=$3`, stateID, tenantScopeID, siteID))
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, ErrScopeMismatch
	}
	return state, err
}

const stateColumns = `state.id,state.tenant_scope_id,scope.tenant_id,state.site_id,state.source_cc_policy_id,state.rule_id,
		state.client_cidr::text,state.host,state.path,state.method,state.listen_port,state.protocol,state.request_class,
		state.generation,state.state,state.reason_code,state.hit_count,state.node_count,
		COALESCE(state.current_policy_version,0),COALESCE(state.lkg_policy_version,0),state.expires_at,
		state.release_hold_until,state.updated_at`

type stateScanner interface {
	Scan(...any) error
}

func scanState(row stateScanner) (State, error) {
	var state State
	err := row.Scan(&state.ID, &state.TenantScopeID, &state.TenantID, &state.SiteID, &state.SourcePolicyID, &state.RuleID,
		&state.ClientCIDR, &state.Host, &state.Path, &state.Method, &state.ListenerPort, &state.Protocol,
		&state.RequestClass, &state.Generation, &state.State, &state.ReasonCode, &state.HitCount,
		&state.NodeCount, &state.CurrentPolicyVersion, &state.LKGPolicyVersion, &state.ExpiresAt,
		&state.ReleaseHoldTill, &state.UpdatedAt)
	return state, err
}

func containsNode(values []uuid.UUID, target uuid.UUID) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func aggregateDigest(policyID uuid.UUID, fact Fact) [sha256.Size]byte {
	return sha256.Sum256([]byte(strings.Join([]string{policyID.String(), fact.RuleID.String(), fact.ClientCIDR,
		fact.Host, fact.Path, fact.Method, strconv.Itoa(int(fact.ListenerPort)), fact.Protocol, fact.RequestClass}, "\x00")))
}

func actionPayload(action Action) ([]byte, [sha256.Size]byte, error) {
	payload, err := json.Marshal(struct {
		SchemaVersion   string    `json:"schema_version"`
		TenantScopeID   uuid.UUID `json:"tenant_scope_id"`
		SiteID          uuid.UUID `json:"site_id"`
		SourcePolicyID  uuid.UUID `json:"source_cc_policy_id"`
		StateID         uuid.UUID `json:"state_id"`
		Generation      int64     `json:"generation"`
		Operation       string    `json:"operation"`
		ReasonCode      string    `json:"reason_code"`
		RuleID          uuid.UUID `json:"rule_id"`
		ClientCIDR      string    `json:"client_cidr"`
		Host            string    `json:"host"`
		Path            string    `json:"path"`
		Method          string    `json:"method"`
		ListenerPort    uint16    `json:"listen_port"`
		Protocol        string    `json:"protocol"`
		RequestClass    string    `json:"request_class"`
		ExpectedVersion int64     `json:"expected_active_policy_version"`
	}{SchemaVersion, action.TenantScopeID, action.SiteID, action.SourcePolicyID, action.StateID,
		action.Generation, action.Operation, action.ReasonCode, action.RuleID, action.ClientCIDR,
		action.Host, action.Path, action.Method, action.ListenerPort, action.Protocol, action.RequestClass,
		action.ExpectedVersion})
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return payload, sha256.Sum256(payload), nil
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	return time.Second << (attempt - 1)
}
