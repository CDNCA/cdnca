package acmehttp01

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/idna"
	"google.golang.org/protobuf/proto"
)

// Node-global HTTP-01 overlay (FX05①, ADR-0003). A challenge is frozen to the
// serving nodes of its site's line groups; each node gets one full snapshot
// generation (the union of every live challenge targeting it). Delivery,
// receipts, retries and timeouts are per node generation.

var (
	ErrChallengeWithdrawn = errors.New("ACME HTTP-01 challenge was withdrawn")
	ErrLostClaim          = errors.New("ACME HTTP-01 node delivery claim was lost")
)

// NodeUnsupportedError refuses a challenge whose target nodes cannot serve
// the overlay (agent without ACME_HTTP01_OVERLAY v1). It is not retryable:
// the node must be upgraded first.
type NodeUnsupportedError struct{ NodeIDs []uuid.UUID }

func (e *NodeUnsupportedError) Error() string {
	return "ACME HTTP-01 overlay is not supported on nodes " + joinNodeIDs(e.NodeIDs) +
		" (节点 agent 不支持 HTTP-01 验证，请升级节点或改用 DNS 验证)"
}

// NodeDeliveryError reports the target nodes that did not confirm the token:
// failed lists nodes whose delivery is exhausted, pending the ones still
// working when the wait ended.
type NodeDeliveryError struct {
	Failed  []uuid.UUID
	Pending []uuid.UUID
}

func (e *NodeDeliveryError) Error() string {
	message := "ACME HTTP-01 token was not confirmed by every target node"
	if len(e.Failed) != 0 {
		message += "; failed on " + joinNodeIDs(e.Failed)
	}
	if len(e.Pending) != 0 {
		message += "; still pending on " + joinNodeIDs(e.Pending)
	}
	return message
}

func joinNodeIDs(nodes []uuid.UUID) string {
	values := make([]string, len(nodes))
	for index, node := range nodes {
		values[index] = node.String()
	}
	return strings.Join(values, ", ")
}

type NodeStoreConfig struct {
	Clock             func() time.Time
	ChallengeLifetime time.Duration
	MaxTargets        int
	// MaxAttempts per generation delivery (agent precheck/activation/health
	// failures and timeouts are retried until then).
	MaxAttempts    int
	AttemptTimeout time.Duration
	RetryBase      time.Duration
	RetryMaximum   time.Duration
	LeaseDuration  time.Duration
	// CleanupLifetime is the deadline of a generation carrying no token.
	CleanupLifetime time.Duration
	// StaleRetryInterval re-delivers the current generation to a node whose
	// last healthy snapshot still serves a withdrawn or expired token after
	// its attempts were exhausted (a node that was offline).
	StaleRetryInterval time.Duration
	// ExpiryMargin drops a token from new generations this long before it
	// expires so a snapshot never reaches a node already expired.
	ExpiryMargin time.Duration
}

func DefaultNodeStoreConfig() NodeStoreConfig {
	return NodeStoreConfig{
		Clock: time.Now, ChallengeLifetime: 15 * time.Minute, MaxTargets: 1000, MaxAttempts: 3,
		AttemptTimeout: time.Minute, RetryBase: 2 * time.Second, RetryMaximum: 30 * time.Second,
		LeaseDuration: 30 * time.Second, CleanupLifetime: 24 * time.Hour,
		StaleRetryInterval: 5 * time.Minute, ExpiryMargin: 30 * time.Second,
	}
}

type NodeStore struct {
	pool   *pgxpool.Pool
	config NodeStoreConfig
	alerts DriftAlertEnqueuer
}

func NewNodeStore(pool *pgxpool.Pool, config NodeStoreConfig) (*NodeStore, error) {
	if pool == nil || config.Clock == nil || config.ChallengeLifetime < time.Minute ||
		config.ChallengeLifetime > MaxNodeChallengeLifetime || config.MaxTargets < 1 || config.MaxTargets > 10000 ||
		config.MaxAttempts < 1 || config.MaxAttempts > 100 || config.AttemptTimeout < time.Second ||
		config.RetryBase <= 0 || config.RetryMaximum < config.RetryBase || config.LeaseDuration < time.Second ||
		config.CleanupLifetime < time.Minute || config.CleanupLifetime > MaxNodeChallengeLifetime ||
		config.StaleRetryInterval <= 0 || config.ExpiryMargin < 0 || config.ExpiryMargin >= config.ChallengeLifetime {
		return nil, ErrInvalidConfig
	}
	return &NodeStore{pool: pool, config: config}, nil
}

// MaxNodeChallengeLifetime is the agent's MaxChallengeLifetime.
const MaxNodeChallengeLifetime = 24 * time.Hour

// maxNodeSnapshotEntries is the agent's MaxEntries.
const maxNodeSnapshotEntries = 4096

type challengeKey struct {
	ScopeID     uuid.UUID
	OperationID string
	AttemptID   uuid.UUID
}

func (k challengeKey) String() string {
	return k.ScopeID.String() + "/" + k.OperationID + "/" + k.AttemptID.String()
}

func (s *NodeStore) now() time.Time { return s.config.Clock().UTC().Truncate(time.Microsecond) }

// PublishChallenge records the challenge in its site's open epoch (opening
// one frozen to the site's candidate nodes when none is open), targets the
// epoch's active members and regenerates their snapshots. A replay of the
// same challenge is a no-op.
func (s *NodeStore) PublishChallenge(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	key, domain, err := normalizeNodeChallenge(challenge)
	if err != nil || ctx == nil || !nodeTokenPattern.MatchString(challenge.Token) ||
		!validNodeChallengeValue(challenge.Token, challenge.ExactValue) {
		return ErrInvalidChallenge
	}
	tokenDigest := sha256.Sum256([]byte(challenge.Token))
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockOverlay(ctx, tx); err != nil {
			return err
		}
		var existingDomain string
		var existingDigest []byte
		var withdrawn *time.Time
		err := tx.QueryRow(ctx, `SELECT domain,token_sha256,withdrawn_at FROM acme_http01_node_challenges
			WHERE tenant_scope_id=$1 AND operation_id=$2 AND attempt_id=$3 FOR UPDATE`,
			key.ScopeID, key.OperationID, key.AttemptID).Scan(&existingDomain, &existingDigest, &withdrawn)
		if err == nil {
			if existingDomain != domain || !bytes.Equal(existingDigest, tokenDigest[:]) {
				return ErrInvalidChallenge
			}
			if withdrawn != nil {
				return ErrChallengeWithdrawn
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var matches bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM acme_issuance_challenge_attempts
			WHERE tenant_scope_id=$1 AND operation_id=$2 AND attempt_id=$3 AND challenge_type='http-01'
			  AND NOT wildcard AND identifier=$4 AND token=$5 AND exact_value=$6)`,
			key.ScopeID, key.OperationID, key.AttemptID, domain, challenge.Token, challenge.ExactValue).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return ErrInvalidChallenge
		}
		siteID, err := resolveChallengeSite(ctx, tx, key.ScopeID, domain)
		if err != nil {
			return err
		}
		candidates, err := s.siteCandidates(ctx, tx, key.ScopeID, siteID)
		if err != nil {
			return err
		}
		if len(candidates) == 0 {
			return ErrNoTarget
		}
		unsupported, err := nodesWithoutOverlay(ctx, tx, candidates)
		if err != nil {
			return err
		}
		if len(unsupported) != 0 {
			return &NodeUnsupportedError{NodeIDs: unsupported}
		}
		now := s.now()
		site := siteKey{ScopeID: key.ScopeID, SiteID: siteID}
		touched := map[uuid.UUID]bool{}
		// An epoch whose tokens all expired closes before a new one opens.
		if err := s.refreshSite(ctx, tx, site, now, touched); err != nil {
			return err
		}
		epoch, err := s.openEpoch(ctx, tx, site, candidates, now, touched)
		if err != nil {
			return err
		}
		if len(epoch.Active) == 0 {
			return ErrNoTarget
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_challenges(tenant_scope_id,operation_id,attempt_id,
			site_id,domain,token_sha256,target_count,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			key.ScopeID, key.OperationID, key.AttemptID, siteID, domain, tokenDigest[:], len(epoch.Active),
			now.Add(s.config.ChallengeLifetime), now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_challenge_targets(tenant_scope_id,operation_id,attempt_id,node_id)
			SELECT $1,$2,$3,node_id FROM unnest($4::uuid[]) node_id`, key.ScopeID, key.OperationID, key.AttemptID, epoch.Active); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_challenge_epochs(tenant_scope_id,operation_id,attempt_id,epoch_id)
			VALUES($1,$2,$3,$4)`, key.ScopeID, key.OperationID, key.AttemptID, epoch.EpochID); err != nil {
			return err
		}
		return s.settle(ctx, tx, []siteKey{site}, touched, now, nil)
	})
}

// WithdrawChallenge stops serving the challenge: its site gets a version
// without it (the last one closes the epoch) and every target node a new
// generation. Withdrawing an unknown challenge (publish never recorded it) is
// a no-op.
func (s *NodeStore) WithdrawChallenge(ctx context.Context, challenge acmeworker.ChallengeIdentity) error {
	key, _, err := normalizeNodeChallenge(challenge)
	if err != nil || ctx == nil {
		return ErrInvalidChallenge
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockOverlay(ctx, tx); err != nil {
			return err
		}
		nodes, err := challengeTargets(ctx, tx, key)
		if err != nil || len(nodes) == 0 {
			return err
		}
		var site siteKey
		if err := tx.QueryRow(ctx, `SELECT tenant_scope_id,site_id FROM acme_http01_node_challenges
			WHERE tenant_scope_id=$1 AND operation_id=$2 AND attempt_id=$3`,
			key.ScopeID, key.OperationID, key.AttemptID).Scan(&site.ScopeID, &site.SiteID); err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.Exec(ctx, `UPDATE acme_http01_node_challenges SET withdrawn_at=$4
			WHERE tenant_scope_id=$1 AND operation_id=$2 AND attempt_id=$3 AND withdrawn_at IS NULL`,
			key.ScopeID, key.OperationID, key.AttemptID, now); err != nil {
			return err
		}
		touched := make(map[uuid.UUID]bool, len(nodes))
		for _, node := range nodes {
			touched[node] = true
		}
		return s.settle(ctx, tx, []siteKey{site}, touched, now, nil)
	})
}

// NodeChallengeStatus is where a challenge stands on each target node.
type NodeChallengeStatus struct {
	Withdrawn bool
	Confirmed []uuid.UUID
	Pending   []uuid.UUID
	// Failed: the node's current generation delivery is terminal and will
	// not be retried.
	Failed []uuid.UUID
	// Released: targets that left the site's epoch (offline, removed); they
	// owe a cleanup debt and no longer block the issuance.
	Released []uuid.UUID
	// Serving: targets (released ones included) whose latest healthy
	// generation still serves the challenge's host and token.
	Serving []uuid.UUID
}

// ChallengeStatus: a node confirms a challenge once its latest healthy
// generation serves the challenge's host and token. A target released from
// the challenge's epoch is reported apart: it does not block the issuance.
func (s *NodeStore) ChallengeStatus(ctx context.Context, challenge acmeworker.ChallengeIdentity) (NodeChallengeStatus, error) {
	key, _, err := normalizeNodeChallenge(challenge)
	if err != nil || ctx == nil {
		return NodeChallengeStatus{}, ErrInvalidChallenge
	}
	var status NodeChallengeStatus
	var withdrawn *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT withdrawn_at FROM acme_http01_node_challenges
		WHERE tenant_scope_id=$1 AND operation_id=$2 AND attempt_id=$3`,
		key.ScopeID, key.OperationID, key.AttemptID).Scan(&withdrawn); errors.Is(err, pgx.ErrNoRows) {
		return NodeChallengeStatus{}, ErrInvalidChallenge
	} else if err != nil {
		return NodeChallengeStatus{}, err
	}
	status.Withdrawn = withdrawn != nil
	rows, err := s.pool.Query(ctx, nodeChallengeStatusSQL, key.ScopeID, key.OperationID, key.AttemptID)
	if err != nil {
		return NodeChallengeStatus{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID uuid.UUID
		var served, failed, released bool
		if err := rows.Scan(&nodeID, &served, &failed, &released); err != nil {
			return NodeChallengeStatus{}, err
		}
		if served {
			status.Serving = append(status.Serving, nodeID)
		}
		switch {
		case released:
			status.Released = append(status.Released, nodeID)
		case served:
			status.Confirmed = append(status.Confirmed, nodeID)
		case failed:
			status.Failed = append(status.Failed, nodeID)
		default:
			status.Pending = append(status.Pending, nodeID)
		}
	}
	return status, rows.Err()
}

// served: the latest healthy generation carries the same host and token.
// failed: the newest attempt of the current generation is terminal and no
// retry follows (attempts exhausted or not retryable).
const nodeChallengeStatusSQL = `
	SELECT target.node_id,
	       EXISTS (
	           SELECT 1 FROM acme_http01_node_overlay_generation_tokens token
	           JOIN acme_http01_node_challenges served ON served.tenant_scope_id=token.tenant_scope_id
	            AND served.operation_id=token.operation_id AND served.attempt_id=token.attempt_id
	           WHERE token.generation_id=state.latest_healthy_generation_id
	             AND served.domain=challenge.domain AND served.token_sha256=challenge.token_sha256
	       ),
	       COALESCE((
	           SELECT delivery.state IN ('failed','timed_out')
	           FROM acme_http01_node_overlay_deliveries delivery
	           WHERE delivery.generation_id=state.current_generation_id
	           ORDER BY delivery.attempt DESC LIMIT 1
	       ), false),
	       EXISTS (
	           SELECT 1 FROM acme_http01_node_challenge_epochs link
	           JOIN acme_http01_site_overlay_epoch_releases released ON released.epoch_id=link.epoch_id
	            AND released.node_id=target.node_id
	           WHERE link.tenant_scope_id=target.tenant_scope_id AND link.operation_id=target.operation_id
	             AND link.attempt_id=target.attempt_id
	       )
	FROM acme_http01_node_challenge_targets target
	JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=target.tenant_scope_id
	 AND challenge.operation_id=target.operation_id AND challenge.attempt_id=target.attempt_id
	LEFT JOIN acme_http01_node_overlay_states state ON state.node_id=target.node_id
	WHERE target.tenant_scope_id=$1 AND target.operation_id=$2 AND target.attempt_id=$3
	ORDER BY target.node_id`

func normalizeNodeChallenge(challenge acmeworker.ChallengeIdentity) (challengeKey, string, error) {
	if challenge.ScopeID == uuid.Nil || challenge.OperationID == "" || challenge.AttemptID == uuid.Nil ||
		challenge.ChallengeType != acmeworker.ChallengeHTTP01 || challenge.Wildcard ||
		challenge.Identifier == "" || challenge.Identifier != strings.TrimSpace(challenge.Identifier) {
		return challengeKey{}, "", ErrInvalidChallenge
	}
	domain, err := idna.Lookup.ToASCII(challenge.Identifier)
	if err != nil || domain == "" || len(domain) > 253 || strings.HasSuffix(domain, ".") {
		return challengeKey{}, "", ErrInvalidChallenge
	}
	return challengeKey{ScopeID: challenge.ScopeID, OperationID: challenge.OperationID, AttemptID: challenge.AttemptID},
		strings.ToLower(domain), nil
}

var (
	nodeTokenPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)
	nodeThumbprintPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// validNodeChallengeValue mirrors the agent's snapshot check.
func validNodeChallengeValue(token, value string) bool {
	return len(value) == len(token)+1+43 && strings.HasPrefix(value, token+".") &&
		nodeThumbprintPattern.MatchString(value[len(token)+1:])
}

// resolveChallengeSite is the scope's one live site serving the host (its
// primary domain or an active site domain).
func resolveChallengeSite(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, domain string) (uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT site.id FROM sites site
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND site.enabled AND site.status='active'
		  AND (lower(site.domain)=$2 OR EXISTS (SELECT 1 FROM site_domain_active active
		       WHERE active.scope_id=site.scope_id AND active.site_id=site.id AND active.canonical_domain=$2))
		ORDER BY site.id LIMIT 2`, scopeID, domain)
	if err != nil {
		return uuid.Nil, err
	}
	sites, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return uuid.Nil, err
	}
	if len(sites) != 1 {
		return uuid.Nil, ErrInvalidChallenge
	}
	return sites[0], nil
}

// nodesWithoutOverlay lists the nodes whose latest session does not declare
// ACME_HTTP01_OVERLAY v1 (the agent only declares it with a ready route).
func nodesWithoutOverlay(ctx context.Context, tx pgx.Tx, nodes []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (node_id) node_id,capabilities_snapshot,capabilities_sha256
		FROM node_session_capabilities WHERE node_id=ANY($1::uuid[])
		ORDER BY node_id,session_epoch DESC`, nodes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	capable := make(map[uuid.UUID]bool, len(nodes))
	for rows.Next() {
		var nodeID uuid.UUID
		var snapshot, digest []byte
		if err := rows.Scan(&nodeID, &snapshot, &digest); err != nil {
			return nil, err
		}
		actual := sha256.Sum256(snapshot)
		capabilities := new(agentv1.AgentCapabilities)
		if !bytes.Equal(actual[:], digest) || proto.Unmarshal(snapshot, capabilities) != nil {
			continue
		}
		for _, feature := range capabilities.GetFeatures() {
			if feature.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY && feature.GetApiVersion() == 1 {
				capable[nodeID] = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var unsupported []uuid.UUID
	for _, node := range nodes {
		if !capable[node] {
			unsupported = append(unsupported, node)
		}
	}
	return unsupported, nil
}

func challengeTargets(ctx context.Context, tx pgx.Tx, key challengeKey) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT node_id FROM acme_http01_node_challenge_targets
		WHERE tenant_scope_id=$1 AND operation_id=$2 AND attempt_id=$3 ORDER BY node_id`,
		key.ScopeID, key.OperationID, key.AttemptID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// lockNodeStates creates missing node state rows and locks them in node id
// order: every writer locks nodes the same way, so overlapping node sets do
// not deadlock and the later writer re-reads the desired union.
func lockNodeStates(ctx context.Context, tx pgx.Tx, nodes []uuid.UUID, now time.Time) error {
	sorted := append([]uuid.UUID(nil), nodes...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i][:], sorted[j][:]) < 0 })
	if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_states(node_id,current_generation,
		latest_healthy_generation,created_at,updated_at)
		SELECT node_id,0,0,$2,$2 FROM unnest($1::uuid[]) node_id ORDER BY node_id
		ON CONFLICT (node_id) DO NOTHING`, sorted, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT node_id FROM acme_http01_node_overlay_states
		WHERE node_id=ANY($1::uuid[]) ORDER BY node_id FOR UPDATE`, sorted)
	return err
}

// regenerateNodes gives every listed node a new generation when its desired
// union differs from the current one, the current one is near its deadline,
// or minimum (a generation floor after an agent reported a newer pointer)
// requires it.
func (s *NodeStore) regenerateNodes(ctx context.Context, tx pgx.Tx, nodes []uuid.UUID, now time.Time,
	minimum map[uuid.UUID]int64) error {
	if len(nodes) == 0 {
		return nil
	}
	if err := lockNodeStates(ctx, tx, nodes, now); err != nil {
		return err
	}
	sorted := append([]uuid.UUID(nil), nodes...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i][:], sorted[j][:]) < 0 })
	for index, node := range sorted {
		if index > 0 && node == sorted[index-1] {
			continue
		}
		if err := s.regenerateNode(ctx, tx, node, now, minimum[node]); err != nil {
			return err
		}
	}
	return nil
}

type desiredNodeToken struct {
	key     challengeKey
	domain  string
	digest  []byte
	expires time.Time
}

// desiredCoverage is one site coverage of a node generation.
type desiredCoverage struct {
	site    siteKey
	kind    string
	version uuid.UUID
	epoch   uuid.UUID
	digest  []byte
	count   int
	debt    *uuid.UUID
}

func sameCoverage(left, right desiredCoverage) bool {
	return left.site == right.site && left.kind == right.kind && left.version == right.version &&
		(left.debt == nil) == (right.debt == nil) && (left.debt == nil || *left.debt == *right.debt)
}

// regenerateNode gives the node a new generation when its desired snapshot
// (the tokens of the current version of every site it is an active required
// member of) or its site coverage (those sites plus every unresolved cleanup
// debt) differs from the current generation, the current one is near its
// deadline, a pending 063 bootstrap awaits it, or minimum (a floor after an
// agent reported a newer pointer) requires it.
func (s *NodeStore) regenerateNode(ctx context.Context, tx pgx.Tx, node uuid.UUID, now time.Time, minimum int64) error {
	var current int64
	var currentID *uuid.UUID
	var currentDeadline *time.Time
	var floor *int64
	if err := tx.QueryRow(ctx, `SELECT state.current_generation,state.current_generation_id,generation.deadline_at,
		       (SELECT backfill.generation_floor FROM acme_http01_overlay_backfill_nodes backfill
		        WHERE backfill.node_id=state.node_id AND backfill.state='pending')
		FROM acme_http01_node_overlay_states state
		LEFT JOIN acme_http01_node_overlay_generations generation ON generation.id=state.current_generation_id
		WHERE state.node_id=$1`, node).Scan(&current, &currentID, &currentDeadline, &floor); err != nil {
		return err
	}
	if floor != nil {
		minimum = max(minimum, *floor)
	}
	rows, err := tx.Query(ctx, `SELECT site.tenant_scope_id,site.site_id,version.id,version.epoch_id,
		       version.token_set_sha256,version.token_count,debt.id
		FROM acme_http01_site_overlay_epoch_members member
		JOIN acme_http01_site_overlay_states site ON site.open_epoch_id=member.epoch_id
		JOIN acme_http01_site_overlay_versions version ON version.id=site.current_version_id AND version.token_count > 0
		LEFT JOIN acme_http01_node_overlay_cleanup_debts debt ON debt.node_id=member.node_id
		 AND debt.tenant_scope_id=site.tenant_scope_id AND debt.site_id=site.site_id AND NOT EXISTS (
		     SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
		     WHERE resolved.debt_id=debt.id AND resolved.event IN ('resolved_cleanup','resolved_required'))
		WHERE member.node_id=$1 AND NOT EXISTS (
		    SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
		    WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id)
		UNION ALL
		SELECT debt.tenant_scope_id,debt.site_id,site.current_version_id,debt.required_epoch_id,
		       NULL::bytea,0,debt.id
		FROM acme_http01_node_overlay_cleanup_debts debt
		JOIN acme_http01_site_overlay_states site ON site.tenant_scope_id=debt.tenant_scope_id AND site.site_id=debt.site_id
		WHERE debt.node_id=$1 AND NOT EXISTS (
		    SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
		    WHERE resolved.debt_id=debt.id AND resolved.event IN ('resolved_cleanup','resolved_required'))
		ORDER BY 1,2`, node)
	if err != nil {
		return err
	}
	collected, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (desiredCoverage, error) {
		var value desiredCoverage
		err := row.Scan(&value.site.ScopeID, &value.site.SiteID, &value.version, &value.epoch,
			&value.digest, &value.count, &value.debt)
		return value, err
	})
	if err != nil {
		return err
	}
	var coverage []desiredCoverage
	required := map[siteKey]bool{}
	for _, item := range collected {
		if item.count > 0 {
			item.kind = "required"
			required[item.site] = true
			coverage = append(coverage, item)
		}
	}
	empty := map[siteKey][sha256.Size]byte{}
	requiredCount := len(coverage)
	for _, item := range collected {
		if item.count == 0 && !required[item.site] {
			item.kind = "cleanup_debt"
			digest, ok := empty[item.site]
			if !ok {
				digest = siteTokenSetDigest(item.site.SiteID, nil)
				empty[item.site] = digest
			}
			item.digest = digest[:]
			coverage = append(coverage, item)
		}
	}
	var desired []desiredNodeToken
	for _, item := range coverage[:requiredCount] {
		rows, err := tx.Query(ctx, `SELECT challenge.tenant_scope_id,challenge.operation_id,challenge.attempt_id,
			       challenge.domain,challenge.token_sha256,challenge.expires_at
			FROM acme_http01_site_overlay_version_tokens token
			JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=token.tenant_scope_id
			 AND challenge.operation_id=token.operation_id AND challenge.attempt_id=token.attempt_id
			WHERE token.version_id=$1 ORDER BY token.ordinal`, item.version)
		if err != nil {
			return err
		}
		tokens, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (desiredNodeToken, error) {
			var value desiredNodeToken
			err := row.Scan(&value.key.ScopeID, &value.key.OperationID, &value.key.AttemptID,
				&value.domain, &value.digest, &value.expires)
			return value, err
		})
		if err != nil {
			return err
		}
		desired = append(desired, tokens...)
	}
	sort.SliceStable(desired, func(i, j int) bool {
		if order := strings.Compare(desired[i].domain, desired[j].domain); order != 0 {
			return order < 0
		}
		return bytes.Compare(desired[i].digest, desired[j].digest) < 0
	})
	for index := 1; index < len(desired); index++ {
		if desired[index].domain == desired[index-1].domain && bytes.Equal(desired[index].digest, desired[index-1].digest) {
			return fmt.Errorf("%w: node %s would serve host %s with one token for two sites", ErrNoTarget, node, desired[index].domain)
		}
	}
	if len(desired) > maxNodeSnapshotEntries {
		return fmt.Errorf("%w: node %s would serve more than %d HTTP-01 tokens", ErrNoTarget, node, maxNodeSnapshotEntries)
	}
	if currentID == nil && len(coverage) == 0 && minimum == 0 {
		return nil
	}
	if currentID != nil && floor == nil && minimum <= current && currentDeadline.After(now.Add(s.config.ExpiryMargin)) {
		same, err := sameGeneration(ctx, tx, *currentID, desired, coverage)
		if err != nil || same {
			return err
		}
	}
	generation := max(current+1, minimum)
	deadline := now.Add(s.config.CleanupLifetime)
	keys := make([]challengeKey, len(desired))
	for index, token := range desired {
		keys[index] = token.key
		if token.expires.Before(deadline) {
			deadline = token.expires
		}
	}
	purpose := "apply"
	var proof []byte
	if requiredCount == 0 && len(coverage) != 0 {
		var admin string
		var serving bool
		if err := tx.QueryRow(ctx, `SELECT node.admin_state, EXISTS (
			    SELECT 1 FROM node_line_endpoint_published endpoint
			    JOIN node_line_groups line_group ON line_group.tenant_scope_id=endpoint.tenant_scope_id
			     AND line_group.id=endpoint.line_group_id AND line_group.current_revision=endpoint.config_revision
			     AND line_group.deleted_at IS NULL
			    WHERE endpoint.node_id=node.id AND endpoint.published)
			FROM nodes node WHERE node.id=$1`, node).Scan(&admin, &serving); err != nil {
			return err
		}
		if (admin == "draining" || admin == "retired") && !serving {
			purpose = "cleanup_only"
			digest := nonServingProof(node, admin, generation)
			proof = digest[:]
		}
	}
	digest := nodeGenerationDigest(node, generation, keys)
	generationID := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_generations(id,node_id,generation,
		previous_generation,snapshot_sha256,token_count,deadline_at,created_at,purpose,required_coverage_count,
		cleanup_debt_coverage_count,non_serving_proof_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		generationID, node, generation, current, digest[:], len(keys), deadline, now, purpose, requiredCount,
		len(coverage)-requiredCount, proof); err != nil {
		return err
	}
	if len(keys) != 0 {
		scopes, operations, attempts := make([]uuid.UUID, len(keys)), make([]string, len(keys)), make([]uuid.UUID, len(keys))
		for index, key := range keys {
			scopes[index], operations[index], attempts[index] = key.ScopeID, key.OperationID, key.AttemptID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_generation_tokens(generation_id,ordinal,
			tenant_scope_id,operation_id,attempt_id)
			SELECT $1,ordinal,scope_id,operation_id,attempt_id
			FROM unnest($2::uuid[],$3::text[],$4::uuid[]) WITH ORDINALITY AS item(scope_id,operation_id,attempt_id,ordinal)`,
			generationID, scopes, operations, attempts); err != nil {
			return err
		}
	}
	for _, item := range coverage {
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_generation_coverages(generation_id,node_id,
			tenant_scope_id,site_id,coverage_kind,site_version_id,site_token_set_sha256,site_token_count,
			required_epoch_id,cleanup_debt_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			generationID, node, item.site.ScopeID, item.site.SiteID, item.kind, item.version, item.digest, item.count,
			item.epoch, item.debt); err != nil {
			return err
		}
		if item.debt != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_cleanup_debt_events(debt_id,sequence,event,
				generation_id,occurred_at)
				SELECT $1,max(sequence)+1,'scheduled',$2,$3 FROM acme_http01_node_overlay_cleanup_debt_events WHERE debt_id=$1`,
				*item.debt, generationID, now); err != nil {
				return err
			}
		}
	}
	// Only the newest generation may still be delivered.
	if _, err := tx.Exec(ctx, `UPDATE acme_http01_node_overlay_deliveries
		SET state='superseded',failure_code='superseded',lease_token=NULL,lease_expires_at=NULL,updated_at=$2
		WHERE node_id=$1 AND state IN ('pending','published','applied')`, node, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_deliveries(generation_id,node_id,generation,
		attempt,state,not_before,created_at,updated_at) VALUES($1,$2,$3,1,'pending',$4,$4,$4)`,
		generationID, node, generation, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE acme_http01_node_overlay_states
		SET current_generation=$2,current_generation_id=$3,updated_at=$4 WHERE node_id=$1`,
		node, generation, generationID, now); err != nil {
		return err
	}
	if floor != nil {
		_, err = tx.Exec(ctx, `UPDATE acme_http01_overlay_backfill_nodes SET state='bootstrapped',bootstrap_generation_id=$2,
			updated_at=greatest(updated_at,$3) WHERE node_id=$1 AND state='pending'`, node, generationID, now)
	}
	return err
}

// sameGeneration: the generation already carries exactly these tokens and
// this coverage.
func sameGeneration(ctx context.Context, tx pgx.Tx, generationID uuid.UUID, desired []desiredNodeToken,
	coverage []desiredCoverage) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT tenant_scope_id,operation_id,attempt_id
		FROM acme_http01_node_overlay_generation_tokens WHERE generation_id=$1 ORDER BY ordinal`, generationID)
	if err != nil {
		return false, err
	}
	existing, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (challengeKey, error) {
		var key challengeKey
		return key, row.Scan(&key.ScopeID, &key.OperationID, &key.AttemptID)
	})
	if err != nil || len(existing) != len(desired) {
		return false, err
	}
	for index := range existing {
		if existing[index] != desired[index].key {
			return false, nil
		}
	}
	rows, err = tx.Query(ctx, `SELECT tenant_scope_id,site_id,coverage_kind,site_version_id,cleanup_debt_id
		FROM acme_http01_node_overlay_generation_coverages WHERE generation_id=$1 ORDER BY tenant_scope_id,site_id`, generationID)
	if err != nil {
		return false, err
	}
	stored, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (desiredCoverage, error) {
		var value desiredCoverage
		return value, row.Scan(&value.site.ScopeID, &value.site.SiteID, &value.kind, &value.version, &value.debt)
	})
	if err != nil || len(stored) != len(coverage) {
		return false, err
	}
	for _, want := range coverage {
		if !slices.ContainsFunc(stored, func(have desiredCoverage) bool { return sameCoverage(have, want) }) {
			return false, nil
		}
	}
	return true, nil
}

// nodeGenerationDigest is acme_http01_node_generation_digest_337 in Go.
func nodeGenerationDigest(node uuid.UUID, generation int64, keys []challengeKey) [sha256.Size]byte {
	var builder strings.Builder
	fmt.Fprintf(&builder, "cdnca.acme.http01-node-generation/v1\n%s\n%d\n", node, generation)
	for index, key := range keys {
		if index > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(key.String())
	}
	return sha256.Sum256([]byte(builder.String()))
}

// retryableNodeFailure: agent and transport failures a new attempt of the
// same generation may cure. Conflicts are cured by a new generation instead.
func retryableNodeFailure(code string) bool {
	switch code {
	case "attempt_timeout", "precheck_failed", "activation_failed", "health_failed", "rolled_back",
		"overlay_failed", "artifact_unavailable":
		return true
	}
	return false
}

func (s *NodeStore) backoff(attempt int) time.Duration {
	delay := s.config.RetryBase
	for step := 1; step < attempt && delay < s.config.RetryMaximum; step++ {
		delay *= 2
	}
	return min(delay, s.config.RetryMaximum)
}

// scheduleRetry adds the next attempt of a terminal delivery when the
// generation is still the node's current one, attempts remain and the
// generation has time left. The caller holds the node state lock.
func (s *NodeStore) scheduleRetry(ctx context.Context, tx pgx.Tx, generationID uuid.UUID, attempt int,
	code string, now time.Time, force bool) (bool, error) {
	if !force && (!retryableNodeFailure(code) || attempt >= s.config.MaxAttempts) || attempt >= 1000 {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_deliveries(generation_id,node_id,generation,
		attempt,state,not_before,created_at,updated_at)
		SELECT generation.id,generation.node_id,generation.generation,$2::integer+1,'pending',$3,$4,$4
		FROM acme_http01_node_overlay_generations generation
		JOIN acme_http01_node_overlay_states state ON state.node_id=generation.node_id
		 AND state.current_generation_id=generation.id
		WHERE generation.id=$1 AND generation.deadline_at > $3::timestamptz + $5::interval`,
		generationID, attempt, now.Add(s.backoff(attempt)), now, s.config.AttemptTimeout.String())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// NodeDelivery is one claimed delivery attempt.
type NodeDelivery struct {
	GenerationID uuid.UUID
	NodeID       uuid.UUID
	Generation   int64
	Attempt      int
	LeaseToken   uuid.UUID
}

// ClaimDeliveries leases due pending attempts for the dispatcher.
func (s *NodeStore) ClaimDeliveries(ctx context.Context, limit int) ([]NodeDelivery, error) {
	if ctx == nil || limit < 1 || limit > 256 {
		return nil, ErrInvalidConfig
	}
	now := s.now()
	rows, err := s.pool.Query(ctx, `UPDATE acme_http01_node_overlay_deliveries delivery
		SET lease_token=gen_random_uuid(),lease_expires_at=$2,updated_at=$1
		WHERE (delivery.generation_id,delivery.attempt) IN (
		    SELECT generation_id,attempt FROM acme_http01_node_overlay_deliveries
		    WHERE state='pending' AND not_before <= $1 AND (lease_expires_at IS NULL OR lease_expires_at <= $1)
		    ORDER BY not_before,generation_id LIMIT $3 FOR UPDATE SKIP LOCKED)
		RETURNING delivery.generation_id,delivery.node_id,delivery.generation,delivery.attempt,delivery.lease_token`,
		now, now.Add(s.config.LeaseDuration), limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (NodeDelivery, error) {
		var value NodeDelivery
		return value, row.Scan(&value.GenerationID, &value.NodeID, &value.Generation, &value.Attempt, &value.LeaseToken)
	})
}

// CompleteDelivery records the dispatcher's outcome under its lease. A lost
// lease (a receipt or a newer generation already moved the attempt) returns
// ErrLostClaim and changes nothing.
func (s *NodeStore) CompleteDelivery(ctx context.Context, delivery NodeDelivery, published, retryable bool, code string) error {
	if ctx == nil || delivery.LeaseToken == uuid.Nil || !published && (code == "" || !validFailureCode(code)) {
		return ErrInvalidConfig
	}
	now := s.now()
	var tag interface{ RowsAffected() int64 }
	var err error
	switch {
	case published:
		tag, err = s.pool.Exec(ctx, `UPDATE acme_http01_node_overlay_deliveries
			SET state='published',lease_token=NULL,lease_expires_at=NULL,attempt_deadline_at=$4,updated_at=$3
			WHERE generation_id=$1 AND attempt=$2 AND state='pending' AND lease_token=$5`,
			delivery.GenerationID, delivery.Attempt, now, now.Add(s.config.AttemptTimeout), delivery.LeaseToken)
	case retryable:
		tag, err = s.pool.Exec(ctx, `UPDATE acme_http01_node_overlay_deliveries
			SET lease_token=NULL,lease_expires_at=NULL,publish_failures=publish_failures+1,
			    not_before=$3 + least(interval '1 second' * power(2, least(publish_failures,6)), $5::interval),updated_at=$3
			WHERE generation_id=$1 AND attempt=$2 AND state='pending' AND lease_token=$4`,
			delivery.GenerationID, delivery.Attempt, now, delivery.LeaseToken, s.config.RetryMaximum.String())
	default:
		tag, err = s.pool.Exec(ctx, `UPDATE acme_http01_node_overlay_deliveries
			SET state='failed',failure_code=$5,lease_token=NULL,lease_expires_at=NULL,updated_at=$3
			WHERE generation_id=$1 AND attempt=$2 AND state='pending' AND lease_token=$4`,
			delivery.GenerationID, delivery.Attempt, now, delivery.LeaseToken, code)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLostClaim
	}
	return nil
}

func validFailureCode(code string) bool {
	if code == "" || len(code) > 64 || code[0] < 'a' || code[0] > 'z' {
		return false
	}
	for _, character := range code {
		if character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

// nodeDeliveryBinding is everything an overlay command or artifact for one
// delivery attempt is built from.
type nodeDeliveryBinding struct {
	GenerationID  uuid.UUID
	NodeID        uuid.UUID
	Generation    int64
	Attempt       int
	CreatedAt     time.Time
	Deadline      time.Time
	State         string
	NewerAttempt  bool
	NotCurrent    bool
	Purpose       string // "apply" or "cleanup_only"
	SnapshotSHA   [sha256.Size]byte
	Entries       []snapshotEntry
	expectedCount int
}

func (s *NodeStore) loadDeliveryBinding(ctx context.Context, generationID uuid.UUID, attempt int) (nodeDeliveryBinding, error) {
	if ctx == nil || generationID == uuid.Nil || attempt < 1 {
		return nodeDeliveryBinding{}, ErrArtifactBinding
	}
	var binding nodeDeliveryBinding
	var digest []byte
	err := s.pool.QueryRow(ctx, `SELECT generation.id,generation.node_id,generation.generation,delivery.attempt,
		       generation.created_at,generation.deadline_at,delivery.state,generation.snapshot_sha256,generation.token_count,
		       generation.purpose,
		       EXISTS (SELECT 1 FROM acme_http01_node_overlay_deliveries newer
		               WHERE newer.generation_id=delivery.generation_id AND newer.attempt>delivery.attempt),
		       state.current_generation_id IS DISTINCT FROM generation.id
		FROM acme_http01_node_overlay_deliveries delivery
		JOIN acme_http01_node_overlay_generations generation ON generation.id=delivery.generation_id
		JOIN acme_http01_node_overlay_states state ON state.node_id=generation.node_id
		WHERE delivery.generation_id=$1 AND delivery.attempt=$2`, generationID, attempt).Scan(
		&binding.GenerationID, &binding.NodeID, &binding.Generation, &binding.Attempt, &binding.CreatedAt,
		&binding.Deadline, &binding.State, &digest, &binding.expectedCount, &binding.Purpose, &binding.NewerAttempt,
		&binding.NotCurrent)
	if errors.Is(err, pgx.ErrNoRows) {
		return nodeDeliveryBinding{}, ErrArtifactBinding
	}
	if err != nil {
		return nodeDeliveryBinding{}, err
	}
	if len(digest) != sha256.Size {
		return nodeDeliveryBinding{}, ErrArtifactIntegrity
	}
	copy(binding.SnapshotSHA[:], digest)
	binding.CreatedAt, binding.Deadline = binding.CreatedAt.UTC(), binding.Deadline.UTC()
	rows, err := s.pool.Query(ctx, `SELECT token.tenant_scope_id,token.operation_id,token.attempt_id,
		       challenge.domain,challenge.token_sha256,challenge.expires_at,attempt.identifier,attempt.token,
		       attempt.exact_value,attempt.challenge_type,attempt.wildcard
		FROM acme_http01_node_overlay_generation_tokens token
		JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=token.tenant_scope_id
		 AND challenge.operation_id=token.operation_id AND challenge.attempt_id=token.attempt_id
		JOIN acme_issuance_challenge_attempts attempt ON attempt.tenant_scope_id=token.tenant_scope_id
		 AND attempt.operation_id=token.operation_id AND attempt.attempt_id=token.attempt_id
		WHERE token.generation_id=$1 ORDER BY token.ordinal`, generationID)
	if err != nil {
		return nodeDeliveryBinding{}, err
	}
	defer rows.Close()
	var keys []challengeKey
	for rows.Next() {
		var key challengeKey
		var domain, identifier, token, value, challengeType string
		var tokenDigest []byte
		var expires time.Time
		var wildcard bool
		if err := rows.Scan(&key.ScopeID, &key.OperationID, &key.AttemptID, &domain, &tokenDigest, &expires,
			&identifier, &token, &value, &challengeType, &wildcard); err != nil {
			return nodeDeliveryBinding{}, err
		}
		actual := sha256.Sum256([]byte(token))
		if !bytes.Equal(actual[:], tokenDigest) || identifier != domain || challengeType != string(acmeworker.ChallengeHTTP01) ||
			wildcard || !nodeTokenPattern.MatchString(token) || !validNodeChallengeValue(token, value) {
			return nodeDeliveryBinding{}, ErrArtifactIntegrity
		}
		keys = append(keys, key)
		binding.Entries = append(binding.Entries, snapshotEntry{Host: domain, Token: token, Value: value, ExpiresAt: expires.UTC()})
	}
	if err := rows.Err(); err != nil {
		return nodeDeliveryBinding{}, err
	}
	if len(keys) != binding.expectedCount || nodeGenerationDigest(binding.NodeID, binding.Generation, keys) != binding.SnapshotSHA ||
		binding.Purpose != "apply" && (binding.Purpose != snapshotPurposeCleanupOnly || len(keys) != 0) {
		return nodeDeliveryBinding{}, ErrArtifactIntegrity
	}
	return binding, nil
}

// NodeReceipt is one agent status mapped onto a delivery attempt.
type NodeReceipt struct {
	GenerationID uuid.UUID
	NodeID       uuid.UUID
	Generation   int64
	Attempt      int
	// State is "applied", "healthy" or "failed".
	State       string
	FailureCode string
	// ActiveRevision is the node's active overlay revision on a failure.
	ActiveRevision uint64
}

// RecordReceipt applies a receipt. A healthy receipt advances the node's
// latest healthy generation even for a superseded attempt (it is still what
// the node serves). A conflict or stale attempt reported against the current
// generation moves the node to a generation above the agent's revision.
func (s *NodeStore) RecordReceipt(ctx context.Context, receipt NodeReceipt) error {
	if ctx == nil || receipt.GenerationID == uuid.Nil || receipt.Attempt < 1 ||
		receipt.State != "applied" && receipt.State != "healthy" && receipt.State != "failed" ||
		receipt.State == "failed" && !validFailureCode(receipt.FailureCode) {
		return ErrInvalidConfig
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockOverlay(ctx, tx); err != nil {
			return err
		}
		var nodeID uuid.UUID
		var generation int64
		if err := tx.QueryRow(ctx, `SELECT node_id,generation FROM acme_http01_node_overlay_deliveries
			WHERE generation_id=$1 AND attempt=$2`, receipt.GenerationID, receipt.Attempt).Scan(&nodeID, &generation); errors.Is(err, pgx.ErrNoRows) {
			return ErrArtifactBinding
		} else if err != nil {
			return err
		}
		if nodeID != receipt.NodeID || generation != receipt.Generation {
			return ErrArtifactBinding
		}
		now := s.now()
		if err := lockNodeStates(ctx, tx, []uuid.UUID{nodeID}, now); err != nil {
			return err
		}
		var state string
		var currentGeneration int64
		var current bool
		if err := tx.QueryRow(ctx, `SELECT delivery.state,overlay.current_generation,
			       overlay.current_generation_id=delivery.generation_id
			FROM acme_http01_node_overlay_deliveries delivery
			JOIN acme_http01_node_overlay_states overlay ON overlay.node_id=delivery.node_id
			WHERE delivery.generation_id=$1 AND delivery.attempt=$2
			FOR UPDATE OF delivery`, receipt.GenerationID, receipt.Attempt).Scan(&state, &currentGeneration, &current); err != nil {
			return err
		}
		active := state == "pending" || state == "published" || state == "applied"
		switch receipt.State {
		case "healthy":
			if _, err := tx.Exec(ctx, `UPDATE acme_http01_node_overlay_states
				SET latest_healthy_generation=$2,latest_healthy_generation_id=$3,updated_at=$4
				WHERE node_id=$1 AND latest_healthy_generation < $2`, nodeID, generation, receipt.GenerationID, now); err != nil {
				return err
			}
			if err := resolveDebts(ctx, tx, nodeID, receipt.GenerationID, now); err != nil {
				return err
			}
			if active {
				_, err := tx.Exec(ctx, `UPDATE acme_http01_node_overlay_deliveries
					SET state='healthy',lease_token=NULL,lease_expires_at=NULL,updated_at=$3
					WHERE generation_id=$1 AND attempt=$2`, receipt.GenerationID, receipt.Attempt, now)
				return err
			}
			return nil
		case "applied":
			if state == "pending" || state == "published" {
				_, err := tx.Exec(ctx, `UPDATE acme_http01_node_overlay_deliveries
					SET state='applied',lease_token=NULL,lease_expires_at=NULL,
					    attempt_deadline_at=COALESCE(attempt_deadline_at,$4),updated_at=$3
					WHERE generation_id=$1 AND attempt=$2`, receipt.GenerationID, receipt.Attempt, now,
					now.Add(s.config.AttemptTimeout))
				return err
			}
			return nil
		}
		if !active {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE acme_http01_node_overlay_deliveries
			SET state='failed',failure_code=$3,lease_token=NULL,lease_expires_at=NULL,updated_at=$4
			WHERE generation_id=$1 AND attempt=$2`, receipt.GenerationID, receipt.Attempt, receipt.FailureCode, now); err != nil {
			return err
		}
		if !current {
			return nil
		}
		if receipt.FailureCode == "conflict" || receipt.FailureCode == "stale_attempt" {
			floor := currentGeneration + 1
			if receipt.ActiveRevision >= uint64(floor) && receipt.ActiveRevision < 9007199254740990 {
				floor = int64(receipt.ActiveRevision) + 1
			}
			return s.settle(ctx, tx, nil, map[uuid.UUID]bool{nodeID: true}, now, map[uuid.UUID]int64{nodeID: floor})
		}
		_, err := s.scheduleRetry(ctx, tx, receipt.GenerationID, receipt.Attempt, receipt.FailureCode, now, false)
		return err
	})
}

// resolveDebts closes the debts the node's latest healthy generation (when
// it is generationID) proves: a cleanup_debt coverage while the node is not
// required for the site again, or a required coverage of the site's current
// non-empty version while it is.
func resolveDebts(ctx context.Context, tx pgx.Tx, node, generationID uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_cleanup_debt_events(debt_id,sequence,event,generation_id,occurred_at)
		SELECT coverage.cleanup_debt_id,
		       (SELECT max(event.sequence)+1 FROM acme_http01_node_overlay_cleanup_debt_events event
		        WHERE event.debt_id=coverage.cleanup_debt_id),
		       CASE coverage.coverage_kind WHEN 'required' THEN 'resolved_required' ELSE 'resolved_cleanup' END,
		       coverage.generation_id,$3
		FROM acme_http01_node_overlay_generation_coverages coverage
		JOIN acme_http01_node_overlay_states state ON state.node_id=coverage.node_id
		 AND state.latest_healthy_generation_id=coverage.generation_id
		LEFT JOIN LATERAL (
		    SELECT site.current_version_id FROM acme_http01_site_overlay_states site
		    JOIN acme_http01_site_overlay_epoch_members member ON member.epoch_id=site.open_epoch_id
		     AND member.node_id=coverage.node_id
		    JOIN acme_http01_site_overlay_versions version ON version.id=site.current_version_id AND version.token_count > 0
		    WHERE site.tenant_scope_id=coverage.tenant_scope_id AND site.site_id=coverage.site_id
		      AND NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
		                      WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id)
		) required_again ON true
		WHERE coverage.node_id=$1 AND coverage.generation_id=$2 AND coverage.cleanup_debt_id IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
		                  WHERE resolved.debt_id=coverage.cleanup_debt_id
		                    AND resolved.event IN ('resolved_cleanup','resolved_required'))
		  AND ((coverage.coverage_kind='cleanup_debt' AND required_again.current_version_id IS NULL) OR
		       (coverage.coverage_kind='required' AND required_again.current_version_id=coverage.site_version_id))`,
		node, generationID, now)
	return err
}

// NodeReconcileResult counts what one Reconcile pass did.
type NodeReconcileResult struct {
	TimedOut    int
	Regenerated int
	Redelivered int
}

// Reconcile times out attempts past their deadline (retrying them), gives a
// node a new generation once its current one carries a withdrawn or expiring
// token, and re-delivers the current generation to a node that still serves
// stale tokens after its attempts were exhausted.
func (s *NodeStore) Reconcile(ctx context.Context, limit int) (NodeReconcileResult, error) {
	if ctx == nil || limit < 1 || limit > 1000 {
		return NodeReconcileResult{}, ErrInvalidConfig
	}
	var result NodeReconcileResult
	now := s.now()
	rows, err := s.pool.Query(ctx, `SELECT generation_id,attempt,node_id FROM acme_http01_node_overlay_deliveries
		WHERE state IN ('published','applied') AND attempt_deadline_at <= $1
		ORDER BY attempt_deadline_at LIMIT $2`, now, limit)
	if err != nil {
		return result, err
	}
	type expired struct {
		generationID uuid.UUID
		attempt      int
		nodeID       uuid.UUID
	}
	overdue, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (expired, error) {
		var value expired
		return value, row.Scan(&value.generationID, &value.attempt, &value.nodeID)
	})
	if err != nil {
		return result, err
	}
	for _, item := range overdue {
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if err := lockOverlay(ctx, tx); err != nil {
				return err
			}
			now := s.now()
			if err := lockNodeStates(ctx, tx, []uuid.UUID{item.nodeID}, now); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `UPDATE acme_http01_node_overlay_deliveries
				SET state='timed_out',failure_code='attempt_timeout',updated_at=$3
				WHERE generation_id=$1 AND attempt=$2 AND state IN ('published','applied') AND attempt_deadline_at <= $3`,
				item.generationID, item.attempt, now)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			result.TimedOut++
			_, err = s.scheduleRetry(ctx, tx, item.generationID, item.attempt, "attempt_timeout", now, false)
			return err
		})
		if err != nil {
			return result, err
		}
	}
	if err := s.reconcileSites(ctx, limit, &result); err != nil {
		return result, err
	}
	if err := s.alertDriftingSites(ctx, limit); err != nil {
		return result, err
	}
	rows, err = s.pool.Query(ctx, `SELECT state.node_id,
		       EXISTS (
		           SELECT 1 FROM acme_http01_node_overlay_generation_tokens token
		           JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=token.tenant_scope_id
		            AND challenge.operation_id=token.operation_id AND challenge.attempt_id=token.attempt_id
		           WHERE token.generation_id=state.current_generation_id
		             AND (challenge.withdrawn_at IS NOT NULL OR challenge.expires_at <= $1)
		       ) OR current.deadline_at <= $1 AND (current.token_count > 0 OR current.cleanup_debt_coverage_count > 0)
		       OR EXISTS (SELECT 1 FROM acme_http01_overlay_backfill_nodes backfill
		                  WHERE backfill.node_id=state.node_id AND backfill.state='pending') AS regenerate,
		       latest.generation_id,latest.attempt,current.deadline_at
		FROM acme_http01_node_overlay_states state
		JOIN acme_http01_node_overlay_generations current ON current.id=state.current_generation_id
		LEFT JOIN acme_http01_node_overlay_generations healthy ON healthy.id=state.latest_healthy_generation_id
		LEFT JOIN LATERAL (
		    SELECT delivery.generation_id,delivery.attempt,delivery.state,delivery.updated_at
		    FROM acme_http01_node_overlay_deliveries delivery
		    WHERE delivery.generation_id=state.current_generation_id
		    ORDER BY delivery.attempt DESC LIMIT 1
		) latest ON true
		WHERE EXISTS (
		          SELECT 1 FROM acme_http01_node_overlay_generation_tokens token
		          JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=token.tenant_scope_id
		           AND challenge.operation_id=token.operation_id AND challenge.attempt_id=token.attempt_id
		          WHERE token.generation_id=state.current_generation_id
		            AND (challenge.withdrawn_at IS NOT NULL OR challenge.expires_at <= $1)
		      ) OR current.deadline_at <= $1 AND (current.token_count > 0 OR current.cleanup_debt_coverage_count > 0)
		   OR EXISTS (SELECT 1 FROM acme_http01_overlay_backfill_nodes backfill
		              WHERE backfill.node_id=state.node_id AND backfill.state='pending')
		   OR (state.latest_healthy_generation < state.current_generation AND (healthy.token_count > 0 OR
		       EXISTS (SELECT 1 FROM nodes node WHERE node.id=state.node_id AND node.admin_state='active') AND
		       EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debts debt WHERE debt.node_id=state.node_id
		               AND NOT EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
		                               WHERE resolved.debt_id=debt.id
		                                 AND resolved.event IN ('resolved_cleanup','resolved_required'))))
		       AND latest.state IN ('failed','timed_out') AND latest.updated_at <= $2)
		ORDER BY state.node_id LIMIT $3`,
		now.Add(s.config.ExpiryMargin), now.Add(-s.config.StaleRetryInterval), limit)
	if err != nil {
		return result, err
	}
	type stale struct {
		nodeID       uuid.UUID
		regenerate   bool
		generationID *uuid.UUID
		attempt      *int
		deadline     time.Time
	}
	nodes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (stale, error) {
		var value stale
		return value, row.Scan(&value.nodeID, &value.regenerate, &value.generationID, &value.attempt, &value.deadline)
	})
	if err != nil {
		return result, err
	}
	for _, item := range nodes {
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if err := lockOverlay(ctx, tx); err != nil {
				return err
			}
			now := s.now()
			if item.regenerate || item.generationID == nil || !item.deadline.After(now.Add(s.config.AttemptTimeout)) {
				if err := s.settle(ctx, tx, nil, map[uuid.UUID]bool{item.nodeID: true}, now, nil); err != nil {
					return err
				}
				result.Regenerated++
				return nil
			}
			if err := lockNodeStates(ctx, tx, []uuid.UUID{item.nodeID}, now); err != nil {
				return err
			}
			var terminal bool
			if err := tx.QueryRow(ctx, `SELECT state IN ('failed','timed_out') FROM acme_http01_node_overlay_deliveries
				WHERE generation_id=$1 ORDER BY attempt DESC LIMIT 1`, *item.generationID).Scan(&terminal); err != nil || !terminal {
				return err
			}
			var latestAttempt int
			if err := tx.QueryRow(ctx, `SELECT max(attempt) FROM acme_http01_node_overlay_deliveries WHERE generation_id=$1`,
				*item.generationID).Scan(&latestAttempt); err != nil {
				return err
			}
			retried, err := s.scheduleRetry(ctx, tx, *item.generationID, latestAttempt, "stale_redelivery", now, true)
			if retried {
				result.Redelivered++
			}
			return err
		})
		if err != nil {
			return result, err
		}
	}
	return result, nil
}

// reconcileSites refreshes every open epoch whose current version carries a
// withdrawn or expiring token or whose active members are no longer all
// candidates (releasing them with a debt), and gives every node still
// awaiting its 063 bootstrap generation one.
func (s *NodeStore) reconcileSites(ctx context.Context, limit int, result *NodeReconcileResult) error {
	rows, err := s.pool.Query(ctx, `SELECT state.tenant_scope_id,state.site_id
		FROM acme_http01_site_overlay_states state
		JOIN acme_http01_site_overlay_versions version ON version.id=state.current_version_id
		WHERE state.open_epoch_id IS NOT NULL AND (
		    EXISTS (SELECT 1 FROM acme_http01_site_overlay_version_tokens token
		            JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=token.tenant_scope_id
		             AND challenge.operation_id=token.operation_id AND challenge.attempt_id=token.attempt_id
		            WHERE token.version_id=version.id AND (challenge.withdrawn_at IS NOT NULL OR challenge.expires_at <= $1))
		    OR version.token_count = 0
		    OR EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_members member
		               WHERE member.epoch_id=state.open_epoch_id
		                 AND NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
		                                 WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id)
		                 AND member.node_id NOT IN (
		                     SELECT acme_http01_site_candidate_nodes(state.tenant_scope_id, state.site_id))))
		ORDER BY 1,2 LIMIT $2`, s.now().Add(s.config.ExpiryMargin), limit)
	if err != nil {
		return err
	}
	sites, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (siteKey, error) {
		var key siteKey
		return key, row.Scan(&key.ScopeID, &key.SiteID)
	})
	if err != nil {
		return err
	}
	for _, site := range sites {
		if err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if err := lockOverlay(ctx, tx); err != nil {
				return err
			}
			now := s.now()
			touched := map[uuid.UUID]bool{}
			if err := s.refreshSite(ctx, tx, site, now, touched); err != nil {
				return err
			}
			var open bool
			if err := tx.QueryRow(ctx, `SELECT open_epoch_id IS NOT NULL FROM acme_http01_site_overlay_states
				WHERE tenant_scope_id=$1 AND site_id=$2`, site.ScopeID, site.SiteID).Scan(&open); err != nil {
				return err
			}
			if open {
				candidates, err := s.siteCandidates(ctx, tx, site.ScopeID, site.SiteID)
				if err != nil {
					return err
				}
				if _, err := s.openEpoch(ctx, tx, site, candidates, now, touched); err != nil {
					return err
				}
			}
			if len(touched) != 0 {
				result.Regenerated++
			}
			return s.settle(ctx, tx, []siteKey{site}, touched, now, nil)
		}); err != nil {
			return err
		}
	}
	rows, err = s.pool.Query(ctx, `SELECT node_id FROM acme_http01_overlay_backfill_nodes WHERE state='pending'
		ORDER BY node_id LIMIT $1`, limit)
	if err != nil {
		return err
	}
	pending, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, node := range pending {
		if err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if err := lockOverlay(ctx, tx); err != nil {
				return err
			}
			result.Regenerated++
			return s.settle(ctx, tx, nil, map[uuid.UUID]bool{node: true}, s.now(), nil)
		}); err != nil {
			return err
		}
	}
	return nil
}

// ChallengeRemoved: no target node's latest healthy generation (released
// targets included) still serves the challenge's host and token.
func (s *NodeStore) ChallengeRemoved(ctx context.Context, challenge acmeworker.ChallengeIdentity) (bool, error) {
	status, err := s.ChallengeStatus(ctx, challenge)
	if errors.Is(err, ErrInvalidChallenge) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return len(status.Serving) == 0, nil
}
