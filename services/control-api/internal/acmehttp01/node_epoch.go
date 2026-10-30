package acmehttp01

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Site epochs and cleanup debts (ADR-0003, migration 342). A site's first
// live challenge opens an epoch and freezes its required membership (the
// site's candidate nodes). Within the epoch every challenge targets the active
// members; a member that stops being a candidate is released with a durable
// cleanup debt; a candidate that is not a member is drift and stays out of the
// site's serving set. The site's last token going away writes the empty
// version, releases every remaining member (site_emptied) and closes the
// epoch.

const (
	releaseMemberRemoved = "member_removed"
	releaseSiteEmptied   = "site_emptied"
)

// lockOverlay serializes every HTTP-01 overlay writer (see migration 342).
func lockOverlay(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('acme-http01-overlay', 0))`)
	return err
}

type siteKey struct {
	ScopeID uuid.UUID
	SiteID  uuid.UUID
}

// siteTokenSetDigest is acme_http01_site_token_set_digest in Go.
func siteTokenSetDigest(site uuid.UUID, keys []challengeKey) [sha256.Size]byte {
	var builder strings.Builder
	fmt.Fprintf(&builder, "cdnca.acme.http01-site-version/v1\n%s\n", site)
	for index, key := range keys {
		if index > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(key.String())
	}
	return sha256.Sum256([]byte(builder.String()))
}

// nonServingProof is acme_http01_non_serving_proof in Go.
func nonServingProof(node uuid.UUID, admin string, generation int64) [sha256.Size]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("cdnca.acme.http01-non-serving/v1\n%s\n%s\n%d", node, admin, generation)))
}

// siteCandidates: the nodes the site's CNAME may reach (before any HTTP-01
// gate), at most MaxTargets.
func (s *NodeStore) siteCandidates(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT node_id FROM acme_http01_site_candidate_nodes($1,$2) node_id
		ORDER BY node_id LIMIT $3`, scopeID, siteID, s.config.MaxTargets+1)
	if err != nil {
		return nil, err
	}
	nodes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	if len(nodes) > s.config.MaxTargets {
		return nil, ErrNoTarget
	}
	return nodes, nil
}

// ensureSiteState creates the site's overlay state when missing and locks it.
func ensureSiteState(ctx context.Context, tx pgx.Tx, site siteKey, now time.Time) error {
	if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_site_overlay_states(tenant_scope_id,site_id,current_version,
		epoch_count,created_at,updated_at) VALUES($1,$2,0,0,$3,$3) ON CONFLICT DO NOTHING`, site.ScopeID, site.SiteID, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT 1 FROM acme_http01_site_overlay_states WHERE tenant_scope_id=$1 AND site_id=$2 FOR UPDATE`,
		site.ScopeID, site.SiteID)
	return err
}

type epochMembership struct {
	EpochID uuid.UUID
	Active  []uuid.UUID
	Members []uuid.UUID
}

// openEpoch returns the site's open epoch with its active members, opening
// one frozen to candidates when none is open. For an open epoch, active
// members that are no longer candidates are released (member_removed) and
// candidates that are not members are reported as drift.
func (s *NodeStore) openEpoch(ctx context.Context, tx pgx.Tx, site siteKey, candidates []uuid.UUID,
	now time.Time, touched map[uuid.UUID]bool) (epochMembership, error) {
	var open *uuid.UUID
	var sequence int64
	if err := tx.QueryRow(ctx, `SELECT open_epoch_id,epoch_count FROM acme_http01_site_overlay_states
		WHERE tenant_scope_id=$1 AND site_id=$2`, site.ScopeID, site.SiteID).Scan(&open, &sequence); err != nil {
		return epochMembership{}, err
	}
	if open == nil {
		if len(candidates) == 0 {
			return epochMembership{}, ErrNoTarget
		}
		epoch := uuid.New()
		digest := nodescheduler.CanonicalNodeSetDigest(candidates)
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_site_overlay_epochs(id,tenant_scope_id,site_id,sequence,
			member_count,member_set_sha256,opened_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			epoch, site.ScopeID, site.SiteID, sequence+1, len(candidates), digest[:], now); err != nil {
			return epochMembership{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_site_overlay_epoch_members(epoch_id,node_id)
			SELECT $1,node_id FROM unnest($2::uuid[]) node_id`, epoch, candidates); err != nil {
			return epochMembership{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE acme_http01_site_overlay_states SET open_epoch_id=$3,epoch_count=$4,
			updated_at=greatest(updated_at,$5) WHERE tenant_scope_id=$1 AND site_id=$2`,
			site.ScopeID, site.SiteID, epoch, sequence+1, now); err != nil {
			return epochMembership{}, err
		}
		return epochMembership{EpochID: epoch, Active: slices.Clone(candidates), Members: slices.Clone(candidates)}, nil
	}
	members, active, err := epochMembers(ctx, tx, *open)
	if err != nil {
		return epochMembership{}, err
	}
	candidate := make(map[uuid.UUID]bool, len(candidates))
	for _, node := range candidates {
		candidate[node] = true
	}
	kept := active[:0:0]
	for _, node := range active {
		if candidate[node] {
			kept = append(kept, node)
			continue
		}
		if err := s.releaseMember(ctx, tx, site, *open, node, releaseMemberRemoved, now); err != nil {
			return epochMembership{}, err
		}
		touched[node] = true
	}
	if drift := epochDrift(members, candidates); len(drift) != 0 {
		slog.Warn("ACME HTTP-01 epoch membership drift: candidates outside the frozen required set stay out of the site's serving set until the epoch closes",
			"site_id", site.SiteID, "epoch_id", *open, "nodes", joinNodeIDs(drift))
		s.alertDrift(ctx, tx, site, *open, drift)
	}
	return epochMembership{EpochID: *open, Active: kept, Members: members}, nil
}

// epochMembers lists the epoch's members and those not released, in node order.
func epochMembers(ctx context.Context, tx pgx.Tx, epoch uuid.UUID) (members, active []uuid.UUID, err error) {
	rows, err := tx.Query(ctx, `SELECT member.node_id, released.node_id IS NULL
		FROM acme_http01_site_overlay_epoch_members member
		LEFT JOIN acme_http01_site_overlay_epoch_releases released ON released.epoch_id=member.epoch_id
		 AND released.node_id=member.node_id
		WHERE member.epoch_id=$1 ORDER BY member.node_id`, epoch)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var node uuid.UUID
		var isActive bool
		if err := rows.Scan(&node, &isActive); err != nil {
			return nil, nil, err
		}
		members = append(members, node)
		if isActive {
			active = append(active, node)
		}
	}
	return members, active, rows.Err()
}

// releaseMember takes node out of the open epoch's required set. It owes a
// cleanup of the epoch's newest non-empty version: a new debt, or (with an
// unresolved debt of the same node and site from an earlier epoch) a
// coalesced event on that debt, which keeps the earliest source.
func (s *NodeStore) releaseMember(ctx context.Context, tx pgx.Tx, site siteKey, epoch, node uuid.UUID,
	reason string, now time.Time) error {
	var versionID uuid.UUID
	var digest []byte
	var count int
	if err := tx.QueryRow(ctx, `SELECT id,token_set_sha256,token_count FROM acme_http01_site_overlay_versions
		WHERE epoch_id=$1 AND token_count > 0 ORDER BY version DESC LIMIT 1`, epoch).Scan(&versionID, &digest, &count); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("ACME HTTP-01 epoch %s has no served version to owe", epoch)
		}
		return err
	}
	var debt uuid.UUID
	var latest int
	err := tx.QueryRow(ctx, `SELECT debt.id,(SELECT max(sequence) FROM acme_http01_node_overlay_cleanup_debt_events event
		    WHERE event.debt_id=debt.id)
		FROM acme_http01_node_overlay_cleanup_debts debt
		WHERE debt.node_id=$1 AND debt.tenant_scope_id=$2 AND debt.site_id=$3 AND NOT EXISTS (
		    SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events resolved
		    WHERE resolved.debt_id=debt.id AND resolved.event IN ('resolved_cleanup','resolved_required'))`,
		node, site.ScopeID, site.SiteID).Scan(&debt, &latest)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		debt = uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_cleanup_debts(id,node_id,tenant_scope_id,site_id,
			required_epoch_id,earliest_uncovered_site_version_id,earliest_token_set_sha256,earliest_token_count,
			opened_reason,opened_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			debt, node, site.ScopeID, site.SiteID, epoch, versionID, digest, count, reason, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_cleanup_debt_events(debt_id,sequence,event,reason,
			epoch_id,site_version_id,occurred_at) VALUES($1,1,'opened',$2,$3,$4,$5)`, debt, reason, epoch, versionID, now); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_node_overlay_cleanup_debt_events(debt_id,sequence,event,reason,
			epoch_id,site_version_id,occurred_at) VALUES($1,$2,'coalesced',$3,$4,$5,$6)`,
			debt, latest+1, reason, epoch, versionID, now); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO acme_http01_site_overlay_epoch_releases(epoch_id,node_id,reason,debt_id,released_at)
		VALUES($1,$2,$3,$4,$5)`, epoch, node, reason, debt, now)
	return err
}

type versionToken struct {
	key     challengeKey
	domain  string
	digest  []byte
	expires time.Time
}

// refreshSite writes a new site version when the live challenges of the
// site's open epoch changed; an empty one closes the epoch. Every node whose
// coverage changes is added to touched.
func (s *NodeStore) refreshSite(ctx context.Context, tx pgx.Tx, site siteKey, now time.Time, touched map[uuid.UUID]bool) error {
	if err := ensureSiteState(ctx, tx, site, now); err != nil {
		return err
	}
	var open *uuid.UUID
	var version int64
	var currentEpoch *uuid.UUID
	var currentDigest []byte
	if err := tx.QueryRow(ctx, `SELECT state.open_epoch_id,state.current_version,version.epoch_id,version.token_set_sha256
		FROM acme_http01_site_overlay_states state
		LEFT JOIN acme_http01_site_overlay_versions version ON version.id=state.current_version_id
		WHERE state.tenant_scope_id=$1 AND state.site_id=$2`, site.ScopeID, site.SiteID).Scan(
		&open, &version, &currentEpoch, &currentDigest); err != nil {
		return err
	}
	if open == nil {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT challenge.tenant_scope_id,challenge.operation_id,challenge.attempt_id,
		       challenge.domain,challenge.token_sha256,challenge.expires_at
		FROM acme_http01_node_challenge_epochs link
		JOIN acme_http01_node_challenges challenge ON challenge.tenant_scope_id=link.tenant_scope_id
		 AND challenge.operation_id=link.operation_id AND challenge.attempt_id=link.attempt_id
		WHERE link.epoch_id=$1 AND challenge.withdrawn_at IS NULL AND challenge.expires_at > $2
		  AND challenge.created_at <= $3
		ORDER BY convert_to(challenge.domain,'UTF8'),challenge.token_sha256,challenge.created_at,
		         challenge.tenant_scope_id,challenge.operation_id,challenge.attempt_id`,
		*open, now.Add(s.config.ExpiryMargin), now)
	if err != nil {
		return err
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (versionToken, error) {
		var value versionToken
		return value, row.Scan(&value.key.ScopeID, &value.key.OperationID, &value.key.AttemptID,
			&value.domain, &value.digest, &value.expires)
	})
	if err != nil {
		return err
	}
	// The same host and token (a CA reusing a pending authorization) is
	// served once; either challenge is confirmed by it.
	live := all[:0]
	for _, token := range all {
		if len(live) > 0 && live[len(live)-1].domain == token.domain && bytes.Equal(live[len(live)-1].digest, token.digest) {
			continue
		}
		live = append(live, token)
	}
	if len(live) > maxNodeSnapshotEntries {
		return fmt.Errorf("%w: site %s would serve more than %d HTTP-01 tokens", ErrNoTarget, site.SiteID, maxNodeSnapshotEntries)
	}
	keys := make([]challengeKey, len(live))
	for index, token := range live {
		keys[index] = token.key
	}
	digest := siteTokenSetDigest(site.SiteID, keys)
	if currentEpoch != nil && *currentEpoch == *open && bytes.Equal(currentDigest, digest[:]) {
		return nil
	}
	versionID := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_site_overlay_versions(id,tenant_scope_id,site_id,version,epoch_id,
		token_count,token_set_sha256,source,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'refresh',$8)`,
		versionID, site.ScopeID, site.SiteID, version+1, *open, len(keys), digest[:], now); err != nil {
		return err
	}
	if len(keys) != 0 {
		scopes, operations, attempts := make([]uuid.UUID, len(keys)), make([]string, len(keys)), make([]uuid.UUID, len(keys))
		for index, key := range keys {
			scopes[index], operations[index], attempts[index] = key.ScopeID, key.OperationID, key.AttemptID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_http01_site_overlay_version_tokens(version_id,ordinal,tenant_scope_id,
			operation_id,attempt_id)
			SELECT $1,ordinal,scope_id,operation_id,attempt_id
			FROM unnest($2::uuid[],$3::text[],$4::uuid[]) WITH ORDINALITY AS item(scope_id,operation_id,attempt_id,ordinal)`,
			versionID, scopes, operations, attempts); err != nil {
			return err
		}
	}
	members, active, err := epochMembers(ctx, tx, *open)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		// Final empty cleanup: every remaining member owes it.
		for _, node := range active {
			if err := s.releaseMember(ctx, tx, site, *open, node, releaseSiteEmptied, now); err != nil {
				return err
			}
		}
		for _, node := range members {
			touched[node] = true
		}
		if _, err := tx.Exec(ctx, `UPDATE acme_http01_site_overlay_states SET current_version=$3,current_version_id=$4,
			open_epoch_id=NULL,updated_at=greatest(updated_at,$5) WHERE tenant_scope_id=$1 AND site_id=$2`,
			site.ScopeID, site.SiteID, version+1, versionID, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE acme_http01_site_overlay_epochs SET closed_at=greatest(opened_at,$2) WHERE id=$1`, *open, now)
		return err
	}
	for _, node := range active {
		touched[node] = true
	}
	_, err = tx.Exec(ctx, `UPDATE acme_http01_site_overlay_states SET current_version=$3,current_version_id=$4,
		updated_at=greatest(updated_at,$5) WHERE tenant_scope_id=$1 AND site_id=$2`,
		site.ScopeID, site.SiteID, version+1, versionID, now)
	return err
}

// settle refreshes every open-epoch site an affected node actively serves
// (so no generation carries an expired or withdrawn token of another site),
// until no new node is affected, then regenerates the affected nodes.
func (s *NodeStore) settle(ctx context.Context, tx pgx.Tx, sites []siteKey, touched map[uuid.UUID]bool,
	now time.Time, minimum map[uuid.UUID]int64) error {
	done := map[siteKey]bool{}
	pending := slices.Clone(sites)
	for len(pending) != 0 {
		for _, site := range pending {
			if done[site] {
				continue
			}
			done[site] = true
			if err := s.refreshSite(ctx, tx, site, now, touched); err != nil {
				return err
			}
		}
		pending = pending[:0]
		nodes := make([]uuid.UUID, 0, len(touched))
		for node := range touched {
			nodes = append(nodes, node)
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT epoch.tenant_scope_id,epoch.site_id
			FROM acme_http01_site_overlay_epoch_members member
			JOIN acme_http01_site_overlay_epochs epoch ON epoch.id=member.epoch_id AND epoch.closed_at IS NULL
			WHERE member.node_id=ANY($1::uuid[]) AND NOT EXISTS (
			    SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
			    WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id)
			ORDER BY 1,2`, nodes)
		if err != nil {
			return err
		}
		related, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (siteKey, error) {
			var key siteKey
			return key, row.Scan(&key.ScopeID, &key.SiteID)
		})
		if err != nil {
			return err
		}
		for _, site := range related {
			if !done[site] {
				pending = append(pending, site)
			}
		}
	}
	nodes := make([]uuid.UUID, 0, len(touched))
	for node := range touched {
		nodes = append(nodes, node)
	}
	return s.regenerateNodes(ctx, tx, nodes, now, minimum)
}
