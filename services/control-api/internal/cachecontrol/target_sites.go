package cachecontrol

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 创建刷新预热任务不再填站点，按每条 URL 的主机名
// 匹配作用域内的网站（主域名、别名、通配域名），一批 URL 按网站拆成多个任务。

const (
	// TargetReasonNoSite: no site in the scope serves the URL's host.
	TargetReasonNoSite = "target_site_not_found"
	// TargetReasonWildcardPrewarm: a prewarm names a "*." host.
	TargetReasonWildcardPrewarm = "target_wildcard_prewarm"
	// maxResolvedSites bounds one resolution (one task per site).
	maxResolvedSites = 500
)

var resolverHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// TargetSiteCandidate is a site a target may belong to, with its active
// names as the edge serves them (empty Domains: Domain alone).
type TargetSiteCandidate struct {
	SiteID    uuid.UUID
	ScopeID   uuid.UUID
	DisplayID string
	Domain    string
	Domains   []string
}

func (candidate TargetSiteCandidate) names() []string {
	if len(candidate.Domains) == 0 {
		return []string{candidate.Domain}
	}
	return candidate.Domains
}

// TargetSiteGroup is one site's targets, by 1-based ordinal in the request.
type TargetSiteGroup struct {
	Site     TargetSiteCandidate
	Ordinals []int
}

type UnmatchedTarget struct {
	Ordinal int
	Reason  string
}

type TargetSiteGrouping struct {
	Groups    []TargetSiteGroup
	Unmatched []UnmatchedTarget
}

type ResolveTargetSitesRequest struct {
	Action     Action
	TargetType TargetType
	Targets    []string
}

// targetHost is the lower-case host of a target URL ("*.x" for a wildcard
// purge target), or "" when the URL is not an http(s) URL with a host.
func targetHost(raw string) string {
	if raw == "" || len(raw) > maxTargetBytes || strings.TrimSpace(raw) != raw {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		(strings.ToLower(parsed.Scheme) != "http" && strings.ToLower(parsed.Scheme) != "https") {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	bare := strings.TrimPrefix(host, "*.")
	if !resolverHostPattern.MatchString(bare) || !strings.Contains(bare, ".") {
		return ""
	}
	return host
}

// GroupTargetsBySite assigns every target to the site that serves its host:
// an exact name first, else the narrowest "*." name, the way nginx
// server_name routes it. A "*." purge target goes to every site it stays
// within (servesWildcard). Groups keep the order of each site's first target.
func GroupTargetsBySite(
	targets []string,
	action Action,
	targetType TargetType,
	candidates []TargetSiteCandidate,
) TargetSiteGrouping {
	result := TargetSiteGrouping{Groups: []TargetSiteGroup{}, Unmatched: []UnmatchedTarget{}}
	index := map[uuid.UUID]int{}
	add := func(site TargetSiteCandidate, ordinal int) {
		position, exists := index[site.SiteID]
		if !exists {
			position = len(result.Groups)
			index[site.SiteID] = position
			result.Groups = append(result.Groups, TargetSiteGroup{Site: site})
		}
		result.Groups[position].Ordinals = append(result.Groups[position].Ordinals, ordinal)
	}
	for offset, raw := range targets {
		ordinal := offset + 1
		host := targetHost(raw)
		if host == "" || targetType == TargetWholeSite {
			result.Unmatched = append(result.Unmatched, UnmatchedTarget{Ordinal: ordinal, Reason: TargetReasonInvalidURL})
			continue
		}
		if suffix, wildcard := strings.CutPrefix(host, "*."); wildcard {
			if action != ActionPurge {
				result.Unmatched = append(result.Unmatched, UnmatchedTarget{Ordinal: ordinal, Reason: TargetReasonWildcardPrewarm})
				continue
			}
			matched := false
			for _, candidate := range candidates {
				if SiteServesWildcard(candidate.names(), suffix) {
					add(candidate, ordinal)
					matched = true
				}
			}
			if !matched {
				result.Unmatched = append(result.Unmatched, UnmatchedTarget{Ordinal: ordinal, Reason: TargetReasonNoSite})
			}
			continue
		}
		best, bestRank := -1, -1
		for position, candidate := range candidates {
			if rank := serveRank(candidate.names(), host); rank > bestRank {
				best, bestRank = position, rank
			}
		}
		if best < 0 {
			result.Unmatched = append(result.Unmatched, UnmatchedTarget{Ordinal: ordinal, Reason: TargetReasonNoSite})
			continue
		}
		add(candidates[best], ordinal)
	}
	return result
}

// serveRank: -1 when the names do not serve host; an exact name outranks
// every "*." name, a longer (narrower) "*." name outranks a shorter one.
func serveRank(names []string, host string) int {
	rank := -1
	for _, name := range names {
		if name == host {
			return 1 << 20
		}
		if SiteServesHost([]string{name}, host) && len(name) > rank {
			rank = len(name)
		}
	}
	return rank
}

// targetSiteCandidateNames are the domain facts that can serve the targets:
// each host and "*." of each parent (exact lookups), and for a "*." purge
// target its suffix (names under it).
func targetSiteCandidateNames(targets []string) (names []string, wildcardSuffixes []string) {
	seen := map[string]bool{}
	addName := func(name string) {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, raw := range targets {
		host := targetHost(raw)
		if host == "" {
			continue
		}
		bare, wildcard := strings.CutPrefix(host, "*.")
		addName(host)
		if wildcard && !slices.Contains(wildcardSuffixes, bare) {
			wildcardSuffixes = append(wildcardSuffixes, bare)
		}
		labels := strings.Split(bare, ".")
		for start := 1; start < len(labels); start++ {
			addName("*." + strings.Join(labels[start:], "."))
		}
	}
	return names, wildcardSuffixes
}

// ResolveTargetSites groups the targets by the sites that serve their hosts.
// A tenant actor matches its own scope's sites. A platform actor with
// allScopes (ScopeID its own platform scope) matches every tenant's sites;
// otherwise the target tenant scope's. It reads with sites.read.
func (store *Store) ResolveTargetSites(
	ctx context.Context,
	actor Actor,
	allScopes bool,
	request ResolveTargetSitesRequest,
) (TargetSiteGrouping, error) {
	if ctx == nil || !validActor(actor) ||
		(request.Action != ActionPurge && request.Action != ActionPrewarm) ||
		(request.TargetType != TargetExactURL && request.TargetType != TargetDirectoryPrefix) ||
		request.Action == ActionPrewarm && request.TargetType != TargetExactURL ||
		len(request.Targets) == 0 || len(request.Targets) > maxTargets ||
		allScopes && actor.ScopeID != actor.ActorScopeID {
		return TargetSiteGrouping{}, ErrInvalidInput
	}
	names, suffixes := targetSiteCandidateNames(request.Targets)
	var result TargetSiteGrouping
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		var scopeFilter *uuid.UUID
		if allScopes {
			if err := store.authorizePlatformActor(ctx, tx, actor, "sites.read"); err != nil {
				return err
			}
		} else {
			if _, err := store.authorizeActor(ctx, tx, actor, "sites.read"); err != nil {
				return err
			}
			scopeFilter = &actor.ScopeID
		}
		candidates, err := loadTargetSiteCandidates(ctx, tx, scopeFilter, names, suffixes)
		if err != nil {
			return err
		}
		result = GroupTargetsBySite(request.Targets, request.Action, request.TargetType, candidates)
		if len(result.Groups) > maxResolvedSites {
			return ErrInvalidInput
		}
		return nil
	})
	return result, err
}

func loadTargetSiteCandidates(
	ctx context.Context,
	tx pgx.Tx,
	scopeFilter *uuid.UUID,
	names, suffixes []string,
) ([]TargetSiteCandidate, error) {
	if len(names) == 0 {
		return nil, nil
	}
	if suffixes == nil {
		suffixes = []string{}
	}
	// Facts are matched by name (the domain index) or, for a "*." purge, by
	// suffix; a site's current names are its latest fact per name (as
	// loadSiteDescriptor reads them). Inside one scope a site without facts
	// is matched by its primary domain.
	rows, err := tx.Query(ctx, `
		WITH matched AS (
			SELECT DISTINCT ON (fact.scope_id,fact.site_id,fact.canonical_domain)
			       fact.scope_id,fact.site_id,fact.action
			FROM site_domain_facts fact
			WHERE ($1::uuid IS NULL OR fact.scope_id=$1)
			  AND (fact.canonical_domain = ANY($2::text[]) OR EXISTS (
			      SELECT 1 FROM unnest($3::text[]) suffix
			      WHERE fact.canonical_domain LIKE '%.' || suffix))
			ORDER BY fact.scope_id,fact.site_id,fact.canonical_domain,fact.global_sequence DESC
		), hits AS (
			SELECT scope_id,site_id FROM matched WHERE action='activate'
			UNION
			SELECT site.scope_id,site.id FROM sites site
			WHERE $1::uuid IS NOT NULL AND site.scope_id=$1 AND site.deleted_at IS NULL
			  AND lower(site.domain) = ANY($2::text[])
		)
		SELECT site.id,site.scope_id,site.display_id::text,site.domain,COALESCE((
		         SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
		         FROM (
		             SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
		             FROM site_domain_facts fact
		             WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
		             ORDER BY fact.canonical_domain,fact.global_sequence DESC
		         ) current_domain WHERE current_domain.action='activate'
		       ),ARRAY[site.domain]::text[])
		FROM hits
		JOIN sites site ON site.scope_id=hits.scope_id AND site.id=hits.site_id AND site.deleted_at IS NULL
		JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
		ORDER BY site.scope_id,site.id
		LIMIT $4`, scopeFilter, names, suffixes, maxResolvedSites*4)
	if err != nil {
		return nil, fmt.Errorf("read cache operation target sites: %w", err)
	}
	defer rows.Close()
	var candidates []TargetSiteCandidate
	for rows.Next() {
		var candidate TargetSiteCandidate
		if err := rows.Scan(&candidate.SiteID, &candidate.ScopeID, &candidate.DisplayID,
			&candidate.Domain, &candidate.Domains); err != nil {
			return nil, fmt.Errorf("scan cache operation target site: %w", err)
		}
		candidate.Domain = strings.ToLower(candidate.Domain)
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read cache operation target sites: %w", err)
	}
	return candidates, nil
}

// authorizePlatformActor admits a platform actor reading across tenants:
// ScopeID is its own platform scope and it holds the permission (or
// platform.admin) there.
func (store *Store) authorizePlatformActor(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if actor.ScopeID != actor.ActorScopeID {
		return ErrPermissionDenied
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`, actor.ScopeID).Scan(&kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("read cache control platform scope: %w", err)
	}
	if kind != "platform" {
		return ErrPermissionDenied
	}
	if store.authorizer != nil {
		session, ok := ctx.Value(sessionAuthorizationContextKey{}).(sessionAuthorization)
		if !ok || session.rawToken == "" {
			return ErrPermissionDenied
		}
		sealed, err := store.authorizer.AuthorizeSession(ctx, tx, session.rawToken, actor.ScopeID, permission)
		if err != nil {
			return fmt.Errorf("%w: formal session authorization", ErrPermissionDenied)
		}
		if _, hasTenant := sealed.TenantID(); hasTenant || sealed.UserID() != actor.UserID ||
			sealed.AuthenticationScopeID() != actor.ScopeID || sealed.TargetScopeID() != actor.ScopeID {
			return ErrPermissionDenied
		}
		return nil
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM memberships membership
		JOIN users actor_user ON actor_user.id=membership.user_id AND actor_user.status='active'
		JOIN role_assignments assignment
		  ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions role_permission ON role_permission.role_id=assignment.role_id
		WHERE membership.scope_id=$1 AND membership.user_id=$2 AND membership.status='active'
		  AND role_permission.permission_name IN ($3,'platform.admin'))`,
		actor.ScopeID, actor.UserID, permission).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize cache control platform actor: %w", err)
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// CarryingNode is a node an automatic operation of the scope goes to.
type CarryingNode struct {
	ID        uuid.UUID
	DisplayID string
	Name      string
	IPv4      string
	IPv6      string
}

// CarryingNodes lists the nodes an operation of the scope without node IDs
// runs on (carryingNodes): the choices of the create dialog's node picker.
func (store *Store) CarryingNodes(ctx context.Context, actor Actor) ([]CarryingNode, error) {
	if ctx == nil || !validActor(actor) {
		return nil, ErrInvalidInput
	}
	nodes := []CarryingNode{}
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, "sites.read"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT node.id,node.display_id::text,node.name,COALESCE(host(node.ipv4),''),COALESCE(host(node.ipv6),'')
			FROM node_config_state state
			JOIN nodes node ON node.id=state.node_id AND node.admin_state='active'
			WHERE state.configuration_scope_id=$1 AND state.current_config_version_id IS NOT NULL
			  AND tenant_carries_node_287($1,state.node_id)
			ORDER BY node.name,node.id
			LIMIT $2`, actor.ScopeID, maxNodes)
		if err != nil {
			return fmt.Errorf("read cache operation carrying nodes: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var node CarryingNode
			if err := rows.Scan(&node.ID, &node.DisplayID, &node.Name, &node.IPv4, &node.IPv6); err != nil {
				return fmt.Errorf("scan cache operation carrying node: %w", err)
			}
			nodes = append(nodes, node)
		}
		return rows.Err()
	})
	return nodes, err
}
