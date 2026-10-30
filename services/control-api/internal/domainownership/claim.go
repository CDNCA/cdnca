package domainownership

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// verifiedOwnership returns the caller's verified proof for apex.
func verifiedOwnership(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, apex string, lock bool) (Ownership, error) {
	query := `SELECT ` + ownershipColumns + ` FROM domain_ownerships WHERE scope_id=$1 AND apex=$2 AND status='verified'`
	if lock {
		query += ` FOR SHARE`
	}
	item, err := scanOwnership(tx.QueryRow(ctx, query, scopeID, apex))
	if errors.Is(err, pgx.ErrNoRows) {
		return Ownership{}, ErrNotVerified
	}
	return item, err
}

// Conflicts lists domains under the caller's verified apex that other
// accounts still have on their sites.
func (s *Service) Conflicts(ctx context.Context, actor Actor, domain string) ([]Conflict, error) {
	apex, err := normalizeApex(domain)
	if err != nil {
		return nil, ErrInvalidInput
	}
	items := make([]Conflict, 0)
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTenant(ctx, tx, actor, "sites.read"); err != nil {
			return err
		}
		if err := requirePolicy(ctx, tx); err != nil {
			return err
		}
		if _, err := verifiedOwnership(ctx, tx, actor.ScopeID, apex, false); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT active.canonical_domain, count(*)::int,
			       bool_or(suspension.id IS NULL)
			FROM site_domain_active active
			JOIN sites site ON site.scope_id=active.scope_id AND site.id=active.site_id AND site.deleted_at IS NULL
			LEFT JOIN domain_claim_suspensions suspension ON suspension.scope_id=active.scope_id AND
			     suspension.site_id=active.site_id AND suspension.canonical_domain=active.canonical_domain AND
			     suspension.released_at IS NULL
			WHERE active.scope_id<>$1 AND (regexp_replace(active.canonical_domain,'^\*\.','')=$2 OR
			      regexp_replace(active.canonical_domain,'^\*\.','') LIKE '%.' || $2)
			GROUP BY active.canonical_domain ORDER BY active.canonical_domain LIMIT $3`,
			actor.ScopeID, apex, maxListLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item Conflict
			if err := rows.Scan(&item.Domain, &item.SiteCount, &item.Claimable); err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list domain conflicts: %w", err)
	}
	return items, nil
}

type claimTarget struct {
	scopeID, siteID, ownerID uuid.UUID
	domains                  []string
	enabled                  bool
	revision                 int64
}

// claimScope is a tenant scope whose sites the claim disables, with its
// source revision read under the configuration row lock before any change.
type claimScope struct {
	ownerID      uuid.UUID
	fromRevision int64
}

// Claim disables every other account's site that still serves one of the
// requested domains under the caller's DNS-TXT-verified apex.
func (s *Service) Claim(ctx context.Context, actor Actor, request ClaimRequest) (ClaimResult, error) {
	apex, err := normalizeApex(request.Apex)
	if err != nil || len(request.Domains) < 1 || len(request.Domains) > maxClaimDomains ||
		!domaintrust.ValidMetadata(request.IdempotencyKey) || !domaintrust.ValidMetadata(request.RequestID) {
		return ClaimResult{}, ErrInvalidInput
	}
	domains := make([]string, 0, len(request.Domains))
	seen := map[string]struct{}{}
	for _, raw := range request.Domains {
		domain, err := domaintrust.Normalize(raw, true)
		if err != nil {
			return ClaimResult{}, ErrInvalidInput
		}
		if domainApex, err := domaintrust.Apex(domain); err != nil || domainApex != apex {
			return ClaimResult{}, ErrInvalidInput
		}
		if _, duplicate := seen[domain]; !duplicate {
			seen[domain] = struct{}{}
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	digest, err := domaintrust.Digest(struct {
		Apex    string   `json:"apex"`
		Domains []string `json:"domains"`
	}{apex, domains})
	if err != nil {
		return ClaimResult{}, err
	}
	write := domaintrust.Write{ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID,
		Operation: operationClaim, Key: request.IdempotencyKey, Digest: digest}
	var result ClaimResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTenant(ctx, tx, actor, "sites.manage"); err != nil {
			return err
		}
		now := s.clock()
		replayed, err := domaintrust.ClaimWrite(ctx, tx, write, now, &result)
		if err != nil {
			if errors.Is(err, domaintrust.ErrIdempotencyConflict) {
				return ErrIdempotencyConflict
			}
			return err
		}
		if replayed {
			result.Replayed = true
			return nil
		}
		if err := requirePolicy(ctx, tx); err != nil {
			return err
		}
		ownership, err := verifiedOwnership(ctx, tx, actor.ScopeID, apex, true)
		if err != nil {
			return err
		}
		if ownership.Method != MethodDNSTXT {
			return ErrClaimRequiresTXT
		}
		targets, scopes, err := lockClaimTargets(ctx, tx, actor.ScopeID, domains)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return ErrNoConflict
		}
		result = ClaimResult{Apex: apex, Domains: domains}
		events := make([]audit.Event, 0, len(targets)+1)
		disabledScopes := map[uuid.UUID]bool{}
		suspensions := map[uuid.UUID][]uuid.UUID{}
		for _, target := range targets {
			for _, domain := range target.domains {
				id := uuid.New()
				if _, err := tx.Exec(ctx, `INSERT INTO domain_claim_suspensions(id,scope_id,site_id,canonical_domain,
					claimant_scope_id,claimant_user_id,ownership_id,request_id,created_at)
					VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, target.scopeID, target.siteID, domain,
					actor.ScopeID, actor.UserID, ownership.ID, request.RequestID, now); err != nil {
					return err
				}
				suspensions[target.siteID] = append(suspensions[target.siteID], id)
			}
			nextRevision := target.revision
			if target.enabled {
				if err := tx.QueryRow(ctx, `UPDATE sites SET enabled=false,status='disabled',revision=revision+1,
					updated_by_user_id=$2,updated_at=$3 WHERE id=$1 AND deleted_at IS NULL RETURNING revision`,
					target.siteID, actor.UserID, now).Scan(&nextRevision); err != nil {
					return err
				}
				disabledScopes[target.scopeID] = true
				result.SuspendedSites++
			}
			events = append(events, audit.Event{
				ScopeID: target.scopeID, ActorUserID: &actor.UserID, Action: "site.domain_claim.suspend",
				ResourceType: "site", ResourceID: target.siteID.String(), RequestID: request.RequestID, Result: "success",
				Payload: map[string]any{
					"domains": target.domains, "claimant_scope_id": actor.ScopeID.String(), "apex": apex,
					"from_enabled": target.enabled, "from_version": target.revision, "to_version": nextRevision,
				},
			})
		}
		events = append(events, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operationClaim,
			ResourceType: "domain_ownership", ResourceID: ownership.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{
				"apex": apex, "domains": domains, "sites": len(targets), "disabled_sites": result.SuspendedSites,
			},
		})
		if err := appendOrdered(ctx, tx, s.auditor, events); err != nil {
			return err
		}
		ordered := make([]uuid.UUID, 0, len(disabledScopes))
		for scopeID := range disabledScopes {
			ordered = append(ordered, scopeID)
		}
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].String() < ordered[j].String() })
		for _, scopeID := range ordered {
			if err := s.publisher.PublishClaimSuspensionTx(ctx, tx, ClaimSuspensionPublication{
				TargetScopeID: scopeID, SiteOwnerUserID: scopes[scopeID].ownerID,
				FromRevision: scopes[scopeID].fromRevision, Operation: "site.batch.disable",
				ClaimantScopeID: actor.ScopeID, ClaimantUserID: actor.UserID, RequestID: request.RequestID,
			}); err != nil {
				return err
			}
		}
		s.notifySuspended(ctx, tx, targets, suspensions, request.RequestID, &result)
		return domaintrust.CompleteWrite(ctx, tx, write, 200, result, now)
	})
	if err != nil {
		return ClaimResult{}, fmt.Errorf("claim domain: %w", err)
	}
	return result, nil
}

// lockClaimTargets finds other accounts' sites whose current domains overlap
// the requested ones (same rules as the 148 guard), skipping domains already
// suspended, then locks in publication order: each target scope's
// configuration row (reading its source revision before the claim changes
// anything), then the sites.
func lockClaimTargets(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, domains []string) ([]claimTarget, map[uuid.UUID]claimScope, error) {
	rows, err := tx.Query(ctx, `
		SELECT site.scope_id, site.id, site.owner_user_id, site.enabled, site.revision,
		       array_agg(DISTINCT active.canonical_domain ORDER BY active.canonical_domain)
		FROM site_domain_active active
		JOIN unnest($2::text[]) wanted(domain) ON
		     active.canonical_domain = wanted.domain OR
		     (wanted.domain NOT LIKE '*.%' AND active.canonical_domain = '*.' || site_domain_family_299(wanted.domain)) OR
		     (wanted.domain LIKE '*.%' AND active.canonical_domain NOT LIKE '*.%' AND
		      active.family_domain = substring(wanted.domain FROM 3))
		JOIN sites site ON site.scope_id=active.scope_id AND site.id=active.site_id AND site.deleted_at IS NULL
		WHERE active.scope_id<>$1 AND NOT EXISTS (
			SELECT 1 FROM domain_claim_suspensions suspension
			WHERE suspension.scope_id=active.scope_id AND suspension.site_id=active.site_id AND
			      suspension.canonical_domain=active.canonical_domain AND suspension.released_at IS NULL)
		GROUP BY site.scope_id, site.id
		ORDER BY site.scope_id, site.id`, scopeID, domains)
	if err != nil {
		return nil, nil, err
	}
	targets := make([]claimTarget, 0)
	for rows.Next() {
		var target claimTarget
		if err := rows.Scan(&target.scopeID, &target.siteID, &target.ownerID, &target.enabled,
			&target.revision, &target.domains); err != nil {
			rows.Close()
			return nil, nil, err
		}
		targets = append(targets, target)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	scopes := map[uuid.UUID]claimScope{}
	for _, target := range targets { // ordered by scope_id, site_id
		if _, seen := scopes[target.scopeID]; seen {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
			VALUES($1,1,clock_timestamp()) ON CONFLICT(scope_id) DO NOTHING`, target.scopeID); err != nil {
			return nil, nil, err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
			target.scopeID).Scan(&revision); err != nil {
			return nil, nil, err
		}
		scopes[target.scopeID] = claimScope{ownerID: target.ownerID, fromRevision: revision}
	}
	for index := range targets {
		if err := tx.QueryRow(ctx, `SELECT enabled,revision FROM sites WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`,
			targets[index].siteID).Scan(&targets[index].enabled, &targets[index].revision); err != nil {
			return nil, nil, err
		}
	}
	return targets, scopes, nil
}

// notifySuspended tells each disabled site's owner (the unverified side);
// the claimant gets no notice. A delivery problem only
// counts as lost; the claim still commits.
func (s *Service) notifySuspended(ctx context.Context, tx pgx.Tx, targets []claimTarget,
	suspensions map[uuid.UUID][]uuid.UUID, requestID string, result *ClaimResult) {
	if s.notifier == nil {
		return
	}
	for _, target := range targets {
		if len(suspensions[target.siteID]) == 0 {
			continue
		}
		values := notification.TemplateContext{"domain": notification.PublicValue(target.domains[0])}
		_, err := s.notifier.EnqueueTx(ctx, tx, notification.EnqueueRequest{
			ScopeID: target.scopeID, RecipientID: target.ownerID, SourceEventID: suspensions[target.siteID][0].String(),
			EventType: eventSuspended, Policy: notification.DeliverySystemRequired,
			Templates: map[notification.Channel]notification.TemplateRef{
				notification.ChannelSMS:   {ID: templateSuspended, Version: 1, Channel: notification.ChannelSMS},
				notification.ChannelEmail: {ID: templateSuspended, Version: 1, Channel: notification.ChannelEmail},
			},
			Contexts:       map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values},
			AuditRequestID: requestID, SubjectSiteID: &target.siteID,
		})
		if err != nil {
			result.NotificationsLost++
			continue
		}
		result.NotificationsSent++
	}
}

const suspensionColumns = `id,scope_id,site_id,canonical_domain,claimant_scope_id,created_at,released_at,
	COALESCE(release_reason,'')`

func scanSuspensions(rows pgx.Rows, revealClaimant bool) ([]Suspension, error) {
	defer rows.Close()
	items := make([]Suspension, 0)
	for rows.Next() {
		var item Suspension
		var claimant uuid.UUID
		if err := rows.Scan(&item.ID, &item.ScopeID, &item.SiteID, &item.Domain, &claimant, &item.CreatedAt,
			&item.ReleasedAt, &item.ReleaseReason); err != nil {
			return nil, err
		}
		if revealClaimant {
			item.ClaimantScopeID = &claimant
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListMySuspensions returns the caller's sites disabled by a claim.
func (s *Service) ListMySuspensions(ctx context.Context, actor Actor) ([]Suspension, error) {
	var items []Suspension
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTenant(ctx, tx, actor, "sites.read"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+suspensionColumns+` FROM domain_claim_suspensions
			WHERE scope_id=$1 AND released_at IS NULL ORDER BY created_at DESC, id DESC LIMIT $2`,
			actor.ScopeID, maxListLimit)
		if err != nil {
			return err
		}
		items, err = scanSuspensions(rows, false)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list claim suspensions: %w", err)
	}
	return items, nil
}

// ClaimSuspensionPublication is one tenant scope whose sites a claim just
// disabled; the edge must stop serving them.
type ClaimSuspensionPublication struct {
	TargetScopeID   uuid.UUID
	SiteOwnerUserID uuid.UUID // owner of the first disabled site in the scope
	// FromRevision is the scope's source revision read under its
	// configuration row lock before the claim disabled anything.
	FromRevision    int64
	Operation       string // site.batch.disable
	ClaimantScopeID uuid.UUID
	ClaimantUserID  uuid.UUID
	RequestID       string
}

// ClaimSuspensionPublisher publishes the disabled sites inside the claim
// transaction (replace with WithClaimSuspensionPublisher).
type ClaimSuspensionPublisher interface {
	PublishClaimSuspensionTx(context.Context, pgx.Tx, ClaimSuspensionPublication) error
}

// ClaimRepublishImmediately is the smallest delay system republication
// accepts (0 means its 5 s debounce): a claimed site leaves the nodes now.
const ClaimRepublishImmediately = time.Millisecond

// SystemRepublishPublisher hands the disabled sites to system republication
// (trigger domain_ownership): an automatic scope republishes
// through its policy, any other scope redelivers what it last published with
// the claim's site advances attributed to domain ownership.
type SystemRepublishPublisher struct{}

func (SystemRepublishPublisher) PublishClaimSuspensionTx(ctx context.Context, tx pgx.Tx, item ClaimSuspensionPublication) error {
	_, err := edgeautopublish.RequestRepublicationTx(ctx, tx, edgeautopublish.RepublishRequest{
		ScopeID: item.TargetScopeID, Trigger: edgepublish.SystemTriggerDomainOwnership, Operation: item.Operation,
		SourceRequestID: item.RequestID, FromRevision: item.FromRevision, Debounce: ClaimRepublishImmediately,
	})
	return err
}
