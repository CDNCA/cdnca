package site

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Administrator-defined CNAME names (migration 658). Only a platform session
// may write them; the HTTP layer adds the permission.
const (
	CNAMELabelSite      = "site"
	CNAMELabelLineGroup = cnameallocation.KindLineGroup
)

// ErrCNAMELabelFollowsPackage: a site in package mode shares the CNAME of its
// package, so it has no name of its own.
var ErrCNAMELabelFollowsPackage = errors.New("site CNAME follows the sold package")

type CNAMELabelRequest struct {
	Kind      string
	SubjectID uuid.UUID
	// Label is the complete name (site) or the prefix (line group); empty clears it.
	Label     string
	RequestID string
}

type CNAMELabelResult struct {
	Label string `json:"label"`
	// Regenerated: sites whose CNAME was re-allocated under the new name.
	Regenerated int `json:"regenerated"`
}

func (s *Store) requireCNAMELabelActor(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if actor.ScopeKind != "platform" || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrPermissionDenied
	}
	var live bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth_sessions
		WHERE id=$1 AND user_id=$2 AND scope_id=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp())`,
		actor.SessionID, actor.UserID, actor.ScopeID).Scan(&live); err != nil {
		return err
	}
	if !live {
		return ErrPermissionDenied
	}
	return nil
}

func validateCNAMELabel(kind, label string) error {
	if label == "" {
		return nil
	}
	if kind == CNAMELabelSite {
		return cnameallocation.ValidateLabel(label)
	}
	return cnameallocation.ValidatePrefix(label)
}

// GetCNAMELabel returns the stored name or prefix ("" when unset).
func (s *Store) GetCNAMELabel(ctx context.Context, actor Actor, kind string, subjectID uuid.UUID) (string, error) {
	var label string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.requireCNAMELabelActor(ctx, tx, actor); err != nil {
			return err
		}
		var value *string
		var err error
		if kind == CNAMELabelSite {
			err = tx.QueryRow(ctx, `SELECT cname_custom_label FROM sites WHERE id=$1 AND deleted_at IS NULL`, subjectID).Scan(&value)
		} else {
			err = tx.QueryRow(ctx, `SELECT (SELECT label FROM cname_label_settings WHERE subject_kind=$1 AND subject_id=$2)
				WHERE `+subjectExists(kind), kind, subjectID).Scan(&value)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if value != nil {
			label = *value
		}
		return nil
	})
	return label, err
}

func subjectExists(kind string) string {
	return `EXISTS(SELECT 1 FROM node_line_groups WHERE id=$2 AND deleted_at IS NULL)`
}

// cnameLabelTaken reports whether another site already uses the name as a host
// label: a claim or a site's name. The CNAME zone of a not yet allocated site
// is unknown, so the check spans every zone.
func cnameLabelTaken(ctx context.Context, tx pgx.Tx, label string, ownSite uuid.UUID) (bool, error) {
	var taken bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM cname_hostname_claims c JOIN cname_allocations a ON a.id=c.allocation_id
			WHERE split_part(lower(c.hostname),'.',1)=$1 AND NOT (a.mode='site' AND a.site_owner_id=$2))
		OR EXISTS (SELECT 1 FROM sites WHERE cname_custom_label=$1 AND id<>$2 AND deleted_at IS NULL)`,
		label, ownSite).Scan(&taken)
	return taken, err
}

// SetCNAMELabel stores the name or prefix. A site name re-allocates the CNAME of
// the site at once (generation advances, DNS is synchronised, the old record is
// retired); a prefix only shapes CNAMEs allocated later.
func (s *Store) SetCNAMELabel(ctx context.Context, actor Actor, req CNAMELabelRequest) (CNAMELabelResult, error) {
	req.Label = strings.ToLower(strings.TrimSpace(req.Label))
	if req.SubjectID == uuid.Nil || req.RequestID == "" {
		return CNAMELabelResult{}, ErrInvalidInput
	}
	switch req.Kind {
	case CNAMELabelSite, CNAMELabelLineGroup:
	default:
		return CNAMELabelResult{}, ErrInvalidInput
	}
	if err := validateCNAMELabel(req.Kind, req.Label); err != nil {
		return CNAMELabelResult{}, err
	}
	var result CNAMELabelResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.requireCNAMELabelActor(ctx, tx, actor); err != nil {
			return err
		}
		var items []cnameallocation.AffectedSite
		scopeID, err := s.cnameLabelScope(ctx, tx, req)
		if err != nil {
			return err
		}
		if scopeID != uuid.Nil {
			if err := lockEdgeConfigurationScope(ctx, tx, scopeID); err != nil {
				return err
			}
		}
		now := s.now().UTC()
		switch req.Kind {
		case CNAMELabelSite:
			var mode *string
			var subscription *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT cname_mode,package_subscription_id FROM sites WHERE id=$1 FOR UPDATE`, req.SubjectID).
				Scan(&mode, &subscription); err != nil {
				return err
			}
			if mode != nil && *mode == "package" {
				return ErrCNAMELabelFollowsPackage
			}
			if req.Label != "" {
				if taken, err := cnameLabelTaken(ctx, tx, req.Label, req.SubjectID); err != nil {
					return err
				} else if taken {
					return cnameallocation.ErrLabelTaken
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE sites SET cname_custom_label=NULLIF($2,''),revision=revision+1,updated_at=$3,updated_by_user_id=$4
				WHERE id=$1`, req.SubjectID, req.Label, now, actor.UserID); err != nil {
				return err
			}
			if mode != nil {
				items = []cnameallocation.AffectedSite{{ScopeID: scopeID, SiteID: req.SubjectID, SubscriptionID: subscription}}
			}
		default:
			if err := writeCNAMELabelSetting(ctx, tx, actor, req, now); err != nil {
				return err
			}
		}
		regenerated, err := s.regenerateSitesTx(ctx, tx, actor, items, req.RequestID, now)
		if err != nil {
			return err
		}
		result = CNAMELabelResult{Label: req.Label, Regenerated: regenerated}
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: req.Kind + ".cname_label.set", ResourceType: req.Kind, ResourceID: req.SubjectID.String(),
			RequestID: req.RequestID, Result: "success",
			Payload: map[string]any{"label": req.Label, "regenerated": regenerated}})
	})
	return result, err
}

// cnameLabelScope is the tenant scope whose configuration the change touches;
// uuid.Nil for a line group prefix, which touches no site.
func (s *Store) cnameLabelScope(ctx context.Context, tx pgx.Tx, req CNAMELabelRequest) (uuid.UUID, error) {
	var scopeID uuid.UUID
	var err error
	switch req.Kind {
	case CNAMELabelSite:
		err = tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1 AND deleted_at IS NULL`, req.SubjectID).Scan(&scopeID)
	default:
		var exists bool
		err = tx.QueryRow(ctx, `SELECT `+strings.Replace(subjectExists(req.Kind), "$2", "$1", 1), req.SubjectID).Scan(&exists)
		if err == nil && !exists {
			err = pgx.ErrNoRows
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return scopeID, err
}

func writeCNAMELabelSetting(ctx context.Context, tx pgx.Tx, actor Actor, req CNAMELabelRequest, now time.Time) error {
	if req.Label == "" {
		_, err := tx.Exec(ctx, `DELETE FROM cname_label_settings WHERE subject_kind=$1 AND subject_id=$2`, req.Kind, req.SubjectID)
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO cname_label_settings(subject_kind,subject_id,label,updated_by_user_id,updated_at)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT (subject_kind,subject_id) DO UPDATE
		SET label=EXCLUDED.label,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
		req.Kind, req.SubjectID, req.Label, actor.UserID, now)
	return err
}

// CountPrefixAffected: how many sites a regeneration under the new prefix would re-allocate.
func (s *Store) CountPrefixAffected(ctx context.Context, actor Actor, kind string, subjectID uuid.UUID) (int, error) {
	if kind != CNAMELabelLineGroup {
		return 0, ErrInvalidInput
	}
	var count int
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.requireCNAMELabelActor(ctx, tx, actor); err != nil {
			return err
		}
		items, err := cnameallocation.PrefixAffectedSites(ctx, tx, kind, subjectID)
		count = len(items)
		return err
	})
	return count, err
}

// RegeneratePrefix re-allocates the CNAME of every site the prefix applies to.
// It returns the number of sites; sites of one package share one new CNAME.
func (s *Store) RegeneratePrefix(ctx context.Context, actor Actor, kind string, subjectID uuid.UUID, requestID string) (int, error) {
	if kind != CNAMELabelLineGroup || requestID == "" {
		return 0, ErrInvalidInput
	}
	var count int
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.requireCNAMELabelActor(ctx, tx, actor); err != nil {
			return err
		}
		items, err := cnameallocation.PrefixAffectedSites(ctx, tx, kind, subjectID)
		if err != nil {
			return err
		}
		if _, err := s.regenerateSitesTx(ctx, tx, actor, items, requestID, s.now().UTC()); err != nil {
			return err
		}
		count = len(items)
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: kind + ".cname_label.regenerate", ResourceType: kind, ResourceID: subjectID.String(),
			RequestID: requestID, Result: "success", Payload: map[string]any{"sites": count}})
	})
	return count, err
}

// regenerateSitesTx queues a regenerating CNAME intent per site (items are
// ordered by scope, site). Sites of one package share the request ID, so
// the first intent re-allocates and the others bind to the new allocation. The
// request ID carries cnameallocation.RelabelRequestPrefix: the allocation then
// advances to a new name instead of refreshing the platform intent in place.
// The scope locks are taken in order, before the site rows.
func (s *Store) regenerateSitesTx(ctx context.Context, tx pgx.Tx, actor Actor, items []cnameallocation.AffectedSite,
	requestID string, now time.Time) (int, error) {
	scopes := map[uuid.UUID]uuid.UUID{}
	for _, item := range items {
		if _, seen := scopes[item.ScopeID]; seen {
			continue
		}
		if err := lockEdgeConfigurationScope(ctx, tx, item.ScopeID); err != nil {
			return 0, err
		}
		var tenantID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1 AND kind='tenant'`, item.ScopeID).Scan(&tenantID); err != nil {
			return 0, err
		}
		scopes[item.ScopeID] = tenantID
	}
	for _, item := range items {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM sites WHERE id=$1 FOR UPDATE`, item.SiteID); err != nil {
			return 0, err
		}
		current, err := selectSite(ctx, tx, item.SiteID)
		if err != nil {
			return 0, err
		}
		mode, domain, hostname := stringValue(current.CNAMEMode), stringValue(current.CNAMEDomain), stringValue(current.CNAMEHostname)
		shared := item.SiteID.String()
		subscriptionID := uuid.Nil
		if item.SubscriptionID != nil && mode == "package" {
			subscriptionID = *item.SubscriptionID
			shared = subscriptionID.String()
		}
		relabelID := cnameallocation.RelabelRequestPrefix + requestID + "/" + shared
		payload, _ := json.Marshal([]any{"cname_label", item.SiteID, current.Revision + 1, mode, domain, hostname, relabelID})
		digest := sha256.Sum256(payload)
		intent := cnameWriteIntent{tenantID: scopes[item.ScopeID], scopeID: item.ScopeID, jobID: uuid.New(), siteID: item.SiteID,
			packageSubscriptionID: subscriptionID, actorScopeID: actor.ScopeID, actorUserID: actor.UserID,
			actorSessionID: actor.SessionID, mode: mode, domain: domain, hostname: hostname,
			idempotencyKey: hex.EncodeToString(digest[:]), requestID: relabelID, traceID: relabelID,
			expectedSiteRevision: current.Revision + 1, digest: digest, regenerate: true}
		if err := insertCNAMEIntentJob(ctx, tx, intent, now); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `UPDATE sites SET cname_state='pending',cname_task_id=$2,
			cname_current_revision=COALESCE(cname_current_revision,0)+1,revision=revision+1,updated_at=$3,updated_by_user_id=$4
			WHERE id=$1`, item.SiteID, intent.jobID, now, actor.UserID); err != nil {
			return 0, err
		}
		if err := insertCNAMEIntentFact(ctx, tx, intent, now); err != nil {
			return 0, fmt.Errorf("record CNAME intent of site %s: %w", item.SiteID, err)
		}
	}
	return len(items), nil
}
