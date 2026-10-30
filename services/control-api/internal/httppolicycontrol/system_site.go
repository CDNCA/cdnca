package httppolicycontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// System writes for one site (fix-mktsiteconf3 ③): a market leaf keeps its
// site's HTTP policy equal to what the subscriber sends. It has no IAM
// session, so it writes as the tenant owner (the revision trigger checks
// that account's http_policies.manage; a tenant_owner holds it), without the
// session authorizer and the entitlement gate (the subscriber's site already
// passed its own; the leaf grant decides the leaf). The audit events are the
// ones the revision trigger requires, with actor kind system.

// NormalizeConfig validates config as a write would (ErrValidation).
func NormalizeConfig(config Config) (Config, error) { return normalizeConfig(config) }

// ErrSystemWrite: the target is not one site of the scope owned by ownerID.
var ErrSystemWrite = errors.New("HTTP policy system write target is invalid")

// SystemSiteWrite is the HTTP policy wanted for a site: nil config removes it
// (delete when there is one), otherwise it is created or updated enabled.
type SystemSiteWrite struct {
	ScopeID, SiteID, OwnerUserID uuid.UUID
	Config                       *Config
	// RequestID ties the audit events and the publication to the caller.
	RequestID string
	// ActorRef names the system actor in the audit ("job:<name>").
	ActorRef string
}

// SetSiteSystem makes the site's live HTTP policy equal to request.Config
// (validated like a write) and reports whether it wrote a revision.
func (store *Store) SetSiteSystem(ctx context.Context, request SystemSiteWrite) (bool, error) {
	if store == nil || store.pool == nil || request.ScopeID == uuid.Nil || request.SiteID == uuid.Nil ||
		request.OwnerUserID == uuid.Nil || request.RequestID == "" || request.ActorRef == "" {
		return false, ErrSystemWrite
	}
	var wanted Config
	if request.Config != nil {
		normalized, err := normalizeConfig(*request.Config)
		if err != nil {
			return false, err
		}
		wanted = normalized
	}
	now := store.now
	if now == nil {
		now = time.Now
	}
	changed := false
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var tenantID, ownerID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT scope.tenant_id, site.owner_user_id FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
			WHERE site.id=$1 AND site.scope_id=$2 AND site.deleted_at IS NULL FOR SHARE OF site`,
			request.SiteID, request.ScopeID).Scan(&tenantID, &ownerID); errors.Is(err, pgx.ErrNoRows) {
			return ErrSystemWrite
		} else if err != nil {
			return err
		}
		if ownerID != request.OwnerUserID {
			return ErrSystemWrite
		}
		var policyID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM http_policies WHERE tenant_scope_id=$1 AND site_id=$2 AND deleted_at IS NULL`,
			request.ScopeID, request.SiteID).Scan(&policyID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		actor := Actor{UserID: ownerID, ScopeID: request.ScopeID, ScopeKind: "tenant"}
		at := now().UTC().Truncate(time.Microsecond)
		var item storedPolicy
		action := "create"
		if policyID == uuid.Nil {
			if request.Config == nil {
				return nil
			}
			if policyID, err = uuid.NewV7(); err != nil {
				return err
			}
			item = storedPolicy{Policy: Policy{ID: policyID, TenantScopeID: request.ScopeID, SiteID: request.SiteID,
				SiteOwnerUserID: ownerID, Enabled: true, Revision: 1, CreatedAt: at, UpdatedAt: at}, TenantID: tenantID}
			applyConfig(&item.Policy, wanted)
		} else {
			if item, err = lockPolicy(ctx, tx, actor, request.ScopeID, policyID, false); err != nil {
				return err
			}
			switch {
			case request.Config == nil:
				action, item.Enabled, item.Deleted = "delete", false, true
			case !item.Enabled:
				// A disabled policy is deleted and created again enabled: the
				// revision trigger allows an update only within one state.
				action, item.Enabled, item.Deleted = "delete", false, true
			case reflect.DeepEqual(configFromPolicy(item.Policy), wanted):
				return nil
			default:
				action = "update"
				applyConfig(&item.Policy, wanted)
			}
			item.Revision++
			item.UpdatedAt = at
		}
		if err := store.writeSystemRevision(ctx, tx, actor, item, request, action); err != nil {
			return err
		}
		changed = true
		if action == "delete" && request.Config != nil {
			// Re-create the disabled policy enabled with the wanted config.
			next, err := uuid.NewV7()
			if err != nil {
				return err
			}
			item = storedPolicy{Policy: Policy{ID: next, TenantScopeID: request.ScopeID, SiteID: request.SiteID,
				SiteOwnerUserID: ownerID, Enabled: true, Revision: 1, CreatedAt: at, UpdatedAt: at}, TenantID: tenantID}
			applyConfig(&item.Policy, wanted)
			if err := store.writeSystemRevision(ctx, tx, actor, item, request, "create"); err != nil {
				return err
			}
		}
		return store.publishRevisionTx(ctx, tx, request.ScopeID, request.SiteID, request.RequestID)
	})
	if err != nil {
		return false, fmt.Errorf("set site HTTP policy: %w", err)
	}
	return changed, nil
}

// writeSystemRevision writes one revision with its success audit event
// (system actor; the revision trigger requires the owner as actor user).
func (store *Store) writeSystemRevision(ctx context.Context, tx pgx.Tx, actor Actor, item storedPolicy,
	request SystemSiteWrite, action string) error {
	if err := store.ensurePublicationCandidate(ctx, tx, item); err != nil {
		return err
	}
	// http_policy_revisions.trace_id allows [A-Za-z0-9._:-] only (056): ":" joins, not "/".
	metadata := WriteMetadata{RequestID: request.RequestID, TraceID: request.RequestID + ":" + item.ID.String()}
	if err := insertRevision(ctx, tx, actor, item, metadata, action); err != nil {
		return err
	}
	revision, err := publicationRevision(ctx, tx, item.TenantScopeID)
	if err != nil {
		return err
	}
	changes, err := json.Marshal(configFromPolicy(item.Policy))
	if err != nil {
		return err
	}
	return (audit.New(nil)).Append(ctx, tx, audit.Event{
		ScopeID: item.TenantScopeID, ActorUserID: &actor.UserID, ActorKind: "system", ActorRef: request.ActorRef,
		Action: "http_policy." + action, ResourceType: "http_policy", ResourceID: item.ID.String(),
		RequestID: metadata.RequestID, Result: "success",
		Payload: map[string]any{"trace_id": metadata.TraceID, "revision": item.Revision,
			"publication_revision": revision, "site_id": item.SiteID.String(), "enabled": item.Enabled,
			"source": "market_leaf_sync", "config_bytes": len(changes)},
	})
}
