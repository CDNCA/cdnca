package rulepackcontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// NewVersion is a compiled pack version to keep as a downloaded local
// artifact. CreatedBy is the user recorded on the rows (the importer, or the
// subscriber for a subscription version). Actor is who caused it for the
// audit event: nil = the system (a scheduled subscription fetch).
type NewVersion struct {
	Compiled  *rulepack.CompiledPack
	Source    string
	CreatedBy uuid.UUID
	Actor     *Actor
	// Audit carries extra payload keys (e.g. the subscription it came from).
	Audit map[string]any
	// AuditScopeID, when set, is the scope the system event is written to
	// (a market pack: the tenant whose administrator confirmed the plugin).
	AuditScopeID uuid.UUID
}

// SourceMarket marks a developer pack bought on the plugin market (PA-18):
// added by artifact sync, never enabled by itself.
const SourceMarket = "market"

// SubscriptionPackPrefix starts the name of every pack a WAF rule
// subscription keeps for a subscribing tenant (user/<tenant>/waf-sub-<id>).
const SubscriptionPackPrefix = "waf-sub-"

// IsSubscriptionPack reports whether packID is a subscription's user pack.
func IsSubscriptionPack(packID string) bool {
	if _, ok := rulepack.UserPackScope(packID); !ok {
		return false
	}
	return strings.HasPrefix(packID[strings.LastIndex(packID, "/")+1:], SubscriptionPackPrefix)
}

// AddedVersion is what AddVersion did.
type AddedVersion struct {
	PackID          string
	Version         string
	PreviousCurrent string
	Current         bool
}

// AddVersion inserts the pack row (first version) and the artifact in tx,
// makes the version current when it is the first one or the pack updates
// automatically, and writes rule.pack.version.create. Nothing is enabled:
// a new current version reaches a site only when the site is published.
func AddVersion(ctx context.Context, tx pgx.Tx, now time.Time, input NewVersion) (AddedVersion, error) {
	pack := input.Compiled.Pack
	var owner *uuid.UUID
	if pack.Layer == rulepack.LayerUser {
		scope, _ := rulepack.UserPackScope(pack.PackID)
		parsed := uuid.MustParse(scope)
		owner = &parsed
	}
	if input.Source == SourceMarket && pack.Layer != rulepack.LayerDeveloper {
		return AddedVersion{}, fmt.Errorf("%w: a market rule pack must be a developer pack", ErrInvalidInput)
	}
	policy := "manual"
	if pack.Layer == rulepack.LayerSystem || input.Source == "subscription" {
		// System packs and subscriptions follow their source ("自动下载并自动启用新版本"
		// for the current version; sites still publish it themselves).
		policy = "auto"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rule_packs(pack_id,layer,owner_scope_id,current_version,update_policy,
		created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,NULL,$4,$5,$5,$6,$6)
		ON CONFLICT (pack_id) DO NOTHING`, pack.PackID, pack.Layer, owner, policy, input.CreatedBy, now); err != nil {
		return AddedVersion{}, err
	}
	var current *string
	var updatePolicy string
	if err := tx.QueryRow(ctx, `SELECT current_version, update_policy FROM rule_packs WHERE pack_id=$1 FOR UPDATE`,
		pack.PackID).Scan(&current, &updatePolicy); err != nil {
		return AddedVersion{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,
		size_bytes,content,source,state,downloaded_at,created_by_user_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'downloaded',$10,$11,$10)`, pack.PackID, pack.Version, pack.Engine,
		pack.EngineMinVersion, pack.Name, input.Compiled.SHA256, len(input.Compiled.Canonical), input.Compiled.Canonical,
		input.Source, now, input.CreatedBy); err != nil {
		if isUniqueViolation(err) {
			return AddedVersion{}, ErrExists
		}
		return AddedVersion{}, err
	}
	added := AddedVersion{PackID: pack.PackID, Version: pack.Version}
	if current != nil {
		added.PreviousCurrent = *current
	}
	// The first version is current; later ones only under update_policy
	// auto, otherwise an operator picks it.
	if current == nil || updatePolicy == "auto" {
		if _, err := tx.Exec(ctx, `UPDATE rule_packs SET current_version=$2, updated_by_user_id=$3, updated_at=$4
			WHERE pack_id=$1`, pack.PackID, pack.Version, input.CreatedBy, now); err != nil {
			return AddedVersion{}, err
		}
		added.Current = true
	}
	return added, appendVersionAudit(ctx, tx, now, input, added)
}

func appendVersionAudit(ctx context.Context, tx pgx.Tx, now time.Time, input NewVersion, added AddedVersion) error {
	scopeID := input.AuditScopeID
	owner, isUserPack := rulepack.UserPackScope(added.PackID)
	switch {
	case isUserPack:
		scopeID = uuid.MustParse(owner)
	case scopeID != uuid.Nil:
	case input.Actor != nil && input.Actor.platform():
		scopeID = input.Actor.ScopeID
	default:
		if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY id LIMIT 1`).
			Scan(&scopeID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errors.New("rule pack audit: no platform scope")
			}
			return err
		}
	}
	payload := map[string]any{"pack_id": added.PackID, "version": added.Version, "source": input.Source,
		"sha256": input.Compiled.SHA256, "rules": len(input.Compiled.Pack.Rules), "engine": input.Compiled.Pack.Engine,
		"actor": "system", "ip": ""}
	changes := map[string]any{"versions": map[string]any{"added": added.Version}}
	if added.Current {
		changes["current_version"] = map[string]any{"from": added.PreviousCurrent, "to": added.Version}
	}
	payload["changes"] = changes
	for key, value := range input.Audit {
		payload[key] = value
	}
	event := audit.Event{ScopeID: scopeID, Action: "rule.pack.version.create", ResourceType: "rule_pack",
		ResourceID: added.PackID + "@" + added.Version, Result: "success", Payload: payload,
		RequestID: "rule-pack-version-" + uuid.NewString()}
	if actor := input.Actor; actor != nil {
		userID := actor.UserID
		event.ActorUserID = &userID
		payload["actor"], payload["ip"] = "user", actor.SourceIP
		if actor.RequestID != "" {
			event.RequestID = actor.RequestID
		}
	}
	return audit.NewWithClock(nil, func() time.Time { return now }).Append(ctx, tx, event)
}
