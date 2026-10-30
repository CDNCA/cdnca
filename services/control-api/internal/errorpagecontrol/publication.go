package errorpagecontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func lockPublication(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('error-page-publication',0))`)
	return err
}

func (s *Service) appendPublication(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	metadata WriteMetadata,
	targetScopeID uuid.UUID,
	limits EntitlementLimits,
) (PublicationSnapshot, error) {
	return insertPublication(ctx, tx, actor.UserID, actor.ScopeID, metadata, targetScopeID, &limits, storeTime(s.now()))
}

// AppendThemePublication records a new error page publication revision for a
// theme activation (ADR 0007 §7.3): the same rules, pinned to the theme now
// active, so each tenant's next publish carries the theme's default pages and
// node revisions stay monotonic. actor is the platform user who activated it.
func AppendThemePublication(ctx context.Context, tx pgx.Tx, userID, platformScopeID uuid.UUID, requestID, traceID string, now time.Time) (PublicationSnapshot, error) {
	if tx == nil || userID == uuid.Nil || platformScopeID == uuid.Nil {
		return PublicationSnapshot{}, ErrInvalidInput
	}
	if err := validateWriteMetadata(WriteMetadata{IdempotencyKey: requestID, RequestID: requestID, TraceID: traceID}); err != nil {
		return PublicationSnapshot{}, err
	}
	if err := lockPublication(ctx, tx); err != nil {
		return PublicationSnapshot{}, err
	}
	return insertPublication(ctx, tx, userID, platformScopeID,
		WriteMetadata{IdempotencyKey: requestID, RequestID: requestID, TraceID: traceID}, uuid.Nil, nil, storeTime(now))
}

func insertPublication(
	ctx context.Context,
	tx pgx.Tx,
	userID, actorScopeID uuid.UUID,
	metadata WriteMetadata,
	targetScopeID uuid.UUID,
	limits *EntitlementLimits,
	now time.Time,
) (PublicationSnapshot, error) {
	var platformScopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScopeID); err != nil {
		return PublicationSnapshot{}, err
	}
	var previousRevision int64
	var previousHash []byte
	err := tx.QueryRow(ctx, `SELECT revision,snapshot_sha256 FROM error_page_publications
		ORDER BY revision DESC LIMIT 1`).Scan(&previousRevision, &previousHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return PublicationSnapshot{}, err
	}
	revision := previousRevision + 1
	policy, err := buildSnapshot(ctx, tx, revision, MaxPublicationSites, MaxEdgeRulesPerScope)
	if err != nil {
		return PublicationSnapshot{}, err
	}
	canonical, err := json.Marshal(policy)
	if err != nil {
		return PublicationSnapshot{}, err
	}
	if err := validatePublicationBounds(canonical, len(policy.Sites)); err != nil {
		return PublicationSnapshot{}, err
	}
	if limits != nil {
		scopedPolicy, err := buildSnapshotForScope(ctx, tx, revision, limits.MaxPublicationSites,
			limits.MaxRulesPerScope, targetScopeID)
		if err != nil {
			return PublicationSnapshot{}, err
		}
		scopedCanonical, err := json.Marshal(scopedPolicy)
		if err != nil {
			return PublicationSnapshot{}, err
		}
		if err := validatePublicationLimits(scopedCanonical, len(scopedPolicy.Sites), *limits); err != nil {
			return PublicationSnapshot{}, err
		}
	}
	digest := sha256.Sum256(canonical)
	_, err = tx.Exec(ctx, `INSERT INTO error_page_publications (
		revision,platform_scope_id,schema,version,canonical_snapshot,snapshot_sha256,previous_sha256,
		created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, revision, platformScopeID,
		SchemaV1, policy.Version, canonical, digest[:], nullableBytes(previousHash), userID,
		actorScopeID, metadata.RequestID, metadata.TraceID, now)
	if err != nil {
		return PublicationSnapshot{}, err
	}
	return PublicationSnapshot{Policy: policy, SHA256: hex.EncodeToString(digest[:]), CreatedAt: now}, nil
}

func buildSnapshot(
	ctx context.Context,
	tx pgx.Tx,
	revision int64,
	maxSites int,
	maxRulesPerScope int,
) (Snapshot, error) {
	return buildSnapshotForScope(ctx, tx, revision, maxSites, maxRulesPerScope, uuid.Nil)
}

func buildSnapshotForScope(
	ctx context.Context,
	tx pgx.Tx,
	revision int64,
	maxSites int,
	maxRulesPerScope int,
	targetScopeID uuid.UUID,
) (Snapshot, error) {
	if maxSites < 1 || maxRulesPerScope < 1 {
		return Snapshot{}, ErrUnavailable
	}
	if maxSites > MaxPublicationSites {
		maxSites = MaxPublicationSites
	}
	if maxRulesPerScope > MaxEdgeRulesPerScope {
		maxRulesPerScope = MaxEdgeRulesPerScope
	}
	policy := Snapshot{
		Schema: SchemaV1, Version: "control-" + strconv.FormatInt(revision, 10), Revision: revision,
		Global: SnapshotScope{Rules: []SnapshotRule{}}, Sites: []SnapshotSite{},
	}
	rows, err := tx.Query(ctx, `SELECT identity.scope_kind,identity.site_id,identity.id,current.category,
		current.match_kind,current.code_from,current.code_to,asset.mime_type,asset.size_bytes,asset.sha256
		FROM error_page_rules identity
		JOIN LATERAL (
			SELECT revision.* FROM error_page_rule_revisions revision
			WHERE revision.rule_id=identity.id ORDER BY revision.revision DESC LIMIT 1
		) current ON true
		JOIN error_page_assets asset ON asset.id=current.asset_id
		LEFT JOIN sites site ON identity.scope_kind='site' AND site.id=identity.site_id
			AND site.scope_id=identity.scope_id AND site.deleted_at IS NULL
		WHERE current.enabled AND NOT current.deleted AND asset.status='ready'
		  AND ($2::uuid IS NULL OR identity.scope_id=$2)
		  AND (identity.scope_kind='global' OR site.id IS NOT NULL)
		ORDER BY identity.scope_kind,identity.site_id NULLS FIRST,current.category,current.priority,
			current.code_from,current.code_to,identity.id
		LIMIT $1`, maxRulesPerScope*(maxSites+1)+1, nullableUUID(targetScopeID))
	if err != nil {
		return Snapshot{}, err
	}
	defer rows.Close()
	sites := make(map[string][]SnapshotRule)
	ruleCount := 0
	for rows.Next() {
		ruleCount++
		if ruleCount > maxRulesPerScope*(maxSites+1) {
			return Snapshot{}, ErrQuotaExceeded
		}
		var scopeKind, category, matchKind, mime string
		var siteID *uuid.UUID
		var ruleID uuid.UUID
		var from, to int
		var size int64
		var digest []byte
		if err := rows.Scan(&scopeKind, &siteID, &ruleID, &category, &matchKind, &from, &to,
			&mime, &size, &digest); err != nil {
			return Snapshot{}, err
		}
		if len(digest) != 32 {
			return Snapshot{}, ErrConflict
		}
		digestString := hex.EncodeToString(digest)
		rule := SnapshotRule{
			ID: ruleID.String(), Category: category,
			Resource: SnapshotResource{
				MIMEType: mime, Size: size, SHA256: digestString, File: "sha256/" + digestString,
			},
		}
		if matchKind == MatchExact {
			rule.Match.Codes = []int{from}
		} else {
			rule.Match.Ranges = []SnapshotRange{{From: from, To: to}}
		}
		if scopeKind == ScopeGlobal {
			policy.Global.Rules = append(policy.Global.Rules, rule)
			if len(policy.Global.Rules) > maxRulesPerScope {
				return Snapshot{}, ErrQuotaExceeded
			}
			continue
		}
		if siteID == nil {
			return Snapshot{}, ErrConflict
		}
		key := siteID.String()
		sites[key] = append(sites[key], rule)
		if len(sites) > maxSites || len(sites[key]) > maxRulesPerScope {
			return Snapshot{}, ErrQuotaExceeded
		}
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, err
	}
	keys := make([]string, 0, len(sites))
	for key := range sites {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		policy.Sites = append(policy.Sites, SnapshotSite{SiteKey: key, Rules: sites[key]})
	}
	if policy.Slots, err = snapshotSlots(ctx, tx); err != nil {
		return Snapshot{}, err
	}
	if policy.ThemePackageSHA256, err = activeAdminThemePackage(ctx, tx); err != nil {
		return Snapshot{}, err
	}
	return policy, nil
}

// activeAdminThemePackage is the theme node error pages follow ("" before any
// activation). The error page tables predate theme_activations (migration
// 360) and their tests run on schemas migrated only that far, so a schema
// without it simply has no theme. A user console-only activation (migration
// 461) does not change node pages.
func activeAdminThemePackage(ctx context.Context, tx pgx.Tx) (string, error) {
	var themed, slotted bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('theme_activations') IS NOT NULL,
		EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='theme_activations' AND column_name='slot' AND
		table_schema=current_schema())`).Scan(&themed, &slotted); err != nil {
		return "", err
	}
	if !themed {
		return "", nil
	}
	query := `SELECT package_sha256 FROM theme_activations ORDER BY revision DESC LIMIT 1`
	if slotted {
		query = `SELECT package_sha256 FROM theme_activations WHERE slot IN ('admin','all') ORDER BY revision DESC LIMIT 1`
	}
	var themeDigest []byte
	err := tx.QueryRow(ctx, query).Scan(&themeDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(themeDigest) != sha256.Size {
		return "", ErrConflict
	}
	return hex.EncodeToString(themeDigest), nil
}

// snapshotSlots pins the platform's bound error page slots that have a node
// page (slotNodePages): they replace that theme default page on every tenant
// following the platform theme (errpage-content, user 10-25).
func snapshotSlots(ctx context.Context, tx pgx.Tx) ([]SnapshotSlot, error) {
	var present bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('error_page_slots') IS NOT NULL`).Scan(&present); err != nil || !present {
		return nil, err
	}
	rows, err := tx.Query(ctx, slotRecordsQuery+` JOIN access_scopes scope ON scope.id=identity.scope_id
		AND scope.kind='platform' AND scope.tenant_id IS NULL
		WHERE current.asset_id IS NOT NULL AND asset.status='ready' ORDER BY identity.slot_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var slots []SnapshotSlot
	for rows.Next() {
		record, err := scanSlotRecord(rows)
		if err != nil {
			return nil, err
		}
		page, ok := slotNodePages[record.Binding.Key]
		if own, isOwn := slotOwnPages[record.Binding.Key]; isOwn {
			page, ok = own, true
		}
		if !ok {
			continue
		}
		slots = append(slots, SnapshotSlot{Key: record.Binding.Key, Category: page.Category, Status: page.Status,
			Resource: SnapshotResource{MIMEType: record.Binding.MIMEType, Size: record.Binding.SizeBytes,
				SHA256: record.Binding.SHA256, File: "sha256/" + record.Binding.SHA256}})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	overrides, err := snapshotOverrideSlots(ctx, tx)
	if err != nil {
		return nil, err
	}
	return append(slots, overrides...), nil
}

// overrideRegionPattern is the node region a node page selector names: the
// region's catalog code (region_catalog.code, the node's
// KeyDocument.NodeRegion). A region override whose region is not catalogued
// has no code, matches no node and is not published.
var overrideRegionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// snapshotOverrideSlots pins the platform's live region / node overrides
// (errpage-3 E3, migration 220) of the slots a node answers: every node gets
// all of them and picks its own (node, then region, then global). An
// override of http_400 / domain_unconfigured is a node page of that theme
// category (no_host / unknown_site).
func snapshotOverrideSlots(ctx context.Context, tx pgx.Tx) ([]SnapshotSlot, error) {
	var present bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('error_page_scope_overrides') IS NOT NULL`).Scan(&present); err != nil || !present {
		return nil, err
	}
	// fz-x12: a region override names the region (nodes.region, the
	// catalog name, often Chinese); the node knows its region by the
	// catalog code (KeyDocument.NodeRegion), so the snapshot carries that.
	rows, err := tx.Query(ctx, `SELECT identity.target_kind,COALESCE(identity.target_node_id::text,''),
		COALESCE(region.code,''),item.slot_key,asset.mime_type,asset.size_bytes,asset.sha256
		FROM error_page_scope_overrides identity
		JOIN access_scopes scope ON scope.id=identity.scope_id AND scope.kind='platform' AND scope.tenant_id IS NULL
		JOIN LATERAL (
			SELECT revision.revision,revision.deleted FROM error_page_scope_override_revisions revision
			WHERE revision.override_id=identity.id ORDER BY revision.revision DESC LIMIT 1
		) current ON NOT current.deleted
		JOIN error_page_scope_override_items item ON item.override_id=identity.id AND item.revision=current.revision
		JOIN error_page_assets asset ON asset.id=item.asset_id AND asset.status='ready'
		LEFT JOIN nodes node ON node.id=identity.target_node_id
		LEFT JOIN region_catalog region ON identity.target_kind='region' AND
			region.platform_scope_id=identity.scope_id AND region.name=identity.target_region
		WHERE identity.target_kind='region' OR node.admin_state<>'retired'
		ORDER BY item.slot_key,COALESCE(identity.target_node_id::text,''),COALESCE(region.code,'')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var slots []SnapshotSlot
	for rows.Next() {
		var kind, nodeID, region, key, mimeType string
		var size int64
		var digest []byte
		if err := rows.Scan(&kind, &nodeID, &region, &key, &mimeType, &size, &digest); err != nil {
			return nil, err
		}
		if len(digest) != sha256.Size {
			return nil, ErrConflict
		}
		page, ok := slotOwnPages[key]
		// A theme page slot's override is a node page where the theme page
		// is one (no_host, unknown_site); http_502/504 (edge_connect) are site
		// pages: their overrides ride in the site objects as error page
		// variants (errpage-ovr, edgepublish siteErrorPageVariants).
		if theme, isTheme := slotNodePages[key]; isTheme {
			page, ok = theme, theme.Category == CategoryNoHost || theme.Category == CategoryUnknownSite ||
				theme.Category == CategoryEdgeConnect
		}
		if !ok || kind == ScopeOverrideRegion && !overrideRegionPattern.MatchString(region) {
			continue
		}
		slot := SnapshotSlot{Key: key, Category: page.Category, Status: page.Status,
			Resource: SnapshotResource{MIMEType: mimeType, Size: size, SHA256: hex.EncodeToString(digest),
				File: "sha256/" + hex.EncodeToString(digest)}}
		if kind == ScopeOverrideNode {
			slot.NodeID = nodeID
		} else {
			slot.Region = region
		}
		slots = append(slots, slot)
	}
	return slots, rows.Err()
}

func validatePublicationBounds(canonical []byte, siteCount int) error {
	if int64(len(canonical)) > MaxEdgePolicyBytes || siteCount < 0 || siteCount > MaxPublicationSites {
		return ErrQuotaExceeded
	}
	return nil
}

func validatePublicationLimits(canonical []byte, siteCount int, limits EntitlementLimits) error {
	if err := validatePublicationBounds(canonical, siteCount); err != nil {
		return err
	}
	if limits.MaxPublicationBytes < 1 || limits.MaxPublicationSites < 1 {
		return ErrUnavailable
	}
	if int64(len(canonical)) > limits.MaxPublicationBytes || siteCount > limits.MaxPublicationSites {
		return ErrQuotaExceeded
	}
	return nil
}

func (s *Service) PublicationSnapshot(ctx context.Context, actor Actor) (PublicationSnapshot, error) {
	if validateActor(actor) != nil {
		return PublicationSnapshot{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return PublicationSnapshot{}, ErrPermissionDenied
	}
	var result PublicationSnapshot
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeActor(ctx, tx, actor, actor.ScopeID, permissionRead); err != nil {
			return err
		}
		var canonical, digest []byte
		var createdAt time.Time
		err := tx.QueryRow(ctx, `SELECT canonical_snapshot,snapshot_sha256,created_at
			FROM error_page_publications ORDER BY revision DESC LIMIT 1`).Scan(&canonical, &digest, &createdAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if len(digest) != sha256.Size {
			return ErrConflict
		}
		actual := sha256.Sum256(canonical)
		if !equalBytes(actual[:], digest) {
			return ErrConflict
		}
		if err := json.Unmarshal(canonical, &result.Policy); err != nil {
			return ErrConflict
		}
		result.SHA256 = hex.EncodeToString(digest)
		result.CreatedAt = createdAt
		return nil
	})
	if err != nil {
		return PublicationSnapshot{}, fmt.Errorf("get error page publication snapshot: %w", err)
	}
	return result, nil
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
