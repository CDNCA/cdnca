package errorpagecontrol

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	ScopeOverrideNode   = "node"
	ScopeOverrideRegion = "region"

	operationScopeOverrideCreate = "error_page.scope_override.create"
	operationScopeOverrideUpdate = "error_page.scope_override.update"
	operationScopeOverrideDelete = "error_page.scope_override.delete"
)

var ErrorPageScopeOverrideSlotKeys = [...]string{
	SlotHTTP400,
	SlotHTTP403,
	SlotHTTP502,
	SlotHTTP504,
	SlotTrafficExceeded,
	SlotPackageExpired,
	SlotSiteLocked,
	SlotDomainUnconfigured,
	SlotNodeIPAccess,
	SlotConnectionLimit,
}

type ScopeOverrideTarget struct {
	Kind          string `json:"kind"`
	NodeDisplayID string `json:"node_display_id,omitempty"`
	NodeName      string `json:"node_name,omitempty"`
	NodeIP        string `json:"node_ip,omitempty"`
	Region        string `json:"region,omitempty"`
}

type ScopeOverrideItem struct {
	Key     string `json:"key"`
	Content string `json:"content,omitempty"`
}

type ScopeOverride struct {
	DisplayID string              `json:"display_id"`
	Target    ScopeOverrideTarget `json:"target"`
	Items     []ScopeOverrideItem `json:"items"`
	Revision  int64               `json:"revision"`
	UpdatedAt time.Time           `json:"updated_at"`
	Deleted   bool                `json:"deleted,omitempty"`
}

type ScopeOverridePage struct {
	Items []ScopeOverride `json:"items"`
	Total int             `json:"total"`
}

type ScopeOverrideBinding struct {
	Key     string
	AssetID uuid.UUID
}

type CreateScopeOverrideRequest struct {
	TargetKind    string
	NodeDisplayID int64
	Region        string
	Items         []ScopeOverrideBinding
	WriteMetadata
}

type UpdateScopeOverrideRequest struct {
	DisplayID        int64
	ExpectedRevision int64
	Items            []ScopeOverrideBinding
	WriteMetadata
}

type DeleteScopeOverrideRequest struct {
	DisplayID        int64
	ExpectedRevision int64
	WriteMetadata
}

type ResolvedErrorPageSlot struct {
	Source  string
	AssetID *uuid.UUID
}

type scopeOverrideRecord struct {
	ID           uuid.UUID
	ScopeID      uuid.UUID
	TargetNodeID *uuid.UUID
	Value        ScopeOverride
	AssetIDs     map[string]uuid.UUID
}

func validScopeOverrideSlotKey(value string) bool {
	for _, key := range ErrorPageScopeOverrideSlotKeys {
		if value == key {
			return true
		}
	}
	return false
}

func validScopeOverrideTarget(kind string, nodeDisplayID int64, region string) bool {
	if kind == ScopeOverrideNode {
		return nodeDisplayID > 0 && region == ""
	}
	return kind == ScopeOverrideRegion && nodeDisplayID == 0 && region == strings.TrimSpace(region) &&
		len(region) >= 1 && len(region) <= 64
}

func normalizeScopeOverrideBindings(items []ScopeOverrideBinding) ([]ScopeOverrideBinding, error) {
	if len(items) < 1 || len(items) > len(ErrorPageScopeOverrideSlotKeys) {
		return nil, ErrInvalidInput
	}
	order := make(map[string]int, len(ErrorPageScopeOverrideSlotKeys))
	for index, key := range ErrorPageScopeOverrideSlotKeys {
		order[key] = index
	}
	seen := make(map[string]struct{}, len(items))
	result := append([]ScopeOverrideBinding(nil), items...)
	for _, item := range result {
		if !validScopeOverrideSlotKey(item.Key) || item.AssetID == uuid.Nil {
			return nil, ErrInvalidInput
		}
		if _, exists := seen[item.Key]; exists {
			return nil, ErrInvalidInput
		}
		seen[item.Key] = struct{}{}
	}
	sort.Slice(result, func(left, right int) bool { return order[result[left].Key] < order[result[right].Key] })
	return result, nil
}

func (s *Service) ListScopeOverrides(ctx context.Context, actor Actor) (ScopeOverridePage, error) {
	if validateActor(actor) != nil {
		return ScopeOverridePage{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return ScopeOverridePage{}, ErrPermissionDenied
	}
	page := ScopeOverridePage{Items: []ScopeOverride{}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeSlotActor(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, scopeOverrideRecordsQuery+
			` WHERE identity.scope_id=$1 AND NOT current.deleted ORDER BY identity.display_id`, actor.ScopeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := scanScopeOverrideRecord(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, record.Value)
		}
		return rows.Err()
	})
	if err != nil {
		return ScopeOverridePage{}, fmt.Errorf("list error page scope overrides: %w", normalizeDatabaseError(err))
	}
	page.Total = len(page.Items)
	return page, nil
}

func (s *Service) GetScopeOverride(ctx context.Context, actor Actor, displayID int64) (ScopeOverride, error) {
	if validateActor(actor) != nil || displayID < 1 {
		return ScopeOverride{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return ScopeOverride{}, ErrPermissionDenied
	}
	var record scopeOverrideRecord
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeSlotActor(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		loaded, found, err := loadScopeOverrideByDisplayID(ctx, tx, actor.ScopeID, displayID, false)
		if err != nil {
			return err
		}
		if !found || loaded.Value.Deleted {
			return ErrNotFound
		}
		record = loaded
		for index := range record.Value.Items {
			key := record.Value.Items[index].Key
			assetID, found := record.AssetIDs[key]
			if !found {
				return fmt.Errorf("scope override item %s is missing its asset: %w", key, ErrConflict)
			}
			asset, err := loadAssetForActor(ctx, tx, actor, assetID, false)
			if err != nil {
				return fmt.Errorf("load scope override item %s asset: %w", key, err)
			}
			if asset.ScopeID != actor.ScopeID || asset.Status != StatusReady || asset.objectState != "final" ||
				asset.DeletedAt != nil {
				return fmt.Errorf("scope override item %s has invalid asset state: %w", key, ErrConflict)
			}
			body, err := s.readReadySlotContent(ctx, asset)
			if err != nil {
				return fmt.Errorf("read scope override item %s asset: %w", key, err)
			}
			record.Value.Items[index].Content = string(body)
		}
		return nil
	})
	if err != nil {
		return ScopeOverride{}, fmt.Errorf("get error page scope override: %w", normalizeDatabaseError(err))
	}
	return record.Value, nil
}

func (s *Service) CreateScopeOverride(
	ctx context.Context,
	actor Actor,
	request CreateScopeOverrideRequest,
) (WriteResult[ScopeOverride], error) {
	items, err := normalizeScopeOverrideBindings(request.Items)
	if validateActor(actor) != nil || !validScopeOverrideTarget(request.TargetKind, request.NodeDisplayID, request.Region) ||
		err != nil || validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[ScopeOverride]{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return WriteResult[ScopeOverride]{}, ErrPermissionDenied
	}
	digest, err := digestRequest(struct {
		TargetKind    string                 `json:"target_kind"`
		NodeDisplayID int64                  `json:"node_display_id,omitempty"`
		Region        string                 `json:"region,omitempty"`
		Items         []ScopeOverrideBinding `json:"items"`
	}{request.TargetKind, request.NodeDisplayID, request.Region, items})
	if err != nil {
		return WriteResult[ScopeOverride]{}, ErrInvalidInput
	}
	var result ScopeOverride
	var replayed bool
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeSlotActor(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		stored, exists, err := s.claimWrite(ctx, tx, actor, actor.ScopeID,
			operationScopeOverrideCreate, request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if exists {
			decoded, err := decodeReplay[ScopeOverride](stored)
			if err != nil {
				return err
			}
			result, replayed = decoded.Value, true
			return nil
		}

		targetNodeID, err := resolveScopeOverrideTarget(ctx, tx, actor.ScopeID,
			request.TargetKind, request.NodeDisplayID, request.Region)
		if err != nil {
			return err
		}
		record, found, err := loadScopeOverrideByTarget(ctx, tx, actor.ScopeID,
			request.TargetKind, targetNodeID, request.Region, true)
		if err != nil {
			return err
		}
		expectedRevision := int64(0)
		if found {
			if !record.Value.Deleted {
				return ErrConflict
			}
			expectedRevision = record.Value.Revision
		} else {
			record.ID, err = uuid.NewV7()
			if err != nil {
				return err
			}
			now := storeTime(s.now())
			if _, err := tx.Exec(ctx, `INSERT INTO error_page_scope_overrides (
				id,scope_id,target_kind,target_node_id,target_region,
				created_by_user_id,created_by_scope_id,created_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, record.ID, actor.ScopeID, request.TargetKind,
				scopeOverrideNullableUUID(targetNodeID), nullableString(request.Region), actor.UserID, actor.ScopeID, now); err != nil {
				return err
			}
		}
		if err := validateScopeOverrideAssets(ctx, tx, actor, items); err != nil {
			return err
		}
		if err := insertScopeOverrideRevision(ctx, tx, record.ID, expectedRevision+1, false, actor,
			request.WriteMetadata, items, storeTime(s.now())); err != nil {
			return err
		}
		record, found, err = loadScopeOverrideByID(ctx, tx, actor.ScopeID, record.ID, false)
		if err != nil || !found {
			if err == nil {
				err = ErrConflict
			}
			return err
		}
		result = record.Value
		// errpage-3 E3: overrides reach nodes as node pages
		if _, err := s.publishSlotsTx(ctx, tx, actor, request.WriteMetadata); err != nil {
			return err
		}
		if err := s.appendScopeOverrideAudit(ctx, tx, actor, operationScopeOverrideCreate,
			record, expectedRevision, result.Revision, items, request.WriteMetadata); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationScopeOverrideCreate, request.WriteMetadata,
			record.ID, 201, result)
	})
	if err != nil {
		return WriteResult[ScopeOverride]{}, fmt.Errorf("%s: %w", operationScopeOverrideCreate, normalizeDatabaseError(err))
	}
	return WriteResult[ScopeOverride]{Value: result, Replayed: replayed}, nil
}

func (s *Service) UpdateScopeOverride(
	ctx context.Context,
	actor Actor,
	request UpdateScopeOverrideRequest,
) (WriteResult[ScopeOverride], error) {
	items, err := normalizeScopeOverrideBindings(request.Items)
	if validateActor(actor) != nil || request.DisplayID < 1 || request.ExpectedRevision < 1 || err != nil ||
		validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[ScopeOverride]{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return WriteResult[ScopeOverride]{}, ErrPermissionDenied
	}
	return s.changeScopeOverride(ctx, actor, request.DisplayID, request.ExpectedRevision, items, false,
		request.WriteMetadata, operationScopeOverrideUpdate)
}

func (s *Service) DeleteScopeOverride(
	ctx context.Context,
	actor Actor,
	request DeleteScopeOverrideRequest,
) (WriteResult[ScopeOverride], error) {
	if validateActor(actor) != nil || request.DisplayID < 1 || request.ExpectedRevision < 1 ||
		validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[ScopeOverride]{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return WriteResult[ScopeOverride]{}, ErrPermissionDenied
	}
	return s.changeScopeOverride(ctx, actor, request.DisplayID, request.ExpectedRevision, nil, true,
		request.WriteMetadata, operationScopeOverrideDelete)
}

func (s *Service) changeScopeOverride(
	ctx context.Context,
	actor Actor,
	displayID int64,
	expectedRevision int64,
	items []ScopeOverrideBinding,
	deleted bool,
	metadata WriteMetadata,
	operation string,
) (WriteResult[ScopeOverride], error) {
	digest, err := digestRequest(struct {
		DisplayID        int64                  `json:"display_id"`
		ExpectedRevision int64                  `json:"expected_revision"`
		Items            []ScopeOverrideBinding `json:"items"`
		Deleted          bool                   `json:"deleted"`
	}{displayID, expectedRevision, items, deleted})
	if err != nil {
		return WriteResult[ScopeOverride]{}, ErrInvalidInput
	}
	var result ScopeOverride
	var replayed bool
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeSlotActor(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		stored, exists, err := s.claimWrite(ctx, tx, actor, actor.ScopeID, operation, metadata, digest)
		if err != nil {
			return err
		}
		if exists {
			decoded, err := decodeReplay[ScopeOverride](stored)
			if err != nil {
				return err
			}
			result, replayed = decoded.Value, true
			return nil
		}
		record, found, err := loadScopeOverrideByDisplayID(ctx, tx, actor.ScopeID, displayID, true)
		if err != nil {
			return err
		}
		if !found || record.Value.Deleted {
			return ErrNotFound
		}
		if record.Value.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		if !deleted {
			if err := validateScopeOverrideAssets(ctx, tx, actor, items); err != nil {
				return err
			}
		}
		if err := insertScopeOverrideRevision(ctx, tx, record.ID, expectedRevision+1, deleted, actor,
			metadata, items, storeTime(s.now())); err != nil {
			return err
		}
		updated, found, err := loadScopeOverrideByID(ctx, tx, actor.ScopeID, record.ID, false)
		if err != nil || !found {
			if err == nil {
				err = ErrConflict
			}
			return err
		}
		result = updated.Value
		if _, err := s.publishSlotsTx(ctx, tx, actor, metadata); err != nil {
			return err
		}
		if err := s.appendScopeOverrideAudit(ctx, tx, actor, operation, updated,
			expectedRevision, result.Revision, items, metadata); err != nil {
			return err
		}
		status := 200
		if deleted {
			status = 202
		}
		return s.completeWrite(ctx, tx, actor, operation, metadata, updated.ID, status, result)
	})
	if err != nil {
		return WriteResult[ScopeOverride]{}, fmt.Errorf("%s: %w", operation, normalizeDatabaseError(err))
	}
	return WriteResult[ScopeOverride]{Value: result, Replayed: replayed}, nil
}

func (s *Service) appendScopeOverrideAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	record scopeOverrideRecord,
	fromRevision int64,
	toRevision int64,
	items []ScopeOverrideBinding,
	metadata WriteMetadata,
) error {
	keys := make([]string, len(items))
	for index, item := range items {
		keys[index] = item.Key
	}
	return s.appendAudit(ctx, tx, &actor, actor.ScopeID, operation, "error_page_scope_override",
		record.ID.String(), metadata, "success", map[string]any{
			"display_id": record.Value.DisplayID, "target_kind": record.Value.Target.Kind,
			"node_display_id": record.Value.Target.NodeDisplayID, "region": record.Value.Target.Region,
			"item_keys": keys, "from_revision": fromRevision, "to_revision": toRevision,
		})
}

func resolveScopeOverrideTarget(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	kind string,
	nodeDisplayID int64,
	region string,
) (*uuid.UUID, error) {
	if kind == ScopeOverrideNode {
		var nodeID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM nodes
			WHERE scope_id=$1 AND display_id=$2 AND admin_state<>'retired' FOR SHARE`,
			scopeID, nodeDisplayID).Scan(&nodeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return &nodeID, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM nodes WHERE scope_id=$1 AND region=$2 AND admin_state<>'retired'
	)`, scopeID, region).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	return nil, nil
}

func validateScopeOverrideAssets(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	items []ScopeOverrideBinding,
) error {
	for _, item := range items {
		asset, err := loadAssetForActor(ctx, tx, actor, item.AssetID, false)
		if err != nil {
			return err
		}
		if asset.ScopeID != actor.ScopeID || asset.Status != StatusReady || asset.objectState != "final" ||
			asset.DeletedAt != nil {
			return ErrConflict
		}
	}
	return nil
}

func insertScopeOverrideRevision(
	ctx context.Context,
	tx pgx.Tx,
	overrideID uuid.UUID,
	revision int64,
	deleted bool,
	actor Actor,
	metadata WriteMetadata,
	items []ScopeOverrideBinding,
	now time.Time,
) error {
	if _, err := tx.Exec(ctx, `INSERT INTO error_page_scope_override_revisions (
		override_id,revision,deleted,created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, overrideID, revision, deleted, actor.UserID,
		actor.ScopeID, metadata.RequestID, metadata.TraceID, now); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := tx.Exec(ctx, `INSERT INTO error_page_scope_override_items (
			override_id,revision,slot_key,asset_id
		) VALUES($1,$2,$3,$4)`, overrideID, revision, item.Key, item.AssetID); err != nil {
			return err
		}
	}
	return nil
}

func loadScopeOverrideByDisplayID(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	displayID int64,
	lock bool,
) (scopeOverrideRecord, bool, error) {
	query := scopeOverrideRecordsQuery + ` WHERE identity.scope_id=$1 AND identity.display_id=$2`
	if lock {
		query += ` FOR UPDATE OF identity`
	}
	return scanLoadedScopeOverride(tx.QueryRow(ctx, query, scopeID, displayID))
}

func loadScopeOverrideByID(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	id uuid.UUID,
	lock bool,
) (scopeOverrideRecord, bool, error) {
	query := scopeOverrideRecordsQuery + ` WHERE identity.scope_id=$1 AND identity.id=$2`
	if lock {
		query += ` FOR UPDATE OF identity`
	}
	return scanLoadedScopeOverride(tx.QueryRow(ctx, query, scopeID, id))
}

func loadScopeOverrideByTarget(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	kind string,
	nodeID *uuid.UUID,
	region string,
	lock bool,
) (scopeOverrideRecord, bool, error) {
	query := scopeOverrideRecordsQuery + ` WHERE identity.scope_id=$1 AND identity.target_kind=$2 AND (
		($2='node' AND identity.target_node_id=$3) OR ($2='region' AND identity.target_region=$4)
	)`
	if lock {
		query += ` FOR UPDATE OF identity`
	}
	return scanLoadedScopeOverride(tx.QueryRow(ctx, query, scopeID, kind, scopeOverrideNullableUUID(nodeID), nullableString(region)))
}

func scanLoadedScopeOverride(row rowScanner) (scopeOverrideRecord, bool, error) {
	record, err := scanScopeOverrideRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return scopeOverrideRecord{}, false, nil
	}
	return record, err == nil, err
}

const scopeOverrideRecordsQuery = `SELECT
	identity.id,identity.scope_id,identity.display_id,identity.target_kind,identity.target_node_id,
	COALESCE(node.display_id::text,''),COALESCE(node.name,''),
	COALESCE(host(node.ipv4),host(node.ipv6),''),
	CASE WHEN identity.target_kind='region' THEN identity.target_region ELSE COALESCE(node.region,'') END,
	current.revision,current.deleted,current.created_at,
	COALESCE(items.keys,ARRAY[]::text[]),COALESCE(items.asset_ids,ARRAY[]::uuid[])
	FROM error_page_scope_overrides identity
	JOIN LATERAL (
		SELECT revision.revision,revision.deleted,revision.created_at
		FROM error_page_scope_override_revisions revision
		WHERE revision.override_id=identity.id ORDER BY revision.revision DESC LIMIT 1
	) current ON true
	LEFT JOIN nodes node ON node.id=identity.target_node_id
	LEFT JOIN LATERAL (
		SELECT
			array_agg(item.slot_key ORDER BY array_position(ARRAY[
				'http_400','http_403','http_502','http_504','traffic_exceeded','package_expired',
				'site_locked','domain_unconfigured','node_ip_access','connection_limit'
			]::text[],item.slot_key)) AS keys,
			array_agg(item.asset_id ORDER BY array_position(ARRAY[
				'http_400','http_403','http_502','http_504','traffic_exceeded','package_expired',
				'site_locked','domain_unconfigured','node_ip_access','connection_limit'
			]::text[],item.slot_key)) AS asset_ids
		FROM error_page_scope_override_items item
		WHERE item.override_id=identity.id AND item.revision=current.revision
	) items ON true`

func scanScopeOverrideRecord(row rowScanner) (scopeOverrideRecord, error) {
	var record scopeOverrideRecord
	var displayID int64
	var nodeDisplayID string
	var nodeName string
	var nodeIP string
	var region string
	var keys []string
	var assetIDs []uuid.UUID
	if err := row.Scan(&record.ID, &record.ScopeID, &displayID, &record.Value.Target.Kind,
		&record.TargetNodeID, &nodeDisplayID, &nodeName, &nodeIP, &region,
		&record.Value.Revision, &record.Value.Deleted, &record.Value.UpdatedAt, &keys, &assetIDs); err != nil {
		return scopeOverrideRecord{}, err
	}
	if record.Value.Target.Kind != ScopeOverrideNode && record.Value.Target.Kind != ScopeOverrideRegion ||
		displayID < 1 || record.Value.Revision < 1 || len(keys) != len(assetIDs) || len(keys) > 10 {
		return scopeOverrideRecord{}, ErrConflict
	}
	record.Value.DisplayID = strconv.FormatInt(displayID, 10)
	record.Value.Target.NodeDisplayID = nodeDisplayID
	record.Value.Target.NodeName = nodeName
	record.Value.Target.NodeIP = nodeIP
	record.Value.Target.Region = region
	record.Value.Items = make([]ScopeOverrideItem, len(keys))
	record.AssetIDs = make(map[string]uuid.UUID, len(keys))
	for index, key := range keys {
		if !validScopeOverrideSlotKey(key) || assetIDs[index] == uuid.Nil {
			return scopeOverrideRecord{}, ErrConflict
		}
		record.Value.Items[index] = ScopeOverrideItem{Key: key}
		record.AssetIDs[key] = assetIDs[index]
	}
	if !record.Value.Deleted && len(keys) < 1 || record.Value.Deleted && len(keys) != 0 {
		return scopeOverrideRecord{}, ErrConflict
	}
	return record, nil
}

func scopeOverrideNullableUUID(value *uuid.UUID) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (s *Service) ResolveScopeOverrideSlot(
	ctx context.Context,
	actor Actor,
	nodeID uuid.UUID,
	key string,
) (ResolvedErrorPageSlot, error) {
	if validateActor(actor) != nil || nodeID == uuid.Nil || !validSlotKey(key) {
		return ResolvedErrorPageSlot{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return ResolvedErrorPageSlot{}, ErrPermissionDenied
	}
	result := ResolvedErrorPageSlot{Source: "builtin"}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeSlotActor(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		var source string
		var assetID uuid.UUID
		err := tx.QueryRow(ctx, `WITH target AS (
			SELECT id,region FROM nodes WHERE id=$1 AND scope_id=$2 AND admin_state<>'retired'
		), candidates AS (
			SELECT 1 AS priority,'node'::text AS source,item.asset_id
			FROM target
			JOIN error_page_scope_overrides identity ON identity.scope_id=$2 AND
				identity.target_kind='node' AND identity.target_node_id=target.id
			JOIN LATERAL (
				SELECT revision.revision,revision.deleted FROM error_page_scope_override_revisions revision
				WHERE revision.override_id=identity.id ORDER BY revision.revision DESC LIMIT 1
			) current ON NOT current.deleted
			JOIN error_page_scope_override_items item ON item.override_id=identity.id AND
				item.revision=current.revision AND item.slot_key=$3
			UNION ALL
			SELECT 2,'region',item.asset_id
			FROM target
			JOIN error_page_scope_overrides identity ON identity.scope_id=$2 AND
				identity.target_kind='region' AND identity.target_region=target.region
			JOIN LATERAL (
				SELECT revision.revision,revision.deleted FROM error_page_scope_override_revisions revision
				WHERE revision.override_id=identity.id ORDER BY revision.revision DESC LIMIT 1
			) current ON NOT current.deleted
			JOIN error_page_scope_override_items item ON item.override_id=identity.id AND
				item.revision=current.revision AND item.slot_key=$3
			UNION ALL
			SELECT 3,'global',revision.asset_id
			FROM error_page_slots slot
			JOIN LATERAL (
				SELECT current.asset_id FROM error_page_slot_revisions current
				WHERE current.slot_id=slot.id ORDER BY current.revision DESC LIMIT 1
			) revision ON revision.asset_id IS NOT NULL
			WHERE slot.scope_id=$2 AND slot.slot_key=$3
		)
		SELECT source,asset_id FROM candidates ORDER BY priority LIMIT 1`, nodeID, actor.ScopeID, key).
			Scan(&source, &assetID)
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes
				WHERE id=$1 AND scope_id=$2 AND admin_state<>'retired')`, nodeID, actor.ScopeID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrNotFound
			}
			return nil
		}
		if err != nil {
			return err
		}
		result.Source = source
		result.AssetID = &assetID
		return nil
	})
	if err != nil {
		return ResolvedErrorPageSlot{}, fmt.Errorf("resolve error page scope override: %w", normalizeDatabaseError(err))
	}
	return result, nil
}
