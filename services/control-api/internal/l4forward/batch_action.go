package l4forward

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 更多操作 (平台): batch actions on selected streams, each item checked
// against its own revision; a stale or missing item fails alone.
const (
	BatchActionSetStatus   = "set_status"   // 设置状态
	BatchActionCNAMEDomain = "cname_domain" // 修改CNAME域名
	BatchActionCNAMEMode   = "cname_mode"   // 修改CNAME生成模式
	BatchActionLineGroup   = "line_group"   // 修改线路分组
	// cname_regenerate: retry the stream's own CNAME (失败可重试, migration 505).
	BatchActionCNAMERegenerate = "cname_regenerate"

	BatchActionItemsMax = 100

	BatchItemUpdated = "updated"
	BatchItemFailed  = "failed"
)

type BatchActionItem struct {
	ID               uuid.UUID `json:"id"`
	ExpectedRevision int64     `json:"expected_revision"`
}

type BatchActionRequest struct {
	Action      string `json:"action"`
	AdminStatus string `json:"admin_status,omitempty"`
	// cname_domain / cname_mode: the stream's own value, "" = follow the package.
	CNAMEDomain *string `json:"cname_domain,omitempty"`
	CNAMEMode   *string `json:"cname_mode,omitempty"`
	// line_group: 区域 / 线路分组 / 备用线路组; nil = follow the package.
	RegionID          *uuid.UUID        `json:"region_id,omitempty"`
	NodeGroupID       *uuid.UUID        `json:"node_group_id,omitempty"`
	BackupNodeGroupID *uuid.UUID        `json:"backup_node_group_id,omitempty"`
	Items             []BatchActionItem `json:"items"`
	IdempotencyKey    string            `json:"-"`
	RequestID         string            `json:"-"`
}

type BatchActionItemResult struct {
	ID     uuid.UUID       `json:"id"`
	Status string          `json:"status"`
	Stream *Forward        `json:"stream,omitempty"`
	Error  *BatchLineError `json:"error,omitempty"`
}

type BatchActionResult struct {
	Items    []BatchActionItemResult `json:"items"`
	Replayed bool                    `json:"-"`
}

func (s *Service) BatchAction(ctx context.Context, actor Actor, request BatchActionRequest) (BatchActionResult, error) {
	if !validActor(actor) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) ||
		len(request.Items) == 0 || len(request.Items) > BatchActionItemsMax {
		return BatchActionResult{}, ErrInvalidInput
	}
	if actor.ScopeKind != "platform" {
		return BatchActionResult{}, ErrPermissionDenied // admin only
	}
	if !validBatchActionValue(&request) {
		return BatchActionResult{}, ErrInvalidInput
	}
	seen := make(map[uuid.UUID]struct{}, len(request.Items))
	for _, item := range request.Items {
		if item.ID == uuid.Nil || item.ExpectedRevision < 1 {
			return BatchActionResult{}, ErrInvalidInput
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return BatchActionResult{}, ErrInvalidInput
		}
		seen[item.ID] = struct{}{}
	}
	digest, err := digestRequest(request)
	if err != nil {
		return BatchActionResult{}, err
	}
	return s.store.BatchAction(ctx, actor, request, digest)
}

// BatchAction applies the action item by item in one transaction (items in
// request order; each locked and compared with its expected revision).
func (s *Store) BatchAction(ctx context.Context, actor Actor, request BatchActionRequest, digest [32]byte) (BatchActionResult, error) {
	const operation = "stream.batch_action"
	var result BatchActionResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// The IAM lock and the automatic publication authorization come
		// first, once, for every target scope (lock order), as for sites.
		scopes := make(map[uuid.UUID]uuid.UUID, len(request.Items))
		var targetScopes []uuid.UUID
		for _, entry := range request.Items {
			scopeID, err := mutationTargetScope(ctx, tx, actor, entry.ID)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			scopes[entry.ID] = scopeID
			targetScopes = append(targetScopes, scopeID)
		}
		if len(targetScopes) > 0 {
			if err := authorizeAutomaticMutations(ctx, tx, actor, targetScopes); err != nil {
				return err
			}
		}
		write, err := s.claimWrite(ctx, tx, actor.UserID, actor.ScopeID, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result); err != nil {
				return fmt.Errorf("decode stored stream batch action response: %w", err)
			}
			for index := range result.Items {
				if result.Items[index].Stream != nil {
					markPublicationUnknown(&result.Items[index].Stream.PublishIntent)
				}
			}
			result.Replayed = true
			return nil
		}
		result.Items = make([]BatchActionItemResult, len(request.Items))
		resourcesChecked := false
		for index, entry := range request.Items {
			item := &result.Items[index]
			item.ID = entry.ID
			scopeID, found := scopes[entry.ID]
			if !found {
				item.Status, item.Error = BatchItemFailed, &BatchLineError{Code: "stream_not_found"}
				continue
			}
			if !resourcesChecked {
				// The picked domain / line groups, share-locked until commit.
				if err := requireBatchActionResources(ctx, tx, request); err != nil {
					return err
				}
				resourcesChecked = true
			}
			forward, code, err := s.applyBatchAction(ctx, tx, actor, entry, scopeID, request)
			if err != nil {
				return err
			}
			if code != "" {
				item.Status, item.Error = BatchItemFailed, &BatchLineError{Code: code}
				continue
			}
			item.Status, item.Stream = BatchItemUpdated, &forward
		}
		return s.completeWrite(ctx, tx, actor.UserID, operation, request.IdempotencyKey, actor.ScopeID, 200, result)
	})
	if err != nil {
		return BatchActionResult{}, fmt.Errorf("batch stream action: %w", err)
	}
	return result, nil
}

// applyBatchAction applies the action to one stream. A status other than
// normal takes the stream off the nodes (its intent is "disabled"), normal
// serves it again; a CNAME or line change republishes it (the line group
// decides which nodes carry it). code is the item's failure
// (stream_not_found, version_conflict).
func (s *Store) applyBatchAction(ctx context.Context, tx pgx.Tx, actor Actor, entry BatchActionItem, scopeID uuid.UUID,
	request BatchActionRequest) (Forward, string, error) {
	current, deleted, err := s.lockForward(ctx, tx, actor, entry.ID)
	if errors.Is(err, ErrNotFound) || deleted || err == nil && current.ScopeID != scopeID {
		return Forward{}, "stream_not_found", nil
	}
	if err != nil {
		return Forward{}, "", err
	}
	if current.Revision != entry.ExpectedRevision {
		return Forward{}, "version_conflict", nil
	}
	if request.Action == BatchActionCNAMERegenerate {
		return s.regenerateStreamCNAME(ctx, tx, actor, current, request.RequestID)
	}
	next := current.Overrides
	status := current.AdminStatus
	action, payload := "", map[string]any{}
	switch request.Action {
	case BatchActionSetStatus:
		status, action = request.AdminStatus, "stream.status.set"
		payload["admin_status"], payload["previous_admin_status"] = status, current.AdminStatus
	case BatchActionCNAMEDomain:
		next.CNAMEDomain, action = emptyAsNil(*request.CNAMEDomain), "stream.cname_domain.set"
		payload["cname_domain"], payload["previous_cname_domain"] = stringOrEmpty(next.CNAMEDomain), stringOrEmpty(current.Overrides.CNAMEDomain)
	case BatchActionCNAMEMode:
		next.CNAMEMode, action = emptyAsNil(*request.CNAMEMode), "stream.cname_mode.set"
		payload["cname_mode"], payload["previous_cname_mode"] = stringOrEmpty(next.CNAMEMode), stringOrEmpty(current.Overrides.CNAMEMode)
	case BatchActionLineGroup:
		next.RegionID, next.NodeGroupID, next.BackupNodeGroupID = request.RegionID, request.NodeGroupID, request.BackupNodeGroupID
		action = "stream.line_group.set"
		payload["region_id"], payload["node_group_id"], payload["backup_node_group_id"] =
			uuidOrEmpty(next.RegionID), uuidOrEmpty(next.NodeGroupID), uuidOrEmpty(next.BackupNodeGroupID)
		payload["previous_node_group_id"] = uuidOrEmpty(current.Overrides.NodeGroupID)
	}
	item, err := scanForwardWithoutIntent(tx.QueryRow(ctx, `
		UPDATE l4_forwards SET admin_status=$2, cname_domain=$3, cname_mode=$4, region_id=$5, node_group_id=$6,
			backup_node_group_id=$7, revision=revision+1, updated_by_user_id=$8, updated_at=$9
		WHERE id=$1 AND revision=$10 AND deleted_at IS NULL
		RETURNING `+forwardColumns("l4_forwards")+`,
		          (SELECT display_name FROM users WHERE id = l4_forwards.owner_user_id)`,
		entry.ID, status, next.CNAMEDomain, next.CNAMEMode, next.RegionID, next.NodeGroupID, next.BackupNodeGroupID,
		actor.UserID, s.now().UTC(), entry.ExpectedRevision))
	if errors.Is(err, pgx.ErrNoRows) {
		return Forward{}, "version_conflict", nil
	}
	if err != nil {
		return Forward{}, "", err
	}
	if request.Action == BatchActionCNAMEDomain || request.Action == BatchActionCNAMEMode {
		if err := syncStreamCNAME(ctx, tx, actor, current.Overrides, item, request.RequestID, false, s.now().UTC()); err != nil {
			return Forward{}, "", err
		}
	}
	if err := loadAdditionalListeners(ctx, tx, &item); err != nil {
		return Forward{}, "", err
	}
	if item.Groups, err = loadGroupReferences(ctx, tx, item.ID); err != nil {
		return Forward{}, "", err
	}
	if err := refreshEligibility(ctx, tx, &item, false); err != nil {
		return Forward{}, "", err
	}
	intent, err := s.appendPublishIntent(ctx, tx, actor.UserID, item, "update")
	if err != nil {
		return Forward{}, "", err
	}
	item.PublishIntent = intent
	if err := enqueueAutomaticMutation(ctx, tx, actor, item.ScopeID, item.ID, intent, "stream.update", request.RequestID); err != nil {
		return Forward{}, "", err
	}
	payload["revision"], payload["publish_version"] = item.Revision, intent.Version
	payload["publish_intent_id"], payload["configuration_source_revision"] = intent.ID.String(), intent.ConfigurationSourceRevision
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: item.ScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: "stream", ResourceID: item.ID.String(), RequestID: request.RequestID, Result: "success",
		Payload: automaticAuditPayload(actor, item.ScopeID, "stream.update", payload),
	}); err != nil {
		return Forward{}, "", err
	}
	return item, "", nil
}

// validBatchActionValue checks the action carries exactly its own value(s).
// cname_domain / cname_mode "" clears the stream's value (follow the package).
func validBatchActionValue(request *BatchActionRequest) bool {
	lineSet := request.RegionID != nil || request.NodeGroupID != nil || request.BackupNodeGroupID != nil
	switch request.Action {
	case BatchActionCNAMERegenerate:
		return request.AdminStatus == "" && request.CNAMEDomain == nil && request.CNAMEMode == nil && !lineSet
	case BatchActionSetStatus:
		return ValidAdminStatus(request.AdminStatus) && request.CNAMEDomain == nil && request.CNAMEMode == nil && !lineSet
	case BatchActionCNAMEDomain:
		if request.AdminStatus != "" || request.CNAMEDomain == nil || request.CNAMEMode != nil || lineSet {
			return false
		}
		domain := strings.ToLower(strings.TrimSpace(*request.CNAMEDomain))
		request.CNAMEDomain = &domain
		return domain == "" || validCNAMEDomain(domain)
	case BatchActionCNAMEMode:
		return request.AdminStatus == "" && request.CNAMEDomain == nil && request.CNAMEMode != nil && !lineSet &&
			(*request.CNAMEMode == "" || *request.CNAMEMode == "site" || *request.CNAMEMode == "package")
	case BatchActionLineGroup:
		// A backup group needs a primary group, and differs from it.
		return request.AdminStatus == "" && request.CNAMEDomain == nil && request.CNAMEMode == nil &&
			(request.BackupNodeGroupID == nil || request.NodeGroupID != nil && *request.BackupNodeGroupID != *request.NodeGroupID) &&
			(request.RegionID == nil || *request.RegionID != uuid.Nil) && (request.NodeGroupID == nil || *request.NodeGroupID != uuid.Nil)
	}
	return false
}

// validCNAMEDomain matches migration 506's l4_forwards_line_cname_506.
func validCNAMEDomain(domain string) bool {
	if len(domain) > 253 {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for index, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for position, char := range label {
			alpha := char >= 'a' && char <= 'z'
			if !alpha && !(char >= '0' && char <= '9') && char != '-' {
				return false
			}
			if index == len(labels)-1 && position == 0 && !alpha {
				return false
			}
		}
		if index == len(labels)-1 && len(label) < 2 {
			return false
		}
	}
	return true
}

// requireBatchActionResources checks what the action picks exists, as a
// package's resources are checked (packagecatalog.validateProductResources):
// the CNAME domain is one of 节点管理 > DNS配置's zones, the region is in the
// platform catalog, the line groups are live platform general line groups.
// They are share-locked until the batch commits.
func requireBatchActionResources(ctx context.Context, tx pgx.Tx, request BatchActionRequest) error {
	switch request.Action {
	case BatchActionCNAMEDomain:
		if *request.CNAMEDomain == "" {
			return nil
		}
		var known bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform_system_other_settings settings
			JOIN access_scopes platform ON platform.id=settings.platform_scope_id AND platform.kind='platform',
			     jsonb_array_elements(COALESCE(settings.settings->'dns_config'->'zones','[]'::jsonb)) zone
			WHERE lower(zone->>'name')=$1)`, *request.CNAMEDomain).Scan(&known); err != nil {
			return err
		}
		if !known {
			return ErrInvalidInput
		}
	case BatchActionLineGroup:
		if request.RegionID != nil {
			var found bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM region_catalog region
				JOIN access_scopes platform ON platform.id=region.platform_scope_id AND platform.kind='platform'
				WHERE region.id=$1 FOR SHARE OF region)`, *request.RegionID).Scan(&found); err != nil {
				return err
			}
			if !found {
				return ErrInvalidInput
			}
		}
		for _, groupID := range []*uuid.UUID{request.NodeGroupID, request.BackupNodeGroupID} {
			if groupID == nil {
				continue
			}
			var found bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_line_groups line_group
				JOIN access_scopes platform ON platform.id=line_group.tenant_scope_id AND platform.kind='platform'
				WHERE line_group.id=$1 AND line_group.deleted_at IS NULL AND line_group.purpose='general'
				FOR SHARE OF line_group)`, *groupID).Scan(&found); err != nil {
				return err
			}
			if !found {
				return ErrInvalidInput
			}
		}
	}
	return nil
}

func emptyAsNil(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func stringOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func uuidOrEmpty(value *uuid.UUID) string {
	if value == nil {
		return ""
	}
	return value.String()
}
