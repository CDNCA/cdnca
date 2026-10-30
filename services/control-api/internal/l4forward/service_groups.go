package l4forward

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// maxGroupAssignments 限制单条转发可归属的分组数，避免成员表被无界写入。
const maxGroupAssignments = 32

func (s *Service) CreateGroup(ctx context.Context, actor Actor, request GroupCreateRequest) (GroupWriteResult, error) {
	if err := normalizeActorAndTarget(actor, &request.TargetScopeID, &request.OwnerUserID); err != nil {
		return GroupWriteResult{}, err
	}
	if !normalizeGroupFields(&request.Fields) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return GroupWriteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID   `json:"target_scope_id"`
		OwnerUserID   uuid.UUID   `json:"owner_user_id"`
		Fields        GroupFields `json:"fields"`
	}{request.TargetScopeID, request.OwnerUserID, request.Fields})
	if err != nil {
		return GroupWriteResult{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return GroupWriteResult{}, err
	}
	return s.store.CreateGroup(ctx, actor, request, id, digest)
}

func (s *Service) UpdateGroup(ctx context.Context, actor Actor, request GroupUpdateRequest) (GroupWriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!normalizeGroupFields(&request.Fields) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return GroupWriteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID   `json:"id"`
		ExpectedRevision int64       `json:"expected_revision"`
		Fields           GroupFields `json:"fields"`
	}{request.ID, request.ExpectedRevision, request.Fields})
	if err != nil {
		return GroupWriteResult{}, err
	}
	return s.store.UpdateGroup(ctx, actor, request, digest)
}

func (s *Service) DeleteGroup(ctx context.Context, actor Actor, request GroupDeleteRequest) error {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.ID, request.ExpectedRevision})
	if err != nil {
		return err
	}
	_, err = s.store.DeleteGroup(ctx, actor, request, digest)
	return err
}

func (s *Service) ListGroups(ctx context.Context, actor Actor, filter GroupListFilter) (GroupListResult, error) {
	if !validListWindow(actor, filter.Page, filter.Limit) || utf8.RuneCountInString(filter.Search) > 128 {
		return GroupListResult{}, ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" {
		filter.Search = strings.TrimSpace(filter.Search)
	}
	return s.store.ListGroups(ctx, actor, filter)
}

func (s *Service) ListUserDefaults(ctx context.Context, actor Actor, filter UserDefaultListFilter) (UserDefaultListResult, error) {
	if !validListWindow(actor, filter.Page, filter.Limit) || utf8.RuneCountInString(filter.Search) > 128 {
		return UserDefaultListResult{}, ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" {
		filter.Search = strings.TrimSpace(filter.Search)
	}
	return s.store.ListUserDefaults(ctx, actor, filter)
}

func (s *Service) CreateUserDefault(ctx context.Context, actor Actor, request UserDefaultCreateRequest) (UserDefaultWriteResult, error) {
	if err := normalizeActorAndTarget(actor, &request.TargetScopeID, &request.OwnerUserID); err != nil {
		return UserDefaultWriteResult{}, err
	}
	if !normalizeUserDefaultFields(&request.Fields) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return UserDefaultWriteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID         `json:"target_scope_id"`
		OwnerUserID   uuid.UUID         `json:"owner_user_id"`
		Fields        UserDefaultFields `json:"fields"`
	}{request.TargetScopeID, request.OwnerUserID, request.Fields})
	if err != nil {
		return UserDefaultWriteResult{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return UserDefaultWriteResult{}, err
	}
	return s.store.CreateUserDefault(ctx, actor, request, id, digest)
}

func (s *Service) DeleteUserDefault(ctx context.Context, actor Actor, request UserDefaultDeleteRequest) error {
	if !validActor(actor) || request.ID == uuid.Nil || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		ID uuid.UUID `json:"id"`
	}{request.ID})
	if err != nil {
		return err
	}
	_, err = s.store.DeleteUserDefault(ctx, actor, request, digest)
	return err
}

// EffectiveDefaults 是新建草稿的预填值（L4-DEFAULT-01）：与 Create 同一解析（全局→命中分组覆盖），
// 归属校验与新建相同（租户只能看自己；平台须指定租户及其成员）。只读，不写审计。
func (s *Service) EffectiveDefaults(ctx context.Context, actor Actor, targetScopeID, ownerUserID uuid.UUID, groupIDs []uuid.UUID) (FieldDefaults, error) {
	if err := normalizeActorAndTarget(actor, &targetScopeID, &ownerUserID); err != nil {
		return FieldDefaults{}, err
	}
	groupIDs, err := normalizeGroupIDs(groupIDs)
	if err != nil {
		return FieldDefaults{}, err
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		return FieldDefaults{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := authorizeTarget(ctx, tx, actor, targetScopeID, ownerUserID); err != nil {
		return FieldDefaults{}, err
	}
	defaults, err := s.store.ResolveFieldDefaults(ctx, tx, targetScopeID, ownerUserID, groupIDs)
	if err != nil {
		return FieldDefaults{}, err
	}
	return defaults, tx.Commit(ctx)
}

// resolveFieldDefaults 取当前操作者在该用户/分组下的默认设置；无默认或查询失败时不带入。
func (s *Service) resolveFieldDefaults(ctx context.Context, actor Actor, targetScopeID, ownerUserID uuid.UUID, groupIDs []uuid.UUID) (FieldDefaults, error) {
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		return FieldDefaults{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	defaults, err := s.store.ResolveFieldDefaults(ctx, tx, targetScopeID, ownerUserID, groupIDs)
	if err != nil {
		return FieldDefaults{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FieldDefaults{}, err
	}
	return defaults, nil
}

func normalizeGroupFields(fields *GroupFields) bool {
	fields.Name = strings.TrimSpace(fields.Name)
	fields.Remark = strings.TrimSpace(fields.Remark)
	return validDisplayText(fields.Name, 128, false) && validDisplayText(fields.Remark, 256, true)
}

// normalizeUserDefaultFields 把设置项与取值对齐到开放的三项；分组范围必须带分组。
func normalizeUserDefaultFields(fields *UserDefaultFields) bool {
	fields.Value = strings.TrimSpace(fields.Value)
	fields.ScopeName = strings.TrimSpace(fields.ScopeName)
	if fields.ScopeName == "" {
		fields.ScopeName = DefaultScopeGlobal
	}
	switch fields.ScopeName {
	case DefaultScopeGlobal:
		fields.GroupID = nil
	case DefaultScopeGroup:
		if fields.GroupID == nil || *fields.GroupID == uuid.Nil {
			return false
		}
	default:
		return false
	}
	switch fields.SettingName {
	case SettingListenProtocol:
		return fields.Value == ProtocolTCP || fields.Value == ProtocolUDP
	case SettingBalanceWay:
		return fields.Value == BalanceWayRoundRobin || fields.Value == BalanceWayIPHash
	case SettingProxyProtocol:
		return fields.Value == DefaultValueEnabled || fields.Value == DefaultValueDisabled
	default:
		return false
	}
}

func validListWindow(actor Actor, page, limit int) bool {
	return validActor(actor) && page >= 1 && page <= 1_000_000 && limit >= 1 && limit <= 100
}

// normalizeGroupIDs 去重并限制分组数量，防止过期或超量的分组 ID 进入成员表。
func normalizeGroupIDs(groupIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(groupIDs) > maxGroupAssignments {
		return nil, ErrInvalidInput
	}
	seen := make(map[uuid.UUID]struct{}, len(groupIDs))
	result := make([]uuid.UUID, 0, len(groupIDs))
	for _, id := range groupIDs {
		if id == uuid.Nil {
			return nil, ErrInvalidInput
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result, nil
}
