package cachecontrolhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

var (
	metadataPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	displayIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
)

type Service struct {
	control ControlStore
	reader  ReadStore
	cursors cursorCodec
}

type WriteMetadata struct {
	IdempotencyKey string
	RequestID      string
}

type PublishInput struct {
	SiteID                     uuid.UUID
	ExpectedRevision           int64
	BindingMode                cachecontrol.BindingMode
	DefinitionID               uuid.UUID
	DefinitionRevision         int64
	ExpectedDefinitionRevision *int64
	Document                   cachecontrol.PolicyDocument
	WriteMetadata
}

type HistoryInput struct {
	SiteID uuid.UUID
	Limit  int
	Cursor string
}

type CreateOperationInput struct {
	SiteID     uuid.UUID
	Action     cachecontrol.Action
	TargetType cachecontrol.TargetType
	Targets    []string
	NodeIDs    []uuid.UUID
	MaxRetries uint32
	WriteMetadata
}

type OperationListInput struct {
	Filters OperationFilters
	Limit   int
	Cursor  string
}

type CommandInput struct {
	OperationID uuid.UUID
	WriteMetadata
}

func NewService(control ControlStore, reader ReadStore, cursorKey []byte) (*Service, error) {
	if control == nil || reader == nil {
		return nil, ErrInvalidRequest
	}
	codec, err := newCursorCodec(cursorKey)
	if err != nil {
		return nil, err
	}
	return &Service{control: control, reader: reader, cursors: codec}, nil
}

func (service *Service) CurrentPolicy(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	siteID uuid.UUID,
) (PolicyView, error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionPoliciesRead)
	if err != nil || siteID == uuid.Nil {
		return PolicyView{}, firstError(err, ErrInvalidRequest)
	}
	policy, err := service.control.GetPolicy(ctx, actor, siteID, 0)
	if err != nil {
		return PolicyView{}, normalizeControlError(ctx, err)
	}
	return policyView(policy), nil
}

func (service *Service) PolicyRevision(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	siteID uuid.UUID,
	revision int64,
) (PolicyView, error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionPoliciesRead)
	if err != nil || siteID == uuid.Nil || revision < 1 {
		return PolicyView{}, firstError(err, ErrInvalidRequest)
	}
	policy, err := service.control.GetPolicy(ctx, actor, siteID, revision)
	if err != nil {
		return PolicyView{}, normalizeControlError(ctx, err)
	}
	return policyView(policy), nil
}

func (service *Service) PolicyHistory(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	input HistoryInput,
) (PolicyPage, error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionPoliciesRead)
	if err != nil || input.SiteID == uuid.Nil || input.Limit < 1 || input.Limit > 100 || len(input.Cursor) > maxCursorBytes {
		return PolicyPage{}, firstError(err, ErrInvalidRequest)
	}
	binding, err := filterDigest(struct {
		SiteID uuid.UUID `json:"site_id"`
	}{input.SiteID})
	if err != nil {
		return PolicyPage{}, err
	}
	query := PolicyPageQuery{Limit: input.Limit}
	if input.Cursor != "" {
		var cursor pageCursor
		if service.cursors.decode(input.Cursor, &cursor) != nil || cursor.Kind != "policy_history" ||
			cursor.ScopeID != actor.ScopeID || cursor.SiteID == nil || *cursor.SiteID != input.SiteID ||
			cursor.FilterSHA256 != binding || cursor.SnapshotRevision < 1 || cursor.BeforeRevision < 1 ||
			cursor.SnapshotPosition != 0 || cursor.BeforeCreatedAt != nil || cursor.BeforeID != nil {
			return PolicyPage{}, ErrInvalidRequest
		}
		query.SnapshotRevision = cursor.SnapshotRevision
		query.BeforeRevision = cursor.BeforeRevision
	}
	stored, err := service.reader.ListPolicyRevisions(ctx, actor, input.SiteID, query)
	if err != nil {
		return PolicyPage{}, normalizeControlError(ctx, err)
	}
	result := PolicyPage{Items: make([]PolicyView, len(stored.Items))}
	for index, item := range stored.Items {
		if item.ScopeID != actor.ScopeID || item.SiteID != input.SiteID || item.Revision < 1 {
			return PolicyPage{}, ErrInvalidStoreResponse
		}
		result.Items[index] = policyView(item)
	}
	if stored.HasMore {
		if len(stored.Items) == 0 || stored.SnapshotRevision < 1 {
			return PolicyPage{}, ErrInvalidStoreResponse
		}
		siteID := input.SiteID
		result.NextCursor, err = service.cursors.encode(pageCursor{
			Version: cursorVersion, Kind: "policy_history", ScopeID: actor.ScopeID, SiteID: &siteID,
			FilterSHA256: binding, SnapshotRevision: stored.SnapshotRevision,
			BeforeRevision: stored.Items[len(stored.Items)-1].Revision,
		})
		if err != nil {
			return PolicyPage{}, err
		}
	}
	return result, nil
}

func (service *Service) PublishPolicy(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	input PublishInput,
) (WriteResult[PolicyView], error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionPoliciesManage)
	if err != nil || input.SiteID == uuid.Nil || input.ExpectedRevision < 0 || !validMetadata(input.WriteMetadata) {
		return WriteResult[PolicyView]{}, firstError(err, ErrInvalidRequest)
	}
	result, err := service.control.PublishPolicy(ctx, actor, cachecontrol.PublishPolicyRequest{
		SiteID: input.SiteID, ExpectedRevision: input.ExpectedRevision,
		BindingMode: input.BindingMode, DefinitionID: input.DefinitionID,
		DefinitionRevision:         input.DefinitionRevision,
		ExpectedDefinitionRevision: input.ExpectedDefinitionRevision, Document: input.Document,
		IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
	})
	if err != nil {
		return WriteResult[PolicyView]{}, normalizeControlError(ctx, err)
	}
	return WriteResult[PolicyView]{Value: policyView(result.Policy), Replayed: result.Replayed}, nil
}

func (service *Service) CreateOperation(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	input CreateOperationInput,
) (WriteResult[OperationView], error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionOperationsManage)
	if err != nil || input.SiteID == uuid.Nil || !validMetadata(input.WriteMetadata) {
		return WriteResult[OperationView]{}, firstError(err, ErrInvalidRequest)
	}
	result, err := service.control.CreateOperation(ctx, actor, cachecontrol.CreateOperationRequest{
		SiteID: input.SiteID, Action: input.Action, TargetType: input.TargetType,
		Targets: input.Targets, NodeIDs: input.NodeIDs, MaxRetries: input.MaxRetries,
		IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
	})
	if err != nil {
		return WriteResult[OperationView]{}, normalizeControlError(ctx, err)
	}
	return WriteResult[OperationView]{Value: operationView(result.Operation), Replayed: result.Replayed}, nil
}

func (service *Service) Operation(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	operationID uuid.UUID,
) (OperationView, error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionOperationsRead)
	if err != nil || operationID == uuid.Nil {
		return OperationView{}, firstError(err, ErrInvalidRequest)
	}
	operation, err := service.control.GetOperation(ctx, actor, operationID)
	if err != nil {
		return OperationView{}, normalizeControlError(ctx, err)
	}
	return operationView(operation), nil
}

// TargetSites groups target URLs by the sites serving their hosts
// (fix-cachedlg): the create dialog splits one batch into a task per site and
// lists the URLs no site serves before it sends anything. A platform reader
// without a target scope matches every tenant's sites.
func (service *Service) TargetSites(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	input cachecontrol.ResolveTargetSitesRequest,
) (TargetSitesView, error) {
	allScopes := audience == AudiencePlatform && targetScopeID == nil
	var actor cachecontrol.Actor
	var err error
	if allScopes {
		ownScope := principal.ScopeID
		actor, err = cacheActor(principal, audience, &ownScope, PermissionOperationsRead)
	} else {
		actor, err = cacheActor(principal, audience, targetScopeID, PermissionOperationsRead)
	}
	if err != nil || len(input.Targets) == 0 || len(input.Targets) > EdgeCacheTaskV2MaxTargets {
		return TargetSitesView{}, firstError(err, ErrInvalidRequest)
	}
	grouping, err := service.control.ResolveTargetSites(ctx, actor, allScopes, input)
	if err != nil {
		return TargetSitesView{}, normalizeControlError(ctx, err)
	}
	view := TargetSitesView{
		Groups:    make([]TargetSiteGroupView, len(grouping.Groups)),
		Unmatched: make([]UnmatchedTargetView, len(grouping.Unmatched)),
	}
	for index, group := range grouping.Groups {
		view.Groups[index] = TargetSiteGroupView{
			SiteID: group.Site.SiteID, ScopeID: group.Site.ScopeID, SiteDisplayID: group.Site.DisplayID,
			Domain: group.Site.Domain, TargetOrdinals: group.Ordinals,
		}
	}
	for index, item := range grouping.Unmatched {
		view.Unmatched[index] = UnmatchedTargetView{TargetOrdinal: item.Ordinal, Reason: item.Reason}
	}
	return view, nil
}

// CarryingNodes lists the nodes an operation of the scope without node IDs
// runs on: the create dialog's node picker.
func (service *Service) CarryingNodes(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
) (CarryingNodesView, error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionOperationsRead)
	if err != nil {
		return CarryingNodesView{}, err
	}
	nodes, err := service.control.CarryingNodes(ctx, actor)
	if err != nil {
		return CarryingNodesView{}, normalizeControlError(ctx, err)
	}
	view := CarryingNodesView{Items: make([]CarryingNodeView, len(nodes))}
	for index, node := range nodes {
		view.Items[index] = CarryingNodeView{ID: node.ID, DisplayID: node.DisplayID, Name: node.Name, IPv4: node.IPv4, IPv6: node.IPv6}
	}
	return view, nil
}

// WriteReceipt reads what the server did with a write sent with key (fix-cacheflow5).
// Anything the actor may not see is ErrNotFound, like a key never received.
func (service *Service) WriteReceipt(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	request cachecontrol.WriteReceiptRequest,
) (WriteReceiptView, error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionOperationsRead)
	if err != nil {
		return WriteReceiptView{}, err
	}
	receipt, err := service.control.WriteReceipt(ctx, actor, request)
	if err != nil {
		return WriteReceiptView{}, normalizeControlError(ctx, err)
	}
	view := WriteReceiptView{Status: string(receipt.Status), DecidedAt: receipt.DecidedAt.UTC()}
	switch receipt.Status {
	case cachecontrol.WriteAccepted:
		if receipt.Operation.ID == uuid.Nil || receipt.Operation.ScopeID != actor.ScopeID {
			return WriteReceiptView{}, ErrInvalidStoreResponse
		}
		operation := operationView(receipt.Operation)
		view.Operation = &operation
	case cachecontrol.WriteRejected:
		if !metadataPattern.MatchString(receipt.Rejection.Code) {
			return WriteReceiptView{}, ErrInvalidStoreResponse
		}
		view.Rejection = &WriteRejectionView{Code: receipt.Rejection.Code}
		if receipt.Rejection.TargetOrdinal > 0 {
			view.Rejection.Details = &TargetRejection{
				Field: "targets", TargetOrdinal: receipt.Rejection.TargetOrdinal,
				Stage: "target_validation", Reason: receipt.Rejection.TargetReason,
			}
		}
	default:
		return WriteReceiptView{}, ErrInvalidStoreResponse
	}
	return view, nil
}

// DailyUsage is the account's quotas for today (CACHE-01, fix-cachequota:
// per account, not per site): the limits and counts a create is checked
// against.
func (service *Service) DailyUsage(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
) (cachecontrol.DailyUsage, error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionOperationsRead)
	if err != nil {
		return cachecontrol.DailyUsage{}, err
	}
	usage, err := service.control.DailyUsage(ctx, actor)
	if err != nil {
		return cachecontrol.DailyUsage{}, normalizeControlError(ctx, err)
	}
	return usage, nil
}

// SetAccountLimits sets a tenant account's own daily limits (platform
// route only; the user management permission identity.users.manage).
func (service *Service) SetAccountLimits(
	ctx context.Context,
	principal identity.Principal,
	targetScopeID *uuid.UUID,
	request cachecontrol.SetAccountLimitsRequest,
) (cachecontrol.DailyUsage, error) {
	actor, err := cacheActor(principal, AudiencePlatform, targetScopeID, PermissionAccountQuotaManage)
	if err != nil {
		return cachecontrol.DailyUsage{}, err
	}
	usage, err := service.control.SetAccountLimits(ctx, actor, request)
	if err != nil {
		return cachecontrol.DailyUsage{}, normalizeControlError(ctx, err)
	}
	return usage, nil
}

func (service *Service) Operations(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	input OperationListInput,
) (OperationPage, error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionOperationsRead)
	if err != nil || input.Limit < 1 || input.Limit > 100 || len(input.Cursor) > maxCursorBytes || !validFilters(input.Filters) {
		return OperationPage{}, firstError(err, ErrInvalidRequest)
	}
	binding, err := filterDigest(input.Filters)
	if err != nil {
		return OperationPage{}, err
	}
	query := OperationPageQuery{Filters: input.Filters, Limit: input.Limit}
	if input.Cursor != "" {
		var cursor pageCursor
		if service.cursors.decode(input.Cursor, &cursor) != nil || cursor.Kind != "operations" ||
			cursor.ScopeID != actor.ScopeID || cursor.SiteID != nil || cursor.FilterSHA256 != binding ||
			cursor.SnapshotPosition < 1 || cursor.BeforeCreatedAt == nil ||
			cursor.BeforeID == nil || *cursor.BeforeID == uuid.Nil || cursor.SnapshotRevision != 0 || cursor.BeforeRevision != 0 {
			return OperationPage{}, ErrInvalidRequest
		}
		query.SnapshotPosition = cursor.SnapshotPosition
		query.BeforeCreated = cursor.BeforeCreatedAt
		query.BeforeID = cursor.BeforeID
	}
	stored, err := service.reader.ListOperations(ctx, actor, query)
	if err != nil {
		return OperationPage{}, normalizeControlError(ctx, err)
	}
	for _, item := range stored.Items {
		if item.ID == uuid.Nil || item.SiteID == uuid.Nil || item.CreatedAt.IsZero() {
			return OperationPage{}, ErrInvalidStoreResponse
		}
	}
	result := OperationPage{Items: stored.Items, StateCounts: stored.StateCounts}
	if stored.HasMore {
		if len(stored.Items) == 0 || stored.SnapshotPosition < 1 {
			return OperationPage{}, ErrInvalidStoreResponse
		}
		last := stored.Items[len(stored.Items)-1]
		before, beforeID := last.CreatedAt.UTC(), last.ID
		result.NextCursor, err = service.cursors.encode(pageCursor{
			Version: cursorVersion, Kind: "operations", ScopeID: actor.ScopeID, FilterSHA256: binding,
			SnapshotPosition: stored.SnapshotPosition, BeforeCreatedAt: &before, BeforeID: &beforeID,
		})
		if err != nil {
			return OperationPage{}, err
		}
	}
	return result, nil
}

func (service *Service) Retry(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	input CommandInput,
) (WriteResult[OperationView], error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionOperationsManage)
	if err != nil || input.OperationID == uuid.Nil || !validMetadata(input.WriteMetadata) {
		return WriteResult[OperationView]{}, firstError(err, ErrInvalidRequest)
	}
	result, err := service.control.Retry(ctx, actor, cachecontrol.RetryRequest{
		OperationID: input.OperationID, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
	})
	if err != nil {
		return WriteResult[OperationView]{}, normalizeControlError(ctx, err)
	}
	return WriteResult[OperationView]{Value: operationView(result.Operation), Replayed: result.Replayed}, nil
}

// Resubmit creates a new operation from an existing one; WriteMetadata's
// idempotency key is the batch key (shared by one "re-submit selected").
func (service *Service) Resubmit(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	input CommandInput,
) (WriteResult[OperationView], error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionOperationsManage)
	if err != nil || input.OperationID == uuid.Nil || !validMetadata(input.WriteMetadata) {
		return WriteResult[OperationView]{}, firstError(err, ErrInvalidRequest)
	}
	result, err := service.control.Resubmit(ctx, actor, cachecontrol.ResubmitRequest{
		OperationID: input.OperationID, BatchKey: input.IdempotencyKey, RequestID: input.RequestID,
	})
	if err != nil {
		return WriteResult[OperationView]{}, normalizeControlError(ctx, err)
	}
	return WriteResult[OperationView]{Value: operationView(result.Operation), Replayed: result.Replayed}, nil
}

func (service *Service) Cancel(
	ctx context.Context,
	principal identity.Principal,
	audience Audience,
	targetScopeID *uuid.UUID,
	input CommandInput,
) (WriteResult[OperationView], error) {
	actor, err := cacheActor(principal, audience, targetScopeID, PermissionOperationsManage)
	if err != nil || input.OperationID == uuid.Nil || !validMetadata(input.WriteMetadata) {
		return WriteResult[OperationView]{}, firstError(err, ErrInvalidRequest)
	}
	result, err := service.control.Cancel(ctx, actor, cachecontrol.CancelRequest{
		OperationID: input.OperationID, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
	})
	if err != nil {
		return WriteResult[OperationView]{}, normalizeControlError(ctx, err)
	}
	return WriteResult[OperationView]{Value: operationView(result.Operation), Replayed: result.Replayed}, nil
}

func cacheActor(principal identity.Principal, audience Audience, targetScopeID *uuid.UUID, permission string) (cachecontrol.Actor, error) {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil ||
		(!hasExactPermission(principal, permission) &&
			!(principal.ScopeKind == string(AudiencePlatform) && hasExactPermission(principal, "platform.admin"))) {
		return cachecontrol.Actor{}, ErrPermissionDenied
	}
	switch audience {
	case AudienceTenant:
		if principal.ScopeKind != string(AudienceTenant) || targetScopeID != nil {
			return cachecontrol.Actor{}, ErrPermissionDenied
		}
		return cachecontrol.Actor{
			UserID: principal.UserID, ScopeID: principal.ScopeID, ActorScopeID: principal.ScopeID,
		}, nil
	case AudiencePlatform:
		if principal.ScopeKind != string(AudiencePlatform) {
			return cachecontrol.Actor{}, ErrPermissionDenied
		}
		if targetScopeID == nil || *targetScopeID == uuid.Nil {
			return cachecontrol.Actor{}, ErrInvalidRequest
		}
		return cachecontrol.Actor{
			UserID: principal.UserID, ScopeID: *targetScopeID, ActorScopeID: principal.ScopeID,
		}, nil
	default:
		return cachecontrol.Actor{}, ErrInvalidRequest
	}
}

func hasExactPermission(principal identity.Principal, permission string) bool {
	for _, candidate := range principal.Permissions {
		if candidate == permission {
			return true
		}
	}
	return false
}

func normalizeControlError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrWildcardTargetHost), errors.Is(err, cachecontrol.ErrWildcardTargetHost):
		return ErrWildcardTargetHost
	case errors.As(err, new(*TargetRejection)):
		return err
	case errors.As(err, new(*cachecontrol.DailyLimitError)):
		return err
	case errors.As(err, new(*cachecontrol.TargetError)):
		var target *cachecontrol.TargetError
		errors.As(err, &target)
		return &TargetRejection{Field: "targets", TargetOrdinal: target.Ordinal, Stage: "target_validation", Reason: target.Reason}
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, cachecontrol.ErrInvalidInput):
		return ErrInvalidRequest
	case errors.Is(err, ErrPermissionDenied):
		return ErrPermissionDenied
	case errors.Is(err, ErrNotFound), errors.Is(err, cachecontrol.ErrNotFound), errors.Is(err, cachecontrol.ErrPermissionDenied):
		return ErrNotFound
	case errors.Is(err, ErrRevisionConflict), errors.Is(err, cachecontrol.ErrRevisionConflict):
		return ErrRevisionConflict
	case errors.Is(err, ErrIdempotencyConflict), errors.Is(err, cachecontrol.ErrIdempotencyConflict):
		return ErrIdempotencyConflict
	case errors.Is(err, ErrInvalidTransition), errors.Is(err, cachecontrol.ErrInvalidTransition):
		return ErrInvalidTransition
	case errors.Is(err, ErrRetriesExhausted), errors.Is(err, cachecontrol.ErrRetriesExhausted):
		return ErrRetriesExhausted
	case errors.Is(err, ErrEntitlementDenied), errors.Is(err, cachecontrol.ErrEntitlementDenied):
		return ErrEntitlementDenied
	case errors.Is(err, ErrSiteLocked), errors.Is(err, cachecontrol.ErrSiteLocked):
		return ErrSiteLocked
	case errors.Is(err, ErrDailyLimitExceeded), errors.Is(err, cachecontrol.ErrDailyLimitExceeded):
		return ErrDailyLimitExceeded
	case errors.Is(err, ErrNoCarryingNode), errors.Is(err, cachecontrol.ErrNoCarryingNode):
		return ErrNoCarryingNode
	case errors.Is(err, ErrTargetNodeUnavailable), errors.Is(err, cachecontrol.ErrTargetNodeUnavailable):
		return ErrTargetNodeUnavailable
	case errors.Is(err, ErrWildcardPurgeUnsupported), errors.Is(err, cachecontrol.ErrWildcardPurgeUnsupported):
		return ErrWildcardPurgeUnsupported
	case errors.Is(err, ErrInvalidStoreResponse):
		return ErrInvalidStoreResponse
	default:
		return ErrStoreUnavailable
	}
}

func firstError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}

func validMetadata(metadata WriteMetadata) bool {
	return metadataPattern.MatchString(metadata.IdempotencyKey) && metadataPattern.MatchString(metadata.RequestID)
}

func validFilters(filters OperationFilters) bool {
	if filters.Search != strings.TrimSpace(filters.Search) || filters.SiteDisplayID != strings.TrimSpace(filters.SiteDisplayID) ||
		!utf8.ValidString(filters.Search) || len(filters.Search) > 128 ||
		strings.ContainsFunc(filters.Search, unicode.IsControl) {
		return false
	}
	if filters.SiteDisplayID != "" && !displayIDPattern.MatchString(filters.SiteDisplayID) {
		return false
	}
	if filters.SiteID != nil && *filters.SiteID == uuid.Nil {
		return false
	}
	if filters.Action != "" && filters.Action != cachecontrol.ActionPurge && filters.Action != cachecontrol.ActionPrewarm {
		return false
	}
	if filters.TargetType != "" && filters.TargetType != cachecontrol.TargetExactURL &&
		filters.TargetType != cachecontrol.TargetDirectoryPrefix && filters.TargetType != cachecontrol.TargetWholeSite {
		return false
	}
	if len(filters.States) > len(operationStates) {
		return false
	}
	for index, state := range filters.States {
		// Sorted and distinct, so one set of states has one filter digest.
		if !slices.Contains(operationStates, state) || index > 0 && filters.States[index-1] >= state {
			return false
		}
	}
	return true
}

var operationStates = []cachecontrol.State{
	cachecontrol.StateCancelled, cachecontrol.StateFailed, cachecontrol.StatePartialFailed,
	cachecontrol.StateQueued, cachecontrol.StateRunning, cachecontrol.StateSucceeded,
}

func policyView(policy cachecontrol.PolicyRevision) PolicyView {
	return PolicyView{
		SiteID: policy.SiteID, Revision: policy.Revision, BindingMode: policy.BindingMode,
		DefinitionID: policy.DefinitionID, DefinitionRevision: policy.DefinitionRevision, Document: policy.Document,
		CreatedByUserID: policy.CreatedByUserID, RequestID: policy.RequestID, CreatedAt: policy.CreatedAt,
	}
}

func operationView(operation cachecontrol.Operation) OperationView {
	result := OperationView{
		ID: operation.ID, DisplayID: operation.DisplayID, SiteID: operation.SiteID,
		SiteDisplayID: operation.SiteDisplayID, Action: operation.Action, TargetType: operation.TargetType,
		State: operation.State, MaxAttempts: operation.MaxAttempts, Progress: operation.Progress,
		AutoNodes: operation.AutoNodes, ParentOperationID: operation.ParentOperationID,
		Targets: make([]TargetView, len(operation.Targets)), Nodes: make([]NodeProjectionView, len(operation.Nodes)),
		CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt,
	}
	result.CancelRequestedAt = nonzeroTime(operation.CancelRequestedAt)
	result.StartedAt = nonzeroTime(operation.StartedAt)
	result.CompletedAt = nonzeroTime(operation.CompletedAt)
	for index, target := range operation.Targets {
		result.Targets[index] = targetView(target)
	}
	for index, node := range operation.Nodes {
		view := NodeProjectionView{
			NodeID: node.NodeID, NodeDisplayID: node.NodeDisplayID,
			State: node.State, Attempt: node.Attempt, Progress: node.Progress,
			LastErrorCode: node.LastErrorCode, UpdatedAt: node.UpdatedAt, CancelConfirmation: node.CancelConfirmation,
			Targets: make([]TargetProjectionView, len(node.Targets)), CompletedAt: nonzeroTime(node.CompletedAt),
		}
		for targetIndex, target := range node.Targets {
			view.Targets[targetIndex] = TargetProjectionView{
				TargetOrdinal: target.TargetOrdinal, State: target.State, Attempt: target.Attempt,
				Sequence: target.Sequence, ErrorCode: target.ErrorCode, CompletedAt: nonzeroTime(target.CompletedAt),
			}
		}
		result.Nodes[index] = view
	}
	return result
}

func targetView(target cachecontrol.Target) TargetView {
	digest := sha256.Sum256([]byte(target.CanonicalURL))
	result := TargetView{
		Ordinal: target.Ordinal, DisplayURL: target.CanonicalURL, CanonicalPath: target.CanonicalPath,
		TargetSHA256: hex.EncodeToString(digest[:]),
	}
	parsed, err := url.Parse(target.CanonicalURL)
	if err == nil && (parsed.RawQuery != "" || parsed.ForceQuery) {
		parsed.RawQuery = "query=redacted"
		parsed.ForceQuery = false
		result.DisplayURL = parsed.String()
		result.QueryRedacted = true
	}
	return result
}

func nonzeroTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func canonicalUUID(value string) (uuid.UUID, error) {
	if value == "" || strings.ToLower(value) != value {
		return uuid.Nil, ErrInvalidRequest
	}
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, ErrInvalidRequest
	}
	return parsed, nil
}
