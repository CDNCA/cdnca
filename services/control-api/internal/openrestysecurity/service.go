package openrestysecurity

import (
	"context"

	"github.com/google/uuid"
)

type ReadGlobalRequest struct {
	Actor         Actor
	TargetScopeID uuid.UUID
}

type PatchGlobalRequest struct {
	Actor            Actor
	TargetScopeID    uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	Patch            Config
}

type ListOverridesRequest struct {
	Actor         Actor
	TargetScopeID uuid.UUID
	ScopeType     string
	Query         string
	Page          int
	PageSize      int
}

type CreateOverrideRequest struct {
	Actor          Actor
	TargetScopeID  uuid.UUID
	ScopeType      string
	ScopeID        string
	IdempotencyKey string
	RequestID      string
	Config         Config
}

type PatchOverrideRequest struct {
	Actor            Actor
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	Patch            Config
	RemovedFields    []string
}

type DeleteOverrideRequest struct {
	Actor            Actor
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type SearchTargetsRequest struct {
	Actor         Actor
	TargetScopeID uuid.UUID
	ScopeType     string
	Query         string
	Page          int
	PageSize      int
}

type EffectiveRequest struct {
	Actor         Actor
	TargetScopeID uuid.UUID
	NodeID        uuid.UUID
}

type RuleGroupsRequest struct {
	Actor         Actor
	TargetScopeID uuid.UUID
}

type DownloadCCImageRequest struct {
	Actor          Actor
	TargetScopeID  uuid.UUID
	IdempotencyKey string
	RequestID      string
}

type WriteResult struct {
	Document Document
	Replayed bool
}

type API interface {
	GetGlobal(context.Context, ReadGlobalRequest) (Document, error)
	PatchGlobal(context.Context, PatchGlobalRequest) (WriteResult, error)
	ListOverrides(context.Context, ListOverridesRequest) (OverridePage, error)
	CreateOverride(context.Context, CreateOverrideRequest) (WriteResult, error)
	PatchOverride(context.Context, PatchOverrideRequest) (WriteResult, error)
	DeleteOverride(context.Context, DeleteOverrideRequest) (bool, error)
	SearchTargets(context.Context, SearchTargetsRequest) (TargetPage, error)
	Effective(context.Context, EffectiveRequest) (Document, error)
	RuleGroups(context.Context, RuleGroupsRequest) ([]RuleGroup, error)
	SetRuleGroupEnabled(context.Context, RuleGroupStateRequest) error
	DownloadCCImage(context.Context, DownloadCCImageRequest) (bool, error)
}
