package analyticslog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

const blockManagePermission = "security_policies.manage"

const MaxBlockOffset = uint32(1_000_000)

var (
	ErrBlockStateConflict = errors.New("analytics block state conflict")
	ErrBlockStateNotFound = errors.New("analytics block state not found")
	blockWriteKeyPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

type EdgeProgress struct {
	CandidateID uuid.UUID `json:"candidate_id"`
	State       string    `json:"state"`
	TotalNodes  int       `json:"total_nodes"`
	ReadyNodes  int       `json:"ready_nodes"`
	FailedNodes int       `json:"failed_nodes"`
	// SupersededNodes: nodes that ignored the unlock as an old release (they
	// already run a newer revision); not failed (fix-cfgflow3).
	SupersededNodes int `json:"superseded_nodes"`
}

type CurrentBlock struct {
	ID            uuid.UUID     `json:"id"`
	TenantID      uuid.UUID     `json:"tenant_id"`
	SiteID        uuid.UUID     `json:"site_id"`
	SiteDisplayID int64         `json:"site_display_id"`
	Domain        string        `json:"domain"`
	Position      string        `json:"position"`
	PolicyID      uuid.UUID     `json:"policy_id"`
	PolicyVersion int64         `json:"policy_version"`
	CIDR          string        `json:"cidr"`
	ReasonCode    string        `json:"reason_code"`
	BlockedAt     time.Time     `json:"blocked_at"`
	Unlockable    bool          `json:"unlockable"`
	EdgeProgress  *EdgeProgress `json:"edge_progress,omitempty"`
}

type BlockHistory struct {
	ID            uuid.UUID    `json:"id"`
	BlockID       uuid.UUID    `json:"block_id"`
	TenantID      uuid.UUID    `json:"tenant_id"`
	SiteID        uuid.UUID    `json:"site_id"`
	SiteDisplayID int64        `json:"site_display_id"`
	Domain        string       `json:"domain"`
	Position      string       `json:"position"`
	PolicyID      uuid.UUID    `json:"policy_id"`
	CIDR          string       `json:"cidr"`
	ReasonCode    string       `json:"reason_code"`
	ResultCode    string       `json:"result_code"`
	AutoUnlock    bool         `json:"auto_unlock"`
	RequestedAt   time.Time    `json:"requested_at"`
	UnlockedAt    *time.Time   `json:"unlocked_at"`
	EdgeProgress  EdgeProgress `json:"edge_progress"`
}

type BlockListRequest struct {
	SiteID   *uuid.UUID
	PolicyID *uuid.UUID
	CIDR     string
	Limit    uint16
	Offset   uint32
	// OccurredFrom/OccurredTo bound the history window; nil means unbounded on that side.
	OccurredFrom *time.Time
	OccurredTo   *time.Time
}

type CurrentBlockPage struct {
	Items      []CurrentBlock `json:"data"`
	TotalCount uint64         `json:"total_count"`
	SnapshotAt time.Time      `json:"snapshot_at"`
}

type BlockHistoryPage struct {
	Items      []BlockHistory `json:"data"`
	TotalCount uint64         `json:"total_count"`
	SnapshotAt time.Time      `json:"snapshot_at"`
}

type SiteBlacklistCount struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	SiteID        uuid.UUID `json:"site_id"`
	SiteDisplayID int64     `json:"site_display_id"`
	Domain        string    `json:"domain"`
	Count         uint64    `json:"count"`
}

type SiteBlacklistCountPage struct {
	Items      []SiteBlacklistCount `json:"data"`
	TotalCount uint64               `json:"total_count"`
	SnapshotAt time.Time            `json:"snapshot_at"`
}

type BlockActor struct {
	UserID        uuid.UUID
	ActorScopeID  uuid.UUID
	TargetScopeID uuid.UUID
	ScopeKind     string
}

type BlockUnlockPreparation struct {
	Block               CurrentBlock
	Policy              securitypolicy.Policy
	BindingRevision     int64
	ActivePolicyVersion int64
	LatestPolicyVersion int64
	OpenCandidateID     uuid.UUID
	TargetNodeIDs       []uuid.UUID
}

type BlockUnlockResult struct {
	BlockID     uuid.UUID `json:"block_id"`
	CandidateID uuid.UUID `json:"candidate_id"`
	Progress    string    `json:"progress"`
	ReasonCode  string    `json:"reason_code"`
	Replayed    bool      `json:"replayed"`
}

type BlockStateStore interface {
	ListCurrent(context.Context, uuid.UUID, BlockListRequest) (CurrentBlockPage, error)
	ListHistory(context.Context, uuid.UUID, BlockListRequest) (BlockHistoryPage, error)
	CountCurrent(context.Context, uuid.UUID) (SiteBlacklistCountPage, error)
	PrepareUnlock(context.Context, uuid.UUID, uuid.UUID) (BlockUnlockPreparation, error)
}

type blockPolicyUpdater interface {
	Update(context.Context, securitypolicy.Actor, securitypolicy.UpdateRequest) (securitypolicy.WriteResult, error)
}

type BlockActivationStarter interface {
	Start(context.Context, securitypolicy.Actor, securityactivation.StartInput) (securityactivation.StartResult, error)
}

type unavailableBlockActivation struct{}

func (unavailableBlockActivation) Start(context.Context, securitypolicy.Actor,
	securityactivation.StartInput,
) (securityactivation.StartResult, error) {
	return securityactivation.StartResult{}, securityactivation.ErrUnavailable
}

type BlockStateService struct {
	store       BlockStateStore
	policies    blockPolicyUpdater
	activations BlockActivationStarter
	now         func() time.Time
}

func NewBlockStateService(store BlockStateStore, policies blockPolicyUpdater, activations BlockActivationStarter,
	now func() time.Time,
) (*BlockStateService, error) {
	if nilInterface(store) || nilInterface(policies) || nilInterface(activations) || now == nil {
		return nil, ErrInvalidConfiguration
	}
	return &BlockStateService{store: store, policies: policies, activations: activations, now: now}, nil
}

func (service *BlockStateService) ListCurrent(ctx context.Context, scopeID uuid.UUID,
	request BlockListRequest,
) (CurrentBlockPage, error) {
	if service == nil || !validBlockListRequest(request) {
		return CurrentBlockPage{}, ErrInvalidInput
	}
	return service.store.ListCurrent(ctx, scopeID, request)
}

func (service *BlockStateService) ListHistory(ctx context.Context, scopeID uuid.UUID,
	request BlockListRequest,
) (BlockHistoryPage, error) {
	if service == nil || !validBlockListRequest(request) {
		return BlockHistoryPage{}, ErrInvalidInput
	}
	return service.store.ListHistory(ctx, scopeID, request)
}

func (service *BlockStateService) CountCurrent(ctx context.Context, scopeID uuid.UUID,
) (SiteBlacklistCountPage, error) {
	if service == nil {
		return SiteBlacklistCountPage{}, ErrInvalidInput
	}
	return service.store.CountCurrent(ctx, scopeID)
}

func (service *BlockStateService) Unlock(ctx context.Context, actor BlockActor, blockID uuid.UUID,
	reasonCode, idempotencyKey, requestID string,
) (BlockUnlockResult, error) {
	if service == nil || ctx == nil || blockID == uuid.Nil || actor.UserID == uuid.Nil ||
		actor.ActorScopeID == uuid.Nil || actor.TargetScopeID == uuid.Nil ||
		(actor.ScopeKind != "tenant" && actor.ScopeKind != "platform") ||
		reasonCode != securityactivation.RecoveryReasonFalsePositiveConfirmed ||
		!blockWriteKeyPattern.MatchString(idempotencyKey) || !requestIDPattern.MatchString(requestID) {
		return BlockUnlockResult{}, ErrInvalidInput
	}
	prepared, err := service.store.PrepareUnlock(ctx, actor.TargetScopeID, blockID)
	if err != nil {
		return BlockUnlockResult{}, err
	}
	if prepared.Block.ID != blockID || prepared.Policy.ID != prepared.Block.PolicyID ||
		prepared.Policy.ScopeID != actor.TargetScopeID || prepared.Policy.Kind != securitypolicy.KindACL ||
		prepared.ActivePolicyVersion < 1 || prepared.LatestPolicyVersion != prepared.ActivePolicyVersion ||
		prepared.Policy.Revision != prepared.ActivePolicyVersion || prepared.BindingRevision < 1 ||
		prepared.OpenCandidateID != uuid.Nil || len(prepared.TargetNodeIDs) == 0 {
		return BlockUnlockResult{}, ErrBlockStateConflict
	}
	fields, err := blockSuccessor(prepared.Policy, prepared.Block.CIDR)
	if err != nil {
		return BlockUnlockResult{}, err
	}
	policyActor := securitypolicy.Actor{
		UserID: actor.UserID, ScopeID: actor.ActorScopeID, ScopeKind: actor.ScopeKind,
	}
	write, err := service.policies.Update(ctx, policyActor, securitypolicy.UpdateRequest{
		ID: prepared.Policy.ID, ExpectedRevision: prepared.ActivePolicyVersion, Fields: fields,
		IdempotencyKey: derivedBlockWriteKey("policy", idempotencyKey), RequestID: requestID,
	})
	if err != nil {
		return BlockUnlockResult{}, mapBlockDependencyError(err)
	}
	if write.Policy.ID != prepared.Policy.ID || write.Policy.Revision != prepared.ActivePolicyVersion+1 {
		return BlockUnlockResult{}, ErrBlockStateConflict
	}
	nodes := append([]uuid.UUID(nil), prepared.TargetNodeIDs...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].String() < nodes[j].String() })
	now := service.now().UTC().Truncate(time.Microsecond)
	activation, err := service.activations.Start(ctx, policyActor, securityactivation.StartInput{
		TenantScopeID: actor.TargetScopeID, SiteID: prepared.Block.SiteID, PolicyID: prepared.Policy.ID,
		PolicyVersion: write.Policy.Revision, ExpectedBindingRevision: prepared.BindingRevision,
		ExpectedActivePolicyVersion: prepared.ActivePolicyVersion, TargetNodeIDs: nodes, CanarySize: 1,
		IdempotencyKey: derivedBlockWriteKey("activation", idempotencyKey), RequestID: requestID,
		ExpiresAt: now.Add(10 * time.Minute), Recovery: &securityactivation.CIDRRecoveryIntent{
			Operation:  securityactivation.RecoveryOperationCIDRUnlock,
			ReasonCode: reasonCode, CIDRs: []string{prepared.Block.CIDR},
		},
	})
	if err != nil {
		return BlockUnlockResult{}, mapBlockDependencyError(err)
	}
	if activation.Candidate.ID == uuid.Nil || activation.Candidate.Status == "" {
		return BlockUnlockResult{}, ErrBlockStateConflict
	}
	return BlockUnlockResult{
		BlockID: blockID, CandidateID: activation.Candidate.ID, Progress: string(activation.Candidate.Status),
		ReasonCode: activation.ReasonCode, Replayed: write.Replayed || activation.Replayed,
	}, nil
}

func blockSuccessor(policy securitypolicy.Policy, cidr string) (securitypolicy.PolicyFields, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || prefix.Masked().String() != cidr {
		return securitypolicy.PolicyFields{}, ErrBlockStateConflict
	}
	encoded, err := json.Marshal(policy.Rules)
	if err != nil {
		return securitypolicy.PolicyFields{}, ErrBlockStateConflict
	}
	var rules []securitypolicy.Rule
	if err := json.Unmarshal(encoded, &rules); err != nil {
		return securitypolicy.PolicyFields{}, ErrBlockStateConflict
	}
	found := false
	kept := rules[:0]
	for _, rule := range rules {
		if rule.Enabled && rule.Action == securitypolicy.ActionBlock {
			for index := range rule.Conditions {
				condition := &rule.Conditions[index]
				if condition.Field != "client_ip" || condition.Operator != "ip_in_cidr" {
					continue
				}
				values := condition.Values[:0]
				for _, value := range condition.Values {
					candidate, parseErr := netip.ParsePrefix(value)
					if parseErr == nil && candidate.Masked().String() == cidr {
						found = true
						continue
					}
					values = append(values, value)
				}
				condition.Values = values
			}
		}
		drop := false
		for _, condition := range rule.Conditions {
			if condition.Field == "client_ip" && condition.Operator == "ip_in_cidr" && len(condition.Values) == 0 {
				drop = true
			}
		}
		if !drop {
			kept = append(kept, rule)
		}
	}
	if !found || len(kept) == 0 {
		return securitypolicy.PolicyFields{}, ErrBlockStateConflict
	}
	return securitypolicy.PolicyFields{
		Kind: policy.Kind, Name: policy.Name, Description: policy.Description, Enabled: policy.Enabled,
		DefaultAction: policy.DefaultAction, Rules: kept, WAFSettings: securitypolicy.CloneWAFSettings(policy.WAFSettings),
	}, nil
}

func blockIdentity(siteID, policyID uuid.UUID, cidr string) uuid.UUID {
	return uuid.NewSHA1(policyID, []byte(siteID.String()+"\x00"+cidr))
}

func validBlockCIDR(cidr string) bool {
	prefix, err := netip.ParsePrefix(cidr)
	return err == nil && prefix.Masked().String() == cidr
}

func derivedBlockWriteKey(kind, key string) string {
	digest := sha256.Sum256([]byte(key))
	return "block-unlock." + kind + "." + hex.EncodeToString(digest[:])
}

func validBlockListRequest(request BlockListRequest) bool {
	if request.Limit < 1 || request.Limit > MaxLimit || request.Offset > MaxBlockOffset || request.SiteID != nil && *request.SiteID == uuid.Nil ||
		request.PolicyID != nil && *request.PolicyID == uuid.Nil {
		return false
	}
	if request.OccurredFrom != nil && request.OccurredTo != nil && request.OccurredTo.Before(*request.OccurredFrom) {
		return false
	}
	return request.CIDR == "" || validBlockCIDR(request.CIDR)
}

func mapBlockDependencyError(err error) error {
	switch {
	case errors.Is(err, securitypolicy.ErrInvalidInput), errors.Is(err, securityactivation.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, securitypolicy.ErrPermissionDenied), errors.Is(err, securityactivation.ErrPermissionDenied):
		return ErrPermissionDenied
	case errors.Is(err, securitypolicy.ErrNotFound), errors.Is(err, securityactivation.ErrNotFound):
		return ErrBlockStateNotFound
	case errors.Is(err, securitypolicy.ErrRevisionConflict), errors.Is(err, securitypolicy.ErrIdempotencyConflict),
		errors.Is(err, securityactivation.ErrConflict), errors.Is(err, securityactivation.ErrIdempotencyConflict),
		errors.Is(err, securityactivation.ErrSourceRevisionConflict), errors.Is(err, securityactivation.ErrSiteLocked):
		return ErrBlockStateConflict
	case errors.Is(err, securityactivation.ErrUnavailable):
		return ErrStorageUnavailable
	default:
		return ErrStorageUnavailable
	}
}
