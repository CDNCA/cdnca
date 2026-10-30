package ja4block

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

const (
	claimLease      = 30 * time.Second
	minimumDuration = time.Minute
	maximumDuration = 30 * 24 * time.Hour
)

var (
	keyPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type Service struct {
	store        WorkflowStore
	authority    AuthoritySource
	policies     PolicyWriter
	publications PublicationWriter
	now          func() time.Time
}

func NewService(store WorkflowStore, authority AuthoritySource, policies PolicyWriter,
	publications PublicationWriter, now func() time.Time,
) (*Service, error) {
	if nilInterface(store) || nilInterface(authority) || nilInterface(policies) || nilInterface(publications) || now == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Service{store: store, authority: authority, policies: policies, publications: publications, now: now}, nil
}

func (service *Service) Submit(ctx context.Context, actor Actor, input SubmitInput) (Workflow, error) {
	if service == nil || ctx == nil || !validActor(actor) || !validSubmit(input) || actor.SessionID != input.SessionID {
		return Workflow{}, ErrInvalidInput
	}
	now := service.now().UTC()
	verifiedAt := input.StepUpVerifiedAt.UTC()
	if verifiedAt.After(now) || now.Sub(verifiedAt) > mfa.MaxStepUpTTL {
		return Workflow{}, ErrPermissionDenied
	}
	if actor.ScopeKind == "tenant" {
		if input.TenantScopeID != actor.ScopeID {
			return Workflow{}, ErrScopeConflict
		}
	} else if input.TenantScopeID == uuid.Nil {
		return Workflow{}, ErrInvalidInput
	}
	snapshot, err := service.authority.Resolve(ctx, AuthorityRequest{
		TenantScopeID: input.TenantScopeID, SiteID: input.SiteID, JA4: input.JA4,
		SnapshotAt: input.SnapshotAt.UTC().Truncate(time.Millisecond),
	})
	if err != nil {
		return Workflow{}, mapDependencyError(err)
	}
	if snapshot.TenantScopeID != input.TenantScopeID || snapshot.SiteID != input.SiteID || snapshot.JA4 != input.JA4 {
		return Workflow{}, ErrScopeConflict
	}
	if !snapshot.SnapshotAt.Equal(input.SnapshotAt.UTC().Truncate(time.Millisecond)) ||
		snapshot.Consistency != "latest_event_id_at_snapshot" {
		return Workflow{}, ErrSnapshotStale
	}
	if !snapshot.SnapshotExpiresAt.After(now) || snapshot.SnapshotAt.After(now.Add(time.Minute)) {
		return Workflow{}, ErrSnapshotExpired
	}
	if snapshot.RequestCount == 0 || !validPublicationTarget(snapshot) {
		return Workflow{}, ErrInvalidInput
	}
	snapshot.TargetNodeIDs = canonicalNodes(snapshot.TargetNodeIDs)
	ja4Digest := sha256.Sum256([]byte(input.JA4))
	workflow := Workflow{
		ID: uuid.New(), TenantScopeID: input.TenantScopeID, SiteID: input.SiteID,
		ActorUserID: actor.UserID, ActorScopeID: actor.ScopeID, ActorScopeKind: actor.ScopeKind,
		SessionID: input.SessionID, StepUpEvidenceID: input.StepUpEvidenceID, StepUpVerifiedAt: input.StepUpVerifiedAt.UTC(),
		JA4: input.JA4, JA4SHA256: hex.EncodeToString(ja4Digest[:]), SnapshotAt: snapshot.SnapshotAt,
		FilterFrom: snapshot.FilterFrom, FilterTo: snapshot.FilterTo, FilterTimezone: snapshot.FilterTimezone,
		SnapshotExpiresAt: snapshot.SnapshotExpiresAt, RequestCount: snapshot.RequestCount,
		ResponseBytes: snapshot.ResponseBytes, Duration: input.Duration, Reason: input.Reason,
		Phase: PhaseQueued, Revision: 1, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
		CurrentPolicy:           clonePolicy(snapshot.CurrentPolicy),
		ExpectedBindingRevision: snapshot.ExpectedBindingRevision,
		ExpectedActiveVersion:   snapshot.ExpectedActiveVersion,
		TargetSnapshotID:        snapshot.TargetSnapshotID,
		TargetSnapshotRevision:  snapshot.TargetSnapshotRevision,
		TargetSnapshotSHA256:    snapshot.TargetSnapshotSHA256,
		TargetNodeIDs:           canonicalNodes(snapshot.TargetNodeIDs), RolloutID: snapshot.RolloutID,
		AvailableAt: now, CreatedAt: now, UpdatedAt: now,
	}
	requestBytes, err := canonicalRequestBytes(workflow)
	if err != nil {
		return Workflow{}, ErrInvalidInput
	}
	workflow.RequestSHA256 = sha256.Sum256(requestBytes)
	return service.store.Create(ctx, workflow)
}

func (service *Service) RunOne(ctx context.Context, workerID string) (RunResult, error) {
	if service == nil || ctx == nil || !keyPattern.MatchString(workerID) {
		return RunResult{}, ErrInvalidInput
	}
	now := service.now().UTC()
	claim, found, err := service.store.Claim(ctx, workerID, now, claimLease)
	if err != nil {
		return RunResult{}, mapStoreError(err)
	}
	if !found {
		return RunResult{}, nil
	}
	var workflow Workflow
	switch claim.Action {
	case ActionApplyPolicy:
		workflow, err = service.applyPolicy(ctx, claim)
	case ActionPublishBinding:
		workflow, err = service.publishBinding(ctx, claim)
	default:
		err = ErrRevisionConflict
	}
	if err != nil {
		if errors.Is(err, ErrStoreUnavailable) || errors.Is(err, ErrClaimLost) {
			return RunResult{Claimed: true, Workflow: claim.Workflow}, err
		}
		retryErr := service.store.Retry(ctx, claim, stableDependencyCode(err), now.Add(retryDelay(claim.Workflow.AttemptCount)))
		if retryErr != nil {
			return RunResult{Claimed: true, Workflow: claim.Workflow}, mapStoreError(retryErr)
		}
		return RunResult{Claimed: true, Workflow: claim.Workflow}, err
	}
	return RunResult{Claimed: true, Workflow: workflow}, nil
}

func (service *Service) Get(ctx context.Context, actor Actor, tenantScopeID, workflowID uuid.UUID) (Workflow, error) {
	if service == nil || ctx == nil || !validActor(actor) || tenantScopeID == uuid.Nil || workflowID == uuid.Nil ||
		(actor.ScopeKind == "tenant" && actor.ScopeID != tenantScopeID) {
		return Workflow{}, ErrPermissionDenied
	}
	return service.store.Get(ctx, tenantScopeID, workflowID)
}

func (service *Service) RecordEdgeReceipt(ctx context.Context, actor Actor, input EdgeReceiptInput) (Workflow, error) {
	if service == nil || ctx == nil || !validActor(actor) || input.ReceiptID == uuid.Nil ||
		input.TenantScopeID == uuid.Nil || input.SiteID == uuid.Nil || input.WorkflowID == uuid.Nil ||
		input.PolicyID == uuid.Nil || input.PolicyRevision < 1 || input.BindingID == uuid.Nil || input.BindingRevision < 1 ||
		input.PublicationID == uuid.Nil || input.RolloutID == uuid.Nil || input.NodeID == uuid.Nil ||
		input.ConfigSHA256 == ([32]byte{}) || input.ReceiptSHA256 == ([32]byte{}) ||
		input.ExpectedRevision < 1 || input.ActivePolicyRevision < 0 ||
		(input.State != "active" && input.State != "failed" && input.State != "rolled_back") ||
		!reasonPattern.MatchString(input.ReasonCode) || input.ObservedAt.IsZero() ||
		(actor.ScopeKind == "tenant" && actor.ScopeID != input.TenantScopeID) {
		return Workflow{}, ErrInvalidInput
	}
	item, err := service.store.Get(ctx, input.TenantScopeID, input.WorkflowID)
	if err != nil {
		return Workflow{}, mapStoreError(err)
	}
	if item.SiteID != input.SiteID || item.PolicyID != input.PolicyID || item.PolicyRevision != input.PolicyRevision ||
		item.BindingID != input.BindingID || item.BindingRevision != input.BindingRevision ||
		item.PublicationID != input.PublicationID || item.RolloutID != input.RolloutID ||
		item.ActorUserID != actor.UserID || item.ActorScopeID != actor.ScopeID ||
		item.ActorScopeKind != actor.ScopeKind || item.SessionID != actor.SessionID ||
		!slices.Contains(item.TargetNodeIDs, input.NodeID) {
		return Workflow{}, ErrRevisionConflict
	}
	terminalReplay := item.Phase == PhaseActive || item.Phase == PhaseFailed
	if (!terminalReplay && (item.Phase != PhaseEdgePending || item.Revision != input.ExpectedRevision)) ||
		(terminalReplay && item.Revision != input.ExpectedRevision+1) || input.ObservedAt.UTC().Before(item.UpdatedAt.UTC()) ||
		input.ObservedAt.UTC().After(service.now().UTC().Add(time.Minute)) {
		return Workflow{}, ErrRevisionConflict
	}
	if (input.State == "active" && input.ActivePolicyRevision != item.PolicyRevision) ||
		(input.State != "active" && input.ActivePolicyRevision != item.ExpectedActiveVersion) {
		return Workflow{}, ErrRevisionConflict
	}
	return service.store.SetEdgeReceipt(ctx, input)
}

func (service *Service) applyPolicy(ctx context.Context, claim Claim) (Workflow, error) {
	item := claim.Workflow
	actor := securitypolicy.Actor{UserID: item.ActorUserID, ScopeID: item.ActorScopeID, ScopeKind: item.ActorScopeKind}
	fields, err := policyFields(item)
	if err != nil {
		return Workflow{}, err
	}
	var result securitypolicy.WriteResult
	if item.CurrentPolicy == nil {
		result, err = service.policies.Create(ctx, actor, securitypolicy.CreateRequest{
			TargetScopeID: item.TenantScopeID, OwnerUserID: item.ActorUserID, Fields: fields,
			IdempotencyKey: derivedKey("policy", item.ID), RequestID: item.RequestID,
		})
	} else {
		result, err = service.policies.Update(ctx, actor, securitypolicy.UpdateRequest{
			ID: item.CurrentPolicy.ID, ExpectedRevision: item.CurrentPolicy.Revision, Fields: fields,
			IdempotencyKey: derivedKey("policy", item.ID), RequestID: item.RequestID,
		})
	}
	if err != nil {
		return Workflow{}, mapDependencyError(err)
	}
	expectedRevision := int64(1)
	if item.CurrentPolicy != nil {
		expectedRevision = item.CurrentPolicy.Revision + 1
	}
	if result.Policy.ID == uuid.Nil || result.Policy.ScopeID != item.TenantScopeID ||
		result.Policy.Kind != securitypolicy.KindWAF || result.Policy.Revision != expectedRevision {
		return Workflow{}, ErrDependencyUnavailable
	}
	workflow, err := service.store.SetPolicy(ctx, claim, result)
	if err != nil {
		return Workflow{}, mapStoreError(err)
	}
	return workflow, nil
}

func (service *Service) publishBinding(ctx context.Context, claim Claim) (Workflow, error) {
	item := claim.Workflow
	actor := securitypolicy.Actor{UserID: item.ActorUserID, ScopeID: item.ActorScopeID, ScopeKind: item.ActorScopeKind}
	result, err := service.publications.Publish(ctx, actor, securitybinding.PublishRequest{
		TenantScopeID: item.TenantScopeID, SiteID: item.SiteID, PolicyID: item.PolicyID,
		PolicyVersion: item.PolicyRevision, TargetNodeIDs: append([]uuid.UUID(nil), item.TargetNodeIDs...),
		ExpectedBindingRevision: item.ExpectedBindingRevision, ExpectedActiveVersion: item.ExpectedActiveVersion,
		RolloutID: item.RolloutID, IdempotencyKey: derivedKey("binding", item.ID), RequestID: item.RequestID,
	})
	if err != nil {
		return Workflow{}, mapDependencyError(err)
	}
	if result.BundleID == uuid.Nil || result.BindingID == uuid.Nil || result.BindingRevision < 1 ||
		result.TenantScopeID != item.TenantScopeID || result.SiteID != item.SiteID ||
		result.PolicyID != item.PolicyID || result.PolicyKind != securitypolicy.KindWAF ||
		result.PolicyVersion != item.PolicyRevision || result.ExpectedActiveVersion != item.ExpectedActiveVersion ||
		result.RolloutID != item.RolloutID || !slices.Equal(canonicalNodes(result.TargetNodeIDs), item.TargetNodeIDs) {
		return Workflow{}, ErrDependencyUnavailable
	}
	workflow, err := service.store.SetPublication(ctx, claim, result)
	if err != nil {
		return Workflow{}, mapStoreError(err)
	}
	return workflow, nil
}

func policyFields(item Workflow) (securitypolicy.PolicyFields, error) {
	rule := securitypolicy.Rule{ID: uuid.NewSHA1(item.ID, []byte("ja4-block")), Name: "JA4 block",
		Priority: 1, Enabled: true, ExpiresAt: item.CreatedAt.Add(item.Duration).UTC().Format(time.RFC3339),
		Conditions: []securitypolicy.Condition{{Field: "ja4", Operator: "equals", Values: []string{item.JA4}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop}
	if item.CurrentPolicy == nil {
		return securitypolicy.PolicyFields{Kind: securitypolicy.KindWAF, Name: "JA4 automatic blocks",
			Description: item.Reason, Enabled: true, DefaultAction: securitypolicy.ActionAllow,
			Rules: []securitypolicy.Rule{rule}}, nil
	}
	if item.CurrentPolicy.ScopeID != item.TenantScopeID || item.CurrentPolicy.Kind != securitypolicy.KindWAF ||
		item.CurrentPolicy.Revision != item.ExpectedActiveVersion {
		return securitypolicy.PolicyFields{}, ErrRevisionConflict
	}
	rules := append([]securitypolicy.Rule(nil), item.CurrentPolicy.Rules...)
	for _, existing := range rules {
		if existing.ID == rule.ID {
			return securitypolicy.PolicyFields{}, ErrRevisionConflict
		}
	}
	rules = append(rules, rule)
	return securitypolicy.PolicyFields{Kind: item.CurrentPolicy.Kind, Name: item.CurrentPolicy.Name,
		Description: item.CurrentPolicy.Description, Enabled: item.CurrentPolicy.Enabled,
		DefaultAction: item.CurrentPolicy.DefaultAction, Rules: rules,
		WAFSettings: securitypolicy.CloneWAFSettings(item.CurrentPolicy.WAFSettings)}, nil
}

func validSubmit(input SubmitInput) bool {
	return input.TenantScopeID != uuid.Nil && input.SiteID != uuid.Nil && edgeconfig.ValidJA4(input.JA4) &&
		!strings.EqualFold(input.JA4, "__unknown__") && !input.SnapshotAt.IsZero() &&
		input.Duration >= minimumDuration && input.Duration <= maximumDuration && input.Duration%time.Second == 0 &&
		reasonPattern.MatchString(input.Reason) &&
		input.ExpectedRevision == 0 && keyPattern.MatchString(input.IdempotencyKey) && keyPattern.MatchString(input.RequestID) &&
		input.SessionID != uuid.Nil && input.StepUpEvidenceID != uuid.Nil && !input.StepUpVerifiedAt.IsZero()
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.SessionID != uuid.Nil &&
		(actor.ScopeKind == "tenant" || actor.ScopeKind == "platform")
}

func validPublicationTarget(snapshot AuthoritySnapshot) bool {
	if snapshot.RolloutID == uuid.Nil || snapshot.TargetSnapshotID == uuid.Nil || snapshot.TargetSnapshotRevision < 1 ||
		snapshot.TargetSnapshotSHA256 == ([32]byte{}) || len(snapshot.TargetNodeIDs) == 0 || len(snapshot.TargetNodeIDs) > 10_000 ||
		snapshot.ExpectedBindingRevision < 0 || snapshot.ExpectedActiveVersion < 0 {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(snapshot.TargetNodeIDs))
	for _, id := range snapshot.TargetNodeIDs {
		if id == uuid.Nil {
			return false
		}
		if _, ok := seen[id]; ok {
			return false
		}
		seen[id] = struct{}{}
	}
	if nodescheduler.CanonicalNodeSetDigest(snapshot.TargetNodeIDs) != snapshot.TargetSnapshotSHA256 {
		return false
	}
	if snapshot.CurrentPolicy == nil {
		return snapshot.ExpectedActiveVersion == 0
	}
	return snapshot.CurrentPolicy.ID != uuid.Nil && snapshot.CurrentPolicy.ScopeID == snapshot.TenantScopeID &&
		snapshot.CurrentPolicy.Kind == securitypolicy.KindWAF && snapshot.CurrentPolicy.Revision == snapshot.ExpectedActiveVersion
}

func canonicalRequestBytes(workflow Workflow) ([]byte, error) {
	return json.Marshal(struct {
		TenantScopeID           uuid.UUID              `json:"tenant_scope_id"`
		SiteID                  uuid.UUID              `json:"site_id"`
		ActorUserID             uuid.UUID              `json:"actor_user_id"`
		ActorScopeID            uuid.UUID              `json:"actor_scope_id"`
		ActorScopeKind          string                 `json:"actor_scope_kind"`
		SessionID               uuid.UUID              `json:"session_id"`
		StepUpEvidenceID        uuid.UUID              `json:"step_up_evidence_id"`
		StepUpVerifiedAt        time.Time              `json:"step_up_verified_at"`
		JA4                     string                 `json:"ja4"`
		FilterFrom              time.Time              `json:"filter_from"`
		FilterTo                time.Time              `json:"filter_to"`
		FilterTimezone          string                 `json:"filter_timezone"`
		SnapshotAt              time.Time              `json:"snapshot_at"`
		SnapshotExpiresAt       time.Time              `json:"snapshot_expires_at"`
		RequestCount            uint64                 `json:"request_count"`
		ResponseBytes           uint64                 `json:"response_bytes"`
		DurationSeconds         int64                  `json:"duration_seconds"`
		Reason                  string                 `json:"reason"`
		CurrentPolicy           *securitypolicy.Policy `json:"current_policy,omitempty"`
		ExpectedBindingRevision int64                  `json:"expected_binding_revision"`
		ExpectedActiveVersion   int64                  `json:"expected_active_version"`
		TargetSnapshotID        uuid.UUID              `json:"target_snapshot_id"`
		TargetSnapshotRevision  int64                  `json:"target_snapshot_revision"`
		TargetSnapshotSHA256    [32]byte               `json:"target_snapshot_sha256"`
		TargetNodeIDs           []uuid.UUID            `json:"target_node_ids"`
		RolloutID               uuid.UUID              `json:"rollout_id"`
	}{workflow.TenantScopeID, workflow.SiteID, workflow.ActorUserID, workflow.ActorScopeID,
		workflow.ActorScopeKind, workflow.SessionID, workflow.StepUpEvidenceID, workflow.StepUpVerifiedAt,
		workflow.JA4, workflow.FilterFrom, workflow.FilterTo, workflow.FilterTimezone,
		workflow.SnapshotAt, workflow.SnapshotExpiresAt,
		workflow.RequestCount, workflow.ResponseBytes, int64(workflow.Duration / time.Second), workflow.Reason,
		workflow.CurrentPolicy, workflow.ExpectedBindingRevision, workflow.ExpectedActiveVersion,
		workflow.TargetSnapshotID, workflow.TargetSnapshotRevision, workflow.TargetSnapshotSHA256,
		workflow.TargetNodeIDs, workflow.RolloutID})
}

func canonicalNodes(nodes []uuid.UUID) []uuid.UUID {
	result := append([]uuid.UUID(nil), nodes...)
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}

func clonePolicy(policy *securitypolicy.Policy) *securitypolicy.Policy {
	if policy == nil {
		return nil
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil
	}
	var cloned securitypolicy.Policy
	if json.Unmarshal(encoded, &cloned) != nil {
		return nil
	}
	return &cloned
}

func retryDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 6 {
		attempt = 6
	}
	return time.Second * time.Duration(1<<attempt)
}

func derivedKey(kind string, id uuid.UUID) string { return "ja4-" + kind + "-" + id.String() }

func stableDependencyCode(err error) string {
	switch {
	case errors.Is(err, ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, ErrScopeConflict):
		return "scope_conflict"
	default:
		return "dependency_unavailable"
	}
}

func mapDependencyError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, securitypolicy.ErrRevisionConflict) || errors.Is(err, securitybinding.ErrBindingRevision) ||
		errors.Is(err, securitybinding.ErrActiveVersionConflict) || errors.Is(err, securitybinding.ErrPolicyVersionConflict) {
		return ErrRevisionConflict
	}
	if errors.Is(err, securitypolicy.ErrIdempotencyConflict) || errors.Is(err, securitybinding.ErrIdempotencyConflict) {
		return ErrIdempotencyConflict
	}
	return ErrDependencyUnavailable
}

func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrIdempotencyConflict) || errors.Is(err, ErrRevisionConflict) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrClaimLost) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrStoreUnavailable
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
