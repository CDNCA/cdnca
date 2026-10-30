package gatewayclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	multiTenantRuntimeAPIVersion = 1
	// multiTenantDeploymentQueueLimit is the agreed per-node limit of scoped
	// deployments waiting for the node-level apply lock.
	multiTenantDeploymentQueueLimit = 16
	// Not ".json": the journal scanner treats every .json as a record.
	scopeApplyResultsFile = "scope-apply-results.state"
)

// ScopedDeploymentManager is a DeploymentManager that keeps one deployment
// state machine per configuration scope (deployment.ScopedManager). A client
// given one declares MULTI_TENANT_RUNTIME.
type ScopedDeploymentManager interface {
	DeploymentManager
	ScopePointers(scopeID string) (deployment.Pointers, error)
	Scopes() []string
}

func (c *Client) scopedManager() (ScopedDeploymentManager, bool) {
	scoped, ok := c.manager.(ScopedDeploymentManager)
	return scoped, ok
}

func gatewayHelloHasMultiTenantRuntimeV1(hello *agentv1.GatewayHello) bool {
	for _, capability := range hello.GetEnabledCapabilities() {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME &&
			capability.GetApiVersion() == multiTenantRuntimeAPIVersion {
			return true
		}
	}
	return false
}

// historyPointerSets is every pointer set whose identity evidence the journal
// must keep: the node's pair, or one pair per configuration scope.
func (c *Client) historyPointerSets() ([]deployment.Pointers, error) {
	_, sets, err := c.scopedPointerSets()
	return sets, err
}

// scopedPointerSets returns the pointer sets and, on a multi-scope node, the
// scope each set belongs to (same order).
func (c *Client) scopedPointerSets() ([]string, []deployment.Pointers, error) {
	scoped, ok := c.scopedManager()
	if !ok {
		pointers, err := c.manager.Pointers()
		return nil, []deployment.Pointers{pointers}, err
	}
	scopes := scoped.Scopes()
	sets := make([]deployment.Pointers, 0, len(scopes))
	for _, scopeID := range scopes {
		pointers, err := scoped.ScopePointers(scopeID)
		if err != nil {
			return nil, nil, err
		}
		sets = append(sets, pointers)
	}
	return scopes, sets, nil
}

func (c *Client) refreshDeploymentHistory() (deploymentHistory, error) {
	sets, err := c.historyPointerSets()
	if err != nil {
		return deploymentHistory{}, err
	}
	return c.deploymentHistoryFor(sets)
}

// commandPointers are the pointers a command's terminal identity is judged
// against: its own scope's on a multi-scope node.
func (c *Client) commandPointers(command *agentv1.DeploymentCommand) (deployment.Pointers, error) {
	if scoped, ok := c.scopedManager(); ok && command != nil && command.ConfigurationScopeId != nil {
		return scoped.ScopePointers(command.GetConfigurationScopeId())
	}
	return c.manager.Pointers()
}

func commandScopeID(command *agentv1.DeploymentCommand) string {
	if command == nil {
		return ""
	}
	return command.GetConfigurationScopeId()
}

// scopedConfigIdentities builds one entry per scope with local state: its
// current/previous identity (when verifiable) and its last apply result. The
// pointers are the ones the history snapshot was built from, and results are
// read before that snapshot, so a result is never newer than the pointers it
// is reported with.
func (c *Client) scopedConfigIdentities(results map[string]scopeApplyResult, scopes []string, sets []deployment.Pointers, records []*durableRecord) ([]*agentv1.ScopedConfigIdentity, error) {
	if len(scopes) != len(sets) {
		return nil, fmt.Errorf("scoped pointer snapshot is inconsistent")
	}
	pointersByScope := make(map[string]deployment.Pointers, len(scopes))
	scopeIDs := map[string]struct{}{}
	for index, scopeID := range scopes {
		pointersByScope[scopeID] = sets[index]
		scopeIDs[scopeID] = struct{}{}
	}
	for scopeID := range results {
		scopeIDs[scopeID] = struct{}{}
	}
	ordered := make([]string, 0, len(scopeIDs))
	for scopeID := range scopeIDs {
		ordered = append(ordered, scopeID)
	}
	sort.Strings(ordered)
	entries := make([]*agentv1.ScopedConfigIdentity, 0, len(ordered))
	for _, scopeID := range ordered {
		pointers := pointersByScope[scopeID]
		entry := &agentv1.ScopedConfigIdentity{ConfigurationScopeId: scopeID}
		_, uncertain := c.activeConfigRuntimeUncertain(pointers, records)
		if current := c.activeConfigIdentity(pointers.Current, pointers.CurrentDigest, records); current != nil && !uncertain {
			entry.CurrentConfigVersionId = proto.String(pointers.Current)
			entry.CurrentConfigIdentity = current
			if previous := c.activeConfigIdentity(pointers.Previous, pointers.PreviousDigest, records); previous != nil {
				entry.PreviousConfigVersionId = proto.String(pointers.Previous)
				entry.PreviousConfigIdentity = previous
			}
		}
		if result, ok := results[scopeID]; ok {
			entry.LastApplyResult = result.proto()
		}
		if entry.CurrentConfigVersionId == nil && entry.LastApplyResult == nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// mirrorScopedLegacyIdentity keeps the legacy node-wide fields consistent
// with the scoped list: a single scope with a current release is mirrored
// exactly, otherwise there is no node-wide current version.
func mirrorScopedLegacyIdentity(hello *agentv1.AgentHello) {
	hello.CurrentConfigVersionId, hello.CurrentConfigIdentity = nil, nil
	hello.PreviousConfigVersionId, hello.PreviousConfigIdentity = nil, nil
	if len(hello.ScopedConfigIdentities) != 1 || hello.ScopedConfigIdentities[0].CurrentConfigVersionId == nil {
		return
	}
	entry := hello.ScopedConfigIdentities[0]
	hello.CurrentConfigVersionId = proto.String(entry.GetCurrentConfigVersionId())
	hello.CurrentConfigIdentity = cloneActiveConfigIdentity(entry.CurrentConfigIdentity)
	if entry.PreviousConfigVersionId != nil {
		hello.PreviousConfigVersionId = proto.String(entry.GetPreviousConfigVersionId())
		hello.PreviousConfigIdentity = cloneActiveConfigIdentity(entry.PreviousConfigIdentity)
	}
}

// supersedeKey groups configuration deployments of one scope: a newer one
// replaces a not-yet-started older one. Secret, overlay and rollback commands
// never supersede or get superseded.
func supersedeKey(command *agentv1.DeploymentCommand) string {
	if isSiteObjectCommand(command) && command.ConfigurationScopeId != nil {
		return command.GetConfigurationScopeId() + "/configuration"
	}
	if command == nil || command.ConfigurationScopeId == nil || len(command.Artifacts) != 1 || command.Artifacts[0] == nil ||
		command.Artifacts[0].Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION ||
		(command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY && command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_RECONCILE) ||
		isCertificateCommand(command) || isChallengeCommand(command) || isURLAuthCommand(command) || isErrorPageCommand(command) || isOriginAuthCommand(command) || isArtifactSetCommand(command) {
		return ""
	}
	return command.GetConfigurationScopeId() + "/configuration"
}

type scopedEnqueueOutcome int

const (
	scopedEnqueued scopedEnqueueOutcome = iota
	scopedQueueFull
)

// enqueueScopedDeployment places a scoped deployment in the node queue. It
// returns the pending item the new one superseded, if any. Superseding keeps
// the replaced item's place in line and is allowed when the queue is full.
func enqueueScopedDeployment(pending []workItem, keys map[workItem]string, item workItem, key string) ([]workItem, *workItem, scopedEnqueueOutcome) {
	if key != "" {
		for index, existing := range pending {
			if existing.kind == workDeployment && keys[existing] == key {
				replaced := existing
				pending[index] = item
				return pending, &replaced, scopedEnqueued
			}
		}
	}
	scopedPending := 0
	for _, existing := range pending {
		if _, scoped := keys[existing]; scoped {
			scopedPending++
		}
	}
	if scopedPending >= multiTenantDeploymentQueueLimit {
		return pending, nil, scopedQueueFull
	}
	return append(pending, item), nil, scopedEnqueued
}

// recordIsScoped reports whether the record entered the node queue on a
// multi-tenant session: it then carries AGENT_QUEUED and the shifted sequence.
func recordIsScoped(record *durableRecord) bool {
	statuses, err := statusesFromRecord(record)
	if err != nil {
		return false
	}
	for _, status := range statuses {
		if status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED {
			return true
		}
	}
	return false
}

func recordHasState(record *durableRecord, state agentv1.NodeDeploymentState) bool {
	statuses, err := statusesFromRecord(record)
	if err != nil {
		return false
	}
	for _, status := range statuses {
		if status.State == state {
			return true
		}
	}
	return false
}

// scopeApplyResult is the durable last terminal outcome of one scope.
type scopeApplyResult struct {
	DeploymentID    string    `json:"deployment_id"`
	Attempt         uint32    `json:"attempt"`
	ConfigVersionID string    `json:"config_version_id"`
	State           int32     `json:"state"`
	FinishedAt      time.Time `json:"finished_at"`
	ErrorCode       int32     `json:"error_code"`
}

func (r scopeApplyResult) proto() *agentv1.ScopedApplyResult {
	return &agentv1.ScopedApplyResult{
		DeploymentId: r.DeploymentID, Attempt: r.Attempt, ConfigVersionId: r.ConfigVersionID,
		State: agentv1.NodeDeploymentState(r.State), FinishedTime: timestamppb.New(r.FinishedAt),
		ErrorCode: commonv1.ErrorCode(r.ErrorCode),
	}
}

func scopeApplyResultFor(status *agentv1.DeploymentStatus) (scopeApplyResult, bool) {
	failed := false
	switch status.State {
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED:
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED:
		failed = true
	default:
		return scopeApplyResult{}, false
	}
	code := commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED
	if failed {
		code = status.GetError().GetCode()
		if code == commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
			code = commonv1.ErrorCode_ERROR_CODE_INTERNAL
		}
	}
	finished := time.Now().UTC()
	if status.GetEvent().GetOccurredTime() != nil {
		finished = status.Event.OccurredTime.AsTime().UTC()
	}
	return scopeApplyResult{
		DeploymentID: status.DeploymentId, Attempt: status.Attempt, ConfigVersionID: status.ConfigVersionId,
		State: int32(status.State), FinishedAt: finished, ErrorCode: int32(code),
	}, true
}

// scopeApplyResults reads the durable per-scope results; missing means none.
func (s *durableStore) scopeApplyResults() (map[string]scopeApplyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scopeApplyResultsLocked()
}

func (s *durableStore) scopeApplyResultsLocked() (map[string]scopeApplyResult, error) {
	path := filepath.Join(s.directory, scopeApplyResultsFile)
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]scopeApplyResult{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open scope apply results: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("scope apply results file is invalid")
	}
	results := map[string]scopeApplyResult{}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&results); err != nil {
		return nil, fmt.Errorf("decode scope apply results")
	}
	for scopeID := range results {
		if !canonicalUUID(scopeID) {
			return nil, fmt.Errorf("scope apply results name an invalid scope")
		}
	}
	return results, nil
}

func (s *durableStore) saveScopeApplyResultLocked(scopeID string, result scopeApplyResult) error {
	results, err := s.scopeApplyResultsLocked()
	if err != nil {
		return err
	}
	results[scopeID] = result
	encoded, err := json.Marshal(results)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.directory, ".scope-results-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(s.directory, scopeApplyResultsFile)); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}

// scopedSnapshot is a consistent view of every scope for hello and heartbeat.
type scopedSnapshot struct {
	pointers deployment.Pointers
	history  deploymentHistory
	scopes   []string
	sets     []deployment.Pointers
	results  map[string]scopeApplyResult
}

func (c *Client) stableScopedSnapshot() (scopedSnapshot, error) {
	results, err := c.store.scopeApplyResults()
	if err != nil {
		return scopedSnapshot{}, err
	}
	for range 3 {
		scopes, before, err := c.scopedPointerSets()
		if err != nil {
			return scopedSnapshot{}, err
		}
		history, err := c.deploymentHistoryFor(before)
		if err != nil {
			return scopedSnapshot{}, err
		}
		afterScopes, after, err := c.scopedPointerSets()
		if err != nil {
			return scopedSnapshot{}, err
		}
		if samePointerSets(before, after) && sameStrings(scopes, afterScopes) {
			pointers, err := c.manager.Pointers()
			if err != nil {
				return scopedSnapshot{}, err
			}
			return scopedSnapshot{pointers: pointers, history: history, scopes: scopes, sets: before, results: results}, nil
		}
	}
	return scopedSnapshot{}, fmt.Errorf("scoped config pointers changed during snapshot construction")
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
