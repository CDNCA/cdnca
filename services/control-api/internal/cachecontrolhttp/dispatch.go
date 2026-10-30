package cachecontrolhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
)

const (
	EdgeCacheTaskSchemaVersion                = 2
	EdgeCacheTaskV2MaxDeliveryAttempt         = 1_000_000
	EdgeCacheTaskV2MaxTargets                 = 500
	EdgeCacheTaskV2MaxAttempts                = 5
	EdgeCacheTaskV2MaxConcurrency             = 8
	EdgeCacheTaskV2MaxPurgeEntries            = 100000
	EdgeCacheTaskV2MaxScanEntries             = 1000000
	EdgeCacheTaskV2MaxScanBytes         int64 = 256 << 20
	EdgeCacheTaskV2MaxScanDuration            = 30 * time.Second
	EdgeCacheTaskV2MaxResourceBytes     int64 = 4 << 30
	EdgeCacheTaskV2MaxTotalBytes        int64 = 64 << 30
	EdgeCacheTaskV2MaxRequestsPerSecond       = 10
	EdgeCacheTaskV2MaxBurst                   = 2
	EdgeCacheTaskV2MaxDeadlineHorizon         = 24 * time.Hour
	EdgeCacheTaskV2MaxTargetBytes             = 16 << 10
	EdgeCacheTaskV2MaxTaskTargetBytes         = 256 << 10
	EdgeCacheTaskV2MaxInitialBackoff          = time.Minute
	EdgeCacheTaskV2MaxRetryBackoff            = 10 * time.Minute
)

var (
	dispatchIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	dispatchDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type DispatchBudgetV2 struct {
	MaxAttempts         int           `json:"max_attempts"`
	MaxConcurrency      int           `json:"max_concurrency"`
	MaxPurgeEntries     int           `json:"max_purge_entries"`
	MaxScanEntries      int           `json:"max_scan_entries"`
	MaxScanBytes        int64         `json:"max_scan_bytes"`
	MaxScanDuration     time.Duration `json:"max_scan_duration"`
	MaxTotalBytes       int64         `json:"max_total_bytes"`
	MaxResourceBytes    int64         `json:"max_resource_bytes"`
	RequestsPerSecond   float64       `json:"requests_per_second"`
	Burst               int           `json:"burst"`
	InitialRetryBackoff time.Duration `json:"initial_retry_backoff"`
	MaximumRetryBackoff time.Duration `json:"maximum_retry_backoff"`
}

type DispatchTaskV2 struct {
	SchemaVersion   int              `json:"schema_version"`
	TaskID          string           `json:"task_id"`
	OperationID     string           `json:"operation_id"`
	TenantID        string           `json:"tenant_id"`
	SiteID          string           `json:"site_id"`
	Scope           string           `json:"scope"`
	ConfigVersionID string           `json:"config_version_id"`
	ConfigRevision  uint64           `json:"config_revision"`
	DeliveryAttempt int              `json:"delivery_attempt"`
	Deadline        time.Time        `json:"deadline"`
	Budget          DispatchBudgetV2 `json:"budget"`
	Action          string           `json:"action"`
	Targets         []string         `json:"targets,omitempty"`
}

type DispatchCorrelation struct {
	ScopeID     uuid.UUID
	OperationID uuid.UUID
	NodeID      uuid.UUID
	LeaseID     uuid.UUID
	Attempt     uint32
	Targets     []DispatchTargetCorrelation
}

type DispatchTargetCorrelation struct {
	Index         int
	TargetOrdinal int
	TargetDigest  string
}

type DispatchResultItemV2 struct {
	Index        int
	TargetDigest string
}

type DispatchResultTargetV2 struct {
	Index         int
	TargetOrdinal int
	TargetDigest  string
}

type DispatchEnvelopeV2 struct {
	Task        DispatchTaskV2
	Correlation DispatchCorrelation
}

type DispatchParameters struct {
	ConfigVersionID string
	ConfigRevision  uint64
	DeliveryAttempt int
	ValidationTime  time.Time
	Deadline        time.Time
	Budget          DispatchBudgetV2
}

func BuildDispatchEnvelopeV2(
	operation cachecontrol.Operation,
	claim cachecontrol.Claim,
	parameters DispatchParameters,
) (DispatchEnvelopeV2, error) {
	if operation.ID == uuid.Nil || operation.TenantID == uuid.Nil || operation.ScopeID == uuid.Nil || operation.SiteID == uuid.Nil ||
		claim.OperationID != operation.ID || claim.ScopeID != operation.ScopeID || claim.SiteID != operation.SiteID ||
		claim.Action != operation.Action || claim.TargetType != operation.TargetType ||
		claim.NodeID == uuid.Nil || claim.LeaseID == uuid.Nil || claim.Attempt == 0 ||
		!dispatchIDPattern.MatchString(parameters.ConfigVersionID) || parameters.ConfigRevision == 0 ||
		parameters.DeliveryAttempt < 1 || parameters.DeliveryAttempt > EdgeCacheTaskV2MaxDeliveryAttempt ||
		parameters.ValidationTime.IsZero() || parameters.Deadline.IsZero() ||
		parameters.Deadline.After(parameters.ValidationTime.Add(EdgeCacheTaskV2MaxDeadlineHorizon)) {
		return DispatchEnvelopeV2{}, ErrInvalidRequest
	}
	action, scope, err := dispatchAction(operation.Action, operation.TargetType)
	if err != nil {
		return DispatchEnvelopeV2{}, err
	}
	if !validDispatchBudget(operation.Action, parameters.Budget) {
		return DispatchEnvelopeV2{}, ErrInvalidRequest
	}
	if len(claim.Targets) == 0 || len(claim.Targets) > EdgeCacheTaskV2MaxTargets ||
		(operation.TargetType == cachecontrol.TargetWholeSite && len(claim.Targets) != 1) {
		return DispatchEnvelopeV2{}, ErrInvalidStoreResponse
	}
	taskIdentity := fmt.Sprintf("cc-%s-%s-%d", operation.ID, claim.NodeID, claim.Attempt)
	if !dispatchIDPattern.MatchString(taskIdentity) {
		return DispatchEnvelopeV2{}, ErrInvalidStoreResponse
	}
	targets := make([]string, 0, len(claim.Targets))
	correlations := make([]DispatchTargetCorrelation, len(claim.Targets))
	seenOrdinals := make(map[int]struct{}, len(claim.Targets))
	targetBytes := 0
	for index, target := range claim.Targets {
		if target.Ordinal < 1 || target.CanonicalURL == "" || len(target.CanonicalURL) > EdgeCacheTaskV2MaxTargetBytes {
			return DispatchEnvelopeV2{}, ErrInvalidStoreResponse
		}
		if _, exists := seenOrdinals[target.Ordinal]; exists {
			return DispatchEnvelopeV2{}, ErrInvalidStoreResponse
		}
		seenOrdinals[target.Ordinal] = struct{}{}
		correlations[index] = DispatchTargetCorrelation{Index: index, TargetOrdinal: target.Ordinal}
		if operation.TargetType != cachecontrol.TargetWholeSite {
			targetBytes += len(target.CanonicalURL)
			if targetBytes > EdgeCacheTaskV2MaxTaskTargetBytes {
				return DispatchEnvelopeV2{}, ErrInvalidStoreResponse
			}
			targets = append(targets, target.CanonicalURL)
			digest := sha256.Sum256([]byte(target.CanonicalURL))
			correlations[index].TargetDigest = hex.EncodeToString(digest[:])
		}
	}
	return DispatchEnvelopeV2{
		Task: DispatchTaskV2{
			SchemaVersion: EdgeCacheTaskSchemaVersion, TaskID: taskIdentity, OperationID: taskIdentity,
			TenantID: operation.TenantID.String(), SiteID: operation.SiteID.String(), Scope: scope,
			ConfigVersionID: parameters.ConfigVersionID, ConfigRevision: parameters.ConfigRevision,
			DeliveryAttempt: parameters.DeliveryAttempt, Deadline: parameters.Deadline.UTC(),
			Budget: parameters.Budget, Action: action, Targets: targets,
		},
		Correlation: DispatchCorrelation{
			ScopeID: claim.ScopeID, OperationID: claim.OperationID, NodeID: claim.NodeID,
			LeaseID: claim.LeaseID, Attempt: claim.Attempt, Targets: correlations,
		},
	}, nil
}

func MapDispatchResultTargetsV2(
	correlation DispatchCorrelation,
	items []DispatchResultItemV2,
) ([]DispatchResultTargetV2, error) {
	if correlation.ScopeID == uuid.Nil || correlation.OperationID == uuid.Nil || correlation.NodeID == uuid.Nil ||
		correlation.LeaseID == uuid.Nil || correlation.Attempt == 0 || len(correlation.Targets) == 0 ||
		len(items) != len(correlation.Targets) {
		return nil, ErrInvalidRequest
	}
	byIndex := make(map[int]DispatchTargetCorrelation, len(correlation.Targets))
	ordinals := make(map[int]struct{}, len(correlation.Targets))
	for _, target := range correlation.Targets {
		if target.Index < 0 || target.Index >= len(correlation.Targets) || target.TargetOrdinal < 1 ||
			(target.TargetDigest != "" && !dispatchDigestPattern.MatchString(target.TargetDigest)) {
			return nil, ErrInvalidStoreResponse
		}
		if _, exists := byIndex[target.Index]; exists {
			return nil, ErrInvalidStoreResponse
		}
		if _, exists := ordinals[target.TargetOrdinal]; exists {
			return nil, ErrInvalidStoreResponse
		}
		byIndex[target.Index] = target
		ordinals[target.TargetOrdinal] = struct{}{}
	}
	seen := make(map[int]struct{}, len(items))
	result := make([]DispatchResultTargetV2, 0, len(items))
	for _, item := range items {
		if !dispatchDigestPattern.MatchString(item.TargetDigest) {
			return nil, ErrInvalidRequest
		}
		target, exists := byIndex[item.Index]
		if !exists {
			return nil, ErrInvalidRequest
		}
		if _, duplicate := seen[item.Index]; duplicate ||
			(target.TargetDigest != "" && target.TargetDigest != item.TargetDigest) {
			return nil, ErrInvalidRequest
		}
		seen[item.Index] = struct{}{}
		result = append(result, DispatchResultTargetV2{
			Index: item.Index, TargetOrdinal: target.TargetOrdinal, TargetDigest: item.TargetDigest,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TargetOrdinal < result[j].TargetOrdinal })
	return result, nil
}

func dispatchAction(action cachecontrol.Action, targetType cachecontrol.TargetType) (string, string, error) {
	switch {
	case action == cachecontrol.ActionPurge && targetType == cachecontrol.TargetExactURL:
		return "purge_exact", "url", nil
	case action == cachecontrol.ActionPurge && targetType == cachecontrol.TargetDirectoryPrefix:
		return "purge_prefix", "directory", nil
	case action == cachecontrol.ActionPurge && targetType == cachecontrol.TargetWholeSite:
		return "purge_site", "site", nil
	case action == cachecontrol.ActionPrewarm && targetType == cachecontrol.TargetExactURL:
		return "prewarm", "url", nil
	default:
		return "", "", ErrInvalidStoreResponse
	}
}

func validDispatchBudget(action cachecontrol.Action, budget DispatchBudgetV2) bool {
	if budget.MaxAttempts < 1 || budget.MaxAttempts > EdgeCacheTaskV2MaxAttempts ||
		budget.InitialRetryBackoff < time.Millisecond || budget.InitialRetryBackoff > EdgeCacheTaskV2MaxInitialBackoff ||
		budget.MaximumRetryBackoff < budget.InitialRetryBackoff || budget.MaximumRetryBackoff > EdgeCacheTaskV2MaxRetryBackoff {
		return false
	}
	if action != cachecontrol.ActionPrewarm {
		return budget.MaxConcurrency == 1 && budget.MaxPurgeEntries >= 1 &&
			budget.MaxPurgeEntries <= EdgeCacheTaskV2MaxPurgeEntries && budget.MaxTotalBytes == 0 &&
			budget.MaxScanEntries >= 1 && budget.MaxScanEntries <= EdgeCacheTaskV2MaxScanEntries &&
			budget.MaxScanBytes >= 1 && budget.MaxScanBytes <= EdgeCacheTaskV2MaxScanBytes &&
			budget.MaxScanDuration >= time.Millisecond && budget.MaxScanDuration <= EdgeCacheTaskV2MaxScanDuration &&
			budget.MaxResourceBytes == 0 && budget.RequestsPerSecond == 0 && budget.Burst == 0
	}
	return budget.MaxConcurrency >= 1 && budget.MaxConcurrency <= EdgeCacheTaskV2MaxConcurrency &&
		budget.MaxPurgeEntries == 0 && budget.MaxScanEntries == 0 && budget.MaxScanBytes == 0 &&
		budget.MaxScanDuration == 0 && budget.MaxResourceBytes >= 1 &&
		budget.MaxResourceBytes <= EdgeCacheTaskV2MaxResourceBytes &&
		budget.MaxTotalBytes >= budget.MaxResourceBytes && budget.MaxTotalBytes <= EdgeCacheTaskV2MaxTotalBytes &&
		budget.RequestsPerSecond > 0 && budget.RequestsPerSecond <= EdgeCacheTaskV2MaxRequestsPerSecond &&
		budget.Burst >= 1 && budget.Burst <= EdgeCacheTaskV2MaxBurst
}
