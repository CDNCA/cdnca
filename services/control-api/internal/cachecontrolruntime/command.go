package cachecontrolruntime

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var cacheCommandNamespace = uuid.MustParse("4180f1e9-5864-5d85-a3f5-aa104592cd08")

func buildCommand(claim cachecontrol.Claim) (*agentv1.CacheControlCommand, error) {
	if claim.OperationID == uuid.Nil || claim.ScopeID == uuid.Nil || claim.SiteID == uuid.Nil ||
		claim.TenantID == uuid.Nil || claim.NodeID == uuid.Nil || claim.LeaseID == uuid.Nil ||
		claim.WorkerID == "" || claim.Attempt == 0 ||
		claim.ConfigVersionID == uuid.Nil || claim.ConfigRevision == 0 ||
		claim.Priority != "normal" || len(claim.Targets) < 1 || len(claim.Targets) > 16 ||
		!claim.LeaseExpiresAt.After(claim.ClaimedAt) {
		return nil, ErrInvalidConfig
	}
	action, scope, err := wireActionScope(claim.Action, claim.TargetType)
	if err != nil {
		return nil, err
	}
	taskID := taskID(claim)
	eventID := stableUUID("event:" + taskID)
	requestID := stableUUID("request:" + taskID)
	targets := make([]*agentv1.CacheControlTarget, len(claim.Targets))
	ordinals := make(map[int]struct{}, len(claim.Targets))
	digests := make(map[[sha256.Size]byte]struct{}, len(claim.Targets))
	for index, target := range claim.Targets {
		canonicalURL, valid := canonicalCacheTarget(target, claim.TargetType)
		if !valid {
			return nil, ErrInvalidConfig
		}
		digest := sha256.Sum256([]byte(canonicalURL))
		if target.Ordinal < 1 || target.Ordinal > 1000 {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := ordinals[target.Ordinal]; duplicate {
			return nil, ErrInvalidConfig
		}
		ordinals[target.Ordinal] = struct{}{}
		if _, duplicate := digests[digest]; duplicate {
			return nil, ErrInvalidConfig
		}
		digests[digest] = struct{}{}
		targets[index] = &agentv1.CacheControlTarget{
			Index: uint32(index), TargetOrdinal: uint32(target.Ordinal),
			CanonicalUrl: canonicalURL, Sha256: digest[:],
		}
	}
	command := &agentv1.CacheControlCommand{
		Event: &commonv1.EventMetadata{
			EventId: eventID.String(), RequestId: requestID.String(),
			OccurredTime: timestamppb.New(claim.ClaimedAt), CorrelationId: claim.OperationID.String(),
			TaskId: stringPointer(taskID),
		},
		TaskId: taskID, ScopeId: claim.ScopeID.String(), SiteId: claim.SiteID.String(),
		TenantId: claim.TenantID.String(),
		NodeId:   claim.NodeID.String(), ControlOperationId: claim.OperationID.String(),
		LeaseId: claim.LeaseID.String(), Attempt: claim.Attempt,
		ConfigVersionId: claim.ConfigVersionID.String(), ConfigRevision: claim.ConfigRevision,
		Action: action, Scope: scope,
		Priority:      agentv1.CacheControlPriority_CACHE_CONTROL_PRIORITY_NORMAL,
		RequestDigest: append([]byte(nil), claim.RequestDigest[:]...), Targets: targets,
		DeadlineTime: timestamppb.New(claim.LeaseExpiresAt),
	}
	return command, nil
}

func canonicalCacheTarget(target cachecontrol.Target, targetType cachecontrol.TargetType) (string, bool) {
	if targetType == cachecontrol.TargetWholeSite {
		return "", target.CanonicalURL == "/" && target.CanonicalPath == "/"
	}
	raw := target.CanonicalURL
	if raw == "" || len(raw) > 16<<10 || strings.TrimSpace(raw) != raw {
		return "", false
	}
	for index := range len(raw) {
		if raw[index] < 0x21 || raw[index] > 0x7e {
			return "", false
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" ||
		parsed.Opaque != "" || parsed.Host == "" || parsed.Path == "" ||
		parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Path != target.CanonicalPath {
		return "", false
	}
	hostname := parsed.Hostname()
	if hostname == "" || hostname != strings.ToLower(strings.TrimSuffix(hostname, ".")) ||
		strings.Contains(hostname, "%") {
		return "", false
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 ||
			parsed.Scheme == "http" && value == 80 || parsed.Scheme == "https" && value == 443 {
			return "", false
		}
		host = net.JoinHostPort(hostname, port)
	}
	if targetType == cachecontrol.TargetDirectoryPrefix &&
		(parsed.RawQuery != "" || parsed.ForceQuery || !strings.HasSuffix(parsed.Path, "/")) {
		return "", false
	}
	canonical := (&url.URL{
		Scheme: parsed.Scheme, Host: host, Path: parsed.Path,
		RawQuery: parsed.RawQuery, ForceQuery: parsed.ForceQuery,
	}).String()
	return canonical, canonical == raw
}

func wireActionScope(action cachecontrol.Action, targetType cachecontrol.TargetType) (
	agentv1.CacheControlAction, agentv1.CacheControlScope, error,
) {
	switch {
	case action == cachecontrol.ActionPurge && targetType == cachecontrol.TargetExactURL:
		return agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_EXACT,
			agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL, nil
	case action == cachecontrol.ActionPurge && targetType == cachecontrol.TargetDirectoryPrefix:
		return agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_PREFIX,
			agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_DIRECTORY, nil
	case action == cachecontrol.ActionPurge && targetType == cachecontrol.TargetWholeSite:
		return agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PURGE_SITE,
			agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_SITE, nil
	case action == cachecontrol.ActionPrewarm && targetType == cachecontrol.TargetExactURL:
		return agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PREWARM,
			agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL, nil
	default:
		return 0, 0, ErrInvalidConfig
	}
}

func commandMatchesStatus(command *agentv1.CacheControlCommand, status *agentv1.CacheControlStatus) bool {
	if command == nil || command.Event == nil || status == nil || status.Event == nil {
		return false
	}
	return status.TaskId == command.TaskId && status.ScopeId == command.ScopeId &&
		status.TenantId == command.TenantId && status.SiteId == command.SiteId && status.NodeId == command.NodeId &&
		status.ControlOperationId == command.ControlOperationId && status.LeaseId == command.LeaseId &&
		status.Attempt == command.Attempt && status.ConfigVersionId == command.ConfigVersionId &&
		status.ConfigRevision == command.ConfigRevision && status.Action == command.Action &&
		status.Scope == command.Scope && bytes.Equal(status.RequestDigest, command.RequestDigest) &&
		status.Event.CausationId != nil && status.Event.GetCausationId() == command.Event.EventId &&
		status.Event.RequestId == command.Event.RequestId &&
		status.Event.CorrelationId == command.Event.CorrelationId &&
		status.Event.TaskId != nil && status.Event.GetTaskId() == command.TaskId
}

func taskID(claim cachecontrol.Claim) string {
	return "cc-" + claim.OperationID.String() + "-" + claim.NodeID.String() + "-" +
		strconv.FormatUint(uint64(claim.Attempt), 10)
}

func stableUUID(value string) uuid.UUID {
	return uuid.NewSHA1(cacheCommandNamespace, []byte(value))
}

func stringPointer(value string) *string { return &value }

func canonicalUUID(value string) (uuid.UUID, bool) {
	parsed, err := uuid.Parse(value)
	return parsed, err == nil && parsed.String() == value
}

func describeClaim(claim cachecontrol.Claim) string {
	return fmt.Sprintf("%s/%s/%d", claim.OperationID, claim.NodeID, claim.Attempt)
}
