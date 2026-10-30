package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const maxEntries = 10000

var firewallIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

var forbiddenNetworks = []netip.Prefix{
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
}

func normalize(version FirewallVersion) (FirewallVersion, string, error) {
	if !firewallIDPattern.MatchString(version.TaskID) || !firewallIDPattern.MatchString(version.VersionID) || len(version.Entries) > maxEntries {
		return FirewallVersion{}, "", ErrInvalidVersion
	}
	if version.Aggregate && (version.TenantID != "" || version.SiteID != "") {
		return FirewallVersion{}, "", ErrInvalidVersion
	}
	scoped := version.TenantID != "" || version.SiteID != ""
	if scoped {
		if !canonicalUUID(version.TenantID) || !canonicalUUID(version.SiteID) || !canonicalUUID(version.IdempotencyKey) ||
			!validPolicyIdentity(version.PolicyKind, version.PolicyID) ||
			version.PolicyVersion == 0 || version.PolicyVersion != version.ExpectedActivePolicyVersion+1 ||
			version.TaskRevision < version.PolicyVersion || !validDigest(version.CommandDigest) || !validOperation(version.Operation, version.RecoveryReason) {
			return FirewallVersion{}, "", ErrInvalidVersion
		}
	} else if !version.Aggregate && (version.TaskRevision != 0 || version.IdempotencyKey != "" || version.PolicyKind != "" || version.PolicyID != "" || version.PolicyVersion != 0 ||
		version.ExpectedActivePolicyVersion != 0 || version.Operation != "" || version.RecoveryReason != "" || version.CommandDigest != "") {
		return FirewallVersion{}, "", ErrInvalidVersion
	}
	normalized := FirewallVersion{
		TaskID: version.TaskID, TaskRevision: version.TaskRevision, IdempotencyKey: version.IdempotencyKey,
		TenantID: version.TenantID, SiteID: version.SiteID, PolicyKind: version.PolicyKind, PolicyID: version.PolicyID, PolicyVersion: version.PolicyVersion,
		ExpectedActivePolicyVersion: version.ExpectedActivePolicyVersion, Operation: version.Operation,
		RecoveryReason: version.RecoveryReason, CommandDigest: version.CommandDigest,
		VersionID: version.VersionID, Entries: make([]Entry, 0, len(version.Entries)), Aggregate: version.Aggregate,
	}
	seen := make(map[string]Entry, len(version.Entries))
	for _, entry := range version.Entries {
		if entry.Action != ActionAllow && entry.Action != ActionDeny {
			return FirewallVersion{}, "", ErrInvalidVersion
		}
		if !validProtocolPorts(entry.Protocol, entry.PortStart, entry.PortEnd) {
			return FirewallVersion{}, "", ErrInvalidVersion
		}
		prefix, err := normalizeNetwork(entry.Network)
		if err != nil || !validMetadata(entry.Source, 64) || !validMetadata(entry.Reason, 256) {
			return FirewallVersion{}, "", ErrInvalidVersion
		}
		if scoped && (entry.TenantID != version.TenantID || entry.SiteID != version.SiteID) ||
			version.Aggregate && (!canonicalUUID(entry.TenantID) || !canonicalUUID(entry.SiteID)) ||
			!scoped && !version.Aggregate && (entry.TenantID != "" || entry.SiteID != "") {
			return FirewallVersion{}, "", ErrInvalidVersion
		}
		normalizedEntry := Entry{
			TenantID: entry.TenantID, SiteID: entry.SiteID, Action: entry.Action,
			Network: prefix.String(), Protocol: entry.Protocol, PortStart: entry.PortStart, PortEnd: entry.PortEnd,
			Source: entry.Source, Reason: entry.Reason,
		}
		if entry.ExpiresAt != nil {
			if entry.ExpiresAt.IsZero() {
				return FirewallVersion{}, "", ErrInvalidVersion
			}
			expires := entry.ExpiresAt.UTC()
			normalizedEntry.ExpiresAt = &expires
		}
		key := normalizedEntry.TenantID + "\x00" + normalizedEntry.SiteID + "\x00" + string(normalizedEntry.Action) + "\x00" +
			normalizedEntry.Network + "\x00" + string(normalizedEntry.Protocol) + "\x00" +
			fmt.Sprintf("%d-%d", normalizedEntry.PortStart, normalizedEntry.PortEnd)
		if previous, exists := seen[key]; exists {
			if !equalEntry(previous, normalizedEntry) {
				return FirewallVersion{}, "", ErrInvalidVersion
			}
			continue
		}
		seen[key] = normalizedEntry
		normalized.Entries = append(normalized.Entries, normalizedEntry)
	}
	sort.Slice(normalized.Entries, func(i, j int) bool {
		left, right := normalized.Entries[i], normalized.Entries[j]
		if left.TenantID != right.TenantID {
			return left.TenantID < right.TenantID
		}
		if left.SiteID != right.SiteID {
			return left.SiteID < right.SiteID
		}
		if left.Action != right.Action {
			return left.Action == ActionAllow
		}
		leftPrefix, rightPrefix := netip.MustParsePrefix(left.Network), netip.MustParsePrefix(right.Network)
		if comparison := leftPrefix.Addr().Compare(rightPrefix.Addr()); comparison != 0 {
			return comparison < 0
		}
		if leftPrefix.Bits() != rightPrefix.Bits() {
			return leftPrefix.Bits() < rightPrefix.Bits()
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		if left.PortStart != right.PortStart {
			return left.PortStart < right.PortStart
		}
		if left.PortEnd != right.PortEnd {
			return left.PortEnd < right.PortEnd
		}
		if left.Reason != right.Reason {
			return left.Reason < right.Reason
		}
		return expirationString(left.ExpiresAt) < expirationString(right.ExpiresAt)
	})
	payload := struct {
		TaskRevision                uint64         `json:"task_revision,omitempty"`
		IdempotencyKey              string         `json:"idempotency_key,omitempty"`
		TenantID                    string         `json:"tenant_id,omitempty"`
		SiteID                      string         `json:"site_id,omitempty"`
		PolicyKind                  string         `json:"policy_kind,omitempty"`
		PolicyID                    string         `json:"policy_id,omitempty"`
		PolicyVersion               uint64         `json:"policy_version,omitempty"`
		ExpectedActivePolicyVersion uint64         `json:"expected_active_policy_version,omitempty"`
		Operation                   Operation      `json:"operation,omitempty"`
		RecoveryReason              RecoveryReason `json:"recovery_reason,omitempty"`
		CommandDigest               string         `json:"command_digest,omitempty"`
		VersionID                   string         `json:"version_id"`
		Entries                     []Entry        `json:"entries"`
	}{
		TaskRevision: normalized.TaskRevision, IdempotencyKey: normalized.IdempotencyKey,
		TenantID: normalized.TenantID, SiteID: normalized.SiteID, PolicyKind: normalized.PolicyKind, PolicyID: normalized.PolicyID, PolicyVersion: normalized.PolicyVersion,
		ExpectedActivePolicyVersion: normalized.ExpectedActivePolicyVersion, Operation: normalized.Operation,
		RecoveryReason: normalized.RecoveryReason, CommandDigest: normalized.CommandDigest,
		VersionID: normalized.VersionID, Entries: normalized.Entries,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return FirewallVersion{}, "", ErrInvalidVersion
	}
	digest := sha256.Sum256(encoded)
	return normalized, hex.EncodeToString(digest[:]), nil
}

// PolicyKindL4Guard scopes the kernel bans the agent raises for L4 guard
// rules (G4-d): one scope per stream (policy ID = stream ID), applied
// locally, never by the control plane.
const PolicyKindL4Guard = "l4_guard"

func validPolicyIdentity(kind, id string) bool {
	if kind != "acl" && kind != "global" && kind != "legacy_acl" && kind != PolicyKindL4Guard && !banSourceKinds[kind] {
		return false
	}
	return canonicalUUID(id)
}

func validProtocolPorts(protocol Protocol, start, end uint16) bool {
	switch protocol {
	case ProtocolAny, ProtocolICMP:
		return start == 0 && end == 0
	case ProtocolTCP, ProtocolUDP:
		return start == 0 && end == 0 || start > 0 && end >= start
	default:
		return false
	}
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validOperation(operation Operation, reason RecoveryReason) bool {
	if operation == OperationApply {
		return reason == RecoveryReasonNotApplicable
	}
	if operation != OperationRecover || reason == RecoveryReasonNotApplicable {
		return false
	}
	switch reason {
	case RecoveryReasonFalsePositive, RecoveryReasonPolicyRegression, RecoveryReasonHealthFailure, RecoveryReasonOperatorRequest:
		return true
	default:
		return false
	}
}

func normalizeNetwork(value string) (netip.Prefix, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return netip.Prefix{}, ErrInvalidVersion
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		address, addressErr := netip.ParseAddr(value)
		if addressErr != nil || address.Zone() != "" {
			return netip.Prefix{}, ErrInvalidVersion
		}
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	if prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return netip.Prefix{}, ErrInvalidVersion
	}
	prefix = prefix.Masked()
	if prefix.Bits() == 0 || (prefix.Bits() == prefix.Addr().BitLen() && prefix.Addr().IsUnspecified()) {
		return netip.Prefix{}, ErrInvalidVersion
	}
	for _, forbidden := range forbiddenNetworks {
		if prefixesOverlap(prefix, forbidden) {
			return netip.Prefix{}, ErrInvalidVersion
		}
	}
	return prefix, nil
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() && (left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func validMetadata(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func equalEntry(left, right Entry) bool {
	if left.Action != right.Action || left.Network != right.Network || left.Source != right.Source || left.Reason != right.Reason {
		return false
	}
	if left.ExpiresAt == nil || right.ExpiresAt == nil {
		return left.ExpiresAt == nil && right.ExpiresAt == nil
	}
	return left.ExpiresAt.Equal(*right.ExpiresAt)
}

func expirationString(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.Format(time.RFC3339Nano)
}
