package firewallcontrol

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"context"
	"github.com/google/uuid"
)

var writeKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Service struct {
	store storePort
	now   func() time.Time
}

func NewService(store storePort, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}
}

func (service *Service) Put(ctx context.Context, request PutRequest) (WriteResult, error) {
	if service == nil || service.store == nil {
		return WriteResult{}, ErrUnavailable
	}
	if err := authorize(request.Actor, request.TargetScopeID, PermissionManage); err != nil {
		return WriteResult{}, err
	}
	if request.ExpectedRevision < 0 || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	policy, err := normalizePolicy(request.Policy)
	if err != nil {
		return WriteResult{}, err
	}
	request.Policy = policy
	requestBytes, err := json.Marshal(struct {
		TargetScopeID uuid.UUID   `json:"target_scope_id"`
		Expected      int64       `json:"expected_revision"`
		Policy        PolicyInput `json:"policy"`
	}{request.TargetScopeID, request.ExpectedRevision, policy})
	if err != nil {
		return WriteResult{}, ErrInvalidInput
	}
	documentBytes, err := json.Marshal(policy)
	if err != nil {
		return WriteResult{}, ErrInvalidInput
	}
	request.RequestSHA256 = sha256.Sum256(requestBytes)
	request.DocumentSHA256 = sha256.Sum256(documentBytes)
	return service.store.Put(ctx, request)
}

func (service *Service) Get(ctx context.Context, request ReadRequest) (Policy, error) {
	if service == nil || service.store == nil {
		return Policy{}, ErrUnavailable
	}
	if err := authorize(request.Actor, request.TargetScopeID, PermissionRead); err != nil {
		return Policy{}, err
	}
	return service.store.Get(ctx, request)
}

func (service *Service) Recover(ctx context.Context, request RecoverRequest) (WriteResult, error) {
	if service == nil || service.store == nil {
		return WriteResult{}, ErrUnavailable
	}
	if err := authorize(request.Actor, request.TargetScopeID, PermissionManage); err != nil {
		return WriteResult{}, err
	}
	if request.ExpectedRevision < 1 || request.RecoverRevision < 1 || request.RecoverRevision >= request.ExpectedRevision ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) ||
		!slices.Contains([]string{RecoveryFalsePositive, RecoveryHealthFailure, RecoveryOperator}, request.Reason) {
		return WriteResult{}, ErrInvalidInput
	}
	return service.store.Recover(ctx, request)
}

func (service *Service) ListHits(ctx context.Context, filter HitFilter) (HitPage, error) {
	if service == nil || service.store == nil {
		return HitPage{}, ErrUnavailable
	}
	if err := authorize(filter.Actor, filter.TargetScopeID, PermissionRead); err != nil {
		return HitPage{}, err
	}
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	if filter.Limit < 1 || filter.Limit > 100 || len(filter.Cursor) > 1024 {
		return HitPage{}, ErrInvalidInput
	}
	return service.store.ListHits(ctx, filter)
}

func authorize(actor Actor, targetScopeID uuid.UUID, permission string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || (actor.ScopeKind != ScopeTenant && actor.ScopeKind != ScopePlatform) {
		return ErrUnauthenticated
	}
	if targetScopeID == uuid.Nil {
		return ErrInvalidInput
	}
	if actor.ScopeKind == ScopeTenant && actor.ScopeID != targetScopeID {
		return ErrNotFound
	}
	if !slices.Contains(actor.Permissions, permission) && !slices.Contains(actor.Permissions, "platform.admin") {
		return ErrPermissionDenied
	}
	return nil
}

func validWriteMetadata(key, requestID string) bool {
	return writeKeyPattern.MatchString(key) && uuid.Validate(requestID) == nil && strings.ToLower(requestID) == requestID
}

func normalizePolicy(input PolicyInput) (PolicyInput, error) {
	input.DefaultAction = strings.TrimSpace(input.DefaultAction)
	if (input.DefaultAction != ActionAllow && input.DefaultAction != ActionDeny) || len(input.Rules) > 10_000 {
		return PolicyInput{}, ErrInvalidInput
	}
	rules := make([]RuleInput, len(input.Rules))
	copy(rules, input.Rules)
	priorities := make(map[int]struct{}, len(rules))
	targetCount := 0
	for index := range rules {
		rule := &rules[index]
		rule.Action = strings.TrimSpace(rule.Action)
		rule.Protocol = strings.TrimSpace(rule.Protocol)
		if rule.ID == uuid.Nil || rule.Priority < 1 || rule.Priority > 1_000_000 || (rule.Action != ActionAllow && rule.Action != ActionDeny) ||
			!validProtocolPorts(rule.Protocol, rule.PortStart, rule.PortEnd) || len(rule.CIDRs) < 1 || len(rule.CIDRs) > 256 || len(rule.SiteIDs) > 128 {
			return PolicyInput{}, ErrInvalidInput
		}
		if _, duplicate := priorities[rule.Priority]; duplicate {
			return PolicyInput{}, ErrInvalidInput
		}
		priorities[rule.Priority] = struct{}{}
		seenCIDR := make(map[string]struct{}, len(rule.CIDRs))
		cidrs := make([]string, 0, len(rule.CIDRs))
		for _, raw := range rule.CIDRs {
			canonical, err := canonicalCIDR(raw)
			if err != nil {
				return PolicyInput{}, ErrInvalidInput
			}
			if _, duplicate := seenCIDR[canonical]; duplicate {
				return PolicyInput{}, ErrInvalidInput
			}
			seenCIDR[canonical] = struct{}{}
			cidrs = append(cidrs, canonical)
		}
		sort.Strings(cidrs)
		rule.CIDRs = cidrs
		sort.Slice(rule.SiteIDs, func(i, j int) bool { return rule.SiteIDs[i].String() < rule.SiteIDs[j].String() })
		for siteIndex, siteID := range rule.SiteIDs {
			if siteID == uuid.Nil || siteIndex > 0 && siteID == rule.SiteIDs[siteIndex-1] {
				return PolicyInput{}, ErrInvalidInput
			}
		}
		if rule.ExpiresAt != nil {
			if rule.ExpiresAt.IsZero() {
				return PolicyInput{}, ErrInvalidInput
			}
			expires := rule.ExpiresAt.UTC().Truncate(time.Second)
			rule.ExpiresAt = &expires
		}
		targetCount += len(rule.CIDRs)
		if targetCount > 4092 {
			return PolicyInput{}, ErrInvalidInput
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	input.Rules = rules
	return input, nil
}

func canonicalCIDR(raw string) (string, error) {
	if !utf8.ValidString(raw) || strings.TrimSpace(raw) != raw {
		return "", ErrInvalidInput
	}
	if address, err := netip.ParseAddr(raw); err == nil {
		if invalidAddress(address) {
			return "", ErrInvalidInput
		}
		return netip.PrefixFrom(address, address.BitLen()).String(), nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix != prefix.Masked() || invalidAddress(prefix.Addr()) || prefix.Bits() == 0 {
		return "", ErrInvalidInput
	}
	return prefix.String(), nil
}

func invalidAddress(address netip.Addr) bool {
	return !address.IsValid() || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast()
}

func validProtocolPorts(protocol string, start, end uint16) bool {
	switch protocol {
	case ProtocolAny, ProtocolICMP:
		return start == 0 && end == 0
	case ProtocolTCP, ProtocolUDP:
		return start == 0 && end == 0 || start > 0 && end >= start
	default:
		return false
	}
}
