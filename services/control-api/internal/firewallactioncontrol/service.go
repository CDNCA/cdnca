package firewallactioncontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var writeKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Service struct{ store storePort }

func NewService(store storePort) *Service { return &Service{store: store} }

func (service *Service) Put(ctx context.Context, request PutRequest) (WriteResult, error) {
	if service == nil || service.store == nil {
		return WriteResult{}, ErrUnavailable
	}
	if err := authorize(request.Actor, request.TargetScopeID, request.SiteID, PermissionManage); err != nil {
		return WriteResult{}, err
	}
	if request.ExpectedRevision < 0 || request.ExpectedRevision > 1<<53-1 || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	policy, err := normalizePolicy(request.Policy)
	if err != nil {
		return WriteResult{}, err
	}
	policyID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("cdnca/firewall-action/"+request.TargetScopeID.String()+"/"+request.SiteID.String()))
	request.Policy = policy
	request.Document = EdgePolicy{
		SchemaVersion: SchemaVersion, PolicyVersion: uint64(request.ExpectedRevision + 1),
		TenantID: request.TargetScopeID.String(), SiteID: request.SiteID.String(), PolicyID: policyID.String(),
		ExpectedActivePolicyVersion: uint64(request.ExpectedRevision), NormalAction: policy.NormalAction,
		EscalatedAction: policy.EscalatedAction, EngageThreshold: policy.EngageThreshold, RecoverThreshold: policy.RecoverThreshold,
		RecoveryWindows: policy.RecoveryWindows, BlockNetworks: policy.BlockNetworks, TrustedProxies: policy.TrustedProxies,
		TrustedCrawlers: policy.TrustedCrawlers, ReturnPage: policy.ReturnPage,
	}
	document, err := json.Marshal(request.Document)
	if err != nil {
		return WriteResult{}, ErrInvalidInput
	}
	request.DocumentSHA256 = sha256.Sum256(document)
	requestDigest, err := json.Marshal(struct {
		TargetScopeID uuid.UUID   `json:"target_scope_id"`
		SiteID        uuid.UUID   `json:"site_id"`
		Expected      int64       `json:"expected_revision"`
		RequestID     string      `json:"request_id"`
		Policy        PolicyInput `json:"policy"`
	}{request.TargetScopeID, request.SiteID, request.ExpectedRevision, request.RequestID, policy})
	if err != nil {
		return WriteResult{}, ErrInvalidInput
	}
	request.RequestSHA256 = sha256.Sum256(requestDigest)
	return service.store.Put(ctx, request)
}

func (service *Service) Get(ctx context.Context, request ReadRequest) (Policy, error) {
	if service == nil || service.store == nil {
		return Policy{}, ErrUnavailable
	}
	if err := authorize(request.Actor, request.TargetScopeID, request.SiteID, PermissionRead); err != nil {
		return Policy{}, err
	}
	return service.store.Get(ctx, request)
}

func (service *Service) Recover(ctx context.Context, request RecoverRequest) (WriteResult, error) {
	if service == nil || service.store == nil {
		return WriteResult{}, ErrUnavailable
	}
	if err := authorize(request.Actor, request.TargetScopeID, request.SiteID, PermissionManage); err != nil {
		return WriteResult{}, err
	}
	if request.ExpectedRevision < 1 || request.ExpectedRevision > 1<<53-1 || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	encoded, _ := json.Marshal(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		SiteID        uuid.UUID `json:"site_id"`
		Expected      int64     `json:"expected_revision"`
		RequestID     string    `json:"request_id"`
	}{request.TargetScopeID, request.SiteID, request.ExpectedRevision, request.RequestID})
	request.RequestSHA256 = sha256.Sum256(encoded)
	return service.store.Recover(ctx, request)
}

func authorize(actor Actor, targetScopeID, siteID uuid.UUID, permission string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != ScopeTenant && actor.ScopeKind != ScopePlatform {
		return ErrUnauthenticated
	}
	if targetScopeID == uuid.Nil || siteID == uuid.Nil {
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
	if input.NormalAction != ActionDisconnect && input.NormalAction != ActionReturnPage || input.EscalatedAction != ActionNFTables ||
		input.EngageThreshold == 0 || input.RecoverThreshold >= input.EngageThreshold || input.RecoveryWindows == 0 || input.RecoveryWindows > 60 ||
		len(input.BlockNetworks) == 0 || len(input.BlockNetworks) > 4092 || len(input.TrustedProxies) > 256 || len(input.TrustedCrawlers) > 64 {
		return PolicyInput{}, ErrInvalidInput
	}
	var err error
	input.BlockNetworks, err = normalizeNetworks(input.BlockNetworks, false)
	if err != nil {
		return PolicyInput{}, err
	}
	input.TrustedProxies, err = normalizeNetworks(input.TrustedProxies, true)
	if err != nil {
		return PolicyInput{}, err
	}
	for index := range input.TrustedCrawlers {
		crawler := &input.TrustedCrawlers[index]
		crawler.Name = strings.TrimSpace(crawler.Name)
		if !validMetadataText(crawler.Name, 64) || len(crawler.Networks) == 0 || len(crawler.Networks) > 256 ||
			len(crawler.UserAgentPrefixes) == 0 || len(crawler.UserAgentPrefixes) > 32 {
			return PolicyInput{}, ErrInvalidInput
		}
		crawler.Networks, err = normalizeNetworks(crawler.Networks, false)
		if err != nil {
			return PolicyInput{}, err
		}
		for prefixIndex := range crawler.UserAgentPrefixes {
			prefix := strings.TrimSpace(crawler.UserAgentPrefixes[prefixIndex])
			if !validText(prefix, 128) || strings.ContainsAny(prefix, "*?") {
				return PolicyInput{}, ErrInvalidInput
			}
			crawler.UserAgentPrefixes[prefixIndex] = prefix
		}
		sort.Strings(crawler.UserAgentPrefixes)
		for prefixIndex := 1; prefixIndex < len(crawler.UserAgentPrefixes); prefixIndex++ {
			if crawler.UserAgentPrefixes[prefixIndex] == crawler.UserAgentPrefixes[prefixIndex-1] {
				return PolicyInput{}, ErrInvalidInput
			}
		}
	}
	sort.Slice(input.TrustedCrawlers, func(i, j int) bool { return input.TrustedCrawlers[i].Name < input.TrustedCrawlers[j].Name })
	for index := 1; index < len(input.TrustedCrawlers); index++ {
		if input.TrustedCrawlers[index].Name == input.TrustedCrawlers[index-1].Name {
			return PolicyInput{}, ErrInvalidInput
		}
	}
	protected := slices.Clone(input.TrustedProxies)
	for _, crawler := range input.TrustedCrawlers {
		protected = append(protected, crawler.Networks...)
	}
	for _, block := range input.BlockNetworks {
		for _, trusted := range protected {
			if overlaps(netip.MustParsePrefix(block), netip.MustParsePrefix(trusted)) {
				return PolicyInput{}, ErrInvalidInput
			}
		}
	}
	if input.ReturnPage.Status < 400 || input.ReturnPage.Status > 599 ||
		input.ReturnPage.ContentType != "text/html; charset=utf-8" && input.ReturnPage.ContentType != "text/plain; charset=utf-8" ||
		!validText(input.ReturnPage.Body, 16<<10) || strings.ContainsAny(input.ReturnPage.Body, "<>") {
		return PolicyInput{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeNetworks(values []string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, ErrInvalidInput
	}
	result := make([]netip.Prefix, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		if raw != strings.TrimSpace(raw) || strings.Contains(raw, "%") {
			return nil, ErrInvalidInput
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() {
			return nil, ErrInvalidInput
		}
		canonical := prefix.String()
		if _, exists := seen[canonical]; exists {
			return nil, ErrInvalidInput
		}
		seen[canonical] = struct{}{}
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool {
		if compared := result[i].Addr().Compare(result[j].Addr()); compared != 0 {
			return compared < 0
		}
		return result[i].Bits() < result[j].Bits()
	})
	canonical := make([]string, len(result))
	for index, prefix := range result {
		canonical[index] = prefix.String()
	}
	return canonical, nil
}

func overlaps(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() && (left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func validText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\n' && character != '\r' && character != '\t' {
			return false
		}
	}
	return true
}

func validMetadataText(value string, maximum int) bool {
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
