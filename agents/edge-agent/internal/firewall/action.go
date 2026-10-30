package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const FirewallActionSchemaV1 = "cdnca.edge.firewall-action/v1"

var (
	ErrInvalidActionPolicy         = errors.New("invalid firewall action policy")
	ErrInvalidActionObservation    = errors.New("invalid firewall action observation")
	ErrActionPolicyRegression      = errors.New("firewall action policy version must advance")
	ErrActionActiveVersionConflict = errors.New("firewall action active policy version conflict")
	ErrActionApplyFailed           = errors.New("firewall action candidate was not applied")
)

type RequestAction string

const (
	RequestActionPass       RequestAction = "pass"
	RequestActionDisconnect RequestAction = "disconnect"
	RequestActionReturnPage RequestAction = "return_page"
	RequestActionNFTables   RequestAction = "nftables"
)

type ControlledReturnPage struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

type TrustedCrawler struct {
	Name              string   `json:"name"`
	Networks          []string `json:"networks"`
	UserAgentPrefixes []string `json:"user_agent_prefixes"`
}

type ActionPolicy struct {
	SchemaVersion               string               `json:"schema_version"`
	PolicyVersion               uint64               `json:"policy_version"`
	TenantID                    string               `json:"tenant_id"`
	SiteID                      string               `json:"site_id"`
	PolicyID                    string               `json:"policy_id"`
	ExpectedActivePolicyVersion uint64               `json:"expected_active_policy_version"`
	NormalAction                RequestAction        `json:"normal_action"`
	EscalatedAction             RequestAction        `json:"escalated_action"`
	EngageThreshold             uint64               `json:"engage_threshold"`
	RecoverThreshold            uint64               `json:"recover_threshold"`
	RecoveryWindows             uint32               `json:"recovery_windows"`
	BlockNetworks               []string             `json:"block_networks"`
	TrustedProxies              []string             `json:"trusted_proxies"`
	TrustedCrawlers             []TrustedCrawler     `json:"trusted_crawlers"`
	ReturnPage                  ControlledReturnPage `json:"return_page"`
}

type ActionPolicyIdentity struct {
	TenantID      string
	SiteID        string
	PolicyID      string
	PolicyVersion uint64
}

func ValidateActionPolicy(candidate []byte, identity ActionPolicyIdentity) error {
	policy, err := decodeActionPolicy(candidate)
	if err != nil || policy.TenantID != identity.TenantID || policy.SiteID != identity.SiteID ||
		policy.PolicyID != identity.PolicyID || policy.PolicyVersion != identity.PolicyVersion {
		return ErrInvalidActionPolicy
	}
	return nil
}

type ActionObservation struct {
	PeerAddress  string
	ForwardedFor []string
	UserAgent    string
	Load         uint64
}

type ActionDecision struct {
	Action              RequestAction
	ClientAddress       string
	Reason              string
	Page                *ControlledReturnPage
	PolicyVersion       uint64
	NFTablesActive      bool
	RunningLKGUnchanged bool
}

type FirewallVersionApplier interface {
	Apply(context.Context, FirewallVersion) (Result, error)
}

type ActionEngine struct {
	mu                    sync.Mutex
	applier               FirewallVersionApplier
	policy                ActionPolicy
	policySHA256          [sha256.Size]byte
	configured            bool
	engaged               bool
	nftablesActive        bool
	recoveryWindows       uint32
	firewallPolicyVersion uint64
}

func NewActionEngine(applier FirewallVersionApplier, candidate []byte) (*ActionEngine, error) {
	if applier == nil {
		return nil, ErrInvalidActionPolicy
	}
	if len(candidate) == 0 {
		return &ActionEngine{applier: applier}, nil
	}
	policy, err := decodeActionPolicy(candidate)
	if err != nil {
		return nil, err
	}
	return &ActionEngine{
		applier: applier, policy: policy, policySHA256: sha256.Sum256(candidate), configured: true,
		firewallPolicyVersion: policy.ExpectedActivePolicyVersion,
	}, nil
}

func (engine *ActionEngine) ActivePolicyVersion() uint64 {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.policy.PolicyVersion
}

func (engine *ActionEngine) ApplyCandidate(ctx context.Context, candidate []byte) error {
	policy, err := decodeActionPolicy(candidate)
	if err != nil {
		return err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.configured && policy.PolicyVersion <= engine.policy.PolicyVersion {
		return ErrActionPolicyRegression
	}
	if policy.ExpectedActivePolicyVersion != engine.firewallPolicyVersion {
		return ErrActionActiveVersionConflict
	}
	nftablesActive := engine.nftablesActive
	if engine.engaged {
		var err error
		nftablesActive, err = engine.publishLocked(ctx, policy, true)
		if err != nil {
			return err
		}
	}
	engine.policy = policy
	engine.policySHA256 = sha256.Sum256(candidate)
	engine.configured = true
	engine.nftablesActive = nftablesActive
	engine.recoveryWindows = 0
	return nil
}

// StageCandidate prepares an inactive replacement without mutating the running
// engine. An engaged engine can only be reused byte-for-byte because changing
// its policy would otherwise diverge the registry from already-applied rules.
func (engine *ActionEngine) StageCandidate(candidate []byte) (*ActionEngine, bool, error) {
	policy, err := decodeActionPolicy(candidate)
	if err != nil {
		return nil, false, err
	}
	digest := sha256.Sum256(candidate)
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.configured && engine.policySHA256 == digest &&
		engine.policy.TenantID == policy.TenantID && engine.policy.SiteID == policy.SiteID &&
		engine.policy.PolicyID == policy.PolicyID && engine.policy.PolicyVersion == policy.PolicyVersion {
		return engine, true, nil
	}
	if engine.engaged || engine.nftablesActive {
		return nil, false, ErrActionActiveVersionConflict
	}
	if engine.configured && (policy.TenantID != engine.policy.TenantID || policy.SiteID != engine.policy.SiteID ||
		policy.PolicyID != engine.policy.PolicyID || policy.PolicyVersion <= engine.policy.PolicyVersion) {
		return nil, false, ErrActionPolicyRegression
	}
	if policy.ExpectedActivePolicyVersion != engine.firewallPolicyVersion {
		return nil, false, ErrActionActiveVersionConflict
	}
	return &ActionEngine{
		applier: engine.applier, policy: policy, policySHA256: digest, configured: true,
		firewallPolicyVersion: engine.firewallPolicyVersion,
	}, false, nil
}

func (engine *ActionEngine) CanRetire() bool {
	if engine == nil {
		return true
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return !engine.engaged && !engine.nftablesActive
}

func (engine *ActionEngine) Observe(ctx context.Context, observation ActionObservation) (ActionDecision, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	client, err := resolveActionClient(observation.PeerAddress, observation.ForwardedFor, engine.policy.TrustedProxies)
	if err != nil {
		return ActionDecision{}, err
	}
	decision := ActionDecision{ClientAddress: client.String(), PolicyVersion: engine.policy.PolicyVersion, NFTablesActive: engine.nftablesActive}
	if !engine.configured {
		decision.Action = RequestActionPass
		decision.Reason = "policy_unconfigured"
		return decision, nil
	}

	// Exemption precedes threshold state, and requires both network and UA evidence.
	if trustedActionCrawler(client, observation.UserAgent, engine.policy.TrustedCrawlers) {
		decision.Action = RequestActionPass
		decision.Reason = "trusted_crawler"
		return decision, nil
	}
	if !engine.engaged && observation.Load >= engine.policy.EngageThreshold {
		nftablesActive, err := engine.publishLocked(ctx, engine.policy, true)
		if err != nil {
			decision.Action = RequestActionDisconnect
			decision.Reason = "nft_candidate_rejected_lkg"
			decision.RunningLKGUnchanged = true
			return decision, err
		}
		engine.engaged = true
		engine.nftablesActive = nftablesActive
		engine.recoveryWindows = 0
		decision.Action = RequestActionDisconnect
		decision.Reason = "threshold_engaged_l7_only"
		if nftablesActive {
			decision.Reason = "threshold_engaged"
		}
		decision.NFTablesActive = nftablesActive
		return decision, nil
	}
	if engine.engaged {
		if observation.Load <= engine.policy.RecoverThreshold {
			engine.recoveryWindows++
			if engine.recoveryWindows >= engine.policy.RecoveryWindows {
				nftablesActive, err := engine.publishLocked(ctx, engine.policy, false)
				if err != nil {
					decision.Action = RequestActionDisconnect
					decision.Reason = "nft_candidate_rejected_lkg"
					decision.RunningLKGUnchanged = true
					return decision, err
				}
				engine.engaged = false
				engine.nftablesActive = nftablesActive
				engine.recoveryWindows = 0
				decision = engine.normalDecision(client, "threshold_recovered")
				return decision, nil
			}
			decision.Action = RequestActionDisconnect
			decision.Reason = "recovery_pending_l7_only"
			if engine.nftablesActive {
				decision.Reason = "recovery_pending"
			}
			decision.NFTablesActive = engine.nftablesActive
			return decision, nil
		}
		engine.recoveryWindows = 0
		decision.Action = RequestActionDisconnect
		decision.Reason = "threshold_active_l7_only"
		if engine.nftablesActive {
			decision.Reason = "threshold_active"
		}
		decision.NFTablesActive = engine.nftablesActive
		return decision, nil
	}
	return engine.normalDecision(client, "below_engage_threshold"), nil
}

// ActionRuntimeState is the node runtime's escalation state of one site
// action (firewallaction.engine status, FX45): the OpenResty engine counts the
// blocked requests per second and decides engage and recovery.
type ActionRuntimeState struct {
	TenantID      string
	SiteID        string
	PolicyID      string
	PolicyVersion uint64
	Active        bool
}

// Mirror makes nftables follow the runtime state: an active site's block
// networks are applied, a recovered site's are withdrawn. A state of another
// policy (a status read across a republication) changes nothing. It reports
// whether nftables changed.
func (engine *ActionEngine) Mirror(ctx context.Context, state ActionRuntimeState) (bool, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if !engine.configured || state.TenantID != engine.policy.TenantID || state.SiteID != engine.policy.SiteID ||
		state.PolicyID != engine.policy.PolicyID || state.PolicyVersion != engine.policy.PolicyVersion ||
		state.Active == engine.engaged {
		return false, nil
	}
	nftablesActive, err := engine.publishLocked(ctx, engine.policy, state.Active)
	if err != nil {
		return false, err
	}
	engine.engaged = state.Active
	engine.nftablesActive = nftablesActive
	engine.recoveryWindows = 0
	return true, nil
}

// NewRuntimeActionEngine is the engine of a dynamic routing site's policy
// object (FX45): its nftables scope (tenant, site, global, policy) version
// and engaged state are read back from fw, so an agent restart or a
// republication continues from what the kernel holds; the next Mirror
// withdraws an engagement the runtime no longer reports.
func NewRuntimeActionEngine(ctx context.Context, fw ScopedFirewall, candidate []byte) (*ActionEngine, error) {
	if fw == nil {
		return nil, ErrInvalidActionPolicy
	}
	policy, err := decodeActionPolicy(candidate)
	if err != nil {
		return nil, err
	}
	version, entries, err := fw.ScopeEntries(ctx, policy.TenantID, policy.SiteID, "global", policy.PolicyID)
	if err != nil {
		return nil, err
	}
	engaged := len(entries) > 0
	return &ActionEngine{
		applier: fw, policy: policy, policySHA256: sha256.Sum256(candidate), configured: true,
		engaged: engaged, nftablesActive: engaged, firewallPolicyVersion: version,
	}, nil
}

// Withdraw recovers an engaged engine whose site left the runtime; it
// reports whether nftables changed.
func (engine *ActionEngine) Withdraw(ctx context.Context) (bool, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if !engine.configured || !engine.engaged && !engine.nftablesActive {
		return false, nil
	}
	if _, err := engine.publishLocked(ctx, engine.policy, false); err != nil {
		return false, err
	}
	engine.engaged, engine.nftablesActive, engine.recoveryWindows = false, false, 0
	return true, nil
}

func (engine *ActionEngine) normalDecision(client netip.Addr, reason string) ActionDecision {
	decision := ActionDecision{
		Action: engine.policy.NormalAction, ClientAddress: client.String(), Reason: reason,
		PolicyVersion: engine.policy.PolicyVersion,
	}
	if decision.Action == RequestActionReturnPage {
		page := engine.policy.ReturnPage
		decision.Page = &page
	}
	return decision
}

func (engine *ActionEngine) publishLocked(ctx context.Context, policy ActionPolicy, engage bool) (bool, error) {
	nextPolicyVersion := engine.firewallPolicyVersion + 1
	phase := "recover"
	blockNetworks := []string(nil)
	if engage {
		phase = "engage"
		blockNetworks = effectiveActionBlockNetworks(policy)
	}
	digestPayload := struct {
		SchemaVersion         string   `json:"schema_version"`
		ActionPolicyVersion   uint64   `json:"action_policy_version"`
		TenantID              string   `json:"tenant_id"`
		SiteID                string   `json:"site_id"`
		PolicyID              string   `json:"policy_id"`
		FirewallPolicyVersion uint64   `json:"firewall_policy_version"`
		Phase                 string   `json:"phase"`
		BlockNetworks         []string `json:"block_networks"`
	}{
		SchemaVersion: FirewallActionSchemaV1, ActionPolicyVersion: policy.PolicyVersion,
		TenantID: policy.TenantID, SiteID: policy.SiteID, PolicyID: policy.PolicyID,
		FirewallPolicyVersion: nextPolicyVersion, Phase: phase,
	}
	if engage {
		digestPayload.BlockNetworks = blockNetworks
	}
	encoded, _ := json.Marshal(digestPayload)
	digest := sha256.Sum256(encoded)
	commandDigest := fmt.Sprintf("%x", digest)
	idempotencyKey := uuid.NewSHA1(uuid.NameSpaceOID, digest[:]).String()
	version := FirewallVersion{
		TaskID: "sec06-action-" + idempotencyKey, TaskRevision: nextPolicyVersion, IdempotencyKey: idempotencyKey,
		TenantID: policy.TenantID, SiteID: policy.SiteID, PolicyKind: "global", PolicyID: policy.PolicyID,
		PolicyVersion: nextPolicyVersion, ExpectedActivePolicyVersion: engine.firewallPolicyVersion,
		Operation: OperationApply, RecoveryReason: RecoveryReasonNotApplicable, CommandDigest: commandDigest,
		VersionID: "runtime-" + idempotencyKey,
	}
	if engage {
		version.Entries = make([]Entry, 0, len(blockNetworks))
		for _, network := range blockNetworks {
			version.Entries = append(version.Entries, Entry{
				TenantID: policy.TenantID, SiteID: policy.SiteID,
				Action: ActionDeny, Network: network, Protocol: ProtocolAny,
				Source: "waf_action", Reason: "automatic_threshold",
			})
		}
	}
	result, err := engine.applier.Apply(ctx, version)
	if err != nil || result.State != StateApplied || result.ActivePolicyVersion != nextPolicyVersion {
		return false, ErrActionApplyFailed
	}
	engine.firewallPolicyVersion = nextPolicyVersion
	return engage && len(blockNetworks) > 0, nil
}

func effectiveActionBlockNetworks(policy ActionPolicy) []string {
	protected := make([]netip.Prefix, 0, len(policy.TrustedProxies)+len(policy.TrustedCrawlers))
	for _, network := range policy.TrustedProxies {
		protected = append(protected, netip.MustParsePrefix(network))
	}
	for _, crawler := range policy.TrustedCrawlers {
		for _, network := range crawler.Networks {
			protected = append(protected, netip.MustParsePrefix(network))
		}
	}
	effective := make([]string, 0, len(policy.BlockNetworks))
	for _, network := range policy.BlockNetworks {
		prefix := netip.MustParsePrefix(network)
		overlaps := false
		for _, trusted := range protected {
			if prefixesOverlap(prefix, trusted) {
				overlaps = true
				break
			}
		}
		if !overlaps {
			effective = append(effective, network)
		}
	}
	return effective
}

func decodeActionPolicy(candidate []byte) (ActionPolicy, error) {
	if err := rejectDuplicateJSONKeys(candidate); err != nil {
		return ActionPolicy{}, ErrInvalidActionPolicy
	}
	var policy ActionPolicy
	decoder := json.NewDecoder(bytes.NewReader(candidate))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return ActionPolicy{}, ErrInvalidActionPolicy
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ActionPolicy{}, ErrInvalidActionPolicy
	}
	if policy.SchemaVersion != FirewallActionSchemaV1 || policy.PolicyVersion == 0 ||
		!canonicalUUID(policy.TenantID) || !canonicalUUID(policy.SiteID) || !canonicalUUID(policy.PolicyID) ||
		(policy.NormalAction != RequestActionDisconnect && policy.NormalAction != RequestActionReturnPage) ||
		policy.EscalatedAction != RequestActionNFTables || policy.EngageThreshold == 0 ||
		policy.RecoverThreshold >= policy.EngageThreshold || policy.RecoveryWindows == 0 || policy.RecoveryWindows > 60 ||
		len(policy.BlockNetworks) == 0 || len(policy.BlockNetworks) > maxEntries || len(policy.TrustedCrawlers) > 64 {
		return ActionPolicy{}, ErrInvalidActionPolicy
	}
	var err error
	policy.BlockNetworks, err = normalizeActionNetworks(policy.BlockNetworks)
	if err != nil {
		return ActionPolicy{}, err
	}
	policy.TrustedProxies, err = normalizeActionNetworks(policy.TrustedProxies)
	if err != nil {
		return ActionPolicy{}, err
	}
	for index := range policy.TrustedCrawlers {
		crawler := &policy.TrustedCrawlers[index]
		if !validMetadata(crawler.Name, 64) || len(crawler.Networks) == 0 || len(crawler.UserAgentPrefixes) == 0 || len(crawler.UserAgentPrefixes) > 32 {
			return ActionPolicy{}, ErrInvalidActionPolicy
		}
		crawler.Networks, err = normalizeActionNetworks(crawler.Networks)
		if err != nil {
			return ActionPolicy{}, err
		}
		for _, prefix := range crawler.UserAgentPrefixes {
			if !validActionText(prefix, 128) || strings.ContainsAny(prefix, "*?") {
				return ActionPolicy{}, ErrInvalidActionPolicy
			}
		}
		sort.Strings(crawler.UserAgentPrefixes)
	}
	if !validReturnPage(policy.ReturnPage) {
		return ActionPolicy{}, ErrInvalidActionPolicy
	}
	return policy, nil
}

func normalizeActionNetworks(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := normalizeNetwork(value)
		if err != nil || prefix.Bits() == 0 {
			return nil, ErrInvalidActionPolicy
		}
		value = prefix.String()
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			normalized = append(normalized, value)
		}
	}
	sort.Slice(normalized, func(i, j int) bool {
		left, right := netip.MustParsePrefix(normalized[i]), netip.MustParsePrefix(normalized[j])
		if compared := left.Addr().Compare(right.Addr()); compared != 0 {
			return compared < 0
		}
		return left.Bits() < right.Bits()
	})
	return normalized, nil
}

func validReturnPage(page ControlledReturnPage) bool {
	if page.Status < 400 || page.Status > 599 || (page.ContentType != "text/html; charset=utf-8" && page.ContentType != "text/plain; charset=utf-8") ||
		!validActionText(page.Body, 16<<10) || strings.ContainsAny(page.Body, "<>") {
		return false
	}
	return true
}

func rejectDuplicateJSONKeys(candidate []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(candidate))
	decoder.UseNumber()
	if err := scanUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidActionPolicy
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidActionPolicy
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok {
				return ErrInvalidActionPolicy
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidActionPolicy
			}
			seen[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return ErrInvalidActionPolicy
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return ErrInvalidActionPolicy
		}
	default:
		return ErrInvalidActionPolicy
	}
	return nil
}

func validActionText(value string, maximum int) bool {
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

func resolveActionClient(peerValue string, forwarded []string, trustedProxies []string) (netip.Addr, error) {
	peer, err := netip.ParseAddr(peerValue)
	if err != nil || peer.Zone() != "" || peer.IsUnspecified() || peer.IsMulticast() || peer.Is4In6() {
		return netip.Addr{}, ErrInvalidActionObservation
	}
	current := peer
	if !addressInNetworks(current, trustedProxies) {
		return current, nil
	}
	for index := len(forwarded) - 1; index >= 0; index-- {
		if !addressInNetworks(current, trustedProxies) {
			break
		}
		next, parseErr := netip.ParseAddr(forwarded[index])
		if parseErr != nil || next.Zone() != "" || next.IsUnspecified() || next.IsMulticast() || next.Is4In6() {
			return peer, nil
		}
		current = next
	}
	return current, nil
}

func trustedActionCrawler(client netip.Addr, userAgent string, crawlers []TrustedCrawler) bool {
	for _, crawler := range crawlers {
		if !addressInNetworks(client, crawler.Networks) {
			continue
		}
		for _, prefix := range crawler.UserAgentPrefixes {
			if strings.HasPrefix(userAgent, prefix) {
				return true
			}
		}
	}
	return false
}

func addressInNetworks(address netip.Addr, networks []string) bool {
	for _, network := range networks {
		if netip.MustParsePrefix(network).Contains(address) {
			return true
		}
	}
	return false
}
