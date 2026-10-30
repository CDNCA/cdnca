package securitypolicy

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// Quick block (站点“防护”页“快速屏蔽”卡片): one-click switches
// of a WAF policy that block clients by the node IP intelligence library —
// CN IDC (idc:cn), global IDC (idc:global), chosen carriers (carrier:*) —
// with search engine crawlers exempted.
//
// The switches are stored on the policy (security_policies.quick_block) and
// expanded into system-managed rules in the policy's rules, so the runtime
// snapshot, both edge compilers and the node precheck see ordinary rules.
// The rules carry reserved IDs (QuickBlockRuleID): priority 1 and IDs whose
// first bytes are zero, so they evaluate before every user rule. An update of
// the policy drops whatever the request sent under those IDs and re-derives
// them from the stored switches; only SetQuickBlock changes the switches.
//
// Evaluation (bound WAF state machine: the last matching rule sets the
// action, stop ends the evaluation):
//
//	quick-block:idc      ip_tag in {...}                  block, continue
//	quick-block:carrier  carrier in {...}                 block, continue
//	quick-block:crawler  client_ip in N and UA ^prefix    allow, continue (one per network)
//	user rules ...
//
// A verified crawler only cancels the quick block; a user's later rules still
// apply to it, and a user allow rule still overrides the quick block, as the
// page's execution order (放行规则 → 规则库) says. Only policies whose default
// is allow can carry it (in a default-block policy the crawler allow would
// widen the whitelist).
type QuickBlock struct {
	BlockIDCCN     bool `json:"block_idc_cn"`
	BlockIDCGlobal bool `json:"block_idc_global"`
	// Carriers are carrier:* tags of the library (ipintel tag table).
	Carriers []string `json:"carriers"`
	// AllowedCrawlers reuses the WAF geo authority's trusted crawler
	// contract (networks + user agent prefixes, NormalizeTrustedCrawlers).
	AllowedCrawlers []TrustedCrawler `json:"allowed_crawlers"`
}

const (
	// MaxQuickBlockCrawlerNetworks bounds the crawler networks of one
	// policy (one allow rule each, within the 100 rules of a policy and the
	// 128 node rules of a site).
	MaxQuickBlockCrawlerNetworks = 32
	maxQuickBlockRules           = 2 + MaxQuickBlockCrawlerNetworks

	quickBlockRuleIDC     = "quick-block:idc"
	quickBlockRuleCarrier = "quick-block:carrier"
	quickBlockRuleCrawler = "quick-block:crawler"
)

var (
	// ErrQuickBlockUnsupported: the policy cannot carry a quick block (not a
	// WAF policy, a subscribed library, or its default is block).
	ErrQuickBlockUnsupported = errors.New("security policy cannot carry a quick block")
	// ErrQuickBlockIPIntelUnavailable: enabling needs the control plane to
	// hold a verified IP intelligence library.
	ErrQuickBlockIPIntelUnavailable = errors.New("quick block needs the IP intelligence library")
	// ErrQuickBlockLastRules: turning the quick block off would leave the
	// policy without any rule.
	ErrQuickBlockLastRules = errors.New("quick block rules are the policy's only rules")
	// ErrQuickBlockRuleBudget: the quick block rules and the user rules
	// exceed the 100 rules of a policy.
	ErrQuickBlockRuleBudget = errors.New("quick block rules exceed the policy rule budget")
)

// Active reports whether the switches block anything (crawlers alone do not
// produce rules).
func (block QuickBlock) Active() bool {
	return block.BlockIDCCN || block.BlockIDCGlobal || len(block.Carriers) > 0
}

// NormalizeQuickBlock validates block and puts it in canonical form: carrier
// tags lower case, sorted and unique; crawlers as the WAF geo authority
// orders them; empty lists, never nil.
func NormalizeQuickBlock(block *QuickBlock) error {
	carriers := make([]string, 0, len(block.Carriers))
	for _, raw := range block.Carriers {
		value := strings.ToLower(strings.TrimSpace(raw))
		if _, ok := edgeconfig.IPIntelTagBit(value); !ok || !strings.HasPrefix(value, "carrier:") || slices.Contains(carriers, value) {
			return ErrInvalidInput
		}
		carriers = append(carriers, value)
	}
	sort.Strings(carriers)
	crawlers, err := NormalizeTrustedCrawlers(block.AllowedCrawlers)
	if err != nil {
		return ErrInvalidInput
	}
	networks := 0
	for _, crawler := range crawlers {
		networks += len(crawler.Networks)
		for _, prefix := range crawler.UserAgentPrefixes {
			if len(quickBlockUserAgentPattern(prefix)) > 256 {
				return ErrInvalidInput
			}
		}
	}
	if networks > MaxQuickBlockCrawlerNetworks {
		return ErrInvalidInput
	}
	block.Carriers = carriers
	block.AllowedCrawlers = crawlers
	if block.AllowedCrawlers == nil {
		block.AllowedCrawlers = []TrustedCrawler{}
	}
	return nil
}

// QuickBlockRuleID is the reserved ID of a policy's quick block rule slot
// (1-based): bytes 0..3 zero and 4..5 the slot, so the rules sort first in
// their order; the rest derives from the policy (version 5 layout).
func QuickBlockRuleID(policyID uuid.UUID, slot int) uuid.UUID {
	digest := sha1.Sum(append(policyID[:], []byte(fmt.Sprintf("quick-block-rule:%d", slot))...))
	var id uuid.UUID
	copy(id[:], digest[:16])
	id[0], id[1], id[2], id[3] = 0, 0, 0, 0
	id[4], id[5] = byte(slot>>8), byte(slot)
	id[6] = 0x50 | id[6]&0x0f
	id[8] = 0x80 | id[8]&0x3f
	return id
}

// IsQuickBlockRuleID reports whether id has the reserved quick block layout.
// Time-ordered (v7) and random IDs never do in practice: their first 32
// bits would have to be zero.
func IsQuickBlockRuleID(id uuid.UUID) bool {
	slot := int(id[4])<<8 | int(id[5])
	return id[0] == 0 && id[1] == 0 && id[2] == 0 && id[3] == 0 && slot >= 1 && slot <= maxQuickBlockRules &&
		id[6]>>4 == 5 && id[8]>>6 == 2
}

// QuickBlockRules are the system-managed rules of block (normalized) in
// evaluation order; none when nothing is blocked.
func QuickBlockRules(policyID uuid.UUID, block QuickBlock) []Rule {
	if !block.Active() {
		return nil
	}
	rules := make([]Rule, 0, 2+MaxQuickBlockCrawlerNetworks)
	add := func(name, action string, conditions ...Condition) {
		rules = append(rules, Rule{ID: QuickBlockRuleID(policyID, len(rules)+1), Name: name, Priority: 1, Enabled: true,
			Conditions: conditions, Action: action, Flow: FlowContinue, ActionConfig: ActionConfig{}})
	}
	var idc []string
	if block.BlockIDCCN {
		idc = append(idc, "idc:cn")
	}
	if block.BlockIDCGlobal {
		idc = append(idc, "idc:global")
	}
	if len(idc) > 0 {
		add(quickBlockRuleIDC, ActionBlock, Condition{Field: "ip_tag", Operator: "in", Values: idc})
	}
	if len(block.Carriers) > 0 {
		add(quickBlockRuleCarrier, ActionBlock, Condition{Field: "carrier", Operator: "in", Values: slices.Clone(block.Carriers)})
	}
	type crawlerNetwork struct {
		network  string
		patterns []string
	}
	networks := make([]crawlerNetwork, 0)
	for _, crawler := range block.AllowedCrawlers {
		patterns := make([]string, len(crawler.UserAgentPrefixes))
		for index, prefix := range crawler.UserAgentPrefixes {
			patterns[index] = quickBlockUserAgentPattern(prefix)
		}
		sort.Strings(patterns)
		for _, network := range crawler.Networks {
			networks = append(networks, crawlerNetwork{network: network, patterns: patterns})
		}
	}
	sort.SliceStable(networks, func(left, right int) bool { return networks[left].network < networks[right].network })
	for _, item := range networks {
		add(quickBlockRuleCrawler, ActionAllow,
			Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{item.network}},
			Condition{Field: "user_agent", Operator: "regex", Values: slices.Clone(item.patterns)})
	}
	return rules
}

// quickBlockUserAgentPattern anchors a literal user agent prefix (the WAF
// geo authority's prefix match) as a PCRE / RE2 pattern.
func quickBlockUserAgentPattern(prefix string) string { return "^" + regexp.QuoteMeta(prefix) }

// MergeQuickBlockRules returns rules without any rule under the policy's
// reserved IDs, followed by the rules of block (nil: none).
func MergeQuickBlockRules(policyID uuid.UUID, rules []Rule, block *QuickBlock) []Rule {
	reserved := make(map[uuid.UUID]struct{}, maxQuickBlockRules)
	for slot := 1; slot <= maxQuickBlockRules; slot++ {
		reserved[QuickBlockRuleID(policyID, slot)] = struct{}{}
	}
	result := make([]Rule, 0, len(rules)+maxQuickBlockRules)
	if block != nil {
		result = append(result, QuickBlockRules(policyID, *block)...)
	}
	for _, rule := range rules {
		if _, system := reserved[rule.ID]; system || IsQuickBlockRuleID(rule.ID) {
			continue
		}
		result = append(result, rule)
	}
	return result
}

func cloneQuickBlock(block *QuickBlock) *QuickBlock {
	if block == nil {
		return nil
	}
	value := QuickBlock{BlockIDCCN: block.BlockIDCCN, BlockIDCGlobal: block.BlockIDCGlobal,
		Carriers: slices.Clone(block.Carriers), AllowedCrawlers: make([]TrustedCrawler, len(block.AllowedCrawlers))}
	for index, crawler := range block.AllowedCrawlers {
		value.AllowedCrawlers[index] = TrustedCrawler{Networks: slices.Clone(crawler.Networks),
			UserAgentPrefixes: slices.Clone(crawler.UserAgentPrefixes)}
	}
	return &value
}
