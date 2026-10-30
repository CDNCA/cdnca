package analyticslog

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// fix-wafname: display names of the rule IDs a security event can carry
// besides a named policy / pack rule. Every UUID-shaped rule ID gets a name:
// the page never shows the bare UUID.

// maxRuleNameBytes is the page's rule_name bound.
const maxRuleNameBytes = 128

// systemRuleNames are the internal names of rules the control plane writes
// into a policy (securitypolicy quick block, ja4block).
var systemRuleNames = map[string]string{
	"quick-block:idc":     "快速屏蔽 · IDC 机房",
	"quick-block:carrier": "快速屏蔽 · 运营商",
	"quick-block:crawler": "快速屏蔽 · 放行搜索引擎蜘蛛",
	"JA4 block":           "JA4 自动封禁",
}

// autodefenseBotClasses are cdnca_bot.lua CLASSES.
var autodefenseBotClasses = map[string]string{
	"scanner": "扫描器 UA", "headless": "无头浏览器", "ai_crawler": "AI 爬虫", "bad_ua": "坏 UA（恶意采集）",
	"mismatch": "浏览器指纹不符",
}

// displayRuleName maps a stored rule name to its display name.
func displayRuleName(name string) string {
	if display, ok := systemRuleNames[name]; ok {
		return display
	}
	if strings.HasPrefix(name, "cccoord-") { // cccoord generatedRuleName
		return "CC 跨节点协同封禁"
	}
	return name
}

// fixedRuleName names the rule IDs the node writes itself: auto defense
// (cdnca_autodefense.lua) and a managed WAF set decision without a CRS rule
// (cdnca_managed_waf.lua "managed-waf-<decision id>").
func fixedRuleName(ruleID string) string {
	if strings.HasPrefix(ruleID, "managed-waf-") {
		return "托管 WAF · 规则集判定"
	}
	rest, ok := strings.CutPrefix(ruleID, "autodefense:")
	if !ok || rest == "" {
		return ""
	}
	if level, err := strconv.Atoi(strings.TrimPrefix(rest, "l")); err == nil && strings.HasPrefix(rest, "l") && level > 0 {
		action := "拦截"
		switch level {
		case 1:
			action = "挑战"
		case 2:
			action = "限速"
		}
		return "自动防御 · 第 " + strconv.Itoa(level) + " 级" + action
	}
	if class, ok := strings.CutPrefix(rest, "bot."); ok {
		if name := autodefenseBotClasses[class]; name != "" {
			return "自动防御 · " + name
		}
		return boundName("自动防御 · Bot " + class)
	}
	return boundName("自动防御 · 攻击签名 " + rest)
}

// unnamedRuleName is the name of a UUID rule ID nothing names: a quick
// block rule of a site override (compiled at release only), else
// "未命名规则（<first 8>）" under its policy / pack when that is known.
// Other IDs: "" (the page shows them as they are).
func unnamedRuleName(policyName, ruleID string) string {
	id, err := uuid.Parse(ruleID)
	if err != nil || len(ruleID) != 36 {
		return ""
	}
	if securitypolicy.IsQuickBlockRuleID(id) {
		return "快速屏蔽"
	}
	return joinName(policyName, "未命名规则（"+ruleID[:8]+"）")
}

// defaultRuleName names "<policy_id>:default", the policy default action.
func defaultRuleName(policyName, policyID string) string {
	if policyName != "" {
		return joinName(policyName, "默认动作")
	}
	return "默认动作（策略 " + policyID[:8] + "）"
}

func joinName(owner, name string) string {
	if owner == "" {
		return boundName(name)
	}
	return boundName(owner + " · " + name)
}

// boundName cuts name to maxRuleNameBytes on a rune boundary.
func boundName(name string) string {
	for len(name) > maxRuleNameBytes {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return name
}
