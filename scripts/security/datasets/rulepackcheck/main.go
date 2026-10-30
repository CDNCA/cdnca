// rulepackcheck 编译 gen_rulepacks.py 产出的规则包草稿（libs/rulepack.Compile：
// 结构、预算、正则回溯风险），把全部草稿作为同一站点的平台层挂载做一次
// Resolve（冲突 / 遮蔽检查），并逐个校验已知良性爬虫能否作为 CC v6
// trusted_crawlers（edgeconfig.CanonicalCCV2Policy）。每个包还过发布质量门
// （rulepack.CheckPublishable，授权端 PublishRulePack 同一检查），waf_v2 包
// 全部挂上时的规则计划过节点匹配索引预算（rulepack.CompileMatchIndex
// DefaultMatchBudget，节点 rulepackprecheck 同一检查）。
//
//	scripts/security/datasets/rulepackcheck.sh（拷到临时目录、check.mod 作 go.mod 运行）
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
)

const uuid = "11111111-1111-4111-8111-111111111111"

func main() {
	dir := os.Args[1]
	// rulepacks/system-*.json: the seven packs seeded by license migration 096;
	// rulepacks/imported/system-*.json: packs converted from naxsi /
	// device-detector / bunkerweb (gen_imported_packs.py), published with
	// PublishRulePack. Both are checked together (conflicts, match index);
	// the seed VALUES (second argument) are the top-level ones only.
	files, _ := filepath.Glob(filepath.Join(dir, "system-*.json"))
	sort.Strings(files)
	seeded := len(files)
	imported, _ := filepath.Glob(filepath.Join(dir, "imported", "system-*.json"))
	sort.Strings(imported)
	files = append(files, imported...)
	// rulepacks/vpatch/system-*.json: official virtual patches seeded by
	// later license migrations (111: system/waf-php-vpatch).
	vpatch, _ := filepath.Glob(filepath.Join(dir, "vpatch", "system-*.json"))
	sort.Strings(vpatch)
	files = append(files, vpatch...)
	failed := false
	var requests []rulepack.MountRequest
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}
		compiled, err := rulepack.Compile(content)
		if err != nil {
			fmt.Printf("FAIL compile %s: %v\n", filepath.Base(file), err)
			failed = true
			continue
		}
		if _, err := rulepack.CheckPublishable(compiled, nil); err != nil {
			fmt.Printf("FAIL publishable %s: %v\n", filepath.Base(file), err)
			failed = true
		}
		fmt.Printf("ok   %-34s %s v%d rules=%d regexes=%d units=%d sha256=%s\n", filepath.Base(file), compiled.Pack.Engine,
			compiled.RequiredEngineVersion, compiled.Cost.Rules, compiled.Cost.Regexes, compiled.Cost.Units, compiled.SHA256[:12])
		requests = append(requests, rulepack.MountRequest{Pack: compiled, Priority: rulepack.DefaultPriority,
			Source: rulepack.Source{EnabledAt: rulepack.LevelRef{Level: rulepack.LevelPlatform},
				DisableAt: []rulepack.LevelRef{{Level: rulepack.LevelPlatform}}}})
	}
	resolution := rulepack.Resolve(requests, rulepack.Target{EngineVersions: map[rulepack.Engine]uint32{
		rulepack.EngineCCV2: rulepack.EngineMaxVersion[rulepack.EngineCCV2], rulepack.EngineWAFV2: rulepack.EngineMaxVersion[rulepack.EngineWAFV2]}})
	for _, conflict := range resolution.Conflicts {
		fmt.Printf("FAIL conflict %s: %s\n", conflict.Code, conflict.Message)
		failed = true
	}
	for _, warning := range resolution.Warnings {
		fmt.Printf("warn %s: %s\n", warning.Code, warning.Message)
	}
	fmt.Printf("resolve: mounts=%d rules=%d conflicts=%d warnings=%d cost=%+v\n", len(requests), len(resolution.Rules),
		len(resolution.Conflicts), len(resolution.Warnings), resolution.Cost)
	if err := checkCrawlerUAs(filepath.Join(dir, "imported"), requests[seeded:]); err != nil {
		fmt.Printf("FAIL trusted crawlers: %v\n", err)
		failed = true
	}
	if err := checkMatchIndex(resolution.Rules); err != nil {
		fmt.Printf("FAIL match index: %v\n", err)
		failed = true
	}
	// Every value of each pack's action parameter (the user switching log to
	// block / reject / challenge) must still resolve.
	for _, request := range requests {
		spec, ok := request.Pack.Pack.ParamsSchema["action"]
		if !ok {
			fmt.Printf("FAIL %s has no action parameter\n", request.Pack.Pack.PackID)
			failed = true
			continue
		}
		for _, action := range spec.Enum {
			params, err := rulepack.MergeParams(request.Pack.Pack, rulepack.Params{"action": json.RawMessage(`"` + action + `"`)}, nil)
			variant := request
			variant.Params = params
			result := rulepack.Resolve([]rulepack.MountRequest{variant}, rulepack.Target{EngineVersions: map[rulepack.Engine]uint32{
				rulepack.EngineCCV2: rulepack.EngineMaxVersion[rulepack.EngineCCV2], rulepack.EngineWAFV2: rulepack.EngineMaxVersion[rulepack.EngineWAFV2]}})
			if err != nil || len(result.Conflicts) != 0 || len(result.Rules) == 0 {
				fmt.Printf("FAIL %s action=%s: %v %+v\n", request.Pack.Pack.PackID, action, err, result.Conflicts)
				failed = true
			}
		}
	}

	var crawlers struct {
		Crawlers []struct {
			edgeconfig.CCV2TrustedCrawler
			NetworkSources []string `json:"network_sources"`
		} `json:"crawlers"`
	}
	content, err := os.ReadFile(filepath.Join(dir, "known-good-crawlers.json"))
	if err != nil || json.Unmarshal(content, &crawlers) != nil {
		panic(fmt.Sprint("known-good-crawlers.json: ", err))
	}
	valid, pending, invalid := 0, 0, []string{}
	for _, entry := range crawlers.Crawlers {
		crawler := entry.CCV2TrustedCrawler
		// Only IP range URLs (no inline networks, no rDNS): usable once the ranges are fetched.
		if crawler.Networks == nil && crawler.RDNSSuffixes == nil && len(entry.NetworkSources) != 0 {
			pending++
			continue
		}
		policy := edgeconfig.CCV2Policy{SchemaVersion: edgeconfig.CCV2SchemaVersion, TenantScopeID: uuid, SiteID: uuid,
			PolicyID: uuid, PolicyVersion: 1, BindingID: uuid, BindingRevision: 1, PublicationID: uuid, Enabled: true,
			TrustedProxies: []string{}, Allowlist: []string{}, Rules: []edgeconfig.CCV2Rule{},
			TrustedCrawlers: []edgeconfig.CCV2TrustedCrawler{crawler}}
		if _, err := edgeconfig.CanonicalCCV2Policy(policy); err != nil {
			invalid = append(invalid, crawler.Name)
			continue
		}
		valid++
	}
	fmt.Printf("crawlers: valid=%d pending_ip_fetch=%d invalid=%d %s\n", valid, pending, len(invalid), strings.Join(invalid, ","))
	if failed || len(invalid) != 0 {
		os.Exit(1)
	}
	if len(os.Args) > 2 {
		writeSeed(os.Args[2], requests[:seeded])
	}
}

// writeSeed writes the VALUES rows of the official rule pack migration
// (license-service official_rule_pack_versions): one row per pack with its
// canonical bytes, in pack ID order.
func writeSeed(path string, requests []rulepack.MountRequest) {
	sort.Slice(requests, func(i, j int) bool { return requests[i].Pack.Pack.PackID < requests[j].Pack.Pack.PackID })
	var rows []string
	for _, request := range requests {
		pack := request.Pack
		if strings.Contains(string(pack.Canonical), "$pack$") {
			panic("pack content contains the dollar quote tag")
		}
		rows = append(rows, fmt.Sprintf("    ('%s', '%s', '%s', '%s', $pack$%s$pack$)", pack.Pack.PackID, pack.Pack.Version,
			pack.Pack.Engine, pack.Pack.LicenseSPDX, pack.Canonical))
	}
	if err := os.WriteFile(path, []byte(strings.Join(rows, ",\n")+"\n"), 0o644); err != nil {
		panic(err)
	}
}

// checkMatchIndex builds the node's layered rule plan of every resolved
// waf_v2 rule (one segment per pack, as rulepackprecheck.Compile does) and
// compiles its match index within the node budget.
func checkMatchIndex(rules []rulepack.NodeRule) error {
	var segments []edgeconfig.RulePlanSegmentInput
	last := ""
	for _, rule := range rules {
		if rule.Engine != rulepack.EngineWAFV2 || rule.WAF == nil {
			continue
		}
		if rule.PackID != last {
			last = rule.PackID
			segments = append(segments, edgeconfig.RulePlanSegmentInput{Layer: edgeconfig.RulePlanLayer(rule.Layer),
				Policy: edgeconfig.SecurityPolicy{Kind: edgeconfig.SecurityWAF, PolicyID: rulepack.NodeRuleID(rule.PackID, "@pack"),
					PolicyVersion: 1, BindingRevision: 1, RuntimeSHA256: strings.Repeat("0", 64), Enabled: true,
					DefaultAction: edgeconfig.WAFAllow, Rules: []edgeconfig.WAFRule{}}})
		}
		segment := &segments[len(segments)-1]
		segment.Policy.Rules = append(segment.Policy.Rules, *rule.WAF)
	}
	plan, err := edgeconfig.CompileLayeredRulePlan(segments, false, true)
	if err != nil {
		return err
	}
	index, err := rulepack.CompileMatchIndex(plan, rulepack.DefaultMatchBudget)
	if err != nil {
		return err
	}
	fmt.Printf("match index: %+v budget %+v\n", index.Cost, rulepack.DefaultMatchBudget)
	// RULEPACK_PLAN_OUT=<dir>: the plan with its index (0.json, the node's
	// encoding) and node rule ID -> pack / rule (rules.json) for eval_packs.sh.
	if out := os.Getenv("RULEPACK_PLAN_OUT"); out != "" {
		if err := rulepack.AttachMatchIndex(&plan); err != nil {
			return err
		}
		encoded, err := edgeconfig.EncodeRulePlan(plan)
		if err != nil {
			return err
		}
		names := map[string][2]string{}
		for _, rule := range rules {
			names[rule.NodeID] = [2]string{rule.PackID, rule.RuleID}
		}
		mapping, _ := json.Marshal(names)
		if err := os.WriteFile(filepath.Join(out, "0.json"), encoded, 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, "rules.json"), mapping, 0o644)
	}
	return nil
}

// checkCrawlerUAs: no User-Agent rule of the imported packs may match a
// known-good crawler (imported/trusted-crawler-uas.json). A rule whose
// conditions are all user_agent contains / regex is evaluated the node's
// way (contains: both sides lower-cased; regex: PCRE, here RE2, the same
// for these patterns).
func checkCrawlerUAs(dir string, requests []rulepack.MountRequest) error {
	content, err := os.ReadFile(filepath.Join(dir, "trusted-crawler-uas.json"))
	if err != nil {
		return err
	}
	var uas []string
	if err := json.Unmarshal(content, &uas); err != nil || len(uas) == 0 {
		return fmt.Errorf("trusted-crawler-uas.json: %v", err)
	}
	var hits []string
	checked := 0
	for _, request := range requests {
		for _, rule := range request.Pack.Pack.Rules {
			if rule.WAF == nil || len(rule.WAF.Match.Inspect) == 0 || rule.WAF.Match.Path != nil || rule.WAF.Match.Method != "" {
				continue
			}
			uaOnly := true
			for _, clause := range rule.WAF.Match.Inspect {
				uaOnly = uaOnly && clause.Target == "user_agent" && (clause.Operator == "contains" || clause.Operator == "regex")
			}
			if !uaOnly {
				continue
			}
			checked++
			for _, ua := range uas {
				matched := true
				for _, clause := range rule.WAF.Match.Inspect {
					any := false
					for _, value := range clause.Values {
						if clause.Operator == "contains" {
							any = any || strings.Contains(strings.ToLower(ua), strings.ToLower(value))
						} else if re, err := regexp.Compile(value); err == nil {
							any = any || re.MatchString(ua)
						} else {
							return fmt.Errorf("%s/%s: %v", request.Pack.Pack.PackID, rule.ID, err)
						}
					}
					matched = matched && any
				}
				if matched {
					hits = append(hits, request.Pack.Pack.PackID+"/"+rule.ID+" "+ua)
				}
			}
		}
	}
	fmt.Printf("trusted crawler UAs: %d UAs x %d UA rules, %d hits\n", len(uas), checked, len(hits))
	if len(hits) != 0 {
		return fmt.Errorf("%s", strings.Join(hits, "; "))
	}
	return nil
}
