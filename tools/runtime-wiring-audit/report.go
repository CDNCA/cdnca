package main

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

func renderMarkdown(result report) string {
	var output strings.Builder
	output.WriteString("# 控制面运行时接线审计\n\n")
	output.WriteString("> `pass` 只表示当前检查项具备静态证据，不代表领域完成、可发布或已通过真实运行验收。\n\n")
	fmt.Fprintf(&output, "- Schema: `%s`\n", result.SchemaVersion)
	fmt.Fprintf(&output, "- Snapshot: `%s`（仅证明该次读取时点；需用 manifest 复验当前源码）\n", result.SnapshotSemantics)
	fmt.Fprintf(&output, "- Source SHA-256: `%s`\n", result.SourceSHA256)
	fmt.Fprintf(&output, "- Source manifest SHA-256: `%s`\n", result.SourceManifestSHA256)
	fmt.Fprintf(&output, "- Audit tool source SHA-256: `%s`\n", result.ToolSourceSHA256)
	fmt.Fprintf(&output, "- Audit tool manifest SHA-256: `%s`\n", result.ToolSourceManifestSHA256)
	fmt.Fprintf(&output, "- 领域数: `%d`\n", len(result.Domains))
	fmt.Fprintf(&output, "- 检查结果: pass `%d` / fail `%d` / unknown `%d` / not-applicable `%d`\n\n",
		result.Summary[statusPass], result.Summary[statusFail], result.Summary[statusUnknown], result.Summary[statusNotApplied])

	output.WriteString("## 下一批后端接线任务\n\n")
	if len(result.NextTasks) == 0 {
		output.WriteString("当前规则没有生成无冲突任务建议。\n\n")
	} else {
		for _, task := range result.NextTasks {
			fmt.Fprintf(&output, "%d. **%s** (`%s`): %s\n", task.Priority, escapeMarkdown(task.Title), task.Domain, escapeMarkdown(task.Reason))
			fmt.Fprintf(&output, "   - ownership: `%s`\n", strings.Join(task.Ownership, "`, `"))
			fmt.Fprintf(&output, "   - excludes: `%s`\n", strings.Join(task.Excludes, "`, `"))
		}
		output.WriteString("\n")
	}

	output.WriteString("## 并行冲突过滤\n\n")
	for _, filter := range result.ConflictFilters {
		fmt.Fprintf(&output, "- `%s`: `%s`\n", filter.Name, strings.Join(filter.Globs, "`, `"))
	}
	output.WriteString("\n")

	output.WriteString("## 领域矩阵\n\n")
	for _, domain := range result.Domains {
		fmt.Fprintf(&output, "### %s\n\n", domain.Name)
		fmt.Fprintf(&output, "Packages: `%s`\n\n", strings.Join(domain.Packages, "`, `"))
		output.WriteString("| 检查项 | 状态 | 证据 | 判定依据 |\n")
		output.WriteString("| --- | --- | --- | --- |\n")
		for _, name := range result.CheckOrder {
			check := domain.Checks[name]
			fmt.Fprintf(&output, "| `%s` | `%s` | `%s` | %s |\n", name, check.Status,
				strings.Join(check.Evidence, "<br>"), escapeMarkdown(check.Reason))
		}
		if len(domain.Findings) > 0 {
			output.WriteString("\n负向发现：\n\n")
			for _, item := range domain.Findings {
				fmt.Fprintf(&output, "- `%s` at `%s`: %s\n", item.Code, item.Evidence, item.Detail)
			}
		}
		output.WriteString("\n")
	}
	if len(result.Diagnostics) > 0 {
		output.WriteString("## 解析诊断\n\n")
		for _, diagnostic := range result.Diagnostics {
			fmt.Fprintf(&output, "- `%s`\n", diagnostic)
		}
		output.WriteString("\n")
	}
	return output.String()
}

func escapeMarkdown(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func currentConflictFilters() []conflictFilter {
	return []conflictFilter{
		{Name: "OPS-04 announcement", Globs: []string{
			"services/control-api/internal/announcement/**",
			"services/control-api/internal/announcementhttp/**",
			"services/control-api/cmd/control-api/announcement_runtime*",
			"api/control-announcements.openapi.yaml",
		}},
		{Name: "BILL-04 packagecommerce", Globs: []string{
			"services/control-api/internal/packagecommerce/**",
			"services/control-api/internal/packagecommercehttp/**",
			"services/control-api/internal/packagecommerceworker/**",
			"services/control-api/cmd/control-api/package_commerce_runtime*",
			"api/control-package-commerce.openapi.yaml",
		}},
		{Name: "BILL-09 promotion", Globs: []string{
			"services/control-api/internal/promotion/**",
			"services/control-api/internal/promotionhttp/**",
			"api/control-promotions.openapi.yaml",
		}},
		{Name: "signerrevocation", Globs: []string{
			"services/control-api/internal/signerrevocation/**",
			"services/license-service/internal/signerrevocation*/**",
		}},
		{Name: "signercheckpoint", Globs: []string{
			"services/control-api/internal/signercheckpoint/**",
			"services/license-service/internal/signercheckpoint/**",
		}},
		{Name: "plugin example", Globs: []string{"tests/plugin-example/**", "examples/**plugin*/**"}},
		{Name: "i18n/UI audit", Globs: []string{
			"tools/i18n-audit/**", "tests/i18n-audit/**", "apps/**",
		}},
		{Name: "NODE", Globs: []string{
			"services/control-api/internal/node*/**", "services/control-api/cmd/control-api/*node*", "api/control-nodes.openapi.yaml",
		}},
		{Name: "CACHE", Globs: []string{
			"services/control-api/internal/cachecontrol*/**", "services/control-api/cmd/control-api/*cache*", "api/control-cache*.openapi.yaml",
		}},
		{Name: "SYSTEMCONFIG", Globs: []string{
			"services/control-api/internal/systemconfig/**", "services/control-api/cmd/control-api/*system_config*", "api/control-system-config*.openapi.yaml",
		}},
	}
}

type scoredDomain struct {
	Domain domainResult
	Score  int
	Gaps   []string
}

func suggestTasks(domains []domainResult, filters []conflictFilter) []taskSuggestion {
	var candidates []scoredDomain
	for _, domain := range domains {
		if domain.Checks["core_package"].Status != statusPass || domainConflicted(domain, filters) {
			continue
		}
		score := 0
		var gaps []string
		for name, weight := range map[string]int{
			"router_mount": 100, "runtime_dependency_wiring": 95, "background_worker": 90,
			"migration_runtime_head": 70, "postgres_repository": 60, "rbac_transactional_recheck": 55,
			"openapi_aggregation": 40, "smoke_e2e": 30,
		} {
			if domain.Checks[name].Status == statusFail {
				score += weight
				gaps = append(gaps, name)
			}
		}
		if score > 0 {
			sort.Strings(gaps)
			candidates = append(candidates, scoredDomain{Domain: domain, Score: score, Gaps: gaps})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].Domain.Name < candidates[j].Domain.Name
		}
		return candidates[i].Score > candidates[j].Score
	})

	var result []taskSuggestion
	needsIntegrator := false
	for _, candidate := range candidates {
		needsIntegrator = needsIntegrator || containsString(candidate.Gaps, "router_mount") || containsString(candidate.Gaps, "runtime_dependency_wiring")
	}
	if needsIntegrator {
		result = append(result, taskSuggestion{
			Priority: 1, Domain: "shared-runtime-integrator", Title: "统一回收 cmd/router/OpenAPI 聚合接线",
			Reason: "等待当前并行 ownership 释放后，共享 main、中心 router 与 OpenAPI 聚合只由一个 integrator 顺序接入并复测。",
			Ownership: []string{
				"services/control-api/cmd/control-api/main.go",
				"services/control-api/internal/httpapi/server.go",
				canonicalOpenAPIRoot,
			},
			Excludes: conflictNames(filters),
		})
	}
	for _, candidate := range candidates {
		if len(result) >= 8 {
			break
		}
		ownership := make([]string, 0, len(candidate.Domain.Packages))
		for _, packageName := range candidate.Domain.Packages {
			ownership = append(ownership, "services/control-api/internal/"+packageName+"/**")
		}
		result = append(result, taskSuggestion{
			Priority: len(result) + 1, Domain: candidate.Domain.Name,
			Title:     "补齐 " + candidate.Domain.Name + " 的包级运行接线前置",
			Reason:    "失败检查: " + strings.Join(candidate.Gaps, ", ") + "；共享入口由唯一 integrator 回收。",
			Ownership: ownership,
			Excludes: []string{
				"services/control-api/cmd/control-api/**",
				"services/control-api/internal/httpapi/**",
				canonicalOpenAPIRoot,
			},
		})
	}
	return result
}

func domainConflicted(domain domainResult, filters []conflictFilter) bool {
	for _, packageName := range domain.Packages {
		candidate := "services/control-api/internal/" + packageName + "/"
		for _, filter := range filters {
			for _, glob := range filter.Globs {
				prefix := strings.TrimSuffix(glob, "**")
				prefix = strings.TrimSuffix(prefix, "*")
				pattern := strings.TrimSuffix(glob, "/**")
				matched, _ := path.Match(pattern, strings.TrimSuffix(candidate, "/"))
				if matched || strings.HasPrefix(candidate, prefix) || strings.HasPrefix(prefix, candidate) {
					return true
				}
			}
		}
	}
	return false
}

func conflictNames(filters []conflictFilter) []string {
	result := make([]string, 0, len(filters))
	for _, filter := range filters {
		result = append(result, filter.Name)
	}
	return result
}
