package audit

// Rule pack write operations of rulepackcontrol (PA-10/PA-11). The other
// rule.pack.* events (version create, sealed pack keys) are in
// catalog_security.go.
func init() {
	register(
		e("rule.pack.update", CategoryRule, "修改规则包 {resource} 的当前版本或更新策略{changes}", "updated the current version or update policy of rule pack {resource}{changes}").
			f("pack_id", "layer", "requested"),
		e("rule.pack.version.delete", CategoryRule, "删除规则包版本 {resource}{changes}", "deleted rule pack version {resource}{changes}").
			f("pack_id", "version", "layer", "current", "mounted", "enabled", "pack_removed"),
		e("rule.pack.override.put", CategoryRule, "设置规则包启用 {resource}{changes}", "set rule pack enablement {resource}{changes}").
			f("pack_id", "rule_id", "level", "level_object_id", "version", "requested", "row_existed", "row_removed"),
		e("rule.pack.site.publish", CategoryRule, "发布网站 {resource} 的规则包挂载{changes}", "published the rule pack mounts of site {resource}{changes}").
			f("site_id", "published", "conflicts", "unchanged", "suspended", "suspensions_cleared"),
		e("rule.pack.mount.suspend", CategoryRule, "网站 {resource} 改为 CRS 档位 {crs_profile} 后，规则包 {pack_id}@{version} 超出档位已挂起{changes}",
			"rule pack {pack_id}@{version} of site {resource} was suspended: outside the new CRS profile {crs_profile}{changes}").
			f("site_id", "pack_id", "version", "reason", "crs_profile"),
		e("rule.pack.mount.restore", CategoryRule, "网站 {resource} 的 CRS 档位重新覆盖规则包 {pack_id}@{version}，挂载已恢复生效{changes}",
			"the CRS profile of site {resource} covers rule pack {pack_id}@{version} again; its mount was restored{changes}").
			f("site_id", "pack_id", "version", "reason", "crs_profile"),
		// license-service 写入 license_audit_events（licensing.RuleIntelIngestAction / RuleIntelJobAction，ADR 0011 RI-09），这里只登记目录。
		e("rule.intel.report.ingest", CategoryRule, "接收主控规则情报上报 第 {sequence} 次：采纳 {accepted} 条、墓碑挡住 {blocked} 条、丢弃 {dropped} 条{error_code}",
			"received controller rule intel report #{sequence}: {accepted} accepted, {blocked} tombstoned, {dropped} dropped{error_code}").
			f("sequence", "accepted", "blocked", "dropped", "report_digest", "error_code"),
		e("rule.intel.job.run", CategoryRule, "规则情报日任务（第 {resource} 天）：候选 {candidates} 条、簇 {clusters} 个、归档样本 {archived} 条",
			"rule intel daily job (day {resource}): {candidates} candidates, {clusters} clusters, {archived} samples archived").
			f("candidates", "clusters", "archived", "pool_total", "evidence_pruned", "reports_pruned"),
		// 授权端运营后台"规则情报"页（licensing.RuleIntelCandidate*Action / RuleIntelCorpusAddAction，ADR 0011 §5.7，RI-14）。
		e("rule.intel.candidate.reject", CategoryRule, "驳回规则情报候选 {resource}（{reason_code}，第 {reject_count} 次）{changes}",
			"rejected rule intel candidate {resource} ({reason_code}, rejection #{reject_count}){changes}").
			f("fingerprint", "reason_code", "previous_state", "reject_count", "permanent", "until_day", "note"),
		e("rule.intel.candidate.restore", CategoryRule, "恢复已驳回的规则情报候选 {resource}{changes}",
			"restored rejected rule intel candidate {resource}{changes}").
			f("fingerprint", "previous_state", "note"),
		e("rule.intel.corpus.add", CategoryRule, "向规则情报语料库加入样本 {resource}（{kind}）{changes}",
			"added sample {resource} ({kind}) to the rule intel corpus{changes}").
			f("sample_id", "kind", "attack_class", "fingerprint", "bytes"),
		// 授权端情报并入草稿、质量门、灰度发布与回滚（licensing.RuleIntelMerge*Action / RuleIntelRollout*Action，ADR 0011 RI-12）。
		e("rule.intel.merge.create", CategoryRule, "生成规则情报并入草稿 {resource}（目标 {target}，候选 {candidates} 条，跳过 {skipped} 条）{changes}",
			"created rule intel merge draft {resource} (target {target}, {candidates} candidates, {skipped} skipped){changes}").
			f("target", "bump", "candidates", "skipped", "versions", "pack_sha256"),
		e("rule.intel.merge.gate", CategoryRule, "规则情报草稿 {resource} 运行质量门：{state}{changes}",
			"ran the quality gate of rule intel draft {resource}: {state}{changes}").
			f("target", "state", "pack_sha256", "gate_request_id"),
		e("rule.intel.merge.publish", CategoryRule, "发布规则情报草稿 {resource}（目标 {target}，灰度名单 {canary} 个安装）{changes}",
			"published rule intel draft {resource} (target {target}, {canary} canary installations){changes}").
			f("target", "release_refs", "versions", "candidates", "canary"),
		e("rule.intel.merge.abandon", CategoryRule, "放弃规则情报草稿 {resource}{changes}", "abandoned rule intel draft {resource}{changes}").
			f("target", "previous_state"),
		e("rule.intel.rollout.advance", CategoryRule, "推进规则情报发布 {resource} 的灰度{changes}", "advanced the rollout of rule intel release {resource}{changes}").
			f("reason", "result_merge_id"),
		e("rule.intel.rollout.pause", CategoryRule, "暂停规则情报发布 {resource} 的灰度（{reason}）{changes}",
			"paused the rollout of rule intel release {resource} ({reason}){changes}").
			f("reason", "result_merge_id"),
		e("rule.intel.rollout.resume", CategoryRule, "恢复规则情报发布 {resource} 的灰度{changes}", "resumed the rollout of rule intel release {resource}{changes}").
			f("reason", "result_merge_id"),
		e("rule.intel.rollout.rollback", CategoryRule, "回滚规则情报发布 {resource}（新发布 {result_merge_id}）{changes}",
			"rolled back rule intel release {resource} (new release {result_merge_id}){changes}").
			f("reason", "result_merge_id"),
		// 授权端"已发布规则"页（licensing.RuleIntelRuleWithdrawAction / RuleIntelRuleRestoreAction，ADR 0011 §7.2）。
		e("rule.intel.rule.withdraw", CategoryRule, "下线官方规则 {pack_id}#{rule_id}（{from_version} → {version}）{changes}",
			"withdrew official rule {pack_id}#{rule_id} ({from_version} → {version}){changes}").
			f("pack_id", "rule_id", "from_version", "version", "release_refs", "reason"),
		e("rule.intel.rule.restore", CategoryRule, "从历史恢复官方规则 {pack_id}#{rule_id}（{from_version} → {version}）{changes}",
			"restored official rule {pack_id}#{rule_id} from history ({from_version} → {version}){changes}").
			f("pack_id", "rule_id", "from_version", "version", "release_refs", "reason"),
	)
}
