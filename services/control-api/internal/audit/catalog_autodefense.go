package audit

// Smart auto defense (module.autodefense, ADR 0010 section 9.4). Manual lock
// (item_manual) and resume (item_auto) record who and when in
// locked_by/locked_at and resumed_by/resumed_at besides the event actor.
func init() {
	register(
		e("security.autodefense.mode_change", CategorySecurity,
			"把网站 {site_id} 的智能自动防御从「{before}」改为「{after}」（生效：{effective}；follow = 跟随平台）",
			"changed smart auto defense of site {site_id} from {before} to {after} (in force: {effective}; follow = platform default)").f("site_id", "before", "after", "effective", "batch_size"),
		e("security.autodefense.settings_update", CategorySecurity,
			"修改网站 {site_id} 的智能自动防御设置{changes}",
			"updated smart auto defense settings of site {site_id}{changes}").f("site_id"),
		e("security.autodefense.module_mode", CategorySecurity,
			"把 {resource} 的 {module} 模块从「{before}」切换为「{after}」",
			"switched module {module} of {resource} from {before} to {after}").f("module", "before", "after"),
		e("security.autodefense.item_manual", CategorySecurity,
			"把 {resource} 的 {module} 模块的 {field} 改为人工{changes}，由 {locked_by} 于 {locked_at} 锁定",
			"set {field} of module {module} on {resource} to manual{changes}, locked by {locked_by} at {locked_at}").
			f("module", "field", "before", "after", "locked_by", "locked_at"),
		e("security.autodefense.item_auto", CategorySecurity,
			"把 {resource} 的 {module} 模块的 {field} 恢复为自动，由 {resumed_by} 于 {resumed_at} 恢复",
			"returned {field} of module {module} on {resource} to automatic, resumed by {resumed_by} at {resumed_at}").
			f("module", "field", "before", "after", "resumed_by", "resumed_at", "whole_module"),
		e("security.autodefense.item_range", CategorySecurity,
			"修改 {resource} 的 {module} 模块 {field} 的自动调整上下限{changes}",
			"changed the automatic range of {field} of module {module} on {resource}{changes}").
			f("module", "field", "before", "after"),
		e("security.autodefense.site_release", CategorySecurity,
			"一键解除网站 {site_id} 的自动处置（解封 {released_count} 个，签名转影子 {shadowed_count} 条，仅观察 {observe_minutes} 分钟）",
			"released every automatic mitigation of site {site_id} ({released_count} unblocked, {shadowed_count} signatures to shadow, observe only for {observe_minutes} minutes)").
			f("site_id", "released_count", "shadowed_count", "observe_minutes", "note"),
		e("security.autodefense.circuit_resume", CategorySecurity,
			"恢复网站 {site_id} 的自动防护（熔断原因 {reason}）",
			"resumed automatic defense of site {site_id} (circuit reason {reason})").f("site_id", "reason", "manual_resume"),
		e("security.autodefense.drift_confirm", CategorySecurity,
			"确认网站 {site_id} 的基线漂移（{node_count} 个节点，指标 {metrics}），不改动节点基线",
			"confirmed the baseline drift of site {site_id} ({node_count} nodes, metrics {metrics}); node baselines unchanged").
			f("site_id", "node_count", "nodes", "metrics"),
		e("security.autodefense.mitigation_release", CategorySecurity,
			"解除网站 {site_id} 的自动处置 {targets}",
			"released automatic mitigation {targets} of site {site_id}").f("site_id", "targets", "whitelist", "false_positive", "note"),
		e("security.autodefense.signature_solidify", CategorySecurity,
			"把自动规则 {resource} 固化为网站 {site_id} 的 {kind} 用户规则",
			"turned automatic rule {resource} into a {kind} user rule of site {site_id}").f("site_id", "kind", "rule_id", "pack_id", "version"),
		// Written by the federation round (AD-10); the actor is the plugin.
		e("security.autodefense.signature_promote", CategorySecurity,
			"智能自动防御把网站 {site_id} 的自动规则 {resource} 广播给其他节点（{nodes} 个节点、{sites} 个网站出现，置信度 {confidence_permille}‰）",
			"smart auto defense broadcast automatic rule {resource} of site {site_id} to the other nodes (seen on {nodes} nodes and {sites} sites, confidence {confidence_permille}‰)").
			f("site_id", "nodes", "sites", "confidence_permille", "reason"),
		e("security.autodefense.signature_federation_withdraw", CategorySecurity,
			"智能自动防御撤回网站 {site_id} 已广播的自动规则 {resource}（{reason}）",
			"smart auto defense withdrew the broadcast automatic rule {resource} of site {site_id} ({reason})").
			f("site_id", "nodes", "sites", "confidence_permille", "reason"),
		e("security.autodefense.signature_revoke", CategorySecurity,
			"禁用网站 {site_id} 的自动规则 {resource}",
			"disabled automatic rule {resource} of site {site_id}").f("site_id", "stage"),
		e("security.autodefense.false_positive_report", CategorySecurity,
			"反馈网站 {site_id} 的自动防御误判：{note}",
			"reported a smart auto defense false positive on site {site_id}: {note}").f("site_id", "signature_id", "source", "note"),
		// Admin sign-in source IPs on the allow list (ADR 0010 §7.2 item 3, fix-adplatwire): written by the sign-in
		// (actor the user) and by the snapshot distributor when one expires (actor system).
		e("security.autodefense.admin_login_allow", CategorySecurity,
			"登录来源 {cidr} 加入智能自动防御白名单 {days} 天（到 {until}），期间不被自动处置",
			"added sign-in source {cidr} to the smart auto defense allow list for {days} days (until {until}); it is never mitigated meanwhile").
			f("cidr", "days", "until"),
		e("security.autodefense.admin_login_allow_expire", CategorySecurity,
			"登录来源 {cidr} 的智能自动防御白名单已到期（{until}），移出白名单",
			"the smart auto defense allow list entry of sign-in source {cidr} expired ({until}) and was removed").
			f("cidr", "until"),
		// The site allow list's 解除并加白 entries (ADR 0010 §7.4, fix-adwhitelist): stored by a release with
		// "加入白名单" (delivered to the nodes, never mitigated) and removed from the site detail.
		// fix-adwhitelist3: the entry is a network (cidr) or a JA4 (ja4), with its expiry (until: RFC 3339 or
		// "permanent"); an entry past its expiry is deleted by the distributor (site_allow_expire, actor system).
		e("security.autodefense.site_allow_add", CategorySecurity,
			"把 {resource} 加入网站 {site_id} 的智能自动防御白名单（解除并加白，期限 {until}），节点不再自动处置它",
			"added {resource} to the smart auto defense allow list of site {site_id} (released and allowed, until {until}); nodes never mitigate it").
			f("site_id", "cidr", "ja4", "source", "from", "until"),
		e("security.autodefense.site_allow_remove", CategorySecurity,
			"把 {resource} 移出网站 {site_id} 的智能自动防御白名单",
			"removed {resource} from the smart auto defense allow list of site {site_id}").f("site_id", "cidr", "ja4", "source"),
		// fix-adwhitelist3 §2: a person retried a single release on the nodes (failed_nodes / pending_nodes before)
		e("security.autodefense.release_retry", CategorySecurity,
			"重试网站 {site_id} 对 {target} 的解除下发（第 {retry} 次，此前 {failed_nodes} 个节点失败）",
			"retried the release of {target} on site {site_id} (retry {retry}; {failed_nodes} nodes had failed)").
			f("site_id", "kind", "target", "retry", "failed_nodes", "pending_nodes"),
		e("security.autodefense.site_allow_expire", CategorySecurity,
			"网站 {site_id} 的智能自动防御白名单条目 {resource} 已到期（{expires_at}），系统自动移除并下发节点",
			"the smart auto defense allow list entry {resource} of site {site_id} expired ({expires_at}); removed and delivered to the nodes").
			f("site_id", "cidr", "ja4", "source", "created_by", "expires_at"),
		e("security.autodefense.platform_settings_update", CategorySecurity,
			"修改智能自动防御平台设置{changes}（跟随平台的网站 {following_sites} 个）",
			"updated the smart auto defense platform settings{changes} ({following_sites} sites follow the platform)").f("following_sites"),
		// Written by the snapshot distributor (AD-09) for each round that
		// issued new AutoDefenseCommand revisions; the actor is the system.
		e("security.autodefense.snapshot_publish", CategorySecurity,
			"系统向 {nodes} 个节点下发智能自动防御快照（已授权：{licensed}，自动处置：{auto_mitigation}）",
			"published smart auto defense snapshots to {nodes} nodes (licensed: {licensed}, auto mitigation: {auto_mitigation})").
			f("nodes", "licensed", "auto_mitigation"),
		// Written by ingest (AD-08) when a node reports an automatic overlay
		// change; the actor is the node (actor_ref node:<id>).
		e("security.autodefense.module_adjust", CategorySecurity,
			"节点 {node_id} 自动调整 {resource} 的 {module} 模块{changes}（{reason}）",
			"node {node_id} automatically adjusted module {module} of {resource}{changes} ({reason})").
			f("module", "field", "node_id", "port_group"),
		// WAF adaptive (ADR 0011 RI-06): user operations on automatic exclusions
		// and the per-site grey-zone challenge switch.
		e("security.waf.auto_exclusion_adopt", CategorySecurity,
			"采纳网站 {resource} 的 WAF 自动排除 {exclusion_id}（规则 {rule}，参数 {param}）",
			"adopted WAF automatic exclusion {exclusion_id} on site {resource} (rule {rule}, parameter {param})").
			f("module", "field", "item", "exclusion_id", "rule", "param", "reason", "manual", "until", "actor", "reject_reason"),
		e("security.waf.auto_exclusion_reject", CategorySecurity,
			"驳回网站 {resource} 的 WAF 自动排除 {exclusion_id}（规则 {rule}，参数 {param}，原因 {reject_reason}）",
			"rejected WAF automatic exclusion {exclusion_id} on site {resource} (rule {rule}, parameter {param}, reason {reject_reason})").
			f("module", "field", "item", "exclusion_id", "rule", "param", "reason", "manual", "until", "actor", "reject_reason"),
		e("security.waf.auto_exclusion_revoke", CategorySecurity,
			"撤销网站 {resource} 的 WAF 自动排除 {exclusion_id}（规则 {rule}，参数 {param}，原因 {reject_reason}）",
			"revoked WAF automatic exclusion {exclusion_id} on site {resource} (rule {rule}, parameter {param}, reason {reject_reason})").
			f("module", "field", "item", "exclusion_id", "rule", "param", "reason", "manual", "until", "actor", "reject_reason"),
		e("security.waf.auto_exclusion_manual", CategorySecurity,
			"将网站 {resource} 的 WAF 自动排除 {exclusion_id} 设为人工（规则 {rule}，参数 {param}）",
			"set WAF automatic exclusion {exclusion_id} on site {resource} to manual (rule {rule}, parameter {param})").
			f("module", "field", "item", "exclusion_id", "rule", "param", "reason", "manual", "until", "actor", "reject_reason"),
		e("security.waf.auto_exclusion_resume", CategorySecurity,
			"恢复网站 {resource} 的 WAF 自动排除 {exclusion_id} 为自动（规则 {rule}，参数 {param}）",
			"resumed automatic handling of WAF exclusion {exclusion_id} on site {resource} (rule {rule}, parameter {param})").
			f("module", "field", "item", "exclusion_id", "rule", "param", "reason", "manual", "until", "actor", "reject_reason"),
		e("security.waf.grey_challenge", CategorySecurity,
			"修改网站 {resource} 的 WAF 灰区挑战设置{changes}",
			"updated the WAF grey-zone challenge setting of site {resource}{changes}"),
		e("security.waf.grey_repeat", CategorySecurity,
			"修改网站 {resource} 的 WAF 灰区重复来源阈值{changes}",
			"updated the WAF grey-zone repeat threshold of site {resource}{changes}"),
	)
}
