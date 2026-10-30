package audit

// 攻击自动升级 (module.escalate, migration 460).
func init() {
	register(
		e("node.line_group.tier_update", CategoryNode,
			"把线路组 {resource} 的等级从「{before}」改为「{after}」",
			"changed the tier of line group {resource} from {before} to {after}").f("before", "after"),
		e("node.line_group.grant", CategoryNode,
			"把线路组 {resource} 授权给代理商 {grantee_scope_id}",
			"granted line group {resource} to reseller {grantee_scope_id}").f("grantee_scope_id", "may_regrant"),
		e("node.line_group.grant_revoke", CategoryNode,
			"撤销线路组 {resource} 对代理商 {grantee_scope_id} 的授权，下架套餐 {withdrawn_products}，清空 B/C 的套餐 {cleared_policies}",
			"revoked the grant of line group {resource} to reseller {grantee_scope_id}; withdrew packages {withdrawn_products}, cleared B/C of {cleared_policies}").
			f("grantee_scope_id", "withdrawn_products", "cleared_policies"),
		e("package.escalate_policy.grant_revoked", CategoryPackage,
			"线路组 {line_group_id} 的授权被撤销，套餐 {resource} 的攻击升级 B/C 已清空",
			"the grant of line group {line_group_id} was revoked; B/C of package {resource} were cleared").f("line_group_id", "grant_id", "revision"),
		e("package.escalate_policy.update", CategoryPackage,
			"修改套餐 {resource} 的攻击自动升级设置{changes}",
			"updated the attack escalation settings of package {resource}{changes}").f("revision"),
		e("security.escalate.site_update", CategorySecurity,
			"修改网站 {resource} 的攻击自动升级设置{changes}",
			"updated attack escalation of site {resource}{changes}").f("enabled", "revision"),
		e("security.escalate.lock", CategorySecurity,
			"把网站 {resource} 的攻击自动升级锁定在 {to_level} 级",
			"locked attack escalation of site {resource} at level {to_level}").f("from_level", "to_level"),
		e("security.escalate.unlock", CategorySecurity,
			"解除网站 {resource} 的攻击自动升级锁定",
			"unlocked attack escalation of site {resource}").f("from_level"),
		e("security.escalate.reset", CategorySecurity,
			"把网站 {resource} 从 {from_level} 级一键回切到 A 级",
			"reset attack escalation of site {resource} from level {from_level} to A").f("from_level", "to_level"),
		e("security.escalate.cname_changed", CategorySecurity,
			"确认网站 {resource} 的域名已改为攻击自动升级拆出的独立 CNAME",
			"confirmed the domain of site {resource} points at its split attack escalation CNAME"),
		e("security.escalate.cname_auto_changed", CategorySecurity,
			"自动把网站 {resource} 的域名解析改为攻击自动升级拆出的独立 CNAME {split_cname}{changes}",
			"pointed the domains of site {resource} at its split attack escalation CNAME {split_cname}{changes}").f("split_cname", "domains"),
		e("security.escalate.last_resort_applied", CategorySecurity,
			"网站 {resource} 遭受攻击，攻击自动升级最后一级已生效：{last_resort}（blackhole=黑洞，unlimited=无限防线路组 {line_group_id}）",
			"site {resource} is under attack; the last level of attack escalation took effect: {last_resort} (blackhole, or the unlimited line group {line_group_id})").
			f("from_level", "to_level", "last_resort", "line_group_id"),
		e("security.escalate.cname_auto_failed", CategorySecurity,
			"自动修改网站 {resource} 的域名解析失败（{reason_code}），改为通知站长{changes}",
			"failed to point the domains of site {resource} at its split CNAME ({reason_code}); the owner is told{changes}").f("split_cname", "domains", "reason_code"),
	)
}
