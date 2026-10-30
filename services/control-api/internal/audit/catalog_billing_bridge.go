package audit

// 财务系统对接插件对接密钥（module.billing.bridge，ADR 0019 BB-02，migration 556）。
func init() {
	register(
		e("billing_bridge.key.created", CategorySystem,
			"创建财务对接密钥 {key_id}（{name}）",
			"created billing bridge key {key_id} ({name})").f("key_id", "name", "owner_kind", "revision", "ip_allowlist"),
		e("billing_bridge.key.rotated", CategorySystem,
			"轮换财务对接密钥 {key_id}（{name}）的密钥{changes}",
			"rotated the secret of billing bridge key {key_id} ({name}){changes}").f("key_id", "name", "owner_kind", "revision"),
		e("billing_bridge.key.revoked", CategorySystem,
			"吊销财务对接密钥 {key_id}（{name}）",
			"revoked billing bridge key {key_id} ({name})").f("key_id", "name", "owner_kind", "revision"),
		// bb0405 BB-05：门面签发一次性免密登录票据（migration 557）。
		e("billing_bridge.sso.issued", CategorySystem,
			"财务对接密钥 {key_id} 为用户 {resource} 签发免密登录票据",
			"billing bridge key {key_id} issued a sign-in ticket for user {resource}").f("key_id", "user_id", "tenant_scope_id"),
		// 插件设置（sso_require_mfa，migration 557）。
		e("billing_bridge.settings.updated", CategorySystem,
			"修改财务对接设置{changes}",
			"updated billing bridge settings{changes}").f("owner_kind", "revision"),
	)
}
