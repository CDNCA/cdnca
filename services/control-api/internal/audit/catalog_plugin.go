package audit

// Plugin installation, node plugin bundles and plugin webhooks.
func init() {
	register(
		e("plugin_installation.confirm", CategoryPlugin, "确认安装插件 {resource}", "confirmed installation of plugin {resource}"),
		e("plugin_installation.upgrade", CategoryPlugin, "升级插件 {resource}", "upgraded plugin {resource}"),
		e("plugin_installation.disable", CategoryPlugin, "暂停插件 {resource}", "paused plugin {resource}"),
		e("plugin_installation.resume", CategoryPlugin, "恢复使用插件 {resource}", "resumed plugin {resource}"),
		e("plugin_installation.uninstall", CategoryPlugin, "卸载插件 {resource}", "uninstalled plugin {resource}"),
		e("plugin.artifact.download_request", CategoryPlugin, "请求下载制品 {resource}", "requested downloading artifact {resource}").f("version", "kind"),
		e("plugin.artifact.download", CategoryPlugin, "制品 {resource} 已下载到主控", "artifact {resource} was downloaded to the control plane").f("version"),
		e("plugin.artifact.build", CategoryPlugin, "主控本地构建了制品 {resource}{changes}", "the control plane built artifact {resource}{changes}").f("version", "source_release"),
		e("plugin.artifact.withdraw", CategoryPlugin, "插件市场制品 {resource} 授权已失效，停止使用{changes}", "plugin market artifact {resource} is no longer authorized and was withdrawn{changes}").f("version", "kind"),
		e("plugin.artifact.download_reject", CategoryPlugin, "制品 {resource} 下载校验未通过", "artifact {resource} failed download verification"),
		e("plugin.artifact_catalog.apply", CategoryPlugin, "应用授权端下发的制品目录 {resource}", "applied artifact catalog delivery {resource}"),
		e("plugin.artifact_catalog.reject", CategoryPlugin, "拒绝授权端下发的制品目录 {resource}", "rejected artifact catalog delivery {resource}"),
		// PA-19 ui_page plugins: pages on the plugin's own origin in a sandboxed iframe.
		e("plugin.ui_page.enable", CategoryPlugin, "插件 {resource} 的页面已挂载（来源 {origin}）{changes}", "mounted the pages of plugin {resource} (origin {origin}){changes}").f("version", "origin"),
		e("plugin.ui_page.withdraw", CategoryPlugin, "插件 {resource} 授权已失效，页面已撤下（来源 {origin}）{changes}", "plugin {resource} is no longer authorized; its pages (origin {origin}) were removed{changes}").f("version", "origin"),
		e("plugin.ui_page.reject", CategoryPlugin, "拒绝挂载插件 {resource} 的页面：来源 {origin} 已被其他插件使用", "refused to mount the pages of plugin {resource}: origin {origin} is used by another plugin").f("version", "origin"),
		e("plugin.ui_page.proxy", CategoryPlugin, "在插件 {resource} 的页面「{page_id}」中调用插件后端 {method} {path}", "called the backend of plugin {resource} from page {page_id}: {method} {path}").f("page_id", "method", "path"),
		// PA-22 third-party DNS / SMS / ICP provider plugins: installation contract, then enable.
		e("plugin.provider.materialize", CategoryPlugin, "插件 {resource} 的服务商声明已下载（{kinds}），等待契约测试{changes}", "the provider declaration of plugin {resource} ({kinds}) was downloaded and awaits its contract test{changes}").f("version", "kinds"),
		e("plugin.provider.withdraw", CategoryPlugin, "插件 {resource} 授权已失效，服务商已停用{changes}", "plugin {resource} is no longer authorized; its provider was withdrawn{changes}").f("version"),
		e("plugin.provider.contract", CategoryPlugin, "插件 {resource} 的契约测试结果：{changes}", "contract test of plugin {resource}: {changes}").f("version", "contract_version", "cases"),
		e("plugin.provider.enable", CategoryPlugin, "启用第三方服务商插件 {resource}{changes}", "enabled third-party provider plugin {resource}{changes}").f("version"),
		e("plugin.provider.disable", CategoryPlugin, "停用第三方服务商插件 {resource}{changes}", "disabled third-party provider plugin {resource}{changes}").f("version"),
		// PA-23 third-party payment plugins: a refused "paid" claim is an alert on the plugin.
		e("plugin.provider.payment_alert", CategoryPlugin, "告警：支付插件 {resource} 上报的支付结果未通过主控核验（{reason_code}），未入账", "alert: payment plugin {resource} reported a payment that failed control-plane verification ({reason_code}); nothing was credited").f("order_id", "channel_id", "reason_code"),
		// fix-cfgflow2 §2: market subscription receipts the reconciler completed or gave up on.
		e("plugin.market_supply.receipt_confirmed", CategoryPlugin, "网站 {resource} 在市场供货 {supply} 的第 {revision} 版配置已对账确认", "confirmed the revision {revision} receipt of site {resource} on market supply {supply}").f("site_domain", "supply", "revision", "attempts"),
		e("plugin.market_supply.receipt_unconfirmed", CategoryPlugin, "网站 {resource} 在市场供货 {supply} 的第 {revision} 版配置多次对账仍未确认，已标记为不一致（{reason}）", "gave up confirming the revision {revision} receipt of site {resource} on market supply {supply} ({reason})").f("site_domain", "supply", "revision", "attempts", "reason"),
		// fix-mktsiteconf7 §1: an applied leaf's revision took effect on its nodes, or did not.
		e("plugin.market_supply.node_delivery_confirmed", CategoryPlugin, "网站 {resource} 在市场供货 {supply} 的第 {revision} 版配置已在供货方节点生效", "revision {revision} of site {resource} took effect on the nodes of market supply {supply}").f("site_domain", "supply", "revision", "attempts"),
		e("plugin.market_supply.node_delivery_failed", CategoryPlugin, "网站 {resource} 在市场供货 {supply} 的第 {revision} 版配置未能在供货方节点生效（{reason}）", "revision {revision} of site {resource} did not take effect on the nodes of market supply {supply} ({reason})").f("site_domain", "supply", "revision", "attempts", "reason", "detail"),
		e("plugin.theme.download", CategoryPlugin, "下载主题包 {resource}", "downloaded theme package {resource}"),
		e("plugin.theme.upload", CategoryPlugin, "上传主题包 {resource}", "uploaded theme package {resource}"),
		e("plugin.theme.activate", CategoryPlugin, "启用主题 {resource}{changes}", "activated theme {resource}{changes}"),
		e("plugin.theme.remove", CategoryPlugin, "移除主题包 {resource}", "removed theme package {resource}"),
		// PA-26 white-label themes: a tenant (agent/reseller) theme.
		e("theme.tenant.activate", CategoryPlugin, "把租户 {resource} 的主题切换为「{theme_id}」{changes}", "switched tenant {resource} to theme {theme_id}{changes}").f("theme_id", "assigned_by"),
		e("theme.tenant.selection_update", CategoryPlugin, "修改租户 {resource} 的自选主题权限{changes}", "changed whether tenant {resource} may choose its theme{changes}").f("theme_id"),
		e("theme.tenant_policy.update", CategoryPlugin, "修改平台的租户自选主题默认设置{changes}", "changed the platform default for tenant theme choice{changes}").f("tenant_scopes_changed"),
		e("theme.tenant_domain.bind", CategoryPlugin, "为租户绑定登录域名 {resource}", "bound sign-in hostname {resource} to a tenant").f("tenant_scope_id"),
		e("theme.tenant_domain.unbind", CategoryPlugin, "解除租户登录域名 {resource}", "unbound tenant sign-in hostname {resource}").f("tenant_scope_id"),
		e("plugin_webhook.subscription.create", CategoryPlugin, "新增插件 Webhook 订阅 {resource}", "created plugin webhook subscription {resource}"),
		e("plugin_webhook.subscription.revoke", CategoryPlugin, "撤销插件 Webhook 订阅 {resource}", "revoked plugin webhook subscription {resource}"),
		e("plugin_webhook.test_delivery.create", CategoryPlugin, "发送插件 Webhook 测试投递 {resource}", "sent plugin webhook test delivery {resource}"),
		e("plugin_webhook.delivery.replay", CategoryPlugin, "重放插件 Webhook 投递 {resource}", "replayed plugin webhook delivery {resource}"),
		e("plugin_webhook.secret.rotate", CategoryPlugin, "轮换插件 Webhook 签名密钥 {resource}", "rotated plugin webhook secret {resource}"),
		e("plugin_webhook.secret.activate", CategoryPlugin, "启用插件 Webhook 新签名密钥 {resource}", "activated plugin webhook secret {resource}"),
		// Operator rotation of the broker publication attestation key (control-api plugin-webhook-attestation-key rotate).
		e("plugin.webhook_attestation_key.rotate", CategoryPlugin, "轮换插件 Webhook 投递证明密钥为 {resource}{changes}（有效期至 {expires_at}）", "rotated the plugin webhook publication attestation key to {resource}{changes} (valid until {expires_at})").f("expires_at"),
		e("plugin_webhook.domain_event.publish", CategoryPlugin, "向插件 Webhook 投递业务事件 {resource}", "delivered a domain event to plugin webhook {resource}"),
	)
}
