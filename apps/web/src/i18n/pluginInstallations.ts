import i18n from './index'

export type PluginInstallationsMessageTree = { [key: string]: string | PluginInstallationsMessageTree }
type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }

const zhCN = {
  title: '插件市场', subtitle: '主控管理员给本租户装好的插件都在这里，直接可用，不需要你确认安装。插件运行在开发者自己的服务里，主控只负责授权和推送事件。',
  actions: {
    search: '查询', reset: '重置', refresh: '刷新', retry: '重试', view: '查看详情',
    confirm: '安装', upgrade: '升级', disable: '暂停', resume: '恢复使用', uninstall: '卸载',
    confirmInstall: '确认安装', confirmUpgrade: '确认升级', confirmDisable: '确认暂停', confirmUninstall: '确认卸载',
    cancel: '取消', retrySame: '重新提交', retryResume: '重新恢复', refreshAbandon: '放弃这次操作并刷新',
    refreshState: '刷新状态', clearFilters: '清除筛选',
  },
  filters: { plugin: '插件', pluginPlaceholder: '按插件名称（ID）搜索', status: '状态', all: '全部状态' },
  columns: { plugin: '插件', version: '版本', status: '状态', scopes: '需要的权限', lkg: '可回退版本', updated: '更新时间', actions: '操作' },
  states: {
    pending_confirmation: '可安装', authorized: '已授权', installing: '安装中', enabled: '运行中',
    disabled: '已暂停', upgrade_failed_lkg_preserved: '升级失败，仍在用旧版本', uninstalled: '已卸载',
    platformPaused: '平台已暂停', upgradeAvailable: '可升级到 {{version}}',
    awaitingController: '已购买，待你确认',
  },
  empty: { title: '还没有可用的插件', description: '主控管理员把插件装给本租户后，会显示在这里。',
    noMatch: '没有匹配的插件', status: '没有“{{status}}”的插件',
    group: { all: '尚未获取插件', pending: '暂无待确认插件', installed: '暂无已安装插件', failed: '暂无失败插件' } },
  forbidden: { title: '无权访问', description: '当前账号没有查看插件的权限。' },
  errors: {
    load: '加载插件列表失败', detail: '加载插件详情失败', request: '操作失败',
    permissionDenied: '当前账号没有管理插件的权限', notFound: '找不到这个插件，或它不属于当前账号',
    revisionConflict: '内容已被其他人修改，请刷新后再保存', idempotencyConflict: '这次提交和之前的请求冲突，请刷新后重新操作',
    scopeApproval: '平台还没有批准这个插件需要的权限', manifestInvalid: '插件的签名校验没有通过',
    versionIncompatible: '这个插件版本不支持当前主控版本', licenseUnavailable: '暂时连不上授权服务，请稍后再试',
    resultUnknown: '不确定操作是否成功', invalidResponse: '服务器返回的数据格式不对',
    platformPaused: '平台已暂停这个插件，不能在这里恢复，请联系平台',
    activationResponseInvalid: '授权响应校验未通过，尚未完成，请重试；持续失败请提供请求编号联系平台',
    platformManaged: '这个插件由主控管理员统一管理，租户这里不能安装或修改',
    targetsInvalid: '请选择装给哪些租户：全部租户，或至少选一个租户',
  },
  pause: {
    title: '当前状态',
    checking: '正在确认暂停状态', readFailed: '暂停已提交，当前原因暂时无法读取',
    own: '你已暂停这个插件', ownReason: '你已暂停这个插件，原因：{{reason}}',
    operator: '平台运营已暂停这个插件，原因：{{reason}}。需要由平台处理，联系平台恢复后会自动生效。',
    service: '插件市场已暂停这个插件（下架或安全公告），原因：{{reason}}。需要由平台处理，联系平台恢复后会自动生效。',
    unknown: '平台已暂停这个插件，需要由平台处理，联系平台恢复后会自动生效。',
    noReason: '未注明',
  },
  detail: {
    title: '插件详情', plugin: '插件', version: '版本', status: '状态', revision: '状态版本号',
    installation: '主控编号', verification: '签名校验记录 ID', manifestDigest: '插件清单指纹（SHA-256）', schemaDigest: '配置格式指纹（SHA-256）',
    scopes: '插件申请的权限', approved: '已同意的权限', sensitive: '需要特别确认的权限', added: '本次新增的权限',
    generation: '访问凭据版本', lkg: '可回退版本', compatibility: '版本兼容', reason: '状态说明', updated: '更新时间',
    diagnostics: '诊断信息（联系平台时提供）',
  },
  settingsTab: { overview: '概览', settings: '设置' },
  compatibility: {
    verified: '平台已校验签名，和当前主控版本兼容', pending: '安装后确认',
    incompatible: '当前主控版本不在插件支持的范围内',
  },
  reasons: {
    none: '无', plugin_installation_version_incompatible: '插件版本不支持当前主控',
    control_api_incompatible: '插件要求的主控版本不符', manifest_unverified: '插件清单还没有通过校验',
    catalog_sequence_invalid: '插件目录版本校验失败', publisher_proof_invalid: '发布者签名校验失败',
    configuration_schema_unverified: '插件的配置格式还没有通过校验', scope_approval_required: '平台还没有批准所需权限',
    execution_mode_invalid: '不支持这种插件运行方式', upgrade_apply_failed: '升级没有成功，仍在使用旧版本',
    other: '服务器返回了未知的状态说明',
  },
  operation: {
    confirmed: '{{action}}已完成，当前状态：{{status}}',
    actions: { confirm: '安装', upgrade: '升级', disable: '暂停', resume: '恢复使用', uninstall: '卸载' },
  },
  consent: {
    installTitle: '安装插件', upgradeTitle: '升级插件', exact: '插件只能使用下面勾选的权限，没勾选的一律不给。',
    sensitive: '我已了解这些权限可以读取或修改重要数据', added: '我同意新版本新增的权限', sensitiveHelp: '这些权限涉及重要数据，需要单独确认。', addedHelp: '新版本多要的权限不会自动沿用之前的同意。',
    firstInstall: '我已确认本次安装所需的权限', firstInstallHelp: '首次安装需要你确认插件要用的每一项权限。',
  },
  scopePurpose: {
    platform_themes_provide: '提供主题', security_rule_packs_provide: '提供 WAF 规则包',
    dns_records_manage: '改你自己 DNS 账号下的解析记录（增改删、分线路）。插件拿不到 DNS 账号密钥，每次修改都记入操作日志，暂停或卸载插件即停止',
    probes_dnspup_request: '发起拨测：用平台「拨测（dnspup）」插件的凭据与额度测你指定的公网目标（tcping/ping/http/https/dns），按插件与租户限速计量，结果只回给本插件；插件拿不到 dnspup Key',
  },
  protective: { disableTitle: '暂停插件', disableEffect: '暂停后插件运行身份立即作废，用到它的页面和功能在本主控停止工作；授权和安装记录保留，可以随时恢复使用。', uninstallTitle: '卸载插件', reason: '原因', reasonPlaceholder: '写一下为什么要这样操作，会记入操作日志', reasonRequired: '请填写 1 到 500 个字的原因' },
  lkg: { preserved: '升级没有成功，仍在使用版本 {{version}}', none: '无' },
  unknown: { title: '不确定操作是否成功', description: '可以原样重新提交，或者刷新看看最新状态再决定。放弃只丢弃本页的重试入口，不会撤销已经提交给服务端的操作。',
    resumeTitle: '不确定恢复使用是否完成', resumeDescription: '插件可能已经恢复。点“重新恢复”会原样再提交这次恢复，不会重复恢复，也不需要重新购买或卸载。放弃只丢弃本页的重试入口，不会撤销已经提交给服务端的操作。',
    blocking: '{{plugin}} 的“{{action}}”还没有确认结果。先重新提交或放弃它，再进行其他插件的安装、升级、暂停、恢复或卸载。' },
  pagination: { label: '插件分页', previous: '上一页', next: '下一页', page: '第 {{page}} 页' },
  accessibility: { loading: '正在加载插件列表' },
  platform: {
    subtitle: '在插件商店获取或购买的插件都在这里由你确认安装：主题和规则包装到本主控，页面插件和外部服务选择装给哪些租户。租户不需要也不能确认。',
    emptyTitle: '暂无需要安装的插件', emptyDescription: '功能类插件获取后自动生效，不在这里；主题、规则包、页面插件、外部服务获取后，等待确认的会显示在这里。',
    forbiddenTitle: '当前账号不能管理平台插件', forbiddenDescription: '需要主控管理员的“平台插件安装”权限。',
    pendingHint: '已获取使用权，等你核对权限并确认安装到本主控。',
    pendingTenantHint: '已获取使用权，核对权限并选择装给哪些租户，确认后这些租户直接可用。',
    installed: '已安装到本主控。到对应页面启用后才会生效。', goRulePacks: '去规则包',
    installedTenant: '已安装，下列租户可以直接使用。', managedByPlatform: '由主控管理员管理',
    groups: { label: '按处理阶段筛选', all: '全部', pending: '待确认', installed: '已安装', failed: '失败' },
  },
  targets: {
    title: '装给哪些租户', all: '全部租户（包括以后新建的租户）', selected: '指定租户',
    searchPlaceholder: '输入用户名或用户 ID 搜索租户', searching: '正在搜索租户', none: '没有匹配的租户',
    required: '至少选择一个租户', summaryAll: '全部租户', summaryCount: '{{count}} 个租户',
    edit: '修改租户', save: '保存', saved: '已更新装给的租户', removedHint: '被移出的租户会立即看不到这个插件，已为插件签发的身份同时失效。',
    unnamed: '已删除的租户', noUserPermission: '当前账号没有查看用户的权限，无法按名称搜索租户，只能选择全部租户。',
  },
  uiPage: {
    title: '插件将添加的页面', loading: '正在从插件市场核对页面声明',
    notice: '启用后，下列页面会以隔离框架从 {{origin}} 加载，插件读不到你的登录凭据。',
    origin: '页面来源', api: '插件后端', none: '这个版本不添加页面',
    menuItem: '{{title}}（{{mount}}）', mount: { menu: '菜单', site_tab: '网站详情页签', plugin_settings: '插件详情的设置页' },
    roles: { admin: '平台管理员', user: '租户用户' },
    mismatch: '插件市场里的 {{version}} 版本和待安装的签名清单对不上，无法展示页面声明，请先联系平台核实。',
    unavailable: '暂时无法从插件市场读取页面声明，确认前请向平台核实这个插件会添加哪些页面。',
  },
  signingKey: {
    title: '安装签名公钥', help: '带页面插件的后端用这把公钥校验主控转发的请求（X-Cdnca-Plugin-Signature），把它交给插件开发者配置即可。这是公钥，可以公开。',
    keyId: '密钥 ID', publicKey: '公钥（Ed25519，base64url）', domain: '签名域', installation: '主控编号',
    unavailable: '本主控还没有配置安装密钥，带页面插件的后端接口暂不可用。', load: '读取安装签名公钥失败',
  },
  identityKey: {
    title: '为插件签发 Key', help: '签发一把绑定这个插件的 API Key，交给插件后端调用开放接口（例如写你自己 DNS 账号下的记录）。插件的每次修改都会记入操作日志，写请求按插件限频；暂停或卸载插件后这把 Key 立即失效，也可以在 API 密钥页随时删除。',
    scopes: '这把 Key 的权限：{{scopes}}', noScopes: '这个插件获准的权限你都没有，或都不能交给 API Key，无法签发。',
    issue: '签发 Key', keyName: '插件 {{plugin}}', failed: '签发失败，请稍后重试',
    unavailable: '插件未在运行，不能签发 Key。请先恢复使用这个插件。',
    secretTitle: '插件 Key 已签发', secretWarning: '完整 Key 只显示这一次，关闭后无法再查看。请现在复制并配置到插件后端。',
    secretLabel: '插件 Key', header: '插件后端请求头：Authorization: CdncaKey <这把 Key>', copy: '复制', saved: '我已保存',
  },
  authorization: {
    title: '插件授权', help: '在插件页面点「授权」后，主控会自动签发只属于本租户、只能由该插件使用的插件身份，直接交给插件，无需创建或粘贴 API Key。撤销后插件立即无法再访问。',
    none: '未授权：打开插件页面点「授权」即可开始使用。', by: '授权人', at: '授权时间', scopes: '插件获得的权限',
    revoke: '撤销授权', revokeConfirm: '撤销后插件立即无法再以本租户身份读取网站或修改 DNS，已做的修改不会回滚。确定撤销？',
    revoked: '已撤销授权', failed: '操作失败，请稍后重试', heldByOther: '这个授权由其他成员授予，需要插件管理权限才能撤销。',
    load: '读取插件授权失败',
  },
} as const

const enUS = {
  title: 'Plugin marketplace', subtitle: 'Plugins the controller administrator installed for this tenant are here and ready to use; you do not confirm them. Plugins run on their developers\' services; the controller only grants access and pushes events.',
  actions: {
    search: 'Search', reset: 'Reset', refresh: 'Refresh', retry: 'Retry', view: 'View details',
    confirm: 'Confirm installation', upgrade: 'Revalidate upgrade', disable: 'Pause', resume: 'Resume', uninstall: 'Uninstall',
    confirmInstall: 'Confirm installation', confirmUpgrade: 'Confirm upgrade', confirmDisable: 'Confirm pause', confirmUninstall: 'Confirm uninstall',
    cancel: 'Cancel', retrySame: 'Retry the same request', retryResume: 'Resume again', refreshAbandon: 'Abandon this attempt and refresh',
    refreshState: 'Refresh state', clearFilters: 'Clear filters',
  },
  filters: { plugin: 'Plugin ID', pluginPlaceholder: 'Search plugin ID', status: 'Status', all: 'All statuses' },
  columns: { plugin: 'Plugin', version: 'Version', status: 'Status', scopes: 'Scopes', lkg: 'Last known good', updated: 'Updated', actions: 'Actions' },
  states: {
    pending_confirmation: 'Pending confirmation', authorized: 'Authorized', installing: 'Installing', enabled: 'Enabled',
    disabled: 'Paused', upgrade_failed_lkg_preserved: 'Upgrade failed, LKG preserved', uninstalled: 'Uninstalled',
    platformPaused: 'Paused by platform', upgradeAvailable: 'Upgrade to {{version}} available',
    awaitingController: 'Purchased, awaiting your confirmation',
  },
  empty: { title: 'No plugin installations', description: 'Plugins the controller administrator installs for this tenant appear here.',
    noMatch: 'No matching plugins', status: 'No plugins in "{{status}}"',
    group: { all: 'No plugins obtained yet', pending: 'No plugins awaiting confirmation', installed: 'No installed plugins', failed: 'No failed plugins' } },
  forbidden: { title: 'Forbidden', description: 'This customer identity cannot read plugin installations.' },
  errors: {
    load: 'Failed to load plugin installations', detail: 'Failed to load plugin details', request: 'Action failed',
    permissionDenied: 'Plugin installation management permission is required', notFound: 'The authorization does not exist in this customer scope',
    revisionConflict: 'Someone else changed this content. Refresh before saving.', idempotencyConflict: 'The idempotency key belongs to another request',
    scopeApproval: 'Capability approval is missing or expired', manifestInvalid: 'Plugin manifest verification failed',
    versionIncompatible: 'The plugin version is incompatible with this control plane', licenseUnavailable: 'The license service is unavailable',
    resultUnknown: 'The write result is unknown', invalidResponse: 'The server response violates the versioned contract',
    platformPaused: 'The platform paused this plugin; it cannot be resumed here. Contact the platform.',
    activationResponseInvalid: 'The license response failed verification, so nothing changed. Try again; if it keeps failing, contact the platform with the request ID.',
    platformManaged: 'The controller administrator manages this plugin; it cannot be installed or changed from a tenant',
    targetsInvalid: 'Choose the tenants: all tenants, or at least one tenant',
  },
  pause: {
    title: 'Current state',
    checking: 'Confirming who paused this plugin', readFailed: 'The pause was submitted; its current reason cannot be read right now',
    own: 'You paused this plugin', ownReason: 'You paused this plugin. Reason: {{reason}}',
    operator: 'The platform operator paused this plugin. Reason: {{reason}}. The platform has to resume it; it takes effect here automatically.',
    service: 'The plugin market paused this plugin (delisting or security advisory). Reason: {{reason}}. The platform has to resume it; it takes effect here automatically.',
    unknown: 'The platform paused this plugin. The platform has to resume it; it takes effect here automatically.',
    noReason: 'not given',
  },
  detail: {
    title: 'Plugin installation details', plugin: 'Plugin ID', version: 'Target version', status: 'Status', revision: 'Revision',
    installation: 'Control installation ID', verification: 'Verification', manifestDigest: 'Manifest digest', schemaDigest: 'Configuration schema digest',
    scopes: 'Declared scopes', approved: 'Approved scopes', sensitive: 'Sensitive scopes', added: 'New scopes',
    generation: 'Identity generation', lkg: 'Last known good', compatibility: 'Version compatibility', reason: 'Stable reason', updated: 'Updated',
    diagnostics: 'Diagnostics (give these to the platform)',
  },
  settingsTab: { overview: 'Overview', settings: 'Settings' },
  compatibility: {
    verified: 'Verified by the signed catalog and control service', pending: 'Pending installation authorization',
    incompatible: 'This control plane is outside the plugin signed compatibility range',
  },
  reasons: {
    none: 'None', plugin_installation_version_incompatible: 'The plugin version is incompatible with this control plane',
    control_api_incompatible: 'The declared control API range is incompatible', manifest_unverified: 'The plugin manifest is not verified',
    catalog_sequence_invalid: 'Catalog sequence verification failed', publisher_proof_invalid: 'Publisher proof verification failed',
    configuration_schema_unverified: 'The configuration schema is not verified', scope_approval_required: 'Scope approval is incomplete',
    execution_mode_invalid: 'The plugin execution mode is unsupported', upgrade_apply_failed: 'Upgrade failed and the last known good version was preserved',
    other: 'The server returned an unrecognized stable reason',
  },
  operation: {
    confirmed: '{{action}} was confirmed by the server. Status: {{status}}. Revision: {{revision}}',
    actions: { confirm: 'Installation confirmation', upgrade: 'Upgrade', disable: 'Pause', resume: 'Resume', uninstall: 'Uninstall' },
  },
  consent: {
    installTitle: 'Confirm plugin installation scopes', upgradeTitle: 'Confirm plugin upgrade scopes', exact: 'Only the listed manifest scopes will be approved. Undeclared scopes remain denied.',
    sensitive: 'Confirm sensitive permissions', added: 'Confirm new permissions', sensitiveHelp: 'Sensitive permissions require separate consent.', addedHelp: 'New upgrade permissions never inherit earlier consent.',
    firstInstall: 'I confirm the permissions this installation needs', firstInstallHelp: 'A first installation asks you to confirm each permission the plugin uses.',
  },
  scopePurpose: {
    platform_themes_provide: 'Provide themes', security_rule_packs_provide: 'Provide WAF rule packs',
    dns_records_manage: 'Change records in your own DNS accounts (create, update, delete, per-line). The plugin never sees the DNS account credentials; every change is logged, and pausing or uninstalling the plugin stops it',
    probes_dnspup_request: 'Run probes: probe the public targets you choose (tcping / ping / http / https / dns) with the platform 拨测（dnspup）plugin\'s key pair and quota, rate-limited and metered per plugin and tenant; results go back to this plugin only, which never sees the dnspup key',
  },
  protective: { disableTitle: 'Pause plugin', disableEffect: 'The plugin\'s runtime identity is revoked at once and the pages and functions that use it stop working on this controller. The authorization and the installation record are kept; you can resume it at any time.', uninstallTitle: 'Uninstall plugin', reason: 'Action reason', reasonPlaceholder: 'Enter an auditable reason', reasonRequired: 'Enter a reason between 1 and 500 characters' },
  lkg: { preserved: 'Last known good version {{version}} is preserved', none: 'None' },
  unknown: { title: 'The write result is unknown', description: 'Retry the exact request, or refresh server state before deciding. Abandoning only drops the retry entry on this page; it does not undo what was already sent to the server.',
    resumeTitle: 'Resume may not have finished', resumeDescription: 'The plugin may already be running again. Resume again sends this same resume once more; it does not resume twice and needs no new purchase or uninstall. Abandoning only drops the retry entry on this page; it does not undo what was already sent to the server.',
    blocking: 'The {{action}} of {{plugin}} has no confirmed result yet. Retry or abandon it before installing, upgrading, pausing, resuming or uninstalling other plugins.' },
  pagination: { label: 'Plugin installation pagination', previous: 'Previous', next: 'Next', page: 'Page {{page}}' },
  accessibility: { loading: 'Loading plugin installations' },
  platform: {
    subtitle: 'Plugins you get or buy in the plugin store are confirmed here: themes and rule packs install on this controller, UI page plugins and external services for the tenants you choose. Tenants neither need nor can confirm them.',
    emptyTitle: 'No plugins to install', emptyDescription: 'Feature plugins take effect once obtained and are not listed here; themes, rule packs, UI page plugins and external services you get appear here while they wait for confirmation.',
    forbiddenTitle: 'This account cannot manage platform plugins', forbiddenDescription: 'It needs the controller administrator permission for platform plugin installations.',
    pendingHint: 'Licensed. Review the permissions and confirm installation on this controller.',
    pendingTenantHint: 'Licensed. Review the permissions and choose the tenants; once confirmed those tenants can use it directly.',
    installed: 'Installed on this controller. It takes effect once enabled on its page.', goRulePacks: 'Go to rule packs',
    installedTenant: 'Installed. The tenants below can use it directly.', managedByPlatform: 'Managed by the controller administrator',
    groups: { label: 'Filter by stage', all: 'All', pending: 'Pending', installed: 'Installed', failed: 'Failed' },
  },
  targets: {
    title: 'Install for which tenants', all: 'All tenants (including tenants created later)', selected: 'Chosen tenants',
    searchPlaceholder: 'Search tenants by username or user ID', searching: 'Searching tenants', none: 'No matching tenants',
    required: 'Choose at least one tenant', summaryAll: 'All tenants', summaryCount: '{{count}} tenants',
    edit: 'Change tenants', save: 'Save', saved: 'Tenants updated', removedHint: 'Tenants you remove stop seeing this plugin at once, and identities issued to the plugin for them stop working.',
    unnamed: 'Deleted tenant', noUserPermission: 'This account cannot read users, so tenants cannot be searched by name; only all tenants can be chosen.',
  },
  uiPage: {
    title: 'Pages this plugin adds', loading: 'Checking the page declaration with the plugin market',
    notice: 'Once enabled, these pages load from {{origin}} in an isolated frame; the plugin cannot read your sign-in credentials.',
    origin: 'Page origin', api: 'Plugin backend', none: 'This version adds no pages',
    menuItem: '{{title}} ({{mount}})', mount: { menu: 'menu', site_tab: 'site detail tab', plugin_settings: 'settings in the plugin detail' },
    roles: { admin: 'platform administrators', user: 'tenant users' },
    mismatch: 'Version {{version}} in the plugin market does not match the signed manifest being installed; ask the platform before confirming.',
    unavailable: 'The plugin market page declaration is unavailable; ask the platform which pages this plugin adds before confirming.',
  },
  signingKey: {
    title: 'Installation signing key', help: 'A ui_page plugin backend verifies calls this control plane forwards (X-Cdnca-Plugin-Signature) with this public key; give it to the plugin developer. It is public.',
    keyId: 'Key ID', publicKey: 'Public key (Ed25519, base64url)', domain: 'Signature domain', installation: 'Control installation ID',
    unavailable: 'This control plane has no installation key configured; ui_page plugin backends are unavailable.', load: 'Failed to load the installation signing key',
  },
  identityKey: {
    title: 'Issue a key for this plugin', help: 'Issue an API key bound to this plugin for its backend to call the open API (for example, to write records in your own DNS account). Every change it makes is recorded in the operation log and its writes are rate limited; pausing or uninstalling the plugin revokes the key at once, and you can delete it on the API keys page at any time.',
    scopes: 'Permissions of this key: {{scopes}}', noScopes: 'You hold none of the permissions approved for this plugin that an API key may carry, so no key can be issued.',
    issue: 'Issue key', keyName: 'Plugin {{plugin}}', failed: 'Could not issue the key; try again later',
    unavailable: 'The plugin is not running, so no key can be issued. Resume the plugin first.',
    secretTitle: 'Plugin key issued', secretWarning: 'The full key is shown only once. Copy it now and configure it in the plugin backend.',
    secretLabel: 'Plugin key', header: 'Plugin backend request header: Authorization: CdncaKey <this key>', copy: 'Copy', saved: 'I saved it',
  },
  authorization: {
    title: 'Plugin authorization', help: 'When you click "Authorize" on the plugin page, the control plane issues a plugin identity for this tenant that only this plugin can use and hands it to the plugin: no API key to create or paste. Once revoked, the plugin loses access at once.',
    none: 'Not authorized: open the plugin page and click "Authorize" to start.', by: 'Authorized by', at: 'Authorized at', scopes: 'Permissions the plugin has',
    revoke: 'Revoke authorization', revokeConfirm: 'Once revoked, the plugin can no longer read your sites or change DNS as this tenant. Changes it already made are not rolled back. Revoke?',
    revoked: 'Authorization revoked', failed: 'The operation failed; try again later', heldByOther: 'Another member granted this authorization; revoking it needs plugin management permission.',
    load: 'Failed to load the plugin authorization',
  },
} satisfies MessageShape<typeof zhCN>

function pseudoText(value: string): string {
  const expanded = value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{') && part.endsWith('}}')
    ? part
    : [...part].map((character) => (/\s/u.test(character) ? character : `${character}~`)).join('')).join('')
  return `［${expanded}］`
}

function pseudoTree(tree: PluginInstallationsMessageTree): PluginInstallationsMessageTree {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key, typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
  ]))
}

const pseudo = pseudoTree(zhCN)
export const pluginInstallationsMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', PluginInstallationsMessageTree> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo, 'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(pluginInstallationsMessages)) {
  i18n.addResourceBundle(locale, 'pluginInstallations', messages, true, true)
}
