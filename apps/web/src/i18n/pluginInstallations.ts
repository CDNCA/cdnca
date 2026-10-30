import i18n from './index'

export type PluginInstallationsMessageTree = { [key: string]: string | PluginInstallationsMessageTree }
type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }

const zhCN = {
  title: '插件市场', subtitle: '平台授权给本主控的插件都在这里。插件运行在你自己的服务里，主控只负责授权和推送事件。',
  actions: {
    search: '查询', reset: '重置', refresh: '刷新', retry: '重试', view: '查看详情',
    confirm: '安装', upgrade: '升级', disable: '暂停', resume: '恢复使用', uninstall: '卸载',
    confirmInstall: '确认安装', confirmUpgrade: '确认升级', confirmDisable: '确认暂停', confirmUninstall: '确认卸载',
    cancel: '取消', retrySame: '重新提交', retryResume: '重新恢复', refreshAbandon: '刷新并放弃本次操作',
  },
  filters: { plugin: '插件', pluginPlaceholder: '按插件名称（ID）搜索', status: '状态', all: '全部状态' },
  columns: { plugin: '插件', version: '版本', status: '状态', scopes: '需要的权限', lkg: '可回退版本', updated: '更新时间', actions: '操作' },
  states: {
    pending_confirmation: '可安装', authorized: '已授权', installing: '安装中', enabled: '运行中',
    disabled: '已暂停', upgrade_failed_lkg_preserved: '升级失败，仍在用旧版本', uninstalled: '已卸载',
    platformPaused: '平台已暂停', upgradeAvailable: '可升级到 {{version}}',
    awaitingController: '已购买，待你确认',
  },
  empty: { title: '还没有可用的插件', description: '平台给本主控授权插件后，会显示在这里。' },
  forbidden: { title: '无权访问', description: '当前账号没有查看插件的权限。' },
  errors: {
    load: '加载插件列表失败', detail: '加载插件详情失败', request: '操作失败',
    permissionDenied: '当前账号没有管理插件的权限', notFound: '找不到这个插件，或它不属于当前账号',
    revisionConflict: '插件状态刚刚变了，请刷新后再试', idempotencyConflict: '这次提交和之前的请求冲突，请刷新后重新操作',
    scopeApproval: '平台还没有批准这个插件需要的权限', manifestInvalid: '插件的签名校验没有通过',
    versionIncompatible: '这个插件版本不支持当前主控版本', licenseUnavailable: '暂时连不上授权服务，请稍后再试',
    resultUnknown: '不确定操作是否成功', invalidResponse: '服务器返回的数据格式不对',
    platformPaused: '平台已暂停这个插件，不能在这里恢复，请联系平台',
  },
  pause: {
    title: '当前状态',
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
  },
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
  },
  protective: { disableTitle: '暂停插件', uninstallTitle: '卸载插件', reason: '原因', reasonPlaceholder: '写一下为什么要这样操作，会记入操作日志', reasonRequired: '请填写 1 到 500 个字的原因' },
  lkg: { preserved: '升级没有成功，仍在使用版本 {{version}}', none: '无' },
  unknown: { title: '不确定操作是否成功', description: '可以原样重新提交，或者刷新看看最新状态再决定。',
    resumeTitle: '不确定恢复使用是否完成', resumeDescription: '插件可能已经恢复。点“重新恢复”会原样再提交这次恢复，不会重复恢复，也不需要重新购买或卸载。' },
  pagination: { label: '插件分页', previous: '上一页', next: '下一页', page: '第 {{page}} 页' },
  accessibility: { loading: '正在加载插件列表' },
  platform: {
    subtitle: '本主控用到的用户控制台主题和规则数据包在这里确认安装。确认后到对应页面启用，普通用户不需要也不能处理这些插件。',
    emptyTitle: '没有需要处理的平台插件', emptyDescription: '在“浏览”里获取主题或规则包后，等待确认的会显示在这里。',
    forbiddenTitle: '当前账号不能管理平台插件', forbiddenDescription: '需要主控管理员的“平台插件安装”权限。',
    pendingHint: '已获取使用权，等你核对权限并确认安装到本主控。',
    installed: '已安装到本主控。到对应页面启用后才会生效。', goRulePacks: '去规则包',
    groups: { label: '按处理阶段筛选', all: '全部', pending: '待确认', installed: '已安装', failed: '失败' },
  },
  uiPage: {
    title: '插件将添加的页面', loading: '正在从插件市场核对页面声明',
    notice: '启用后，下列页面会以隔离框架从 {{origin}} 加载，插件读不到你的登录凭据。',
    origin: '页面来源', api: '插件后端', none: '这个版本不添加页面',
    menuItem: '{{title}}（{{mount}}）', mount: { menu: '菜单', site_tab: '网站详情页签' },
    roles: { admin: '平台管理员', user: '租户用户' },
    mismatch: '插件市场里的 {{version}} 版本和待安装的签名清单对不上，无法展示页面声明，请先联系平台核实。',
    unavailable: '暂时无法从插件市场读取页面声明，确认前请向平台核实这个插件会添加哪些页面。',
  },
  signingKey: {
    title: '安装签名公钥', help: '带页面插件的后端用这把公钥校验主控转发的请求（X-Cdnca-Plugin-Signature），把它交给插件开发者配置即可。这是公钥，可以公开。',
    keyId: '密钥 ID', publicKey: '公钥（Ed25519，base64url）', domain: '签名域', installation: '主控编号',
    unavailable: '本主控还没有配置安装密钥，带页面插件的后端接口暂不可用。', load: '读取安装签名公钥失败',
  },
} as const

const enUS = {
  title: 'Plugin marketplace', subtitle: 'Review and manage out-of-process plugin authorization for this customer installation.',
  actions: {
    search: 'Search', reset: 'Reset', refresh: 'Refresh', retry: 'Retry', view: 'View details',
    confirm: 'Confirm installation', upgrade: 'Revalidate upgrade', disable: 'Pause', resume: 'Resume', uninstall: 'Uninstall',
    confirmInstall: 'Confirm installation', confirmUpgrade: 'Confirm upgrade', confirmDisable: 'Confirm pause', confirmUninstall: 'Confirm uninstall',
    cancel: 'Cancel', retrySame: 'Retry the same request', retryResume: 'Resume again', refreshAbandon: 'Refresh and abandon local attempt',
  },
  filters: { plugin: 'Plugin ID', pluginPlaceholder: 'Search plugin ID', status: 'Status', all: 'All statuses' },
  columns: { plugin: 'Plugin', version: 'Version', status: 'Status', scopes: 'Scopes', lkg: 'Last known good', updated: 'Updated', actions: 'Actions' },
  states: {
    pending_confirmation: 'Pending confirmation', authorized: 'Authorized', installing: 'Installing', enabled: 'Enabled',
    disabled: 'Paused', upgrade_failed_lkg_preserved: 'Upgrade failed, LKG preserved', uninstalled: 'Uninstalled',
    platformPaused: 'Paused by platform', upgradeAvailable: 'Upgrade to {{version}} available',
    awaitingController: 'Purchased, awaiting your confirmation',
  },
  empty: { title: 'No plugin installations', description: 'This customer installation has no manageable plugin authorization.' },
  forbidden: { title: 'Forbidden', description: 'This customer identity cannot read plugin installations.' },
  errors: {
    load: 'Failed to load plugin installations', detail: 'Failed to load plugin details', request: 'Action failed',
    permissionDenied: 'Plugin installation management permission is required', notFound: 'The authorization does not exist in this customer scope',
    revisionConflict: 'The record changed; refresh before retrying', idempotencyConflict: 'The idempotency key belongs to another request',
    scopeApproval: 'Capability approval is missing or expired', manifestInvalid: 'Plugin manifest verification failed',
    versionIncompatible: 'The plugin version is incompatible with this control plane', licenseUnavailable: 'The license service is unavailable',
    resultUnknown: 'The write result is unknown', invalidResponse: 'The server response violates the versioned contract',
    platformPaused: 'The platform paused this plugin; it cannot be resumed here. Contact the platform.',
  },
  pause: {
    title: 'Current state',
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
  },
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
  },
  protective: { disableTitle: 'Pause plugin', uninstallTitle: 'Uninstall plugin', reason: 'Action reason', reasonPlaceholder: 'Enter an auditable reason', reasonRequired: 'Enter a reason between 1 and 500 characters' },
  lkg: { preserved: 'Last known good version {{version}} is preserved', none: 'None' },
  unknown: { title: 'The write result is unknown', description: 'Retry the exact request, or refresh server state before abandoning the local attempt.',
    resumeTitle: 'Resume may not have finished', resumeDescription: 'The plugin may already be running again. Resume again sends this same resume once more; it does not resume twice and needs no new purchase or uninstall.' },
  pagination: { label: 'Plugin installation pagination', previous: 'Previous', next: 'Next', page: 'Page {{page}}' },
  accessibility: { loading: 'Loading plugin installations' },
  platform: {
    subtitle: 'Confirm installation of user console themes and rule data packs for this controller here, then enable them on their pages. Tenant users neither need nor can handle these plugins.',
    emptyTitle: 'No platform plugins to handle', emptyDescription: 'Themes or rule packs you get in Browse appear here while they wait for confirmation.',
    forbiddenTitle: 'This account cannot manage platform plugins', forbiddenDescription: 'It needs the controller administrator permission for platform plugin installations.',
    pendingHint: 'Licensed. Review the permissions and confirm installation on this controller.',
    installed: 'Installed on this controller. It takes effect once enabled on its page.', goRulePacks: 'Go to rule packs',
    groups: { label: 'Filter by stage', all: 'All', pending: 'Pending', installed: 'Installed', failed: 'Failed' },
  },
  uiPage: {
    title: 'Pages this plugin adds', loading: 'Checking the page declaration with the plugin market',
    notice: 'Once enabled, these pages load from {{origin}} in an isolated frame; the plugin cannot read your sign-in credentials.',
    origin: 'Page origin', api: 'Plugin backend', none: 'This version adds no pages',
    menuItem: '{{title}} ({{mount}})', mount: { menu: 'menu', site_tab: 'site detail tab' },
    roles: { admin: 'platform administrators', user: 'tenant users' },
    mismatch: 'Version {{version}} in the plugin market does not match the signed manifest being installed; ask the platform before confirming.',
    unavailable: 'The plugin market page declaration is unavailable; ask the platform which pages this plugin adds before confirming.',
  },
  signingKey: {
    title: 'Installation signing key', help: 'A ui_page plugin backend verifies calls this control plane forwards (X-Cdnca-Plugin-Signature) with this public key; give it to the plugin developer. It is public.',
    keyId: 'Key ID', publicKey: 'Public key (Ed25519, base64url)', domain: 'Signature domain', installation: 'Control installation ID',
    unavailable: 'This control plane has no installation key configured; ui_page plugin backends are unavailable.', load: 'Failed to load the installation signing key',
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
