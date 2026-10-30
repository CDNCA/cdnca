import i18n from './index'

const zhCN = {
  admin: {
    title: '域名安全',
    subtitle: '域名黑名单拦截新增站点和别名；已存在的命中站点在“命中站点”里一键停用。所有权验证与认领记录供申诉处理。',
    tabs: { blocklist: '域名黑名单', hits: '命中站点', ownerships: '所有权验证', suspensions: '认领停用' },
  },
  blocklist: {
    pattern: '域名', matchType: '匹配方式', reason: '原因（仅管理员可见）', updatedAt: '更新时间', actions: '操作',
    root: '根域名（含全部子域）', exact: '具体域名', add: '添加', edit: '编辑', delete: '删除', deleteConfirm: '删除后该域名可再被添加，确定删除？',
    search: '搜索域名', import: '批量导入', export: '导出', importTitle: '批量导入黑名单',
    importHint: '每行一条：域名[,root|exact[,原因]]，# 开头为注释。已存在的域名会被更新。',
    patternPlaceholder: '例如 example.com', importPlaceholder: 'example.com\nwww.example.net,exact,钓鱼',
    imported: '已导入：新增 {{created}} 条，更新 {{updated}} 条', saved: '已保存', deleted: '已删除', save: '保存', cancel: '取消',
  },
  hits: {
    hint: '以下站点的域名被黑名单覆盖。停用走站点批量停用，会下发到节点并写审计。',
    site: '站点', domain: '命中域名', pattern: '黑名单规则', status: '状态', enabled: '已启用', disabled: '已停用',
    disable: '一键停用所选', disabled_count: '已停用 {{count}} 个站点', failed_count: '{{count}} 个站点停用失败', none: '没有命中的站点',
  },
  ownership: {
    apex: '根域名', method: '验证方式', status: '状态', verifiedAt: '验证时间', scope: '账户范围',
    revoke: '撤销验证', revokeConfirm: '撤销后对方需重新验证才能继续保护该根域名，确定撤销？', revoked: '已撤销',
    filterStatus: '按状态筛选', all: '全部',
  },
  suspension: {
    domain: '被认领域名', site: '被停用站点', claimant: '认领账户范围', createdAt: '认领时间', releasedAt: '释放时间', reason: '释放原因',
    release: '申诉通过，释放', releaseConfirm: '释放后被停用的站点可由其所有者重新启用。认领方仍在使用该域名时无法释放。',
    released: '已释放', includeReleased: '显示已释放', domain_removed: '对方已删除该域名', admin_released: '管理员释放',
  },
  methods: { dns_txt: 'DNS TXT 记录', http_file: 'HTTP 文件' },
  statuses: { pending: '待验证', verified: '已验证', expired: '已失效', revoked: '已撤销' },
  user: {
    title: '已验证域名',
    subtitle: '验证根域名所有权后长期有效（仅管理员可撤销），其他账户不能再添加该根域名下的任何域名；他人已先添加的同名站点可以认领，对方站点会被自动停用。',
    add: '验证新域名', domain: '域名', domainPlaceholder: '例如 example.com 或 www.example.com', start: '获取验证信息',
    txtStep: '在域名的 DNS 中添加以下 TXT 记录，生效后点“立即检查”：', httpStep: '在网站根目录放置以下文件，内容为验证码：',
    recordName: '主机记录', recordValue: '记录值', fileURL: '文件地址', fileContent: '文件内容',
    check: '立即检查', checking: '检查中', verified: '验证成功', notYet: '还未检测到：{{reason}}',
    switchHTTP: '改用 HTTP 文件验证', switchTXT: '改用 DNS TXT 验证', revoke: '撤销', revokeConfirm: '撤销后其他账户可以验证并认领该根域名，确定撤销？',
    conflicts: '冲突站点', conflictsHint: '以下域名仍在其他账户的站点上。认领后这些站点会被自动停用并通知对方。', claim: '认领所选域名', claimed: '认领完成，已停用 {{count}} 个站点',
    claimNeedsTXT: '认领需要 DNS TXT 验证，请改用 TXT 方式重新验证', noConflicts: '没有冲突站点',
    suspensionsTitle: '被认领停用的站点', suspensionsHint: '这些站点的域名已被验证所有权的账户认领。删除该域名后可重新启用站点；如有异议请联系管理员申诉。',
    failures: { txt_not_found: '没有找到匹配的 TXT 记录', txt_quorum_pending: 'TXT 记录尚未在多数公共解析器生效', resolver_unavailable: '公共解析器暂不可用',
      http_unreachable: '无法访问验证文件', http_status: '验证文件返回了非 200 状态', http_mismatch: '验证文件内容不匹配', http_unsafe_address: '域名解析到了不允许访问的地址',
      check_unavailable: '检查暂不可用', verification_failed: '验证失败', superseded_by_dns_txt: '已被其他账户的 DNS TXT 验证取代' },
  },
  siteCreate: {
    ownershipRequired: '添加 {{domain}} 前需要先验证根域名 {{apex}} 的所有权',
    verifiedByOther: '{{domain}} 的根域名所有权已被其他账户验证，无法添加',
    blocked: '域名 {{domain}} 不允许添加',
    goVerify: '去验证所有权',
  },
  errors: {
    forbidden: '需要域名安全管理权限', load: '加载失败：{{code}}', failed: '操作失败：{{code}}',
    domain_blocked: '该域名不允许使用', domain_verified_by_other: '该根域名的所有权已被其他账户验证',
    domain_ownership_disabled: '平台未开启域名所有权验证', domain_ownership_not_verified: '请先完成该根域名的所有权验证',
    domain_claim_requires_dns_txt: '认领需要 DNS TXT 验证', domain_claim_no_conflict: '这些域名没有被其他账户占用',
    domain_claim_still_held: '认领方仍在使用该域名，暂不能释放', domain_blocklist_conflict: '该域名已在黑名单中',
    version_conflict: '数据已被修改，请刷新后重试', validation_error: '输入的域名格式不正确',
  },
}

type MessageShape<T> = { [K in keyof T]: T[K] extends string ? string : MessageShape<T[K]> }
type Messages = MessageShape<typeof zhCN>

const enUS: Messages = {
  admin: {
    title: 'Domain security',
    subtitle: 'The blocklist refuses new sites and aliases; existing sites it covers can be disabled from Hits. Ownership and claim records support appeals.',
    tabs: { blocklist: 'Blocklist', hits: 'Hits', ownerships: 'Ownership', suspensions: 'Claim suspensions' },
  },
  blocklist: {
    pattern: 'Domain', matchType: 'Match', reason: 'Reason (admins only)', updatedAt: 'Updated', actions: 'Actions',
    root: 'Root domain (all subdomains)', exact: 'Exact domain', add: 'Add', edit: 'Edit', delete: 'Delete', deleteConfirm: 'The domain can be added again after deletion. Delete it?',
    search: 'Search domains', import: 'Import', export: 'Export', importTitle: 'Import blocklist',
    importHint: 'One entry per line: domain[,root|exact[,reason]]; lines starting with # are comments. Existing domains are updated.',
    patternPlaceholder: 'e.g. example.com', importPlaceholder: 'example.com\nwww.example.net,exact,phishing',
    imported: 'Imported: {{created}} created, {{updated}} updated', saved: 'Saved', deleted: 'Deleted', save: 'Save', cancel: 'Cancel',
  },
  hits: {
    hint: 'These sites use a blocklisted domain. Disabling uses the site batch action, publishes to nodes and is audited.',
    site: 'Site', domain: 'Domain', pattern: 'Rule', status: 'Status', enabled: 'Enabled', disabled: 'Disabled',
    disable: 'Disable selected', disabled_count: '{{count}} sites disabled', failed_count: '{{count}} sites could not be disabled', none: 'No sites match',
  },
  ownership: {
    apex: 'Root domain', method: 'Method', status: 'Status', verifiedAt: 'Verified', scope: 'Account scope',
    revoke: 'Revoke', revokeConfirm: 'The account must verify again to keep protecting this root domain. Revoke?', revoked: 'Revoked',
    filterStatus: 'Filter by status', all: 'All',
  },
  suspension: {
    domain: 'Claimed domain', site: 'Disabled site', claimant: 'Claimant scope', createdAt: 'Claimed', releasedAt: 'Released', reason: 'Release reason',
    release: 'Uphold appeal and release', releaseConfirm: 'The site owner can re-enable the site afterwards. Not possible while the claimant still serves the domain.',
    released: 'Released', includeReleased: 'Show released', domain_removed: 'Domain removed by its owner', admin_released: 'Released by an administrator',
  },
  methods: { dns_txt: 'DNS TXT record', http_file: 'HTTP file' },
  statuses: { pending: 'Pending', verified: 'Verified', expired: 'Expired', revoked: 'Revoked' },
  user: {
    title: 'Verified domains',
    subtitle: 'A verified root domain stays verified until an administrator revokes it; other accounts cannot add any domain under it. Sites others added first can be claimed; their sites are disabled.',
    add: 'Verify a domain', domain: 'Domain', domainPlaceholder: 'e.g. example.com or www.example.com', start: 'Get verification details',
    txtStep: 'Add this TXT record to the domain DNS, then click Check now:', httpStep: 'Serve this file from the site root with the token as its content:',
    recordName: 'Name', recordValue: 'Value', fileURL: 'File URL', fileContent: 'File content',
    check: 'Check now', checking: 'Checking', verified: 'Verified', notYet: 'Not detected yet: {{reason}}',
    switchHTTP: 'Use an HTTP file instead', switchTXT: 'Use a DNS TXT record instead', revoke: 'Revoke', revokeConfirm: 'Other accounts can then verify and claim this root domain. Revoke?',
    conflicts: 'Conflicting sites', conflictsHint: 'These domains are still on other accounts’ sites. Claiming disables those sites and notifies their owners.', claim: 'Claim selected', claimed: 'Claimed; {{count}} sites disabled',
    claimNeedsTXT: 'Claiming requires DNS TXT verification; verify again with a TXT record', noConflicts: 'No conflicting sites',
    suspensionsTitle: 'Sites disabled by a claim', suspensionsHint: 'A verified owner claimed these domains. Remove the domain to re-enable the site, or contact the administrator to appeal.',
    failures: { txt_not_found: 'No matching TXT record found', txt_quorum_pending: 'The TXT record is not yet visible on most public resolvers', resolver_unavailable: 'Public resolvers are unavailable',
      http_unreachable: 'The verification file is unreachable', http_status: 'The verification file did not return 200', http_mismatch: 'The verification file content does not match', http_unsafe_address: 'The domain resolves to a disallowed address',
      check_unavailable: 'The check is unavailable', verification_failed: 'Verification failed', superseded_by_dns_txt: 'Superseded by another account’s DNS TXT verification' },
  },
  siteCreate: {
    ownershipRequired: 'Verify ownership of {{apex}} before adding {{domain}}',
    verifiedByOther: 'Another account verified the root domain of {{domain}}; it cannot be added',
    blocked: 'The domain {{domain}} is not allowed',
    goVerify: 'Verify ownership',
  },
  errors: {
    forbidden: 'Domain security permission is required', load: 'Load failed: {{code}}', failed: 'Operation failed: {{code}}',
    domain_blocked: 'This domain is not allowed', domain_verified_by_other: 'Another account verified this root domain',
    domain_ownership_disabled: 'Domain ownership verification is turned off', domain_ownership_not_verified: 'Verify ownership of this root domain first',
    domain_claim_requires_dns_txt: 'Claiming requires DNS TXT verification', domain_claim_no_conflict: 'No other account holds these domains',
    domain_claim_still_held: 'The claimant still serves this domain', domain_blocklist_conflict: 'The domain is already listed',
    version_conflict: 'The record changed; refresh and retry', validation_error: 'The domain is not valid',
  },
}

function pseudoTree(value: unknown): unknown {
  if (typeof value === 'string') return `[${value}]`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudo = pseudoTree(zhCN) as Messages

export const domainTrustMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudo,
  'qps-Ploc': pseudo,
}

for (const [locale, messages] of Object.entries(domainTrustMessages)) {
  i18n.addResourceBundle(locale, 'domainTrust', messages, true, true)
}
