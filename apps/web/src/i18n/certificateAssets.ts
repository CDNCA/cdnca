import i18n from './index'

const zhCN = {
  assetActions: { upload: '上传证书', add: '添加证书', reapply: '重新申请', more: '更多操作', rowMore: '更多', rowMoreNamed: '{{name}} 的更多操作', download: '下载证书', disable: '禁用', enable: '启用', enableAutoRenew: '开启续签', disableAutoRenew: '关闭续签', advancedSearch: '高级搜索', detail: '查看详情', manage: '管理', filter: '筛选', export: '导出', clearSelection: '清除选择', delete: '删除', activate: '激活版本', bind: '绑定网站', unbind: '解绑', close: '关闭', search: '输入域名,模糊搜索', searchSubmit: '查询', orders: '申请记录', backToList: '返回证书列表' },
  orders: { title: '申请记录', all: '全部证书的自动申请记录', scoped: '证书 {{domains}} 的申请记录' },
  advancedFilters: { domain: '域名', domainPlaceholder: '请输入域名，模糊搜索', multiDomain: '多域名', multiDomainPlaceholder: '一行一个域名，精确搜索', user: '用户', userPlaceholder: '输入ID、邮箱、用户名、手机号搜索', certificateID: '证书ID', certificateIDPlaceholder: '请输入证书ID', name: '名称', namePlaceholder: '请输入证书名称，模糊搜索', remark: '备注', remarkPlaceholder: '请输入证书备注，模糊搜索', type: '证书类型', dnsApi: 'DNS API', selectPlaceholder: '请选择', expiresAt: '到期时间', enabled: '自动续签', issueStatus: '签发状态', syncStatus: '同步状态', unrestricted: '不限', search: '搜索', reset: '重置', collapse: '收起搜索', typeUploaded: '手动上传', typeAcme: '自动申请', expiry30: '30天内到期', expiry90: '90天内到期', expiryExpired: '已过期', enabledOn: '开启', enabledOff: '关闭', issued: '已签发', failed: '签发失败', syncComplete: '当前绑定修订已发布', syncPending: '当前绑定发布中', syncFailed: '当前绑定发布失败', syncUnknown: '发布状态未知' },
  assetColumns: { id: 'ID', tenant: '租户', user: '用户', name: '证书信息', type: '类型', domains: '域名', createdAt: '创建时间', expiresAt: '到期时间', autoRenew: '自动续签', status: '状态', source: '来源', revision: '版本', updatedAt: '更新时间', actions: '操作' },
  assetSources: { uploaded: '手动上传', acme: '自动签发' },
  assetStates: { default: '默认', pending_activation: '待激活', active: '已生效', superseded: '已替换', revoked: '已吊销', expired: '已过期', loading: '读取中', unknown: '状态未知', applying: '申请中', disabled: '已禁用' },
  assetValues: { empty: '暂无证书资产', filteredEmpty: '没有匹配的证书资产', unavailable: '未提供', loading: '读取中', userID: 'ID: {{id}}', autoRenewEnabled: '已开启', autoRenewDisabled: '未开启', legacyOwner: '未指定用户', legacyOwnerHint: '无法确定该证书所属的用户（下单人不是该租户成员，且租户没有唯一的所属用户）', tenant: '{{name}}（租户 {{id}}）', noVersions: '暂无证书版本', noBindings: '暂无网站绑定' },
  target: { label: '目标用户', placeholder: '请选择要管理证书的用户', loading: '正在读取用户', empty: '没有匹配的用户', option: '{{username}}（ID: {{displayID}}）', required: '请选择目标用户后管理此项设置。', fromSite: '按网站所属用户申请', loadFailed: '用户列表加载失败', forbidden: '无权读取用户目录，请联系管理员', noUserPermission: '当前账号没有“用户管理”（identity.users.manage）权限，无法列出用户。请联系管理员授予该权限。' },
  filters: { all: '全部', normal: '正常', expiring: '即将到期', expired: '已过期', autoRenew: '自动续签', manualRenew: '未开启续签' },
  stats: { label: '证书状态统计' },
  export: { fileName: '证书列表.csv' },
  versionColumns: { version: '版本', status: '状态', domains: '域名', notAfter: '到期时间', actions: '操作', acmeOrder: 'ACME 订单', renewal: '续期' },
  bindingColumns: { site: '网站 ID', revision: '绑定版本', default: '默认证书', actions: '操作' },
  renewal: { due: '待续期', notDue: '无需续期' },
  values: { enabled: '开启', disabled: '关闭', none: '—' },
  upload: { title: '上传证书', owner: '归属用户', name: '名称', certificatePem: '证书 PEM', privateKeyPem: '私钥 PEM', nameRequired: '请输入证书名称', nameInvalid: '名称长度或格式无效', certificateRequired: '请输入证书 PEM', privateKeyRequired: '请输入私钥 PEM', privateKeyNotice: '私钥仅用于加密保存，提交后不会再次显示。',
    remark: '备注', remarkPlaceholder: '可选，填写用途或来源', remarkInvalid: '备注最多 256 个字符',
    certificateFile: '上传证书文件', privateKeyFile: '上传私钥文件',
    fileErrors: { tooLarge: '文件超过大小上限（证书 256 KB、私钥 64 KB）', notPEM: '文件不是 PEM 格式，或不含对应的证书/私钥', unreadable: '无法读取该文件' } },
  detail: { title: '证书详情', name: '名称', source: '来源', revision: '资产版本' },
  bind: { title: '绑定网站', site: '网站', siteHint: '证书须覆盖网站的全部域名，否则绑定会被拒绝。', sitePlaceholder: '输入域名搜索网站', siteIDPlaceholder: '输入网站 ID', siteOption: '{{domain}}（ID {{id}}）', siteOptionUncovered: '{{domain}}（ID {{id}}，证书不含此域名）', sitesEmpty: '没有匹配的网站', sitesFailed: '网站列表加载失败', version: '证书版本', default: '设为默认证书', confirm: '确认绑定', siteRequired: '请选择网站', siteInvalid: '网站 ID 格式无效' },
  dnsProvider: { configure: '去配置 DNS API' },
  certOps: {
    downloading: '正在准备下载…', downloaded: '证书已下载（含私钥，请妥善保管）', downloadFailed: '下载失败：{{reason}}',
    downloadRevoked: '当前版本已吊销，无法下载', disabledDone: '证书已禁用', enabledDone: '证书已启用', toggleFailed: '操作失败：{{reason}}',
    boundCannotDisable: '证书仍被网站使用，请先解绑后再禁用', disabledHint: '已禁用的证书不能绑定网站，也不会自动续签',
    bulkDone: '已处理 {{done}} 张证书', bulkPartial: '已处理 {{done}} 张，{{failed}} 张失败：{{reason}}', bulkNone: '所选证书都不适用此操作', bulkDeleteConfirm: '确定删除选中的 {{count}} 张证书？仍被网站使用的证书会删除失败。',
  },
  autoRenew: { label: '自动续签', enabled: '已开启自动续签', disabled: '已关闭自动续签', failed: '自动续签修改失败：{{reason}}', uploaded: '手动上传的证书不能自动续签，到期前请重新上传', noPermission: '当前账号没有修改证书的权限' },
  reapply: { title: '重新申请证书', description: '重新申请 {{name}}（{{domains}}）？将沿用原证书的域名、验证方式、DNS 服务商和自动续期设置。', confirm: '确认重新申请', retryHint: '可直接再次确认重新申请。', submitted: '已提交重新申请', uploadedUnsupported: '手动上传的证书没有申请参数，不能重新申请；请上传新证书，或用“添加证书”申请一张新证书。', inFlight: '该证书已有进行中的申请，请在申请记录查看进度。' },
  stuck: { label: '超过 1 小时未完成', hint: '该申请超过 1 小时仍未完成。系统会继续自动重试，重试用尽或遇到无法恢复的错误后会自动标为失败，之后可重新申请。' },
  delete: { title: '删除证书', confirm: '确认删除', description: '确认删除证书“{{name}}”？仍被网站引用的证书不能删除。' },
  assetUncertainty: { title: '操作结果待确认', description: '只能使用完全相同的证书、私钥、名称、请求 ID 和幂等键重试，或关闭并刷新列表核对。' },
  commandUncertainty: { title: '操作结果待确认', description: '只能使用完全相同的操作、目标、前置版本、请求 ID 和幂等键重试，或关闭并刷新列表核对。' },
  actions: { retry: '重试', retrySameRequest: '使用同一请求重试', cancel: '取消', closeAndRefresh: '关闭并刷新', refresh: '刷新' },
  errors: {
    forbiddenTitle: '无权查看证书资产', permission_denied: '当前账号缺少证书资产权限', assetsLoadFailed: '证书资产加载失败', loadFailed: '证书资产加载失败', request_failed: '请求失败，请稍后重试',
    certificate_asset_owner_required: '请选择证书归属用户', certificate_asset_disabled: '证书已禁用，请先启用', certificate_asset_download_unavailable: '证书没有可下载的有效版本', certificate_asset_invalid_request: '证书字段不符合要求', certificate_asset_invalid_certificate_pem: '证书 PEM 无效', certificate_asset_invalid_private_key_pem: '私钥 PEM 无效', certificate_asset_key_mismatch: '证书与私钥不匹配', certificate_asset_permission_denied: '当前账号缺少证书资产权限', certificate_asset_not_found: '证书资产不存在或无权访问', certificate_asset_revision_conflict: '证书资产已被其他操作修改，请刷新后重试', certificate_asset_idempotency_conflict: '该幂等键已用于不同的证书请求', certificate_asset_referenced: '证书仍被网站引用，不能删除', certificate_asset_invalid_transition: '当前证书状态不允许此操作', certificate_asset_domain_not_covered: '证书不包含网站域名', certificate_asset_envelope_unavailable: '私钥加密服务暂不可用', certificate_asset_internal_error: '证书资产服务暂不可用',
  },
} as const

const enUS = {
  assetActions: { upload: 'Upload certificate', add: 'Add certificate', reapply: 'Reapply', more: 'More actions', rowMore: 'More', rowMoreNamed: 'More actions for {{name}}', download: 'Download certificate', disable: 'Disable', enable: 'Enable', enableAutoRenew: 'Turn on auto-renew', disableAutoRenew: 'Turn off auto-renew', advancedSearch: 'Advanced search', detail: 'View details', manage: 'Manage', filter: 'Filter', export: 'Export', clearSelection: 'Clear selection', delete: 'Delete', activate: 'Activate version', bind: 'Bind site', unbind: 'Unbind', close: 'Close', search: 'Enter a domain, fuzzy search', searchSubmit: 'Search', orders: 'Request history', backToList: 'Back to certificates' },
  orders: { title: 'Request history', all: 'Automatic requests for all certificates', scoped: 'Requests for certificate {{domains}}' },
  advancedFilters: { domain: 'Domain', domainPlaceholder: 'Enter a domain, fuzzy search', multiDomain: 'Multiple domains', multiDomainPlaceholder: 'One domain per line, exact search', user: 'User', userPlaceholder: 'Search by ID, email, username, or phone', certificateID: 'Certificate ID', certificateIDPlaceholder: 'Enter certificate ID', name: 'Name', namePlaceholder: 'Enter certificate name, fuzzy search', remark: 'Remark', remarkPlaceholder: 'Enter certificate remark, fuzzy search', type: 'Certificate type', dnsApi: 'DNS API', selectPlaceholder: 'Select', expiresAt: 'Expires', enabled: 'Auto-renew', issueStatus: 'Issuance status', syncStatus: 'Sync status', unrestricted: 'Any', search: 'Search', reset: 'Reset', collapse: 'Collapse search', typeUploaded: 'Manual upload', typeAcme: 'Automatic issuance', expiry30: 'Expires within 30 days', expiry90: 'Expires within 90 days', expiryExpired: 'Expired', enabledOn: 'On', enabledOff: 'Off', issued: 'Issued', failed: 'Issuance failed', syncComplete: 'Current binding revision published', syncPending: 'Current binding publishing', syncFailed: 'Current binding publication failed', syncUnknown: 'Publication status unknown' },
  assetColumns: { id: 'ID', tenant: 'Tenant', user: 'User', name: 'Certificate', type: 'Type', domains: 'Domains', createdAt: 'Created', expiresAt: 'Expires', autoRenew: 'Auto-renew', status: 'Status', source: 'Source', revision: 'Revision', updatedAt: 'Updated', actions: 'Actions' },
  assetSources: { uploaded: 'Manual upload', acme: 'Automatic issuance' },
  assetStates: { default: 'Default', pending_activation: 'Pending activation', active: 'Active', superseded: 'Superseded', revoked: 'Revoked', expired: 'Expired', loading: 'Loading', unknown: 'Unknown', applying: 'Applying', disabled: 'Disabled' },
  assetValues: { empty: 'No certificate assets', filteredEmpty: 'No matching certificate assets', unavailable: 'Not provided', loading: 'Loading', userID: 'ID: {{id}}', autoRenewEnabled: 'Enabled', autoRenewDisabled: 'Disabled', legacyOwner: 'No user assigned', legacyOwnerHint: 'The certificate owner cannot be determined (the orderer is not a member of this tenant and the tenant has no single owner)', tenant: '{{name}} (tenant {{id}})', noVersions: 'No certificate versions', noBindings: 'No site bindings' },
  target: { label: 'Target user', placeholder: 'Select a user whose certificates you want to manage', loading: 'Loading users', empty: 'No matching users', option: '{{username}} (ID: {{displayID}})', required: 'Select a target user to manage these settings.', fromSite: 'Requested for the site owner', loadFailed: 'Failed to load users', forbidden: 'You cannot read the user directory. Contact an administrator.', noUserPermission: 'This account lacks user management (identity.users.manage), so users cannot be listed. Ask an administrator for it.' },
  filters: { all: 'All', normal: 'Normal', expiring: 'Expiring soon', expired: 'Expired', autoRenew: 'Auto-renew', manualRenew: 'Auto-renew off' },
  stats: { label: 'Certificate status summary' },
  export: { fileName: 'certificates.csv' },
  versionColumns: { version: 'Version', status: 'Status', domains: 'Domains', notAfter: 'Expires', actions: 'Actions', acmeOrder: 'ACME order', renewal: 'Renewal' },
  bindingColumns: { site: 'Site ID', revision: 'Binding revision', default: 'Default certificate', actions: 'Actions' },
  renewal: { due: 'Renewal due', notDue: 'No renewal due' },
  values: { enabled: 'Enabled', disabled: 'Disabled', none: '—' },
  upload: { title: 'Upload certificate', owner: 'Certificate owner', name: 'Name', certificatePem: 'Certificate PEM', privateKeyPem: 'Private key PEM', nameRequired: 'Enter a certificate name', nameInvalid: 'The name length or format is invalid', certificateRequired: 'Enter the certificate PEM', privateKeyRequired: 'Enter the private key PEM', privateKeyNotice: 'The private key is encrypted for storage and is never shown again after submission.',
    remark: 'Remark', remarkPlaceholder: 'Optional: purpose or source', remarkInvalid: 'The remark is at most 256 characters',
    certificateFile: 'Upload certificate file', privateKeyFile: 'Upload private key file',
    fileErrors: { tooLarge: 'The file exceeds the size limit (certificate 256 KB, private key 64 KB)', notPEM: 'The file is not PEM or lacks the expected certificate or private key', unreadable: 'The file cannot be read' } },
  detail: { title: 'Certificate details', name: 'Name', source: 'Source', revision: 'Asset revision' },
  bind: { title: 'Bind site', site: 'Site', siteHint: 'The certificate must cover every domain of the site, or the binding is refused.', sitePlaceholder: 'Search sites by domain', siteIDPlaceholder: 'Enter a site ID', siteOption: '{{domain}} (ID {{id}})', siteOptionUncovered: '{{domain}} (ID {{id}}, not covered by the certificate)', sitesEmpty: 'No matching sites', sitesFailed: 'Failed to load sites', version: 'Certificate version', default: 'Use as default certificate', confirm: 'Confirm binding', siteRequired: 'Select a site', siteInvalid: 'The site ID is invalid' },
  dnsProvider: { configure: 'Configure DNS API' },
  certOps: {
    downloading: 'Preparing download…', downloaded: 'Certificate downloaded (includes the private key; keep it safe)', downloadFailed: 'Download failed: {{reason}}',
    downloadRevoked: 'The current version is revoked and cannot be downloaded', disabledDone: 'Certificate disabled', enabledDone: 'Certificate enabled', toggleFailed: 'Operation failed: {{reason}}',
    boundCannotDisable: 'The certificate is still used by a site; unbind it before disabling', disabledHint: 'Disabled certificates cannot be bound to sites and do not auto-renew',
    bulkDone: '{{done}} certificates updated', bulkPartial: '{{done}} updated, {{failed}} failed: {{reason}}', bulkNone: 'None of the selected certificates apply', bulkDeleteConfirm: 'Delete the {{count}} selected certificates? Certificates still used by a site will fail to delete.',
  },
  autoRenew: { label: 'Auto-renew', enabled: 'Auto-renew turned on', disabled: 'Auto-renew turned off', failed: 'Failed to change auto-renew: {{reason}}', uploaded: 'Uploaded certificates cannot auto-renew; upload a new one before it expires', noPermission: 'Your account cannot change certificates' },
  reapply: { title: 'Reapply certificate', description: 'Reapply {{name}} ({{domains}})? The original domains, validation method, DNS provider and auto-renewal are reused.', confirm: 'Confirm reapply', retryHint: 'You can confirm the reapply again.', submitted: 'Reapply submitted', uploadedUnsupported: 'Manually uploaded certificates have no request settings and cannot be reapplied. Upload a new certificate, or request a new one from Add certificate.', inFlight: 'A request for this certificate is already in progress. See request history.' },
  stuck: { label: 'Not finished after 1 hour', hint: 'This request has not finished after an hour. It keeps retrying automatically and is marked failed once retries run out or an unrecoverable error occurs; you can then reapply.' },
  delete: { title: 'Delete certificate', confirm: 'Confirm deletion', description: 'Delete certificate “{{name}}”? Certificates still referenced by sites cannot be deleted.' },
  assetUncertainty: { title: 'Operation outcome unknown', description: 'Retry only with the exact certificate, private key, name, request ID, and idempotency key, or close and refresh the list.' },
  commandUncertainty: { title: 'Operation outcome unknown', description: 'Retry only with the exact operation, target, expected revision, request ID, and idempotency key, or close and refresh the list.' },
  actions: { retry: 'Retry', retrySameRequest: 'Retry the same request', cancel: 'Cancel', closeAndRefresh: 'Close and refresh', refresh: 'Refresh' },
  errors: {
    forbiddenTitle: 'Certificate assets unavailable', permission_denied: 'Your account cannot access certificate assets', assetsLoadFailed: 'Failed to load certificate assets', loadFailed: 'Failed to load certificate assets', request_failed: 'The request failed. Try again later.',
    certificate_asset_owner_required: 'Select the certificate owner', certificate_asset_disabled: 'The certificate is disabled; enable it first', certificate_asset_download_unavailable: 'The certificate has no downloadable version', certificate_asset_invalid_request: 'The certificate fields are invalid', certificate_asset_invalid_certificate_pem: 'The certificate PEM is invalid', certificate_asset_invalid_private_key_pem: 'The private key PEM is invalid', certificate_asset_key_mismatch: 'The certificate does not match the private key', certificate_asset_permission_denied: 'Your account cannot access certificate assets', certificate_asset_not_found: 'The certificate asset does not exist or is not accessible', certificate_asset_revision_conflict: 'Another operation modified the certificate asset. Refresh and try again.', certificate_asset_idempotency_conflict: 'This idempotency key was used for a different certificate request', certificate_asset_referenced: 'The certificate is still referenced by a site and cannot be deleted', certificate_asset_invalid_transition: 'The certificate state does not allow this operation', certificate_asset_domain_not_covered: 'The certificate does not cover the site domain', certificate_asset_envelope_unavailable: 'Private key encryption is unavailable', certificate_asset_internal_error: 'The certificate asset service is unavailable',
  },
} as const

type CertificateAssetsMessages = { [key: string]: string | CertificateAssetsMessages }
function pseudoText(value: string): string {
  return `［${value.split(/({{[^}]+}})/g).map((part) => part.startsWith('{{') ? part : [...part].map((char) => /\s/u.test(char) ? char : `${char}~`).join('')).join('')}］`
}
function pseudoTree(value: unknown): unknown {
  return typeof value === 'string' ? pseudoText(value) : Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudoTree(child)]))
}

const pseudoCN = pseudoTree(zhCN) as CertificateAssetsMessages
export const certificateAssetsMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', CertificateAssetsMessages> = {
  'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudoCN, 'qps-Ploc': pseudoCN,
}
for (const [locale, messages] of Object.entries(certificateAssetsMessages)) i18n.addResourceBundle(locale, 'certificateAssets', messages, true, true)
