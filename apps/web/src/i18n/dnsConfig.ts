import i18n from './index'

const zhCN = {
  title: 'DNS配置',
  tabs: { config: 'DNS配置', cname: 'CNAME域名' },
  installationOnly: {
    description: 'DNS配置是平台安装级设置，只有平台管理员可以查看和修改。你自己的域名解析账号在“我的 DNS API”里管理。',
    ownDnsApi: '前往我的 DNS API', home: '返回概览',
  },
  fields: {
    provider: 'DNS提供商', ttl: 'TTL', ipWeight: '开启IP权重', dnsError: 'DNS错误', region: '区域', projectID: '项目ID',
    dnsComPlan: '套餐档位',
  },
  dnsComPlans: { free: '免费版', enterprise: '企业版', flagship: '旗舰版' },
  placeholders: { enter: '请输入{{label}}', secretKept: '已保存，不修改请留空', ttl: '请输入TTL' },
  providers: {
    aliyun: '阿里云 (aliyun.com, alibabacloud.com)', huawei: '华为云 (huaweicloud.com)', dns_la: 'DNSLA (dns.la)',
    dnspod_cn: 'DNSPod (dnspod.cn)', dnspod_intl: 'DNSPod国际版 (dnspod.com)', dns_com: '帝恩思 (51dns.com)',
    cloudflare: 'Cloudflare (cloudflare.com)', namecom: 'Name.com (name.com)', custom_http: '自定义 HTTP 接口',
    plugin: '第三方插件 {{id}}（v{{version}}）',
  },
  groups: { official: '官方', thirdParty: '第三方插件（已通过契约测试）' },
  units: { seconds: '秒' },
  actions: {
    save: '保存配置', test: '连接测试', repair: '记录修复', cleanup: '清除CDN无关解析', retry: '重试',
    addZone: '新增域名', delete: '删除', edit: '编辑', ok: '确定', cancel: '取消',
  },
  hints: {
    readOnly: '当前账号没有 DNS 写权限。',
    loading: '正在读取当前 DNS 配置，读取完成前不能修改。',
    dnspodIntl: 'DNSPod国际版已迁移到腾讯云国际站 API 3.0（SecretId/SecretKey 签名），暂未接入，请选择其他服务商。',
    cloudflareToken: '填写 Cloudflare API Token（需要 Zone.DNS 编辑权限），不支持 Global API Key。',
    nameComToken: '填写 name.com 账号用户名和 API Token（账号设置 > API 中生成）。name.com 记录 TTL 最低 300 秒，低于 300 的 TTL（如攻击自动升级的 60 秒）按 300 秒写入。',
    linesUnsupported: '该服务商不支持按运营商分线路',
    plugin: '解析记录由该第三方插件写入：插件已在安装时通过契约测试并由管理员启用；插件被停用或升级后未通过契约测试时，解析写入会暂停。',
    customHTTP: '对接自建 DNS：主控以 HTTPS POST 签名 JSON 调用该地址（协议见 docs/dns/custom-http-provider.md），校验证书、不跟随跳转、拒绝内网地址；线路以“默认/电信/联通/移动/境外”传递，由对方映射。',
    ttlRange: '可填 {{min}}-{{max}} 秒，实际下限以服务商套餐为准',
    weightSupported: '开启后按线路分组中各节点的权重写入解析记录',
    weightUnsupported: '当前服务商的接口不支持记录权重，不能开启（仅 DNSPod 支持）',
    lines: {
      all: '支持分线路：默认、电信、联通、移动、境外',
      none: '不支持分线路：只按默认线路解析，跨 CDN 调度只做全局主备',
      dnsComFree: '按套餐开放线路：免费版支持默认、电信、联通、移动；境外需旗舰版',
      dnsComEnterprise: '按套餐开放线路：企业版支持默认、电信、联通、移动，另有拓展（教育网等）、区域（华南等）、大洲线路；境外需旗舰版',
      dnsComFlagship: '按套餐开放线路：旗舰版支持默认、电信、联通、移动、境外',
    },
    dnsComPlan: '请按 DNS.COM 账号实际购买的套餐选择。账号实际不支持某条线路时，该线路标为“套餐不支持”，访客按默认线路解析，不影响其他线路。',
  },
  status: { ok: '没有错误', unread: '未读取（配置加载失败或仍在加载）' },
  // 记录修复 / 清除 item failures: which domain, why, what to do.
  itemError: { repair: '域名 {{name}}：{{reason}}', cleanup: '记录 {{name}}：{{reason}}' },
  advice: {
    dns_no_serving_endpoint: '请检查该网站所用线路分组是否有在线节点',
    dns_allocation_missing: '该网站已删除或已更换 CNAME，无需处理；残留解析可用“清除CDN无关解析”删除',
    dns_provider_unavailable: '请点“连接测试”检查 DNS 账号', dns_reconcile_failed: '请稍后重新点“记录修复”',
    dns_reconcile_timeout: '请稍后重新点“记录修复”', dns_record_delete_failed: '请稍后重试',
  },
  // 审测卡 10：连接测试用当前输入；记录修复/清除用已保存配置。
  draft: {
    scopeNote: '连接测试使用当前输入；记录修复和清除使用已保存的配置。',
    unsavedNote: '有未保存的修改：连接测试使用当前输入，记录修复和清除仍使用已保存的配置。',
    maintenancePrompt: '当前有未保存的修改。记录修复和清除只按已保存的配置执行。要先保存修改再执行，还是放弃修改后按已保存配置执行？',
    saveThenRun: '保存后执行', discardThenRun: '放弃修改后执行',
  },
  connection: {
    testing: '正在连接 DNS提供商…', failed: '未连接：{{reason}}', noZones: '已连接（还没有添加 CNAME 域名）',
    hosted: '已连接：CNAME 域名 {{names}} 都在该账号下', unchecked: '已连接（该服务商不提供域名列表，未核对域名归属）',
    notHosted: '已连接，但以下 CNAME 域名不在该 DNS 账号下（无该域名权限）：{{names}}',
    noSaved: '请先填写{{label}}再测试（切换服务商后已保存的密钥不可用）', readOnly: '只测试连接，不会保存配置或修改解析记录',
  },
  errorSources: {
    platform_sync: '同步配置失败', cname_allocation: 'CNAME 解析写入失败', cname_retarget: 'CNAME 解析切换失败',
    dns_repair: '记录修复失败', dns_cleanup: '清除CDN无关解析失败', cname_line: '分线路解析',
  },
  messages: {
    saved: '保存成功', repairQueued: '已提交记录修复任务，可在 系统管理 > 后台任务 查看结果',
    cleanupQueued: '已提交清除任务，可在 系统管理 > 后台任务 查看结果',
    operationsQueued: '已提交 {{count}} 个「{{subject}}」任务，任务 ID：{{ids}}', viewTasks: '查看本次任务',
    cleanupConfirm: '将删除 CNAME 域名下不属于任何网站 CNAME 的 A/AAAA/CNAME 解析（根域名、NS、MX、TXT 等不受影响），确定继续吗？',
    zoneSaved: '保存成功', zoneDeleted: '删除成功', deleteConfirm: '确定删除选中的 {{count}} 个域名吗？',
    deleteOneConfirm: '确定删除域名 {{name}} 吗？', selectFirst: '请先选择要删除的域名',
  },
  zone: {
    id: 'ID', name: '域名', remark: '备注', actions: '操作', search: '输入域名搜索', empty: '暂无数据',
    addTitle: '新增域名', editTitle: '编辑域名', namePlaceholder: '请输入域名', remarkPlaceholder: '请输入备注',
    nameLabel: '域名：', remarkLabel: '备注：', total: '共 {{total}} 条',
    nameHelp: '这里填写在该 DNS 服务商托管、用于分配 CNAME 的域名，须与套餐里的 CNAME 域名一致。',
    random: '参与随机分配', randomLabel: '参与随机分配：', randomRow: '{{name}} 参与随机分配',
    randomHelp: '新网站会在勾选的域名中随机分配一个；未勾选任何域名时使用默认 CNAME 域名。',
    randomEditHelp: '只影响之后新建的网站，已分配的网站保持原 CNAME 域名。',
    randomSaved: '已更新随机分配设置',
  },
  errors: {
    loadFailedNoWrite: 'DNS配置读取失败：未读到当前配置前不能修改，下方是默认值而非已保存配置，请重试', refreshFailed: 'DNS配置刷新失败：下方是上次读到的配置，可重试', saveFailed: '保存失败', repairFailed: '提交记录修复失败', cleanupFailed: '提交清除任务失败',
    identifierRequired: '请输入{{label}}', secretRequired: '请输入{{label}}', projectRequired: '请输入32位项目ID',
    pluginRequired: '请选择已通过契约测试并已启用的 DNS 插件',
    ttlRange: 'TTL 须为 {{min}}-{{max}} 的整数', secretNeeded: '修改密钥或切换DNS提供商时请重新输入{{label}}',
    zoneName: '请输入正确的域名', remarkInvalid: '备注最多 255 个字，不能含控制字符或首尾空格', zoneInUse: '该域名下还有网站在使用，不能删除或改名',
    zoneConflict: '该域名已存在', deleteFailed: '删除失败', zonesLoadFailed: 'CNAME 域名读取失败',
    codes: {
      provider_credentials_rejected: 'DNS提供商拒绝了该密钥', provider_credentials_invalid: '密钥格式不正确',
      provider_verification_unavailable: '暂时无法连接 DNS提供商，请稍后重试', provider_verification_timeout: '连接 DNS提供商超时',
      provider_verification_rate_limited: 'DNS提供商限流，请稍后重试', credential_encryption_unavailable: '主控未配置凭据加密密钥',
      version_conflict: '配置已被修改，请刷新后重试', dns_not_configured: '请先保存DNS配置', dns_no_tenant: '还没有用户，无需执行',
      dns_zone_not_hosted: '该域名不在所选 DNS 账号下',
      dns_provider_unavailable: '无法从 DNS提供商读取解析记录', validation_error: '输入不正确',
      platform_zone_conflict: '有用户已自建同名域名', platform_sync_retry: '同步被进行中的解析写入阻塞，稍后自动重试',
      platform_provider_name_conflict: '有用户已自建同名服务商', dns_reconcile_unavailable: '解析写入不可用',
      dns_reconcile_failed: '服务商写入解析失败', dns_reconcile_timeout: '解析生效超时', dns_no_serving_endpoint: '线路分组没有可用节点',
      dns_allocation_missing: '网站 CNAME 已不存在', dns_record_changed: '记录已变化，已跳过', dns_record_delete_failed: '删除解析失败',
      dns_provider_unavailable_item: '无法连接 DNS提供商', item_failed: '部分记录失败', all_items_failed: '全部记录失败',
      provider_plugin_not_usable: '该 DNS 插件未通过契约测试或未启用',
      dns_line_not_in_plan: '套餐不支持该线路，已按默认线路解析', dns_lines_unsupported: 'DNS提供商不支持该线路',
      dns_line_unconfirmed: '线路记录写入后未确认生效', dns_provider_failed: '服务商写入线路记录失败',
    },
  },
}

const enUS: typeof zhCN = {
  title: 'DNS configuration',
  tabs: { config: 'DNS configuration', cname: 'CNAME domains' },
  installationOnly: {
    description: 'DNS configuration is an installation-wide setting only platform administrators can view or change. Manage your own DNS accounts under My DNS API.',
    ownDnsApi: 'Go to My DNS API', home: 'Back to overview',
  },
  fields: {
    provider: 'DNS provider', ttl: 'TTL', ipWeight: 'IP weight', dnsError: 'DNS error', region: 'Region', projectID: 'Project ID',
    dnsComPlan: 'Plan',
  },
  dnsComPlans: { free: 'Free', enterprise: 'Enterprise', flagship: 'Flagship' },
  placeholders: { enter: 'Enter {{label}}', secretKept: 'Saved; leave blank to keep it', ttl: 'Enter the TTL' },
  providers: {
    aliyun: 'Alibaba Cloud (aliyun.com, alibabacloud.com)', huawei: 'Huawei Cloud (huaweicloud.com)', dns_la: 'DNSLA (dns.la)',
    dnspod_cn: 'DNSPod (dnspod.cn)', dnspod_intl: 'DNSPod International (dnspod.com)', dns_com: 'DNS.COM (51dns.com)',
    cloudflare: 'Cloudflare (cloudflare.com)', namecom: 'Name.com (name.com)', custom_http: 'Custom HTTP API',
    plugin: 'Third-party plugin {{id}} (v{{version}})',
  },
  groups: { official: 'Official', thirdParty: 'Third-party plugins (contract passed)' },
  units: { seconds: 's' },
  actions: {
    save: 'Save', test: 'Test connection', repair: 'Repair records', cleanup: 'Remove non-CDN records', retry: 'Retry',
    addZone: 'Add domain', delete: 'Delete', edit: 'Edit', ok: 'OK', cancel: 'Cancel',
  },
  hints: {
    readOnly: 'This account cannot change DNS settings.',
    loading: 'Reading the current DNS configuration; it cannot be changed until the read completes.',
    dnspodIntl: 'DNSPod International moved to the Tencent Cloud International API 3.0 and is not integrated yet.',
    cloudflareToken: 'Enter a Cloudflare API token with Zone.DNS edit permission; the Global API Key is not supported.',
    nameComToken: 'Enter the name.com account username and an API token (Account settings > API). name.com records take a TTL of at least 300 seconds; lower TTLs (such as 60 seconds from attack escalation) are written as 300.',
    linesUnsupported: 'This provider cannot split DNS by carrier',
    plugin: 'Records are written by this third-party plugin, which passed its installation contract test and was enabled by an administrator; writes pause while it is disabled or an upgrade has not passed the contract yet.',
    customHTTP: 'Connects your own DNS: the controller calls this URL with signed JSON over HTTPS POST (protocol: docs/dns/custom-http-provider.md), verifies the certificate, follows no redirect and refuses internal addresses. Lines are sent as default/telecom/unicom/mobile/overseas names for your side to map.',
    ttlRange: '{{min}}-{{max}} seconds; the provider plan may require a higher minimum',
    weightSupported: 'Records are written with the node weights of the line group',
    weightUnsupported: 'This provider API has no record weights, so this cannot be turned on (DNSPod only)',
    lines: {
      all: 'DNS lines: default, China Telecom, China Unicom, China Mobile, outside mainland China',
      none: 'No DNS lines: records answer on the default line only; cross-CDN scheduling is global primary/backup',
      dnsComFree: 'Lines by plan: Free has default, China Telecom, China Unicom and China Mobile; overseas needs Flagship',
      dnsComEnterprise: 'Lines by plan: Enterprise has default, China Telecom, China Unicom and China Mobile plus extended (e.g. CERNET), regional (e.g. South China) and continent lines; overseas needs Flagship',
      dnsComFlagship: 'Lines by plan: Flagship has default, China Telecom, China Unicom, China Mobile and overseas',
    },
    dnsComPlan: 'Choose the plan the DNS.COM account actually has. A line the account does not have is marked "not in plan" and its visitors get the default line; other lines are unaffected.',
  },
  status: { ok: 'No errors', unread: 'Not read (the configuration failed to load or is still loading)' },
  itemError: { repair: 'Domain {{name}}: {{reason}}', cleanup: 'Record {{name}}: {{reason}}' },
  advice: {
    dns_no_serving_endpoint: 'Check that the site line group has online nodes',
    dns_allocation_missing: 'The site was deleted or its CNAME changed; nothing to do. Remove leftover records with "Remove non-CDN records"',
    dns_provider_unavailable: 'Use "Test connection" to check the DNS account', dns_reconcile_failed: 'Run "Repair records" again later',
    dns_reconcile_timeout: 'Run "Repair records" again later', dns_record_delete_failed: 'Try again later',
  },
  draft: {
    scopeNote: 'Test connection uses what you entered; repair and cleanup use the saved configuration.',
    unsavedNote: 'Unsaved changes: test connection uses what you entered, repair and cleanup still use the saved configuration.',
    maintenancePrompt: 'You have unsaved changes. Repair and cleanup only run with the saved configuration. Save the changes first, or discard them and run with the saved configuration?',
    saveThenRun: 'Save, then run', discardThenRun: 'Discard changes, then run',
  },
  connection: {
    testing: 'Connecting to the DNS provider…', failed: 'Not connected: {{reason}}', noZones: 'Connected (no CNAME domain added yet)',
    hosted: 'Connected: the CNAME domains {{names}} are in this account', unchecked: 'Connected (this provider has no domain list, so domain ownership was not checked)',
    notHosted: 'Connected, but these CNAME domains are not in this DNS account: {{names}}',
    noSaved: 'Enter {{label}} to test (saved keys do not apply after switching provider)', readOnly: 'Only tests the connection; nothing is saved and no record is changed',
  },
  errorSources: {
    platform_sync: 'Configuration sync failed', cname_allocation: 'CNAME record write failed', cname_retarget: 'CNAME switch failed',
    dns_repair: 'Record repair failed', dns_cleanup: 'Record cleanup failed', cname_line: 'Carrier line records',
  },
  messages: {
    saved: 'Saved', repairQueued: 'Record repair was submitted; see System > Background tasks',
    cleanupQueued: 'Cleanup was submitted; see System > Background tasks',
    operationsQueued: 'Submitted {{count}} "{{subject}}" task(s). Task ID: {{ids}}', viewTasks: 'View these tasks',
    cleanupConfirm: 'Delete the A/AAAA/CNAME records of the CNAME domains that belong to no site CNAME? Apex, NS, MX and TXT records are kept.',
    zoneSaved: 'Saved', zoneDeleted: 'Deleted', deleteConfirm: 'Delete the {{count}} selected domains?',
    deleteOneConfirm: 'Delete the domain {{name}}?', selectFirst: 'Select the domains to delete first',
  },
  zone: {
    id: 'ID', name: 'Domain', remark: 'Remark', actions: 'Actions', search: 'Search domains', empty: 'No data',
    addTitle: 'Add domain', editTitle: 'Edit domain', namePlaceholder: 'Enter the domain', remarkPlaceholder: 'Enter a remark',
    nameLabel: 'Domain:', remarkLabel: 'Remark:', total: '{{total}} in total',
    nameHelp: 'Enter a domain hosted at this DNS provider that CNAMEs are allocated under. It must match the CNAME domain of the package.',
    random: 'Random allocation', randomLabel: 'Random allocation:', randomRow: '{{name}} random allocation',
    randomHelp: 'New sites get one of the checked domains at random; with none checked they use the default CNAME domain.',
    randomEditHelp: 'Only sites created afterwards are affected; allocated sites keep their CNAME domain.',
    randomSaved: 'Random allocation updated',
  },
  errors: {
    ...zhCN.errors,
    loadFailedNoWrite: 'Could not load the DNS configuration. It cannot be changed until it is read; the fields below are defaults, not the saved configuration. Try again', refreshFailed: 'Could not refresh the DNS configuration; the fields below are the last one read. Try again', saveFailed: 'Could not save', repairFailed: 'Could not submit record repair',
    cleanupFailed: 'Could not submit the cleanup', identifierRequired: 'Enter {{label}}', secretRequired: 'Enter {{label}}',
    projectRequired: 'Enter the 32 character project ID', ttlRange: 'The TTL must be an integer from {{min}} to {{max}}',
    secretNeeded: 'Enter {{label}} again to change the keys or the provider', zoneName: 'Enter a valid domain', remarkInvalid: 'At most 255 characters, no control characters or leading/trailing spaces',
    zoneInUse: 'Sites still use this domain; it cannot be deleted or renamed', zoneConflict: 'The domain already exists',
    deleteFailed: 'Could not delete', zonesLoadFailed: 'Could not load the CNAME domains', pluginRequired: 'Choose a DNS plugin that passed its contract test and is enabled',
    codes: {
      ...zhCN.errors.codes,
      dns_zone_not_hosted: 'The domain is not hosted by the selected DNS account',
      dns_line_not_in_plan: 'The plan does not include this line; it answers with the default line',
      dns_lines_unsupported: 'The DNS provider cannot write this line',
      dns_line_unconfirmed: 'The line record was written but not confirmed', dns_provider_failed: 'The provider failed to write the line record',
    },
  },
}

function pseudoText(value: string): string {
  return `［${value.replace(/{{[^}]+}}|\S/g, (part) => part.startsWith('{{') ? part : `${part}~`)}］`
}

function pseudoValue(value: unknown): unknown {
  if (typeof value === 'string') return pseudoText(value)
  if (typeof value !== 'object' || value === null) return value
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, pseudoValue(item)]))
}

export const dnsConfigMessages = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoValue(zhCN) as typeof zhCN,
  'qps-Ploc': pseudoValue(zhCN) as typeof zhCN,
}

for (const [locale, messages] of Object.entries(dnsConfigMessages)) {
  i18n.addResourceBundle(locale, 'dnsConfig', messages, true, true)
}
