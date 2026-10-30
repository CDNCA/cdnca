// README 界面截图：只起前端（Vite），所有 /v1/** 请求在浏览器里拦截并返回模拟数据，不连任何后端。
// 用法：
//   pnpm -C apps/web exec vite --host 127.0.0.1 --port 5991   # 另开一个终端
//   PLAYWRIGHT_CORE=<playwright-core 入口> node scripts/ui/readme-shots.mjs [base] [outDir] [只拍的文件名前缀,逗号分隔]
// 默认 base=http://127.0.0.1:5991/dashboard，outDir=docs/images/readme。需要本机装有 Chrome。
// README_SHOTS_LANG=en：界面切到 en-US、模拟数据换成英文，默认输出到 docs/images/readme/en（英文 README 用）。
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const { chromium } = await import(process.env.PLAYWRIGHT_CORE ?? 'playwright-core')
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const lang = process.env.README_SHOTS_LANG === 'en' ? 'en' : 'zh'
const [base = 'http://127.0.0.1:5991/dashboard', outDir = path.join(repoRoot, lang === 'en' ? 'docs/images/readme/en' : 'docs/images/readme'), only = ''] = process.argv.slice(2)
fs.mkdirSync(outDir, { recursive: true })

// ---------- 通用工具 ----------
const NOW = new Date()
NOW.setUTCSeconds(0, 0)
const iso = (d) => new Date(d).toISOString().replace('.000Z', 'Z')
const ago = (ms) => iso(NOW.getTime() - ms)
const H = 3600_000
const D = 24 * H
const GB = 1024 ** 3
const uuid = (prefix, n) => `${prefix}-0000-4000-8000-${String(n).padStart(12, '0')}`
// 平滑的“日内”曲线：白天高夜里低，加一点确定性抖动。
const wave = (i, period, base, amp, seed = 1) => {
  const v = base + amp * Math.sin((2 * Math.PI * i) / period - Math.PI / 2 + seed) + amp * 0.12 * Math.sin((i * 1.7 * 24) / period + seed * 3)
  return Math.max(0, Math.round(v))
}
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: Math.floor(Date.now() / 1000) + 7200 })}.x`

// ---------- 身份 ----------
const PLATFORM_SCOPE = '00000000-0000-4000-8000-000000000001'
const TENANT_SCOPE = '22222222-2222-4222-8222-222222222222'
const TENANT_ID = '33333333-3333-4333-8333-333333333333'
const adminPermissions = ['platform.admin', 'announcements.manage', 'announcements.read', 'approvals.read', 'billing.read',
  'certificates.manage', 'certificates.read', 'challenge_policies.manage', 'challenge_policies.read', 'control.upgrades.read',
  'dns.manage', 'dns.read', 'domains.security.manage', 'edge_publications.manage', 'edge_publications.read', 'error_pages.read',
  'firewall.read', 'http_policies.read', 'identity.self.read', 'identity.users.manage', 'identity.users.read', 'jobs.read',
  'marketplace.browse', 'marketplace.purchase', 'marketplace.sell', 'node_scheduling.manage', 'node_scheduling.read',
  'nodes.manage', 'nodes.read', 'plugin_installations.manage', 'plugin_installations.read', 'plugin_installations.platform.read',
  'regions.read', 'security_policies.manage', 'security_policies.read', 'sites.manage', 'sites.read', 'streams.read',
  'system.gateway.manage', 'system_configuration.manage', 'system_configuration.read', 'tickets.read']
const tenantPermissions = ['sites.read', 'sites.manage', 'dns.read', 'dns.manage', 'security_policies.read', 'security_policies.manage',
  'certificates.read', 'certificates.manage', 'streams.read', 'identity.self.read', 'announcements.read', 'billing.read',
  'billing.account.read', 'package_subscriptions.read', 'traffic_packages.read', 'jobs.read', 'http_policies.read', 'http_policies.manage',
  'error_pages.read', 'edge_publications.read', 'challenge_policies.read', 'tickets.read']
const principals = {
  admin: { user_id: '11111111-1111-4111-8111-111111111111', scope_id: PLATFORM_SCOPE, scope_kind: 'platform', tenant_id: null,
    display_id: '1', username: 'admin', display_name: '平台管理员', roles: ['platform_admin'], permissions: adminPermissions },
  user: { user_id: '11111111-1111-4111-8111-111111111112', scope_id: TENANT_SCOPE, scope_kind: 'tenant', tenant_id: TENANT_ID,
    display_id: '1001', username: 'demo', display_name: '示例租户', roles: ['tenant_owner'], permissions: tenantPermissions },
}

// ---------- 节点与线路组 ----------
const regions = [
  { code: 'cn-east', name: '华东', city: '上海', province: '上海' },
  { code: 'cn-south', name: '华南', city: '广州', province: '广东' },
  { code: 'cn-north', name: '华北', city: '北京', province: '北京' },
  { code: 'hk', name: '香港', city: '香港', province: '香港' },
]
const isps = ['电信', '联通', '移动', 'BGP']
const nodeSpecs = [
  ['sh-ct-01', 0, 0, '203.0.113.11', 820], ['sh-ct-02', 0, 0, '203.0.113.12', 760], ['sh-cu-01', 0, 1, '203.0.113.21', 540],
  ['gz-ct-01', 1, 0, '198.51.100.11', 910], ['gz-cm-01', 1, 2, '198.51.100.31', 430], ['bj-cu-01', 2, 1, '198.51.100.41', 610],
  ['bj-bgp-01', 2, 3, '198.51.100.51', 980], ['hk-bgp-01', 3, 3, '203.0.113.61', 350], ['hk-bgp-02', 3, 3, '203.0.113.62', 290],
]
const nodes = nodeSpecs.map(([name, r, isp, ip, mbps], i) => ({
  id: uuid('a0000000', i + 1), display_id: String(101 + i), name, description: `${regions[r].city}${isps[isp]}边缘节点`,
  region: regions[r].code, ipv4: ip, admin_state: 'active', revision: 3,
  created_at: ago(90 * D - i * 3 * D), updated_at: ago(2 * D),
  management_settings: { schema_version: 1, sort: 900 - i * 10, node_type: i === 6 ? 'L2' : 'L1', cache_directory: '/data/cache', cache_limit_gb: 500,
    log_directory: '/var/log/cdnca', ip_location: { country: '中国', province: regions[r].province, city: regions[r].city, isp: isps[isp], country_code: r === 3 ? 'HK' : 'CN' },
    auto_disable: { bandwidth_limit: 1000, bandwidth_unit: 'Mbps', traffic_enabled: false, traffic_from_day: 1, traffic_from_time: '00:00:00',
      traffic_total_gb: 0, traffic_types: ['outbound'], excluded_interfaces: '', disabled_periods: '' }, secondary_ips: [], external_probe: false },
  presence: { status: 'online', last_heartbeat_at: ago(8_000), agent_version: '1.0.35', session_epoch: 3, heartbeat_sequence: 18000 + i,
    projection_freshness: 'fresh', lease_signal: 'present', projected_at: ago(8_000), openresty_version: '1.31.1.1' },
  _mbps: mbps, _r: r, _isp: isp,
}))
const publicNode = ({ _mbps, _r, _isp, ...n }) => n
const nodeMetrics = (n, i) => ({
  node_id: n.id, node_name: n.name, config_revision: 42, active_config_revision: 42, publication_sequence: 900 + i, observed_at: ago(10_000),
  probe_port: 80, healthy: true, probe_succeeded: true, consecutive_failures: 0, consecutive_successes: 20, probes_total: 86400, probe_failures_total: 3,
  recovered: false, recovery_notified: false, rolled_back: false, known: true, cpu_percent: 18 + (i * 7) % 30,
  memory_used_bytes: (6 + (i % 4)) * 1024 ** 3, memory_total_bytes: 16 * 1024 ** 3, active_connections: 2400 + i * 530,
  rx_bandwidth_bps: Math.round(n._mbps * 0.12 * 1e6), tx_bandwidth_bps: Math.round(n._mbps * 1e6),
  total_rx_bytes: 8_000_000_000_000 + i * 1e11, total_tx_bytes: 62_000_000_000_000 + i * 3e12,
  telemetry: { schema_version: 1, network_selection: { source: 'default_route', interfaces: ['eth0'] },
    network_interfaces: [{ name: 'eth0', rx_bytes: 8_000_000_000_000 + i * 1e11, tx_bytes: 62_000_000_000_000 + i * 3e12, rx_bandwidth_bps: Math.round(n._mbps * 0.12 * 1e6), tx_bandwidth_bps: Math.round(n._mbps * 1e6) }],
    system_load: { one_minute: 0.8 + i * 0.1, five_minutes: 0.7 + i * 0.1, fifteen_minutes: 0.6 + i * 0.1, running_processes: 3, total_processes: 240 },
    disks: [{ path: '/', total_bytes: 500 * 1024 ** 3, used_bytes: (120 + i * 20) * 1024 ** 3, total_inodes: 32_000_000, used_inodes: 900_000, space_percent: 24 + i * 4, inode_percent: 3 }],
    total_rx_bytes: 8_000_000_000_000 + i * 1e11, total_tx_bytes: 62_000_000_000_000 + i * 3e12,
    xdp: { mode: 'native', interfaces: ['eth0=native'], drops: [{ kind: 'tcp_null', packets: 1200 + i * 37, bytes: 72000 + i * 2000 }, { kind: 'xdp_ban', packets: 48000 + i * 913, bytes: 3_100_000 + i * 50000 }] },
    ddos_protection: { state: 'applied' } },
  puback_stream: 'NODE_MONITORING_STATUS', puback_sequence: 5000 + i, consumer_durable: 'control_api_node_metrics', consumer_sequence: 5000 + i, ingested_at: ago(9_000),
  monthly_traffic: { state: 'available', period_key: NOW.toISOString().slice(0, 7), period_start: iso(Date.UTC(NOW.getUTCFullYear(), NOW.getUTCMonth(), 1)),
    period_end: iso(Date.UTC(NOW.getUTCFullYear(), NOW.getUTCMonth() + 1, 1)), timezone: 'Asia/Shanghai', usage_bytes: Math.round(n._mbps * 4.2e10), source_finalized_through: ago(H), samples: 8000 },
})
const health = { status: 'healthy', consecutive_successes: 20, consecutive_failures: 0, last_sequence: 9000, last_observed_at: ago(10_000), last_changed_at: ago(5 * D), row_revision: 4 }
const lineGroupSpecs = [
  ['默认线路', [0, 1, 2, 3, 4, 5], true], ['华东加速', [0, 1, 2], false], ['华南加速', [3, 4], false], ['全国 BGP', [5, 6], false], ['香港海外', [7, 8], false],
]
const lineGroups = lineGroupSpecs.map(([name, members, isDefault], g) => ({
  id: uuid('b0000000', g + 1), display_id: String(11 + g), tenant_scope_id: PLATFORM_SCOPE, revision: 2, name, region: g === 4 ? 'hk' : 'cn',
  resolved_value: `lg${g + 1}.cdn.example.net`, note: '', sort_order: g, failover_mode: 'primary_offline',
  health_policy: { probe_interval_ms: 5000, probe_timeout_ms: 2000, failure_threshold: 3, recovery_threshold: 2, failure_debounce_ms: 10000, recovery_debounce_ms: 30000 },
  endpoints: members.map((m, k) => ({ id: uuid('b1000000', g * 10 + k + 1), node_id: nodes[m].id, address: nodes[m].ipv4, port: 80,
    region: nodes[m].region, carrier: isps[nodes[m]._isp], priority: 1, sort_order: k, weight: 100, enabled: true, health, published: true })),
  statistics: { node_count: members.length, site_count: [86, 34, 21, 12, 9][g], forward_count: [12, 4, 3, 2, 1][g] },
  configuration_digest: 'a'.repeat(64), created_by_user_id: principals.admin.user_id, created_at: ago(80 * D), sealed_at: ago(80 * D),
  ...(isDefault ? { is_platform_default: true } : {}),
}))

// ---------- 网站 ----------
const owners = [
  { id: TENANT_ID, display_id: '1001', display_name: '示例租户' },
  { id: uuid('33333333', 2), display_id: '1002', display_name: '星河电商' },
  { id: uuid('33333333', 3), display_id: '1003', display_name: '云帆资讯' },
]
const siteSpecs = [
  ['www.example.com', ['example.com'], '203.0.113.200', 0, 0, true], ['shop.example.com', [], '203.0.113.201', 1, 1, true],
  ['api.example.com', [], '198.51.100.200', 0, 0, true], ['static.example.net', ['img.example.net'], '198.51.100.201', 3, 2, true],
  ['news.example.org', [], '203.0.113.202', 2, 0, true], ['video.example.net', [], '198.51.100.202', 3, 3, true],
  ['m.example.com', [], '203.0.113.200', 0, 0, true], ['blog.example.org', [], '203.0.113.203', 2, 4, false],
  ['docs.example.com', [], '198.51.100.203', 0, 1, true], ['pay.example.net', [], '198.51.100.204', 1, 1, true],
]
const siteGroups = ['官网', '电商', '资讯', '静态资源']
const sites = siteSpecs.map(([domain, aliases, origin, ownerIdx, lg, https], i) => {
  const all = [domain, ...aliases]
  return {
    id: uuid('c0000000', i + 1), display_id: String(201 + i), version: 4, owner: ownerIdx === 3 ? owners[1] : owners[ownerIdx % 3], domain, domains: all,
    listen_ports: https ? ['80', '443'] : ['80'], origins: [`${origin}:80`], cname: `s${201 + i}.${lineGroups[lg].resolved_value}`,
    cname_state: 'done', cname_domain: lineGroups[lg].resolved_value, https_enabled: https, https_certificate_bound: https,
    package: { id: uuid('d0000000', 1 + (i % 3)), name: ['企业版', '专业版', '基础版'][i % 3] }, group_name: siteGroups[i % 4],
    region: { name: '中国大陆', node_group_name: lineGroups[lg].name }, status: 'active', status_state: 'normal', status_code: 200, status_recovery: null,
    listener_state: { ipv6_desired_enabled: false, ipv6_runtime_state: 'disabled' },
    lock: { locked: false, reason: null, locked_at: null, operator: null }, created_at: ago((120 - i * 9) * D),
    access_readiness: { state: 'ready', checks: ['package', 'line_group', 'cname_generated', 'dns_resolved', 'https_cert', 'published'].map((code) => ({ code, ok: true, detail: '', checked_at: ago(H) })) },
  }
})
const tenantSites = sites.filter((s, i) => i !== 4).map((s) => ({ ...s, owner: owners[0] }))
const siteDetailOf = (s) => ({
  id: s.id, scope_id: TENANT_SCOPE, version: s.version, owner: s.owner, created_at: s.created_at, updated_at: ago(3 * D), lock: s.lock,
  status_state: 'normal', status_code: 200, status_recovery: null, listener_state: s.listener_state, https_certificate_bound: s.https_enabled,
  access_readiness: s.access_readiness,
  basic: { package_id: s.package.id, package_name: s.package.name, group_id: uuid('e0000000', 1), group_name: s.group_name,
    domains: [...s.domains].sort(), http_enabled: true, http_listen_ports: ['80'], https_listen_ports: s.https_enabled ? ['443'] : [], ipv6_enabled: false,
    tls_protocols: ['TLSv1.2', 'TLSv1.3'], http2_enabled: true, http3_enabled: false, origins: s.origins, cname: s.cname, cname_state: 'done',
    https_enabled: s.https_enabled, force_https: true, enabled: true, status: 'active', sync_status: 'synced', is_default: false },
  origin_pool: { origins: [{ host: s.origins[0].split(':')[0], port: 80, weight: 100, enabled: true }, { host: '198.51.100.210', port: 80, weight: 50, enabled: true }],
    balance_method: 'round_robin', failover_tries: 2, connect_timeout_ms: 5000, read_timeout_ms: 60000, keepalive_enabled: true,
    request_host: { mode: 'visitor', value: '' }, scheme: 'http', http_port: 80, https_port: 443 },
  package_remaining_days: 186,
})

// ---------- WAF 规则 ----------
const wafRule = (name, field, operator, values, action = 'block') => ({ name, priority: 10, enabled: true, conditions: [{ field, operator, values }], action, flow: 'stop', action_config: {} })
const wafPolicies = [
  ['电商站点防护', '登录与下单接口的注入、爬虫与撞库拦截', owners[1], true],
  ['官网基础防护', '常见扫描器与敏感路径拦截', owners[0], true],
  ['API 接口白名单', '仅放行合作方网段，其余拦截', owners[0], true],
  ['资讯站评论区防护', '评论接口 XSS 与垃圾内容过滤', owners[2], true],
  ['静态资源防盗链', 'Referer 校验，拒绝外链引用', owners[1], true],
  ['后台路径保护', '/admin 仅允许办公网访问', owners[2], false],
].map(([name, description, owner, enabled], i) => ({
  id: String(3001 + i), scope_id: TENANT_SCOPE, owner: { id: owner.id, display_name: owner.display_name }, version: 3 + i, created_at: ago((60 - i * 7) * D), updated_at: ago((i + 1) * 9 * H),
  kind: 'waf', name, description, enabled, default_action: 'allow',
  rules: [wafRule('拦截扫描器', 'user_agent', 'contains', ['sqlmap', 'nikto']), wafRule('敏感路径', 'path', 'prefix', ['/.env', '/.git'])],
}))
const wafLibraryList = [
  ['OWASP 核心规则集', 'SQL 注入、XSS、命令执行等通用攻击检测', 'subscribed'],
  ['WordPress 专项防护', 'xmlrpc、插件漏洞与暴力登录防护', 'not_subscribed'],
  ['恶意爬虫与扫描器', '常见扫描器、采集器 User-Agent 与行为特征', 'update_available'],
].map(([name, description, subscription], i) => ({ id: uuid('aa000000', i + 1), name, description, origin: 'system', scope: 'global', enabled: true, subscription, protected: true, revision: 4 + i, updated_at: ago((i + 2) * D) }))
const wafLibraryCopies = wafLibraryList.filter((l) => l.subscription !== 'not_subscribed').map((l, i) => ({
  id: String(2901 + i), scope_id: PLATFORM_SCOPE, version: l.revision, created_at: ago(40 * D), updated_at: l.updated_at, kind: 'waf', name: l.name, description: l.description,
  enabled: true, default_action: 'allow', rules: [], protected: true, library_id: l.id,
}))

const wafSystemRules = [['SQL 注入检测', 'sqli'], ['跨站脚本检测', 'xss'], ['命令执行检测', 'rce'], ['路径穿越检测', 'lfi'], ['扫描器识别', 'scanner']].map(([name, key], i) => ({
  system_key: `waf.${key}`, kind: 'waf_rule_set', legacy_id: String(9001 + i), name, description: name, sort: i + 1, revision: 3, status: 'active', selectable: true, enabled: true,
  visibility: { visible: true, show_to_scope_ids: [], revision: 1 }, updated_at: ago(3 * D),
  body: { waf_rule_set: { rules: [{ id: `${key}-1`, name, enabled: true, action: 'block', matcher_groups: [{ id: 'g1', matchers: [{ field: 'args', operator: 'detect_' + key, key: '', transform: '', value: '' }] }] }] } },
}))

// ---------- DNS ----------
const dnsAccounts = [
  ['阿里云 DNS（主账号）', 'aliyun', ['默认', '电信', '联通', '移动', '境外']], ['Cloudflare', 'cloudflare', ['默认']],
  ['DNSPod', 'dnspod_cn', ['默认', '电信', '联通', '移动', '境外']], ['华为云 DNS', 'huawei', ['默认', '电信', '联通', '移动']],
].map(([name, type, lines], i) => ({ id: `dnsp${i + 1}`, scope_id: TENANT_SCOPE, name, provider_type: type, credentials_configured: true, status: 'verified', managed_by: 'tenant',
  version: 2, created_at: ago((90 - i * 10) * D), updated_at: ago(D), _lines: lines }))
const dnsDomains = [
  ['example.com', 0, 18], ['example.net', 0, 9], ['example.org', 1, 12], ['example.info', 2, 7], ['example.cn', 2, 15], ['example.io', 3, 5],
].map(([apex, a, count]) => ({ provider_id: dnsAccounts[a].id, provider_name: dnsAccounts[a].name, provider_type: dnsAccounts[a].provider_type, apex, record_count: count, last_listed_at: ago(20 * 60_000) }))
const dnsRecords = (providerID, apex) => {
  let seq = 0
  const rec = (name, type, value, line = '默认', managed = null, ttl = 600) => ({ record_ref: `r${++seq}`, name, type, value, ttl, line, weight: 0,
    fqdn: name === '@' ? apex : `${name}.${apex}`, managed })
  const site = sites.find((x) => x.domain.endsWith(apex))
  const m = site ? { kind: 'site_cname', site_id: site.id, site_domain: site.domain } : null
  return { provider_id: providerID, apex, skipped: 0, items: [
    rec('www', 'CNAME', site ? site.cname : `s201.lg1.cdn.example.net`, '默认', m),
    rec('shop', 'CNAME', 's202.lg2.cdn.example.net', '默认', m && { ...m, site_domain: `shop.${apex}` }),
    rec('api', 'CNAME', 's203.lg1.cdn.example.net', '默认', m && { ...m, site_domain: `api.${apex}` }),
    rec('@', 'A', '203.0.113.200', '电信'), rec('@', 'A', '198.51.100.200', '联通'), rec('@', 'A', '198.51.100.201', '移动'),
    rec('@', 'AAAA', '2001:db8::200'), rec('@', 'TXT', 'v=spf1 include:spf.example.net ~all', '默认', null, 3600),
    rec('mail', 'A', '203.0.113.25'), rec('_acme-challenge', 'TXT', 'a1b2c3d4e5f6g7h8', '默认', { kind: 'acme_challenge', site_id: sites[0].id, site_domain: sites[0].domain }, 120),
    rec('m', 'CNAME', 's207.lg1.cdn.example.net', '默认', m && { ...m, site_domain: `m.${apex}` }), rec('docs', 'CNAME', 's209.lg2.cdn.example.net'),
  ] }
}

// ---------- 市场 ----------
const marketMember = { id: 'cdnca-ce-7f3a9c21', display_name: '示例云服务', status: 'active', features: ['market.browse', 'market.purchase'], offers_quota: 20, offers_used: 0,
  supplier: { status: 'none', can_sell: false } }
const pricePlan = (pid, kind, price, interval) => ({ id: `${pid}-plan`, plugin_id: pid, revision: 1, kind, ...(interval ? { interval } : {}), price_minor: price, currency: 'CNY', trial_days: kind === 'free' ? 0 : 7, status: 'active', active_revision: 1 })
const marketPlugins = [
  ['rp-wordpress', 'rule_pack', 'WordPress 防护规则包', '针对 xmlrpc、wp-login 暴力破解与常见插件漏洞的规则集合，开箱即用。', 'community-sec', 12830, 'free', 0],
  ['rp-api-guard', 'rule_pack', 'API 接口防刷规则包', '按接口路径限速、签名校验失败拦截、异常参数检测，适合开放 API。', 'example-labs', 4210, 'subscription', 1900],
  ['rp-crawler', 'rule_pack', '恶意爬虫识别规则包', '覆盖 300+ 采集器与扫描器特征，配合 JS 挑战降低误杀。', 'community-sec', 9120, 'one_time', 4900],
  ['theme-aurora', 'theme', 'Aurora 控制台主题', '深浅双色的控制台主题，含登录页、错误页与用户端整套样式。', 'example-design', 3560, 'free', 0],
  ['theme-minimal', 'theme', '极简白主题', '大留白、细线条的简洁风格，适合面向企业客户的白标部署。', 'example-design', 2140, 'one_time', 2900],
  ['provider-dnsla', 'provider', 'DNS.LA 解析接入', '在多家 DNS 统一管理中接入 DNS.LA 账号，支持分线路解析。', 'example-labs', 1870, 'free', 0],
].map(([pid, kind, title, summary, ns, installs, planKind, price], i) => ({
  id: uuid('ab000000', i + 1), plugin_id: pid, namespace: ns, kind, risk_class: 'sandboxed', title, summary, status: 'published', latest_version: `1.${3 - (i % 3)}.${i}`,
  installs, publisher_kind: i % 3 === 0 ? 'certified' : 'third_party', categories: [kind], ...(kind === 'theme' ? { applies_to: ['admin', 'user'], has_preview: false } : {}),
  price_plans: [pricePlan(pid, planKind, price, planKind === 'subscription' ? 'month' : null)],
}))
const offer = (i, name, seller, model, pricing, extra = {}) => ({
  id: uuid('ac000000', i), seller_id: seller, name, description: '', billing_model: model, status: 'published', revision: 2, category: 'cdn', pricing: { currency: 'CNY', ...pricing },
  allocation: { http_ports: 2, stream_ports: 0, websocket: true, http3: i % 2 === 0 }, compliance: { require_icp: i % 3 === 0 },
  limits: [{ metric: 'domains', cap: [20, 50, 100, 30, 10, 200][i % 6], action: 'reject_new' }, ...(model === 'daily_bundle' ? [{ metric: 'monthly_traffic_bytes', cap: [2, 5, 10][i % 3] * 1024 * GB, action: 'throttle', throttle_bps: 10_000_000 }] : [])],
  tags: { cc_protection: i % 2 ? 'advanced' : 'basic', ddos_protection_gbps: [20, 50, 100, 300][i % 4], complaint_resistant: false, tenancy: 'shared', mobile_reachable: true, region_block: false },
  settlement_mode: 'direct', trial_days: i % 2 ? 3 : 0,
  quality: { score: [2.71, 2.43, 2.88, 2.15, 2.62, 2.36, 2.9][i % 7], tier: 'high', regions: ['华东', '华南', '华北'], carriers: ['电信', '联通', '移动'], serving_nodes: 6 + i * 2, unit_price: null, computed_at: ago(H) },
  seller_credit: { deposit_effective: true, deposit_minor: 500000, required_minor: 300000, sufficient: true, defaults_count: 0, absconded: false, faults_30d: 0 },
  ...extra,
})
const marketOffers = [
  offer(1, '华东三网 CDN 套餐 · 标准版', 'a1c3e5f7-seller', 'daily_bundle', { daily_minor: 1500, min_days: 7, max_days: 365 }),
  offer(2, '全国 BGP 高防加速', 'b2d4f6a8-seller', 'daily_bundle', { daily_minor: 4800, min_days: 30, max_days: 365 }),
  offer(3, '华南电信精品线路 · 按流量', 'c3e5a7b9-seller', 'traffic', { deposit_minor: 20000, tiers: [{ up_to_gb: 10240, price_per_gb_minor: 18 }, { up_to_gb: 0, price_per_gb_minor: 12 }] }),
  offer(4, '香港 CN2 GIA 国际加速', 'd4f6b8c0-seller', 'bandwidth_95', { deposit_minor: 100000, per_mbps_month_minor: 4500 }),
  offer(5, '北方联通大带宽 · 日峰值计费', 'b2d4f6a8-seller', 'bandwidth_daily_peak', { deposit_minor: 50000, per_mbps_day_minor: 120 }),
  offer(6, '视频点播专用 · 按流量', 'a1c3e5f7-seller', 'traffic', { deposit_minor: 20000, tiers: [{ up_to_gb: 51200, price_per_gb_minor: 10 }, { up_to_gb: 0, price_per_gb_minor: 8 }] }),
  offer(7, '入门体验包 · 小站点', 'e5a7c9d1-seller', 'daily_bundle', { daily_minor: 300, min_days: 1, max_days: 90 }),
]
const marketAgreements = [{ kind: 'privacy', version: '2026-09', body: '示例条款', note: '', published_at: ago(40 * D) }]

// ---------- 流量统计 ----------
// 某小时的统计（数字形式，analytics 接口用）。scale 用来区分管理端全平台与单租户。
const hourStats = (hourIndex, scale = 1) => {
  const req = wave(hourIndex, 24, 1_800_000, 1_100_000, 0.4) * scale
  const resp = Math.round(req * 92_000)
  const hit = Math.round(req * 0.86)
  const s4 = Math.round(req * 0.012), s5 = Math.round(req * 0.0015), s3 = Math.round(req * 0.03)
  const sec = Math.round(req * 0.004)
  return { metric_version: 1, request_count: req, request_bytes: Math.round(req * 900), response_bytes: resp, total_bytes: resp + Math.round(req * 900),
    average_bandwidth_bps: Math.round((resp * 8) / 3600), status_2xx: req - s3 - s4 - s5, status_3xx: s3, status_4xx: s4, status_5xx: s5,
    security_events: sec, security_event_rows: Math.round(sec / 3), cache_hit_requests: hit, cache_hit_bytes: Math.round(resp * 0.83),
    unique_client_ips: Math.round(req / 38) }
}
const sumStats = (points) => {
  const out = { ...points[0] }
  for (const k of Object.keys(out)) if (k !== 'metric_version' && k !== 'hour') out[k] = points.reduce((a, p) => a + p[k], 0)
  out.average_bandwidth_bps = Math.round((out.response_bytes * 8) / (points.length * 3600))
  out.unique_client_ips = Math.round(out.unique_client_ips * 0.35)
  delete out.hour
  return out
}
const hourFloor = (t) => Math.floor(t / H) * H
const hoursBetween = (from, to) => {
  const out = []
  for (let t = hourFloor(Date.parse(from)); t < Date.parse(to) && out.length < 744; t += H) out.push(t)
  return out
}
const trendFor = (from, to, scale) => hoursBetween(from, to).map((t) => ({ hour: iso(t), ...hourStats(new Date(t).getUTCHours() + 8, scale) }))
const toDecimal = (s) => Object.fromEntries(Object.entries(s).map(([k, v]) => [k, k === 'metric_version' || k === 'average_bandwidth_bps' || k === 'hour' ? v : String(v)]))
const dashStats = (s) => {
  const d = toDecimal(s)
  delete d.cache_hit_requests; delete d.cache_hit_bytes; delete d.unique_client_ips
  return d
}
const regionsRank = [['广东', 31], ['上海', 22], ['北京', 18], ['浙江', 14], ['江苏', 12], ['四川', 8], ['湖北', 6], ['福建', 5], ['山东', 4], ['香港', 3]]
const carriersRank = [['电信', 46], ['联通', 27], ['移动', 21], ['教育网', 3], ['其他', 2]]
const urlPaths = ['/', '/static/js/app.js', '/static/css/main.css', '/api/v1/products', '/images/banner.webp', '/api/v1/cart', '/video/intro.mp4', '/favicon.ico', '/search', '/login']
const rankItems = (dimension, total, scopeSites) => {
  const weights = [30, 21, 15, 11, 8, 6, 4, 3, 1.5, 0.5]
  const mk = (key, w, extra = {}) => ({ key, request_count: Math.round(total * w / 100), response_bytes: Math.round(total * w / 100 * 92_000), ...extra })
  switch (dimension) {
    case 'domain': return scopeSites.flatMap((s) => s.domains).slice(0, 10).map((d, i) => mk(d, weights[i], { host: d, port: 443 }))
    case 'url': return urlPaths.map((p, i) => mk(`https://${scopeSites[0].domain}${p}`, weights[i], { host: scopeSites[0].domain, port: 443, path: p, scheme: 'https' }))
    case 'ip': return Array.from({ length: 10 }, (_, i) => mk(`${i % 2 ? '198.51.100' : '203.0.113'}.${50 + i * 7}`, weights[i] / 6))
    case 'region': case 'province': return regionsRank.map(([k, w]) => mk(k, w))
    case 'carrier': return carriersRank.map(([k, w]) => mk(k, w))
    case 'browser': return [['Chrome', 52], ['Safari', 24], ['Edge', 9], ['微信', 8], ['Firefox', 4], ['其他', 3]].map(([k, w]) => mk(k, w))
    case 'os': return [['Android', 38], ['iOS', 27], ['Windows', 24], ['macOS', 8], ['Linux', 3]].map(([k, w]) => mk(k, w))
    case 'referer': return [['https://www.example.org/', 40], ['https://search.example.net/', 30], ['(直接访问)', 30]].map(([k, w]) => mk(k, w))
    default: return []
  }
}
const decimalRank = (items) => items.map((it) => ({ ...it, request_count: String(it.request_count), response_bytes: String(it.response_bytes) }))
const analyticsOverview = (from, to, scale, scopeSites) => {
  const trend = trendFor(from, to, scale)
  const summary = sumStats(trend)
  const snap = ago(5 * 60_000)
  const top = (dimension) => ({ dimension, snapshot_at: snap, items: decimalRank(rankItems(dimension, summary.request_count, scopeSites)) })
  return { blocked_ip_count: String(386 * scale), peak_bandwidth_bps: String(Math.round(summary.average_bandwidth_bps * 1.9)), blocked_ip_trend_available: true,
    summary: { ...dashStats(summary), blocked_ip_count: String(386 * scale) }, trend: trend.map((p) => ({ hour: p.hour, ...dashStats(p) })),
    top: ['domain', 'region', 'carrier'].map(top), top_extended: ['domain', 'url', 'ip', 'region', 'carrier'].map(top) }
}
const tzOffsetRange = (range) => {
  // 以 Asia/Shanghai 自然日为界
  const shNow = new Date(NOW.getTime() + 8 * H)
  const dayStart = Date.UTC(shNow.getUTCFullYear(), shNow.getUTCMonth(), shNow.getUTCDate()) - 8 * H
  switch (range) {
    case 'today': return [dayStart, NOW.getTime()]
    case 'yesterday': return [dayStart - D, dayStart]
    case 'thirty_days': return [dayStart - 29 * D, NOW.getTime()]
    case 'previous_month': return [dayStart - 30 * D, dayStart]
    default: return [dayStart - 6 * D, NOW.getTime()]
  }
}
const metaFor = (range, timezone) => {
  const [from, to] = tzOffsetRange(range)
  return { range, timezone, from: iso(from), to: iso(to), generated_at: ago(60_000), snapshot_at: ago(60_000), window_complete: false }
}
const network = { nodes_total: nodes.length, nodes_active: nodes.length, nodes_online: nodes.length, nodes_stale: 0, freshness_cutoff_seconds: 45,
  regions: regions.map((r) => ({ region: r.code, nodes_total: nodes.filter((n) => n.region === r.code).length, nodes_online: nodes.filter((n) => n.region === r.code).length })) }
const ok = (value) => ({ available: true, value })
const dailyPoints = (meta, fn) => {
  const out = []
  for (let t = Date.parse(meta.from), i = 0; t < Date.parse(meta.to); t += D, i++) out.push({ time: iso(t), ...fn(i) })
  return out
}
const adminDashboard = (range, timezone) => {
  const meta = metaFor(range, timezone)
  return {
    dashboard_version: 2, meta,
    accounts: ok({ tenants_total: 128, tenants_active: 117, tenant_users_total: 342, tenant_users_active: 309 }),
    subscriptions: ok({ active: 96 }),
    billing: ok({ currency: 'CNY', gross_settled_debit_minor: '4862300', reversed_credit_minor: '12000', net_settled_minor: '4850300' }),
    resources: ok({ sites_total: 412, sites_active: 405, sites_sync_failed: 0, domains_total: 538, forwards_total: 37, nodes_total: nodes.length,
      certificates_total: 389, certificates_valid: 386, certificates_expiring_30d: 3 }),
    operations: ok({ cache_total: 64, cache_open: 1, cache_failed: 0, cache_updated_at: ago(10 * 60_000), jobs_total: 210, jobs_open: 2, jobs_failed: 0, jobs_updated_at: ago(5 * 60_000) }),
    operation_charts: ok({
      new_users: dailyPoints(meta, (i) => ({ count: [3, 5, 2, 6, 4, 7, 5][i % 7] })),
      package_sold: dailyPoints(meta, (i) => ({ count: [2, 4, 3, 5, 2, 6, 4][i % 7] })),
      recharge: dailyPoints(meta, (i) => ({ sum_minor: String([68000, 125000, 49000, 210000, 88000, 156000, 99000][i % 7]) })),
    }),
    profile: ok({ last_login_at: ago(2 * H), last_login_ip: '203.0.113.8', last_login_geo: 'CN', last_login_region: '上海' }),
    // 与社区版真实安装一致：只有安装记录，没有租约，授权节点和到期时间显示为“—”。
    entitlement: ok({ installation_id: 'community-edition', status: 'uninstalled', lease_status: null }),
    node_health: ok({ total: nodes.length, online_fresh: nodes.length, stale_or_offline: 0, presence_missing: 0, latest_last_seen_at: ago(8_000), freshness_cutoff_seconds: 45 }),
    analytics_health: ok({ active_streams: 4, latest_reconciled_at: ago(60_000), latest_updated_at: ago(30_000), unprepared_stream_gap: '0' }),
    account_security: ok({ active_sessions: 3, users_with_mfa: 2, active_api_keys: 4, recovery_codes_remaining: 8 }),
    network: ok(network),
    analytics: ok(analyticsOverview(meta.from, meta.to, 6, sites)),
  }
}
const tenantDashboard = (range, timezone) => {
  const meta = metaFor(range, timezone)
  return {
    dashboard_version: 2, meta,
    identity_verification: ok({ verified: true }),
    profile: ok({ last_login_at: ago(H), last_login_ip: '198.51.100.8', last_login_geo: 'CN', last_login_region: '广东' }),
    resources: ok({ sites_total: tenantSites.length, sites_active: tenantSites.length, sites_sync_failed: 0, domains_total: 6, forwards_total: 2, nodes_total: 6 }),
    certificates: ok({ total: 5, valid: 5, expiring_30d: 0 }),
    billing: ok({ currency: 'CNY', balance_minor: 1288650, revision: 21, updated_at: ago(D) }),
    subscriptions: ok({ active: 1, items: [{ id: uuid('d1000000', 1), name: '企业版', ends_at: iso(NOW.getTime() + 186 * D), timezone: 'Asia/Shanghai',
      site_limit: '20', domain_limit: '100', node_limit: '-1', traffic_limit_bytes: String(5 * 1024 * GB),
      traffic_progress: ok({ period_key: NOW.toISOString().slice(0, 7), used_bytes: String(Math.round(1830.6 * GB)), finalized_through: ago(H), source_watermark: '88231', source_evidence_sha256: 'b'.repeat(64) }) }] }),
    traffic_packages: ok({ active: 1, granted_bytes: String(1024 * GB), remaining_bytes: String(712 * GB), used_bytes: String(312 * GB) }),
    operations: ok({ cache_total: 12, cache_open: 0, cache_failed: 0, cache_updated_at: ago(H), jobs_total: 30, jobs_open: 0, jobs_failed: 0 }),
    notices: ok({ unread: 1, items: [
      { id: uuid('f0000000', 1), title: '社区版 1.0.35 已发布：新增多家 DNS 统一管理', published_at: ago(2 * D) },
      { id: uuid('f0000000', 2), title: '节点维护通知：华南线路例行升级', published_at: ago(6 * D), read_at: ago(5 * D) },
    ] }),
    account_security: ok({ active_sessions: 2, users_with_mfa: 1, active_api_keys: 1, recovery_codes_remaining: 8 }),
    network: ok(network),
    analytics: ok(analyticsOverview(meta.from, meta.to, 1, tenantSites)),
  }
}
// /v1/(admin/)analytics/site-realtime（query_version 4）：分钟桶曲线，汇总与曲线逐项对账。
const siteRealtime = (u, scale, scopeSites) => {
  const fromS = u.searchParams.get('from'), toS = u.searchParams.get('to')
  const from = Date.parse(fromS), to = Date.parse(toS)
  const bucketSeconds = Math.ceil((to - from) / 60_000 / 744) * 60
  const series = []
  for (let t = from, i = 0; t + bucketSeconds * 1000 <= to; t += bucketSeconds * 1000, i++) {
    const minuteOfDay = ((t + 8 * H) % D) / 60_000
    const req = Math.round(wave(minuteOfDay, 1440, 26_000, 17_000, 0.4) * (bucketSeconds / 60) * scale * (1 + 0.025 * Math.sin(i / 7)))
    const bytes = req * 91_000
    const hits = Math.round(req * 0.87)
    series.push({ bucket: iso(t), requests: req, traffic_bytes: bytes, bandwidth_bps: Math.round(bytes * 8 / bucketSeconds), connections: Math.round(req / 9),
      cache_hits: hits, cache_misses: req - hits, cache_hit_bytes: Math.round(bytes * 0.84), status_4xx: Math.round(req * 0.011), status_5xx: Math.round(req * 0.001),
      origin_total_us: 38_000 + (i % 7) * 900, origin_traffic_bytes: null, origin_bandwidth_bps: null })
  }
  const total = (k) => series.reduce((a, p) => a + p[k], 0)
  const requests = total('requests'), traffic = total('traffic_bytes')
  const s4 = total('status_4xx'), s5 = total('status_5xx'), s3 = Math.round(requests * 0.03)
  const summary = { requests, traffic_bytes: traffic, bandwidth_bps: Math.round(traffic * 8 / ((to - from) / 1000)), connections: Math.round(series.at(-1).connections),
    status_2xx: requests - s3 - s4 - s5, status_3xx: s3, status_4xx: s4, status_5xx: s5, cache_hits: total('cache_hits'), cache_misses: total('cache_misses'),
    errors: s5, average_duration_us: 61_000, origin_connect_us: 4_200, origin_first_byte_us: 31_000, origin_total_us: 41_000 }
  const w = [28, 19, 14, 11, 9, 7, 5, 4, 2, 1]
  const top = scopeSites.slice(0, 10).map((s, i) => ({ host: s.domain, listen_port: 443, requests: Math.round(requests * w[i] / 100), traffic_bytes: Math.round(traffic * w[i] / 100) }))
  const cf = Math.floor(from / H) * H, ct = Math.ceil(to / H) * H, windows = (ct - cf) / H
  return { data: { metric_version: 1, series_bucket_seconds: bucketSeconds, summary, series, top,
    evidence: { access_source_count: requests, connection_source_count: 12, expected_events: 0, observed_events: requests, error_ppm: 0,
      finalized_through: '1970-01-01T00:00:00Z', source_watermark: '1970-01-01T00:00:00Z', coverage_from: iso(cf), coverage_to: iso(ct), snapshot_at: ago(30_000),
      coverage_complete: true, requested_windows: windows, covered_windows: windows, missing_windows: [] } },
    meta: { from: fromS, to: toS, timezone: 'UTC', metric_version: 1, query_version: 4 } }
}
const aMeta = (u) => ({ from: u.searchParams.get('from'), to: u.searchParams.get('to'), timezone: 'UTC', metric_version: 1 })
// /v1/analytics/* 与 /v1/admin/analytics/* 的通用应答；返回 undefined 表示不认识。
const analyticsResponse = (sub, u, scale, scopeSites) => {
  if (sub === 'site-realtime') return siteRealtime(u, scale, scopeSites)
  const meta = aMeta(u)
  if (!meta.from || !meta.to) return undefined
  const trend = trendFor(meta.from, meta.to, scale)
  const total = trend.length ? sumStats(trend) : hourStats(0, scale)
  if (sub === 'summary') return { data: total, meta }
  if (sub === 'hourly-trend') return { data: trend, meta }
  if (sub === 'peak-bandwidth') return { data: { peak_bandwidth_bps: Math.round(total.average_bandwidth_bps * 1.9), bucket_seconds: 300 }, meta }
  if (sub === 'blocked-ip-count') return { blocked_ip_count: 386 * scale, meta }
  if (sub === 'blocked-ip-trend') return { data: trend.map((p, i) => ({ hour: p.hour, blocked_ip_count: wave(i, 24, 16, 10, 1) * scale })), meta }
  const m = sub.match(/^top\/([a-z0-9]+)$/)
  if (m) return { data: rankItems(m[1], total.request_count, scopeSites).slice(0, Number(u.searchParams.get('limit') ?? 10)), dimension: m[1], page: { snapshot_at: ago(5 * 60_000), source: 'history' }, meta }
  if (sub === 'waf-overview') {
    const wt = trend.map((p, i) => { const a = wave(i, 24, 900, 600, 2) * scale; return { hour: p.hour, attacks: a, blocked: Math.round(a * 0.7), intercepted: Math.round(a * 0.2), observed: Math.round(a * 0.1), auto_blocked: Math.round(a * 0.05), clients: Math.round(a / 20) } })
    const sum = (k) => wt.reduce((x, p) => x + p[k], 0)
    const rk = (pairs) => pairs.map(([key, count, name]) => ({ key, count: count * scale, ...(name ? { name } : {}) }))
    return { data: { attacks: sum('attacks'), blocked: sum('blocked'), intercepted: sum('intercepted'), observed: sum('observed'), auto_blocked: sum('auto_blocked'), clients: sum('clients'), trend: wt,
      attack_types: rk([['sqli', 4210, 'SQL 注入'], ['xss', 2980, '跨站脚本'], ['scanner', 1730, '扫描器'], ['rce', 640, '命令执行'], ['lfi', 420, '文件包含']]),
      top_domains: rk(scopeSites.slice(0, 5).map((s, i) => [s.domain, 3000 - i * 500])),
      top_clients: rk([['203.0.113.77', 1820], ['198.51.100.23', 1410], ['203.0.113.145', 990], ['198.51.100.99', 640]]),
      top_countries: rk([['CN', 6200], ['US', 1900], ['SG', 820], ['DE', 410]]), top_provinces: rk([['广东', 2100], ['浙江', 1500], ['北京', 1100]]),
      top_carriers: rk([['电信', 3600], ['联通', 2100], ['移动', 1700]]), top_uris: rk([['/wp-login.php', 2400], ['/api/v1/login', 1300], ['/.env', 900]]) }, meta }
  }
  return undefined
}

// ---------- 安装指南（全新安装后的状态）----------
// 只用于 install-*.png：一台刚装好的主控，一个自注册的待初始化节点，一个刚建好的站点。
const freshNode = (state) => ({
  id: uuid('a1000000', 1), display_id: '1', name: 'edge-01', description: 'Ubuntu 24.04.3 LTS · 6.8.0-71-generic · x86_64',
  region: state === 'pending' ? '' : 'cn-east', ipv4: '203.0.113.11', admin_state: state, revision: state === 'pending' ? 1 : 2,
  created_at: ago(6 * 60_000), updated_at: ago(state === 'pending' ? 6 * 60_000 : 60_000),
  management_settings: { ...nodes[0].management_settings, sort: 0, node_type: 'L1' },
  presence: { ...nodes[0].presence, session_epoch: 1, heartbeat_sequence: 40, last_heartbeat_at: ago(5_000), projected_at: ago(5_000) },
})
const freshLineGroup = (withNode) => ({
  ...lineGroups[0], id: uuid('b2000000', 1), display_id: '1', name: '默认线路', revision: withNode ? 2 : 1, resolved_value: 'lg1.cdn.example.com',
  endpoints: withNode ? [{ ...lineGroups[0].endpoints[0], id: uuid('b2100000', 1), node_id: uuid('a1000000', 1), address: '203.0.113.11' }] : [],
  statistics: { node_count: withNode ? 1 : 0, site_count: 0, forward_count: 0 }, is_platform_default: true,
})
const freshUser = { id: uuid('11111111', 3), display_id: '1001', scope_id: TENANT_SCOPE, tenant_id: TENANT_ID, username: 'demo', display_name: '示例租户',
  email: 'demo@example.com', phone: null, status: 'active', role: 'tenant_owner', group_id: null, group_name: null, revision: 1,
  created_at: ago(30 * 60_000), updated_at: ago(30 * 60_000), metadata: { remark: null, qq: null } }
const freshSite = { ...sites[0], id: uuid('c1000000', 1), display_id: '1', domain: 'www.example.com', domains: ['www.example.com'], owner: owners[0],
  listen_ports: ['80'], origins: ['198.51.100.20:80'], cname: 's1.lg1.cdn.example.com', cname_domain: 'lg1.cdn.example.com',
  https_enabled: false, https_certificate_bound: false, package: null, group_name: null, region: { name: '中国大陆', node_group_name: '默认线路' },
  created_at: ago(3 * 60_000), version: 2 }
const sha = (c) => c.repeat(64)
const freshPublication = { id: uuid('c2000000', 1), configuration_scope_id: TENANT_SCOPE, source_revision: 2, config_version_id: uuid('c3000000', 1),
  rollout_id: uuid('c4000000', 1), canonical_source_sha256: sha('c'), artifact_sha256: sha('d'),
  target: { kind: 'line_group_snapshot', snapshot_id: uuid('c5000000', 1), revision: 2, resolver_sha256: sha('e'), resolved_sha256: sha('f') },
  node_count: 1, created_at: ago(2 * 60_000) }
const freshRollout = { id: freshPublication.rollout_id, configuration_scope_id: TENANT_SCOPE, config_version_id: freshPublication.config_version_id,
  action: 'apply', state: 'succeeded', revision: 3, max_attempts: 3, can_cancel: false, can_retry: false,
  progress: { total: 1, pending: 0, running: 0, succeeded: 1, failed: 0, cancelled: 0, superseded: 0, frozen: 0 },
  created_at: ago(2 * 60_000), updated_at: ago(90_000) }
const installHandlers = (step) => (p, u, method) => {
  if (p === '/v1/nodes/registration-credential') return { key_id: 'a'.repeat(32), credential: `nrk1.${'3f9c2a7e'.repeat(4)}.${'Qm9kZVJlZ2lzdHJhdGlvbktleUV4YW1wbGVWYWx1ZQ'}A`, issued_at: ago(10 * 60_000) }
  if (p === '/v1/nodes' && method === 'GET') {
    const status = u.searchParams.get('status')
    const state = step === 'pending' ? 'pending' : 'active'
    return { order: 'management_sort_desc', items: step !== 'command' && (!status || status === state) ? [freshNode(state)] : [] }
  }
  if (p === '/v1/nodes/metrics/latest') return { observed_at: ago(10_000), items: [], not_reported_node_ids: u.searchParams.getAll('node_id') }
  if (p === '/v1/node-line-groups') return { items: [freshLineGroup(step !== 'pending')] }
  if (p === '/v1/admin/users') return { items: [freshUser], page: Number(u.searchParams.get('page') ?? 1), limit: Number(u.searchParams.get('limit') ?? 20), total: 1 }
  if (p === '/v1/sites' && method === 'GET') {
    const page = Number(u.searchParams.get('page') ?? 1), limit = Number(u.searchParams.get('limit') ?? 10)
    return { items: step === 'site' || step === 'published' ? [freshSite] : [], total: step === 'site' || step === 'published' ? 1 : 0, page, limit }
  }
  if (p === '/v1/admin/site-publications') return { items: [freshPublication], current_source_revision: 2 }
  if (p === '/v1/admin/site-rollouts') return { items: [freshRollout] }
  return undefined
}

// ---------- 路由 ----------
const runtimeFeatures = { cache_control: true, custom_rbac: true, plugin_webhooks: true, approval_center: true, market: true, package_auto_renew: true, origin_auth: true }
const unknown = new Set()
const handlers = (role) => {
  const scopeSites = role === 'admin' ? sites : tenantSites
  const scale = role === 'admin' ? 6 : 1
  return (p, u, method) => {
    if (p === '/v1/auth/refresh') return { access_token: token, token_type: 'Bearer', expires_in: 7200, principal: principals[role] }
    if (p === '/v1/auth/me') return principals[role]
    if (p === '/v1/modules') return { status: 'active', lease_serial: 1, modules: [] }
    if (p === '/v1/runtime-features') return { features: runtimeFeatures }
    if (p === '/v1/admin/dashboard') return adminDashboard(u.searchParams.get('range'), u.searchParams.get('timezone'))
    if (p === '/v1/dashboard') return tenantDashboard(u.searchParams.get('range'), u.searchParams.get('timezone'))
    const am = p.match(/^\/v1\/(?:admin\/)?analytics\/(.+)$/)
    if (am) { const r = analyticsResponse(am[1], u, scale, scopeSites); if (r) return r }
    if (p === '/v1/nodes' && method === 'GET') return { order: 'management_sort_desc', items: nodes.map(publicNode) }
    if (p === '/v1/nodes/metrics/latest') {
      const ids = u.searchParams.getAll('node_id')
      return { observed_at: ago(10_000), items: ids.map((id) => nodeMetrics(nodes.find((n) => n.id === id), nodes.findIndex((n) => n.id === id))), not_reported_node_ids: [] }
    }
    if (p === '/v1/nodes/monitoring/latest') {
      const policy = { enabled: true, requested_protocol: 'tcp', requested_port: 80, probe_interval_ms: 10000, probe_timeout_ms: 3000, failure_threshold: 3, recovery_threshold: 2, failure_debounce_ms: 0, recovery_debounce_ms: 0 }
      const activated = ago(30 * D)
      return { schema_version: 1, observed_at: ago(5_000), configuration: { state: 'active', head_revision: 2, active_revision: 2, activated_at: activated, policy },
        items: u.searchParams.getAll('node_id').map((id, i) => ({ node_id: id, freshness: 'fresh', revision_state: 'current', delivery_state: 'serving', stale_after_ms: 43000,
          sample: { source: 'agent_local_tcp', config_revision: 2, active_config_revision: 2, publication_sequence: String(7000 + i), observed_at: ago(6_000), ingested_at: ago(5_500),
            probe_port: 80, healthy: true, probe_succeeded: true, consecutive_failures: 0, consecutive_successes: 20, probes_total: '259200', probe_failures_total: '4',
            recovered: false, recovery_notified: false, rolled_back: false } })) }
    }
    if (p === '/v1/nodes/installation-tickets') return { observed_at: ago(5_000), items: u.searchParams.getAll('node_id').map((id) => ({ node_id: id, state: 'valid', node_status: 'serving', issued_at: ago(30 * D), not_after: iso(NOW.getTime() + 335 * D), days_left: 335, reported_at: ago(H) })) }
    if (p === '/v1/node-line-groups') return { items: lineGroups }
    if (p === '/v1/sites' && method === 'GET') {
      const page = Number(u.searchParams.get('page') ?? 1), limit = Number(u.searchParams.get('limit') ?? 10)
      return { items: scopeSites.slice((page - 1) * limit, page * limit), total: scopeSites.length, page, limit }
    }
    if (p === '/v1/security-policies' && method === 'GET') {
      const kind = u.searchParams.get('kind')
      const items = kind === 'waf' ? [...wafLibraryCopies, ...wafPolicies] : []
      return { items, total: items.length, page: 1, limit: Number(u.searchParams.get('limit') ?? 10), counts: { all: items.length, enabled: items.filter((x) => x.enabled).length, disabled: items.filter((x) => !x.enabled).length } }
    }
    if (p === '/v1/waf-rule-libraries') return { items: wafLibraryList }
    if (p === '/v1/waf-rule-libraries/pending-publications') return { items: [] }
    if (p === '/v1/security-system-rules/republication') return { pending: false, pending_scopes: 0 }
    if (p === '/v1/security-system-rules') return { items: u.searchParams.get('kind') === 'waf_rule_set' ? wafSystemRules : [] }
    if (p === '/v1/dns/providers') return { items: dnsAccounts.map(({ _lines, ...a }) => a) }
    if (p === '/v1/dns/hub/domains') {
      const pid = u.searchParams.get('provider_id')
      return { accounts: dnsAccounts.map((a) => ({ provider_id: a.id, name: a.name, provider_type: a.provider_type, status: 'verified', last_listed_at: ago(20 * 60_000), list_error: '',
        domain_count: dnsDomains.filter((d) => d.provider_id === a.id).length, supported_lines: a._lines, supports_weight: a.provider_type !== 'cloudflare', record_types: ['A', 'AAAA', 'CNAME', 'TXT'] })),
        items: dnsDomains.filter((d) => !pid || d.provider_id === pid), next_cursor: '' }
    }
    const dr = p.match(/^\/v1\/dns\/hub\/domains\/([^/]+)\/([^/]+)\/records$/)
    if (dr) return dnsRecords(decodeURIComponent(dr[1]), decodeURIComponent(dr[2]))
    if (p === '/v1/site-groups') return { items: siteGroups.map((name, i) => ({ id: uuid('e0000000', i + 1), scope_id: TENANT_SCOPE, name, revision: 1, created_at: ago(100 * D), updated_at: ago(100 * D), display_id: String(i + 1) })), total: 4, page: 1, limit: 20 }
    const os = p.match(/^\/v1\/sites\/([^/]+)\/origin-status$/)
    if (os) {
      const detail = siteDetailOf(sites.find((x) => x.id === os[1]) ?? sites[0])
      return { site_id: os[1], failback_mode: 'auto', active_level: 0, overall: 'healthy', failback_ready: true, levels: [{ level: 0, status: 'healthy' }],
        origins: detail.origin_pool.origins.map((o, i) => ({ position: i, host: o.host, port: o.port, level: 0, enabled: true, status: 'healthy', reason: '', checked_at: ago(30_000) })), switched_at: null, checked_at: ago(30_000) }
    }
    if (p === '/v1/admin/market/member') return marketMember
    if (p === '/v1/admin/market/agreements') return { items: marketAgreements }
    if (p === '/v1/admin/market/offers') return { items: marketOffers, next_cursor: null }
    if (p === '/v1/admin/market/plugins') {
      const kind = u.searchParams.get('kind')
      return { items: marketPlugins.filter((x) => !kind || x.kind === kind), next_cursor: null }
    }
    if (p === '/v1/admin/market/licenses') return { items: [], next_cursor: null }
    if (p === '/v1/admin/market/plugin-library') return { items: [] }
    if (p === '/v1/admin/market/advisories') return { items: [] }
    const sd = p.match(/^\/v1\/sites\/([^/]+)$/)
    if (sd) { const s = scopeSites.find((x) => x.id === sd[1]); if (s) return siteDetailOf(s) }
    return undefined
  }
}

// ---------- 英文模拟数据（README_SHOTS_LANG=en）----------
// 整串精确替换；拼出来的串（节点描述、报价标题等）再按片段替换。
const english = {
  平台管理员: 'Platform admin', 示例租户: 'Demo tenant', 星河电商: 'Galaxy Shop', 云帆资讯: 'Sail News', 示例云服务: 'Demo Cloud',
  华东: 'East China', 华南: 'South China', 华北: 'North China', 香港: 'Hong Kong', 上海: 'Shanghai', 广州: 'Guangzhou', 北京: 'Beijing',
  广东: 'Guangdong', 浙江: 'Zhejiang', 江苏: 'Jiangsu', 四川: 'Sichuan', 湖北: 'Hubei', 福建: 'Fujian', 山东: 'Shandong', 中国: 'China', 中国大陆: 'Mainland China',
  电信: 'China Telecom', 联通: 'China Unicom', 移动: 'China Mobile', 教育网: 'CERNET', 其他: 'Other', 微信: 'WeChat', 默认: 'Default', 境外: 'Overseas',
  默认线路: 'Default line', 华东加速: 'East China accel', 华南加速: 'South China accel', '全国 BGP': 'Nationwide BGP', 香港海外: 'Hong Kong overseas',
  官网: 'Website', 电商: 'E-commerce', 资讯: 'News', 静态资源: 'Static assets', 企业版: 'Enterprise', 专业版: 'Professional', 基础版: 'Basic',
  电商站点防护: 'E-commerce protection', '登录与下单接口的注入、爬虫与撞库拦截': 'Blocks injection, scraping and credential stuffing on login and checkout',
  官网基础防护: 'Website baseline', '常见扫描器与敏感路径拦截': 'Blocks common scanners and sensitive paths',
  'API 接口白名单': 'API allowlist', '仅放行合作方网段，其余拦截': 'Only partner ranges are allowed',
  资讯站评论区防护: 'Comment protection', '评论接口 XSS 与垃圾内容过滤': 'Filters XSS and spam on the comment API',
  静态资源防盗链: 'Hotlink protection', 'Referer 校验，拒绝外链引用': 'Referer check against hotlinking',
  后台路径保护: 'Admin path protection', '/admin 仅允许办公网访问': '/admin from the office network only',
  拦截扫描器: 'Block scanners', 敏感路径: 'Sensitive paths',
  'OWASP 核心规则集': 'OWASP Core Rule Set', 'SQL 注入、XSS、命令执行等通用攻击检测': 'Detects SQL injection, XSS, command execution and more',
  'WordPress 专项防护': 'WordPress protection', 'xmlrpc、插件漏洞与暴力登录防护': 'xmlrpc, plugin exploits and brute-force logins',
  恶意爬虫与扫描器: 'Bad bots and scanners', '常见扫描器、采集器 User-Agent 与行为特征': 'Scanner and scraper User-Agents and behavior',
  'SQL 注入检测': 'SQL injection', 跨站脚本检测: 'Cross-site scripting', 命令执行检测: 'Command execution', 路径穿越检测: 'Path traversal', 扫描器识别: 'Scanner detection',
  'SQL 注入': 'SQL injection', 跨站脚本: 'XSS', 命令执行: 'Command execution', 文件包含: 'File inclusion', 扫描器: 'Scanners',
  '阿里云 DNS（主账号）': 'Alibaba Cloud DNS (main)', '华为云 DNS': 'Huawei Cloud DNS',
  'WordPress 防护规则包': 'WordPress protection pack', '针对 xmlrpc、wp-login 暴力破解与常见插件漏洞的规则集合，开箱即用。': 'Ready-to-use rules for xmlrpc, wp-login brute force and common plugin exploits.',
  'API 接口防刷规则包': 'API abuse protection pack', '按接口路径限速、签名校验失败拦截、异常参数检测，适合开放 API。': 'Per-path rate limits, signature failure blocking and parameter checks for public APIs.',
  恶意爬虫识别规则包: 'Bad bot detection pack', '覆盖 300+ 采集器与扫描器特征，配合 JS 挑战降低误杀。': 'Signatures for 300+ scrapers and scanners, paired with JS challenges to cut false positives.',
  'Aurora 控制台主题': 'Aurora console theme', '深浅双色的控制台主题，含登录页、错误页与用户端整套样式。': 'Light and dark console theme with login, error and user console styles.',
  极简白主题: 'Minimal white theme', '大留白、细线条的简洁风格，适合面向企业客户的白标部署。': 'Airy, thin-line style for white-label enterprise deployments.',
  'DNS.LA 解析接入': 'DNS.LA integration', '在多家 DNS 统一管理中接入 DNS.LA 账号，支持分线路解析。': 'Adds DNS.LA accounts to multi-provider DNS, with per-line resolution.',
  '华东三网 CDN 套餐 · 标准版': 'East China tri-carrier CDN · Standard', '全国 BGP 高防加速': 'Nationwide BGP with DDoS protection',
  '华南电信精品线路 · 按流量': 'South China Telecom premium · per GB', '香港 CN2 GIA 国际加速': 'Hong Kong CN2 GIA international',
  '北方联通大带宽 · 日峰值计费': 'North China Unicom high bandwidth · daily peak', '视频点播专用 · 按流量': 'Video on demand · per GB', '入门体验包 · 小站点': 'Starter pack · small sites',
  示例条款: 'Sample terms', '(直接访问)': '(direct)',
  '社区版 1.0.35 已发布：新增多家 DNS 统一管理': 'Community Edition 1.0.35 released: multi-provider DNS', '节点维护通知：华南线路例行升级': 'Maintenance: South China line upgrade',
}
const englishFragments = [['边缘节点', ' edge node']]
function toEnglish(value) {
  if (typeof value === 'string') {
    if (Object.hasOwn(english, value)) return english[value]
    if (!/[\u4e00-\u9fff]/.test(value)) return value
    let out = value
    for (const [zh, en] of Object.entries(english).sort((a, b) => b[0].length - a[0].length)) out = out.split(zh).join(` ${en} `)
    for (const [zh, en] of englishFragments) out = out.split(zh).join(en)
    return out.replace(/\s+/g, ' ').trim()
  }
  if (Array.isArray(value)) return value.map(toEnglish)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toEnglish(v)]))
  return value
}

// 终端截图：scripts/ui/readme-install-transcript.sh 用真实 install-progress.sh 生成的输出（含 ANSI 颜色）。
const ansiHTML = (text) => {
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  const colors = { 1: 'font-weight:700', 31: 'color:#f87171', 32: 'color:#4ade80' }
  let open = false
  return esc(text).replace(/\x1b\[(\d*)m/g, (_, code) => {
    const close = open ? '</span>' : ''
    open = Boolean(colors[code])
    return close + (open ? `<span style="${colors[code]}">` : '')
  }).replace(/^(root@[^#]+#)/gm, '<span style="color:#60a5fa">$1</span>') + (open ? '</span>' : '')
}
async function shootTerminal(browser, { file, terminal }) {
  const { execFileSync } = await import('node:child_process')
  const text = execFileSync('bash', [path.join(repoRoot, 'scripts/ui/readme-install-transcript.sh'), terminal], { encoding: 'utf8' })
  const page = await browser.newPage({ viewport: { width: 1280, height: 400 }, deviceScaleFactor: 1 })
  await page.setContent(`<!doctype html><meta charset="utf-8"><body style="margin:0;background:#0f172a">
    <div style="padding:14px 18px 6px;display:flex;gap:8px">${['#ef4444', '#f59e0b', '#22c55e'].map((c) => `<i style="width:12px;height:12px;border-radius:50%;background:${c}"></i>`).join('')}</div>
    <pre style="margin:0;padding:6px 22px 22px;color:#e2e8f0;font:14px/1.55 Menlo,'PingFang SC',monospace;white-space:pre-wrap">${ansiHTML(text.trimEnd())}</pre></body>`)
  await page.screenshot({ path: path.join(outDir, file), fullPage: true })
  console.log(`${file} OK`)
  await page.close()
}

async function shoot(browser, { file, role, path: route, ready, before, install, final }) {
  const page = await browser.newPage({ viewport: { width: 1600, height: 900 }, locale: lang === 'en' ? 'en-US' : 'zh-CN', timezoneId: 'Asia/Shanghai', deviceScaleFactor: 1 })
  await page.addInitScript((locale) => window.localStorage.setItem('cdnca.locale', locale), lang === 'en' ? 'en-US' : 'zh-CN')
  // 节点安装命令需要 install-control.sh 写进 runtime-config.js 的升级信任摘要（这里是占位值）。
  if (install) await page.addInitScript(() => { window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = '7'.repeat(64) })
  const problems = []
  page.on('pageerror', (e) => problems.push(`pageerror ${e.message.slice(0, 200)}`))
  page.on('console', async (m) => { if (m.type() === 'error') problems.push(`console ${(await Promise.all(m.args().slice(1, 2).map((a) => a.jsonValue().catch(() => '')))).join(' ')} ${m.text().slice(0, 120)}`) })
  const handle = handlers(role)
  const installHandle = install ? installHandlers(install) : () => undefined
  await page.route('**/v1/**', async (r) => {
    const req = r.request(); const u = new URL(req.url()); const p = u.pathname
    if (p === '/v1/observability/frontend-events') return r.fulfill({ status: 204 })
    // 未登录（登录页）：刷新会话返回 401，登录方式只开密码登录。
    // 没有进行中的四层线路切换（服务端对此返回 404 l4_line_switch_not_found）。
    if (install && /\/l4-line-switches\/current$/.test(p)) return r.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: { code: 'l4_line_switch_not_found', message: 'not found' } }) })
    if (role === 'guest') {
      if (p === '/v1/auth/refresh') return r.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { code: 'unauthorized', message: 'unauthorized' } }) })
      if (p === '/v1/auth/login-methods') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ data: { registration_enabled: false } }) })
    }
    let body
    try { body = installHandle(p, u, req.method()) ?? handle(p, u, req.method()) } catch (e) { problems.push(`mock ${p} ${e.message}`) }
    if (body === undefined && !/^\/v1\/(theme\/current|admin\/inbox|account\/inbox|installation-lock|admin\/system-settings|system-settings\/public|admin\/tickets\/summary|plugin-ui\/pages|account\/messages)/.test(p)) unknown.add(`${file} ${req.method()} ${p}${u.search}`)
    if (body === undefined) body = { items: [] }
    return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(lang === 'en' ? toEnglish(body) : body) })
  })
  await page.goto(`${base}${route}`, { waitUntil: 'networkidle' })
  if (before) await before(page)
  if (ready) await page.getByText(ready).first().waitFor({ timeout: 15000 }).catch(() => problems.push(`未出现「${ready}」`))
  await page.waitForTimeout(1500)
  await page.mouse.move(0, 899)
  if (final) await final(page)
  await page.screenshot({ path: path.join(outDir, file), fullPage: false })
  console.log(`${file}${problems.length ? `\n  ${problems.join('\n  ')}` : ' OK'}`)
  await page.close()
}

const shots = [
  { file: 'admin-overview.png', role: 'admin', path: '/admin-home' },
  { file: 'admin-nodes.png', role: 'admin', path: '/node/list' },
  { file: 'admin-sites.png', role: 'admin', path: '/site/list' },
  { file: 'admin-waf.png', role: 'admin', path: '/site/waf-rule' },
  { file: 'admin-realtime.png', role: 'admin', path: '/monitor/site/realtime' },
  { file: 'user-overview.png', role: 'user', path: '/home' },
  { file: 'user-site-edit.png', role: 'user', path: `/site/${tenantSites[0].id}/edit` },
  { file: 'user-dns-hub.png', role: 'user', path: '/site/dns-hub', before: async (page) => { await page.locator('.dns-hub-domain').first().click(); await page.waitForTimeout(800) } },
  { file: 'user-analysis.png', role: 'user', path: '/monitor/site/analysis' },
  { file: 'market-plugins.png', role: 'admin', path: '/sys/plugin-store' },
  { file: 'market-nodes.png', role: 'admin', path: '/sys/node-market' },
  // 安装指南（README「安装」一节），按安装顺序。
  { file: 'install-1-control.png', terminal: 'control' },
  { file: 'install-2-login.png', role: 'guest', path: '/login' },
  { file: 'install-3-node-command.png', role: 'admin', path: '/node/list', install: 'command',
    before: async (page) => { await page.locator('.node-toolbar-actions button.ant-btn-primary').first().click(); await page.locator('.node-install-command textarea').waitFor() },
    // 开发服务器的本机地址换成示例管理端域名（命令其余部分是 buildNodeInstallCommand 的原样输出）。
    final: (page) => page.locator('.node-install-command textarea').evaluate((el) => { el.value = el.value.replaceAll(window.location.origin, 'https://console.example.com') }) },
  { file: 'install-4-node.png', terminal: 'node' },
  { file: 'install-5-node-init.png', role: 'admin', path: '/node/list', install: 'pending',
    before: async (page) => { await page.locator('.node-tabs .ant-tabs-tab').nth(1).click(); await page.waitForTimeout(800) } },
  { file: 'install-6-line-group.png', role: 'admin', path: '/node/line-group', install: 'active' },
  { file: 'install-7-site-create.png', role: 'admin', path: '/site/list', install: 'active',
    before: async (page) => { await page.locator('.site-list-page button.ant-btn-primary, button.ant-btn-primary').filter({ hasText: /添加|Add/ }).first().click(); await page.waitForTimeout(800)
      const dialog = page.locator('.ant-modal-content')
      await dialog.locator('.ant-select').first().click(); await page.locator('.ant-select-item-option').first().click()
      const inputs = dialog.locator('input.ant-input, textarea.ant-input')
      await inputs.nth(0).fill('www.example.com'); await inputs.nth(1).fill('198.51.100.20:80'); await page.waitForTimeout(400) } },
  { file: 'install-8-publications.png', role: 'admin', path: `/site/publications?target_scope_id=${TENANT_SCOPE}`, install: 'published' },
  { file: 'install-9-site-ready.png', role: 'admin', path: '/site/list', install: 'published' },
]
const wanted = only ? only.split(',') : []
const browser = await chromium.launch({ channel: 'chrome', headless: true })
try {
  for (const shot of shots) {
    if (wanted.length && !wanted.some((w) => shot.file.startsWith(w))) continue
    await (shot.terminal ? shootTerminal(browser, shot) : shoot(browser, shot))
  }
} finally {
  await browser.close()
}
if (unknown.size) console.log(`未模拟的接口：\n  ${[...unknown].join('\n  ')}`)
