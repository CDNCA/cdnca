// fix-l4flow3 本地 mock 截图（不连真实主控）：四层详情页源站池/ACL/IPv6/运营与同步状态、结果未知冻结，
// 以及 fix-l4flow2 的单个新建预填与批量「未写 /tcp…」提示。
//   node apps/web/scripts/fix-l4flow3-shot.mjs <baseURL> <输出目录>
import { chromium } from 'playwright-core'
import fs from 'node:fs'

const [base, out] = process.argv.slice(2)
fs.mkdirSync(out, { recursive: true })
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const tenant = '22222222-2222-4222-8222-222222222222'
const principal = {
  user_id: '44444444-4444-4444-8444-444444444444', scope_id: tenant, scope_kind: 'tenant', tenant_id: tenant,
  username: 'jason', display_name: 'jason', roles: ['tenant_owner'], permissions: ['streams.read', 'streams.manage'],
}
const auth = { access_token: token, token_type: 'Bearer', expires_in: 3600, principal }
const id = '11111111-1111-4111-8111-111111111111'
const geo = { enabled: false, unknown_region_action: 'allow', trusted_proxy_cidrs: [], blocked_regions: [], region_cidrs: [] }
const dns = { positive_min_ttl_seconds: 0, positive_max_ttl_seconds: 0, negative_ttl_seconds: 0, stale_if_error_seconds: 0, allow_private_addresses: false }
const origins = [{ address: '192.0.2.10', weight: 7, down: false }, { address: '192.0.2.11', weight: 3, down: false }, { address: '192.0.2.12', weight: 1, down: true }]
const acl = { default_action: 'deny', rules: [{ cidr: '198.51.100.0/24', action: 'allow' }, { cidr: '203.0.113.7/32', action: 'allow' }] }
const stream = {
  id, display_id: '1', scope_id: tenant, eligibility_state: 'eligible', origins, listen_ipv6: true, acl, admin_status: 'locked',
  line: { region_id: null, region_name: '', node_group_id: null, node_group_name: '', backup_node_group_id: null, backup_node_group_name: '' },
  overrides: { cname_domain: null, cname_mode: null, region_id: null, node_group_id: null, backup_node_group_id: null },
  sync_state: 'failed', package_subscription_id: '55555555-5555-4555-8555-555555555555', package_name: '四层基础版', package_expires_at: '2027-01-01T00:00:00Z',
  owner: { id: principal.user_id, display_name: 'jason' }, name: 'TCP gateway', remark: '游戏登录服', protocol: 'tcp',
  listen_address: '*', listen_port: 18100, upstream_address: '192.0.2.10', upstream_host: '', upstream_port: 9000, dns_policy: dns, geo_policy: geo,
  connect_timeout_ms: 3000, response_timeout_ms: 30000, max_connections_per_client: 100, proxy_protocol_inbound: false, proxy_protocol_v1: false,
  balance_way: 'rr', groups: [], enabled: true, tls_passthrough: false, server_names: [], max_new_connections_per_client_per_second: 0,
  new_connection_burst: 0, new_connection_ban_seconds: 0, toa: false, session_log_enabled: false, guard_rules: [], revision: 3, cname: 'xu9zbvwd.cdnca.com',
  publish_intent: {
    id: '33333333-3333-4333-8333-333333333333', version: 3, operation: 'update', desired_state: 'enabled', resource_revision: 3,
    configuration_source_revision: 41, state: 'failed', automatic_request_id: null, publication_id: '66666666-6666-4666-8666-666666666666', rollout_id: null,
    created_at: '2026-10-27T08:00:00Z',
    runtime_spec: {
      schema_version: 'cdnca.edge.l4/v2', tenant_id: tenant, stream_id: id, revision: 3,
      listener: { protocol: 'tcp', address: '*', port: 18100 },
      endpoint: { address: '192.0.2.10', port: 9000, origins: origins.map((o) => ({ address: o.address, weight: o.weight, ...(o.down ? { down: true } : {}) })) },
      dns, geo: { ...geo, tenant_id: tenant, stream_id: id, revision: 3 },
      connect_timeout_ms: 3000, response_timeout_ms: 30000, max_connections_per_client: 100, drain_timeout_ms: 30000,
      proxy_protocol_inbound: false, proxy_protocol_outbound: false, listen_ipv6: true,
      guard_rules: [{ id: '77777777-7777-4777-8777-777777777771', action: 'allow', client_ip: { cidrs: ['198.51.100.0/24', '203.0.113.7/32'] } },
        { id: '77777777-7777-4777-8777-777777777772', action: 'drop', client_ip: { cidrs: ['0.0.0.0/0', '::/0'] } }],
    },
  },
  created_at: '2026-10-20T00:00:00Z', updated_at: '2026-10-27T08:00:00Z',
}

const browser = await chromium.launch({ channel: 'chrome', headless: true })
for (const [label, viewport] of [['1440', { width: 1440, height: 900 }], ['390', { width: 390, height: 844 }]]) {
  const context = await browser.newContext({ viewport, locale: 'zh-CN', timezoneId: 'Asia/Shanghai' })
  const page = await context.newPage()
  let failUpdate = false
  await page.route('**/v1/**', (route) => {
    const req = route.request()
    const p = new URL(req.url()).pathname
    const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (p === '/v1/auth/refresh') return json(auth)
    if (p === '/v1/auth/me') return json(principal)
    if (p === '/v1/modules') return json({ status: 'active', lease_serial: 1, modules: [] })
    if (p === '/v1/user-configs/effective') return json({ protocol: 'udp', proxy_protocol_inbound: null, balance_way: 'ip_hash' })
    if (p === `/v1/streams/${id}` && req.method() === 'PATCH' && failUpdate) return json({ error: { code: 'temporarily_unavailable', message: 'mock' } }, 503)
    if (p === `/v1/streams/${id}`) return json(stream)
    if (p === '/v1/streams') return json({ items: [stream], total: 1, page: 1, limit: 10 })
    return json({ items: [], total: 0, page: 1, limit: 100 })
  })
  const shot = (name) => page.screenshot({ path: `${out}/${label}-${name}.png`, fullPage: name.startsWith('detail') })
  const audit = () => page.evaluate(() => ({ overflowX: document.documentElement.scrollWidth > window.innerWidth,
    focusOutline: (() => { const el = document.querySelector('.stream-origin-table input'); if (!el) return null; el.focus(); const c = getComputedStyle(el); return { outline: c.outlineStyle, shadow: c.boxShadow !== 'none' } })(),
    deleteButton: (() => { const el = document.querySelector('.stream-origin-table td:last-child button'); if (!el) return null; const r = el.getBoundingClientRect(); return { w: Math.round(r.width), h: Math.round(r.height), label: el.getAttribute('aria-label') } })() }))
  const step = async (name, fn) => { try { await fn() } catch (e) { console.log(label, 'step fail', name, String(e).slice(0, 300)) } }

  await step('detail-basic', async () => {
    await page.goto(`${base}/dashboard/stream/list/${id}`, { waitUntil: 'networkidle' })
    await page.getByRole('heading', { name: '端口 18100' }).waitFor({ timeout: 30000 })
    await page.waitForTimeout(800)
    await shot('detail-1-basic')
    console.log(label, 'audit', JSON.stringify(await audit()))
  })
  await step('publication', async () => {
    await page.locator('.stream-detail-facts').getByRole('button', { name: '发布详情' }).click()
    await page.getByRole('dialog', { name: '发布详情' }).waitFor()
    await page.waitForTimeout(400)
    await page.screenshot({ path: `${out}/${label}-detail-2-publication.png` })
    await page.getByRole('button', { name: '关闭' }).last().click()
    await page.waitForTimeout(300)
  })
  await step('access', async () => {
    await page.getByRole('tab', { name: '访问控制' }).click()
    await page.waitForTimeout(500)
    await shot('detail-3-access')
  })
  await step('unknown', async () => {
    await page.getByRole('tab', { name: '基本配置' }).click()
    failUpdate = true
    await page.getByLabel('备注').fill('结果未知演示')
    await page.getByRole('button', { name: '保存' }).click()
    await page.getByRole('button', { name: '按原请求重试' }).waitFor()
    await page.waitForTimeout(400)
    await page.screenshot({ path: `${out}/${label}-detail-4-unknown.png` })
    failUpdate = false
  })
  await step('single-create', async () => {
    await page.goto(`${base}/dashboard/stream/list`, { waitUntil: 'networkidle' })
    await page.getByRole('button', { name: '添加转发' }).click()
    await page.getByRole('dialog', { name: '添加转发' }).waitFor()
    await page.waitForTimeout(800)
    await page.screenshot({ path: `${out}/${label}-create-1-single.png` })
    await page.getByRole('tab', { name: '批量' }).click()
    await page.getByText('未写 /tcp 或 /udp 的端口按').waitFor()
    await page.waitForTimeout(400)
    await page.screenshot({ path: `${out}/${label}-create-2-batch.png` })
  })
  await context.close()
}
await browser.close()
