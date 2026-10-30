// 节点冻结标签截图（mock 接口，不连真实主控）。
//   NODE_PATH=<playwright-core 所在 node_modules> node scripts/ui/fix-stoppolicy2-shot.mjs <baseURL> <输出目录>
// 节点列表（状态列“已冻结”+悬停说明）与节点详情（授权票据行：原因、恢复条件、最近票据到期时间）；1440 与 390 两种宽度。
import { createRequire } from 'node:module'
import path from 'node:path'

const require = createRequire(path.join(process.env.NODE_PATH ?? '', 'x.js'))
const { chromium } = require('playwright-core')

const [base, out] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const iso = (seconds) => new Date(seconds * 1000).toISOString()
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const principal = {
  user_id: '11111111-1111-4111-8111-111111111112', scope_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', scope_kind: 'platform', tenant_id: null,
  username: 'admin', display_name: 'admin', roles: ['platform_admin'], permissions: ['platform.admin', 'nodes.read'],
}
const auth = { access_token: token, token_type: 'Bearer', expires_in: 3600, principal }
const settings = {
  schema_version: 1, sort: 100, node_type: 'L1', cache_directory: '', cache_limit_gb: 0, log_directory: '',
  ip_location: { country: '', province: '', city: '', isp: '', country_code: '' },
  auto_disable: { bandwidth_limit: 0, bandwidth_unit: 'Mbps', traffic_enabled: true, traffic_from_day: 1, traffic_from_time: '00:00:00',
    traffic_total_gb: 500, traffic_types: ['outbound'], excluded_interfaces: '', disabled_periods: '' },
  secondary_ips: [], external_probe: true,
}
const node = (n, name) => ({
  id: `018f0000-0000-7000-8000-00000000000${n}`, display_id: String(n), name, description: '', region: '华东',
  ipv4: `203.0.113.${n}`, admin_state: 'active', management_settings: settings, revision: 1, created_at: iso(now - 86400 * 60),
  updated_at: iso(now - 3600),
  presence: { status: 'online', projection_freshness: 'fresh', lease_signal: 'present', agent_version: '1.0.35',
    last_heartbeat_at: iso(now - 5), session_epoch: 2, heartbeat_sequence: 30 },
})
const nodes = [node(3, 'edge-gz-01'), node(2, 'edge-sh-02'), node(1, 'edge-sh-01')] // management_sort_desc order
const ticket = (item, frozen) => ({
  node_id: item.id, state: frozen ? 'expired' : 'valid', node_status: frozen ? 'service_ticket_expired' : 'serving',
  issued_at: iso(now - 86400 * (frozen ? 32 : 3)), not_after: iso(now + 86400 * (frozen ? -2 : 27)),
  days_left: frozen ? 0 : 27, reported_at: iso(now - 60),
})
const frozenIDs = new Set([nodes[1].id])

const browser = await chromium.launch({ channel: 'chrome', headless: true })
for (const [label, viewport] of [['1440', { width: 1440, height: 900 }], ['390', { width: 390, height: 844 }]]) {
  const context = await browser.newContext({ viewport, locale: 'zh-CN', timezoneId: 'Asia/Shanghai' })
  const page = await context.newPage()
  await page.route('**/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const p = url.pathname
    const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (p === '/v1/auth/refresh') return json(auth)
    if (p === '/v1/auth/me') return json(principal)
    if (p === '/v1/installation-lock') return json({ locked: false })
    if (p === '/v1/nodes') return json({ items: nodes, order: 'management_sort_desc' })
    if (p === '/v1/nodes/installation-tickets') {
      return json({ observed_at: iso(now), items: url.searchParams.getAll('node_id').map((id) => ticket(nodes.find((n) => n.id === id), frozenIDs.has(id))) })
    }
    const detail = nodes.find((n) => p === `/v1/nodes/${n.id}`)
    if (detail) return json(detail)
    return json({ error: { code: 'not_found', message: 'mock' } }, 404)
  })

  await page.goto(`${base}/node/list`, { waitUntil: 'networkidle' })
  const tag = page.locator('.node-frozen-tag').first()
  await tag.waitFor({ timeout: 30000 })
  await tag.scrollIntoViewIfNeeded()
  await tag.hover()
  await page.getByRole('tooltip').filter({ hasText: '恢复条件' }).waitFor({ timeout: 10000 })
  await page.waitForTimeout(300)
  await page.screenshot({ path: `${out}/node-list-frozen-${label}.png` })
  console.log('list', label, JSON.stringify(await page.evaluate(() => ({ overflowX: document.documentElement.scrollWidth > window.innerWidth }))))

  await page.goto(`${base}/node/list/${nodes[1].id}`, { waitUntil: 'networkidle' })
  // Mock sign-in bumps the session epoch while the first detail read is in
  // flight (that read is dropped as stale); retry once like a user would.
  const retry = page.getByRole('button', { name: '重试' })
  const ready = page.locator('.node-frozen-detail')
  await Promise.race([ready.waitFor({ timeout: 30000 }), retry.waitFor({ timeout: 30000 })])
  if (await retry.isVisible()) await retry.click()
  await page.locator('.node-frozen-detail').waitFor({ timeout: 30000 })
  await page.locator('.node-frozen-detail').scrollIntoViewIfNeeded()
  await page.waitForTimeout(300)
  await page.screenshot({ path: `${out}/node-detail-frozen-${label}.png`, fullPage: true })
  console.log('detail', label, JSON.stringify(await page.evaluate(() => ({ overflowX: document.documentElement.scrollWidth > window.innerWidth }))))
  await context.close()
}
await browser.close()
