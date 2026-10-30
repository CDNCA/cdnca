// 页面改前/改后截图 + 横向滚动容器计数（mock 接口）。
// 用法：node scripts/ui/fix-dblscroll-shot.mjs <base> <outDir> <before|after> [page...]
// page：history（刷新预热→操作记录，租户）、nodes（节点列表，平台管理员）。
// 计数规则：页面内 scrollWidth > clientWidth 且 overflow-x 为 auto/scroll 的元素，
// 以及 document 本身是否横向溢出（390 宽不应整页溢出）。
import { chromium } from 'playwright-core'

const [base, out, tag, ...only] = process.argv.slice(2)
const pages = only.length ? only : ['history', 'nodes']
// 经典（常显）滚动条：与用户 Windows/常显设置一致，两条滚动条才看得见。
const browser = await chromium.launch({ channel: 'chrome', headless: true, args: ['--hide-scrollbars=false', '--disable-features=OverlayScrollbar'] })
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const tenantID = '22222222-2222-4222-8222-222222222222'
const tenant = { user_id: '11111111-1111-4111-8111-111111111111', scope_id: tenantID, scope_kind: 'tenant', tenant_id: tenantID,
  username: 'demo', display_name: 'demo', roles: ['tenant_owner'], permissions: ['sites.read', 'sites.manage'] }
const platform = { user_id: '0199aaaa-1111-7111-8111-111111111111', scope_id: '0199aaaa-2222-7222-8222-222222222222', scope_kind: 'platform', tenant_id: null,
  username: 'admin', display_name: 'admin', roles: ['platform_owner'], permissions: ['nodes.read', 'nodes.manage', 'regions.read', 'line_groups.read', 'node_scheduling.read'] }

const operation = (n) => ({
  id: `55555555-5555-4555-8555-5555555555${String(n).padStart(2, '0')}`, display_id: String(n), site_id: '33333333-3333-4333-8333-333333333333', site_display_id: '3',
  action: n % 3 ? 'purge' : 'prewarm', target_type: 'exact_url', state: n % 4 ? 'succeeded' : 'partial_failed', max_attempts: 4, auto_nodes: false,
  progress: { total: 2, completed: 2, succeeded: n % 4 ? 2 : 1, failed: n % 4 ? 0 : 1, cancelled: 0 },
  target_count: 1, node_count: 2,
  first_target: { ordinal: 1, display_url: `https://www.example.test/static/app-${n}.js`, canonical_path: `/static/app-${n}.js`, target_sha256: 'a'.repeat(64), query_redacted: false },
  created_at: '2026-10-27T07:59:00Z', updated_at: '2026-10-27T08:00:00Z', completed_at: '2026-10-27T08:00:00Z',
})
const node = (n) => ({ id: `018f0000-0000-7000-8000-0000000000${String(n).padStart(2, '0')}`, display_id: String(n),
  name: `edge-sh-${n}`, description: '机房 A 机柜 12', region: '华东-上海电信', ipv4: `192.0.2.${10 + n}`, admin_state: 'active',
  management_settings: { schema_version: 1, sort: 100 - n, node_type: 'L1', cache_directory: '/c', cache_limit_gb: 500, log_directory: '/l',
    ip_location: { country: '中国', province: '上海', city: '上海', isp: '电信', country_code: 'CN' },
    auto_disable: { bandwidth_limit: 0, bandwidth_unit: 'Mbps', traffic_enabled: false, traffic_from_day: 1, traffic_from_time: '00:00:00',
      traffic_total_gb: 0, traffic_types: ['outbound'], excluded_interfaces: '', disabled_periods: '' }, secondary_ips: [], external_probe: true },
  revision: 4, created_at: '2026-10-20T08:00:00Z', updated_at: '2026-10-20T09:00:00Z',
  presence: { status: 'online', last_heartbeat_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), agent_version: '1.0.35', session_epoch: 7,
    heartbeat_sequence: 11, projection_freshness: 'fresh', lease_signal: 'present' } })

const targets = {
  history: { principal: tenant, path: '/site/cache-clean/history', ready: '.cache-operation-history-table .ant-table-row' },
  nodes: { principal: platform, path: '/node/list', ready: '[data-testid="node-table-scroll"] .ant-table-row' },
}

for (const name of pages) {
  const target = targets[name]
  for (const [width, height] of [[1440, 900], [390, 844]]) {
    const page = await browser.newPage({ viewport: { width, height }, locale: 'zh-CN' })
    await page.route('**/v1/**', (route) => {
      const u = new URL(route.request().url()), p = u.pathname
      const json = (body, s = 200) => route.fulfill({ status: s, contentType: 'application/json', body: JSON.stringify(body) })
      if (p === '/v1/auth/refresh') return json({ access_token: token, token_type: 'Bearer', expires_in: 3600, principal: target.principal })
      if (p === '/v1/auth/me') return json(target.principal)
      if (p === '/v1/modules') return json({ status: 'active', lease_serial: 1, modules: [] })
      if (p.endsWith('/cache-operations')) return json({ items: Array.from({ length: 8 }, (_, i) => operation(20 - i)), next_cursor: 'c2' })
      if (p === '/v1/nodes') { const items = [1, 2, 3, 4, 5].map(node); return json(u.searchParams.get('order') ? { order: 'management_sort_desc', items } : { items }) }
      return json({ data: [], items: [], total: 0, page: 1, page_size: 20 })
    })
    await page.goto(`${base}/dashboard${target.path}`, { waitUntil: 'networkidle' })
    await page.locator(target.ready).first().waitFor({ timeout: 15000 })
    await page.waitForTimeout(500)
    await page.screenshot({ path: `${out}/${tag}-${name}-${width}.png`, fullPage: true })
    const info = await page.evaluate(() => {
      const main = document.querySelector('.app-main') ?? document.body
      const scrollers = [...main.querySelectorAll('*')].filter((el) => {
        const s = getComputedStyle(el)
        return /auto|scroll/.test(s.overflowX) && el.scrollWidth > el.clientWidth + 1 && el.closest('.ant-table-wrapper, [class*="table"]')
      }).map((el) => el.className.toString().split(' ').slice(0, 2).join('.'))
      const doc = document.scrollingElement
      return { scrollers, pageOverflow: doc.scrollWidth > doc.clientWidth + 1 }
    })
    console.log(tag, name, width, JSON.stringify(info))
    await page.close()
  }
}
await browser.close()
