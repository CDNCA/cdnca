// fix-logowner LOG-01 本地 mock 截图：日志视图就地显示当前条件已有的下载申请（不连真实主控）。
// 场景：failed（失败原因+重试）、running（正在生成）、completed（可下载）。
// 依赖 playwright-core 与系统 Chrome；先起 vite dev，再：
//   node fix-logowner-shot.mjs <baseURL 如 http://127.0.0.1:5796> <输出目录>
import { chromium } from 'playwright-core'

const [base, out] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const tenant = {
  user_id: '0199aaaa-1111-7111-8111-111111111111', scope_id: '0199aaaa-2222-7222-8222-222222222222', scope_kind: 'tenant',
  tenant_id: '0199aaaa-3333-7333-8333-333333333333', username: 'shop-owner', display_name: '商城运维', roles: ['tenant_owner'],
  permissions: ['sites.read'],
}
const features = { cache_control: true, custom_rbac: false, plugin_webhooks: false, approval_center: false, market: false, package_auto_renew: false, origin_auth: false }
const event = (i) => ({
  event_id: `0199bbbb-0000-7000-8000-00000000000${i}`, occurred_at: `2026-10-28T07:59:0${i}Z`,
  site_id: '0199cccc-0000-7000-8000-000000000001', node_id: '0199dddd-0000-7000-8000-000000000001',
  request_id: `req-${i}`, trace_id: '0af7651916cd43dd8448eb211c80319c', config_version_id: '0199eeee-0000-7000-8000-000000000001',
  host: 'shop.example.test', listen_port: 443, uri_path: `/static/app-${i}.js`, client_ip: '192.0.2.10', country_code: 'CN', carrier: 'CMCC',
  method: 'GET', protocol: 'HTTP/2', cache_status: 'HIT', upstream_result: 'ok', upstream_addr: '', status_code: 200,
  request_bytes: 128, response_bytes: 1024, duration_us: 900, task_id: `task-${i}`, installation_id: 'installation-1',
  request_headers: { 'X-Request-Class': 'asset' }, response_headers: { 'Set-Cookie': '[REDACTED]' },
  request_body: { profile: { name: 'demo' } }, response_body: { cached: true },
  ja4: 't13d1516h2_8daaf6152771', origin_connect_us: 100, origin_first_byte_us: 250, origin_total_us: 400,
})
const base_export = {
  id: '0199ffff-0000-7000-8000-000000000081', snapshot_at: null, row_count: null, byte_count: null,
  created_at: '2026-10-28T08:00:01Z', expires_at: null, downloadable: false,
}
const scenes = {
  failed: { ...base_export, status: 'failed', reason: 'export_rejected' },
  running: { ...base_export, status: 'running', reason: 'running' },
  completed: {
    ...base_export, status: 'completed', reason: 'completed', snapshot_at: '2026-10-28T08:00:00Z', row_count: 1200, byte_count: 20480,
    sha256: 'a'.repeat(64), expires_at: '2999-01-01T00:00:00Z', downloadable: true,
  },
}

const browser = await chromium.launch({ channel: 'chrome' })
for (const [name, job] of Object.entries(scenes)) {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({ viewport: { width, height: width > 600 ? 900 : 844 }, locale: 'zh-CN' })
    await page.route('**/v1/**', (route) => {
      const url = new URL(route.request().url())
      if (process.env.SHOT_TRACE) console.error('REQ', route.request().method(), url.pathname + url.search)
      const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
      if (url.pathname === '/v1/auth/refresh') return json({ access_token: token, token_type: 'Bearer', expires_in: 3600, principal: tenant })
      if (url.pathname === '/v1/auth/me') return json(tenant)
      if (url.pathname === '/v1/runtime-features') return json({ features })
      if (url.pathname === '/v1/analytics/logs/access/exports') return json({ data: [job] })
      if (url.pathname === '/v1/analytics/logs/access') {
        return json({ data: [1, 2, 3].map(event), meta: {
          from: url.searchParams.get('from'), to: url.searchParams.get('to'), timezone: 'UTC', snapshot_at: '2026-10-28T08:00:00Z',
          consistency: 'snapshot', replacement_consistency: 'latest_event_id_at_snapshot', pagination: 'keyset',
        } })
      }
      return json({ error: { code: 'not_found', message: 'mock' } }, 404)
    })
    await page.goto(`${base}/monitor/site/access-log`)
    await page.waitForSelector('.analytics-log-scope-export', { timeout: 20000 })
      .catch(async (error) => { await page.screenshot({ path: `${out}/debug-${name}-${width}.png` }); throw error })
    await page.waitForTimeout(400)
    await page.screenshot({ path: `${out}/${name}-${width}.png` })
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)
    console.log(name, width, overflow ? 'HORIZONTAL_OVERFLOW' : 'ok')
    await page.close()
  }
}
await browser.close()
