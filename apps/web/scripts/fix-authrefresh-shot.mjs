// fix-authrefresh 本地 mock 截图（不连真实主控）：首页「系统授权」卡在提交确认丢失后的待确认+回读、
// 回读失败、授权详情展开，以及锁定时与横幅共用「重新检查」。
//   node apps/web/scripts/fix-authrefresh-shot.mjs <baseURL> <输出目录>
import { chromium } from 'playwright-core'
import fs from 'node:fs'

const [base, out] = process.argv.slice(2)
fs.mkdirSync(out, { recursive: true })
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const scope = '22222222-2222-4222-8222-222222222222'
const principal = {
  user_id: '44444444-4444-4444-8444-444444444444', scope_id: scope, scope_kind: 'platform', tenant_id: null,
  username: 'admin', display_name: 'admin', roles: ['platform_owner'], permissions: ['platform.admin'],
}
const auth = { access_token: token, token_type: 'Bearer', expires_in: 3600, principal }
const section = (value) => ({ available: true, value })
const dashboard = (serial, verifiedAt) => ({
  dashboard_version: 2,
  meta: { range: 'seven_days', timezone: 'Asia/Shanghai', from: '2026-10-21T16:00:00Z', to: '2026-10-28T16:00:00Z',
    generated_at: '2026-10-28T08:00:00Z', snapshot_at: '2026-10-28T08:00:00.000Z', window_complete: false },
  accounts: section({ tenants_total: 12, tenants_active: 10, tenant_users_total: 3456, tenant_users_active: 3000 }),
  subscriptions: section({ active: 23 }),
  billing: section({ currency: 'CNY', gross_settled_debit_minor: '1200000', reversed_credit_minor: '0', net_settled_minor: '1200000' }),
  resources: section({ sites_total: 88, sites_active: 80, sites_sync_failed: 0, domains_total: 96, forwards_total: 24, nodes_total: 6, certificates_total: 72, certificates_valid: 70, certificates_expiring_30d: 3 }),
  operations: section({ cache_total: 9, cache_open: 2, cache_failed: 1, jobs_total: 10, jobs_open: 3, jobs_failed: 1 }),
  profile: section({ last_login_at: '2026-10-28T07:45:00Z', last_login_ip: '192.0.2.10', last_login_geo: 'CN' }),
  entitlement: section({ installation_id: 'control-primary', status: 'valid', lease_status: 'valid', current_serial: serial, node_limit: 30,
    expires_at: '2026-11-27T08:00:00Z', grace_until: '2026-12-27T08:00:00Z', last_verified_at: verifiedAt }),
  node_health: section({ total: 6, online_fresh: 6, stale_or_offline: 0, presence_missing: 0, freshness_cutoff_seconds: 45 }),
  analytics_health: section({ active_streams: 4, unprepared_stream_gap: '0' }),
  account_security: section({ active_sessions: 3, users_with_mfa: 2, active_api_keys: 1, recovery_codes_remaining: 6 }),
  network: section({ nodes_total: 6, nodes_active: 6, nodes_online: 6, nodes_stale: 0, freshness_cutoff_seconds: 45, regions: [] }),
  analytics: { available: false, reason: 'dependency_timeout' },
  operation_charts: { available: false, reason: 'dependency_timeout' },
})

const browser = await chromium.launch({ channel: 'chrome', headless: true })
const scenarios = [
  ['1-lost-ack-reread', { reread: 'ok', locked: false }],
  ['2-reread-failed', { reread: 'fail', locked: false }],
  ['3-locked-shared-check', { reread: 'ok', locked: true }],
]
for (const [label, viewport] of [['1440', { width: 1440, height: 900 }], ['390', { width: 390, height: 844 }]]) {
  for (const [name, scenario] of scenarios) {
    const context = await browser.newContext({ viewport, locale: 'zh-CN', timezoneId: 'Asia/Shanghai', reducedMotion: 'reduce' })
    const page = await context.newPage()
    let refreshed = false
    let locked = scenario.locked
    await page.route('**/v1/**', (route) => {
      const req = route.request()
      const p = new URL(req.url()).pathname
      const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
      if (p === '/v1/auth/refresh') return json(auth)
      if (p === '/v1/auth/me') return json(principal)
      if (p === '/v1/modules') return json({ status: 'active', lease_serial: 1, modules: [] })
      if (p === '/v1/installation-lock' ) return json(locked ? { locked: true, reason: 'lease_expired' } : { locked: false })
      if (p === '/v1/installation-lock/check') { locked = false; refreshed = true; return json({ locked: false }) }
      if (p === '/v1/admin/dashboard') {
        // StrictMode reads twice on load: switch on the refresh call, not a counter.
        if (refreshed && scenario.reread === 'fail') return json({ error: { code: 'dashboard_storage_unavailable', message: 'mock' } }, 503)
        return json(refreshed ? dashboard(2, '2026-10-28T08:05:00Z') : dashboard(1, '2026-10-28T07:00:00Z'))
      }
      if (p === '/v1/admin/entitlement/refresh') {
        refreshed = true
        return json({ error: { code: 'entitlement_refresh_unknown', message: 'mock', request_id: 'entitlement-refresh-mock', outcome: 'unknown' } }, 502)
      }
      if (p.startsWith('/v1/admin/analytics/')) return json({ error: { code: 'dependency_timeout', message: 'mock' } }, 503)
      return json({ items: [], total: 0, page: 1, limit: 100 })
    })
    const card = page.locator('.dashboard-entitlement-card')
    try {
      await page.goto(`${base}/admin-home`, { waitUntil: 'networkidle' })
      await card.getByRole('button', { name: '刷新授权' }).waitFor({ timeout: 30000 })
      await card.getByRole('button', { name: '刷新授权' }).click()
      await page.waitForTimeout(1200)
      if (name === '3-locked-shared-check') await page.screenshot({ path: `${out}/${label}-${name}-page.png` })
      if (name === '2-reread-failed') await card.getByRole('button', { name: '查看授权详情' }).click()
      await card.scrollIntoViewIfNeeded()
      await page.waitForTimeout(300)
      await card.screenshot({ path: `${out}/${label}-${name}.png` })
      const audit = await page.evaluate(() => ({
        overflowX: document.documentElement.scrollWidth > window.innerWidth,
        cardText: document.querySelector('.dashboard-entitlement-card')?.textContent?.slice(0, 400),
      }))
      console.log(label, name, JSON.stringify(audit))
    } catch (error) {
      console.log(label, name, 'fail', String(error).slice(0, 300))
      await page.screenshot({ path: `${out}/${label}-${name}-fail.png` })
    }
    await context.close()
  }
}
await browser.close()
