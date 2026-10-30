// 挑战策略发布状态“已忽略旧发布 N”本地 mock 截图（租户视角）。
//   node scripts/ui/fix-cfgflow3-shot.mjs http://127.0.0.1:5982 docs/ui/fix-cfgflow3 390,1440（需要可解析的 playwright-core，可复制到装有它的目录运行）
import { chromium } from 'playwright-core'
import fs from 'node:fs'
const [base, out, widths = '390,1440'] = process.argv.slice(2)
fs.mkdirSync(out, { recursive: true })
const browser = await chromium.launch({ channel: 'chrome', headless: true })
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'zh-CN' })
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const tscope = '22222222-2222-4222-8222-222222222222'
const user = '11111111-1111-4111-8111-111111111111'
const principal = { user_id: user, scope_id: tscope, scope_kind: 'tenant', tenant_id: tscope,
  username: 'jason', display_name: 'jason', roles: ['tenant_owner'],
  permissions: ['sites.read', 'security_policies.read', 'challenge_policies.read', 'challenge_policies.manage'] }
const auth = { access_token: token, token_type: 'Bearer', expires_in: 3600, principal }
const policy = { id: '44444444-4444-4444-8444-444444444444', tenant_scope_id: tscope,
  site_id: '33333333-3333-4333-8333-333333333333', host: 'app.example.com', priority: 100, mode: 'click',
  min_delay_seconds: 0, challenge_ttl_seconds: 60, pass_ttl_seconds: 900, clock_skew_seconds: 5,
  attempts_per_nonce: 1, failure_window_seconds: 60, max_failures_per_window: 5, ip_binding: 'exact',
  bind_user_agent: true, bypass_routes: [], key_reference_configured: true, external_provider_configured: false,
  enabled: true, deleted: false, revision: 3, created_at: '2026-10-27T08:00:00Z', updated_at: '2026-10-27T09:00:00Z' }
const publication = { policy_id: policy.id, policy_revision: 3, rollout_id: '77777777-7777-4777-8777-777777777777',
  config_version_id: '88888888-8888-4888-8888-888888888888', state: 'healthy', reason: '-',
  total: 3, pending: 0, running: 0, healthy: 2, failed: 0, cancelled: 0, superseded: 1 }
page.on('pageerror', (e) => console.log('pageerror', e.message.slice(0, 300)))
page.on('console', (m) => { if (m.type() === 'error') console.log('console', m.text().slice(0, 400)) })
await page.route('**/v1/**', (route) => {
  const p = new URL(route.request().url()).pathname
  const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
  if (p === '/v1/auth/refresh') return json(auth)
  if (p === '/v1/auth/me') return json(principal)
  if (p === '/v1/modules') return json({ status: 'active', lease_serial: 1, modules: [] })
  if (p === '/v1/runtime-features') return json({ features: {} })
  if (p === '/v1/security-policies') return json({ items: [], total: 0, page: 1, limit: 20 })
  if (p === `/v1/tenant-scopes/${tscope}/challenge-policies`) return json({ items: [policy] })
  if (p === `/v1/tenant-scopes/${tscope}/challenge-policies/${policy.id}/publications`) return json(publication, 202)
  if (p === '/v1/observability/frontend-events') return route.fulfill({ status: 204 })
  return json({ items: [] })
})
for (const w of widths.split(',').map(Number)) {
  await page.setViewportSize({ width: w, height: 900 })
  await page.goto(`${base}/site/cc-rule`, { waitUntil: 'networkidle' })
  await page.getByRole('button', { name: /^(更多|批量操作)/ }).first().click()
  await page.getByRole('menuitem', { name: '挑战策略' }).click()
  await page.getByRole('button', { name: '发布 app.example.com' }).click()
  await page.getByText('已忽略旧发布 1').first().waitFor({ timeout: 10000 })
  // The publication column sits in the table's horizontal scroller; bring it next to the left edge.
  const text = page.getByText('已忽略旧发布 1').first()
  await text.evaluate((node) => {
    const cell = node.closest('td')
    const scroller = node.closest('.ant-table-content, .ant-table-body')
    if (cell && scroller) scroller.scrollLeft = Math.max(0, cell.offsetLeft - 16)
  })
  await page.waitForTimeout(500)
  await page.screenshot({ path: `${out}/after-${w}-challenge-publication.png`, fullPage: false })
  await text.evaluate((node) => node.closest('td')).then(() => page.locator('td', { has: text }).first()
    .screenshot({ path: `${out}/after-${w}-challenge-publication-cell.png` }))
  console.log(w, 'scrollWidth', await page.evaluate(() => document.documentElement.scrollWidth))
}
await browser.close()
