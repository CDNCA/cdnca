// 发布记录页“已忽略旧发布”本地 mock 截图（租户视角）。
//   node scripts/ui/fix-cfgflow2-shot.mjs http://127.0.0.1:5981/dashboard docs/ui/fix-cfgflow2 390,1440（需要可解析的 playwright-core，可复制到装有它的目录运行）
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
const principal = { user_id: user, scope_id: tscope, scope_kind: 'tenant', tenant_id: '33333333-3333-4333-8333-333333333333',
  username: 'jason', display_name: 'jason', roles: ['tenant_owner'], permissions: ['sites.read', 'edge_publications.read', 'edge_publications.manage'] }
const auth = { access_token: token, token_type: 'Bearer', expires_in: 3600, principal }
const rolloutID = 'a1000000-0000-4000-8000-000000000001'
const rollout = { id: rolloutID, config_version_id: 'c1000000-0000-4000-8000-000000000001', action: 'apply', state: 'succeeded',
  revision: 3, max_attempts: 5, progress: { total: 3, pending: 0, running: 0, succeeded: 2, failed: 0, cancelled: 0, superseded: 1 },
  can_cancel: false, can_retry: false, created_at: '2026-10-27T08:00:00Z', updated_at: '2026-10-27T08:03:00Z' }
const dep = (id, state, extra = {}) => ({ id, attempt: 1, max_attempts: 5, state, created_at: '2026-10-27T08:01:00Z',
  updated_at: '2026-10-27T08:02:00Z', can_retry: false, ...extra })
const deployments = { items: [
  dep('d1000000-0000-4000-8000-000000000001', 'healthy'),
  dep('d1000000-0000-4000-8000-000000000002', 'healthy'),
  dep('d1000000-0000-4000-8000-000000000003', 'failed', { error_code: 'ERROR_CODE_STALE_ATTEMPT', superseded: true }),
] }
page.on('pageerror', (e) => console.log('pageerror', e.message.slice(0, 300)))
page.on('console', (m) => { if (m.type() === 'error') console.log('console', m.text().slice(0, 400)) })
await page.route('**/v1/**', (route) => {
  const u = new URL(route.request().url()); const p = u.pathname
  const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
  if (p === '/v1/auth/refresh') return json(auth)
  if (p === '/v1/auth/me') return json(principal)
  if (p === '/v1/modules') return json({ status: 'active', lease_serial: 1, modules: [] })
  if (p === '/v1/runtime-features') return json({ features: {} })
  if (p === '/v1/site-rollouts') return json({ items: [rollout] })
  if (p === `/v1/site-rollouts/${rolloutID}`) return json(rollout)
  if (p === `/v1/site-rollouts/${rolloutID}/deployments`) return json(deployments)
  if (p === '/v1/site-publications') return json({ items: [], current_source_revision: 3 })
  if (p === '/v1/observability/frontend-events') return route.fulfill({ status: 204 })
  return json({ items: [] })
})
for (const w of widths.split(',').map(Number)) {
  await page.setViewportSize({ width: w, height: 900 })
  await page.goto(`${base}/site/publications`, { waitUntil: 'networkidle' })
  await page.getByRole('tab', { name: '部署进度' }).click()
  await page.getByText('已忽略旧发布 1').first().waitFor({ timeout: 10000 })
  await page.waitForTimeout(800)
  await page.screenshot({ path: `${out}/after-${w}-rollouts.png`, fullPage: false })
  await page.getByRole('button', { name: '查看部署', exact: true }).first().click()
  await page.waitForTimeout(1500)
  await page.getByRole('dialog').getByText('节点已在更新版本').waitFor({ timeout: 10000 })
  await page.waitForTimeout(300)
  await page.screenshot({ path: `${out}/after-${w}-deployments.png`, fullPage: false })
  console.log(w, 'scrollWidth', await page.evaluate(() => document.documentElement.scrollWidth))
  await page.keyboard.press('Escape')
}
await browser.close()
