// 操作记录页详情与读取失败/拒绝态截图（mock 接口，不连真实主控）。
// 用法：node scripts/ui/fix-cacheflow4-shot.mjs <base> <outDir>
// 需要可解析的 playwright-core（ESM 不读 NODE_PATH：复制到装有它的目录下运行）。
// 场景：detail（部分失败任务详情，1440/390）、fail（首次读取 503）、
// denied（列表 403），并打印 390 下整页是否横向溢出。
import { chromium } from 'playwright-core'

const [base, out] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const tenant = {
  user_id: '0199aaaa-3333-7333-8333-333333333333', scope_id: '0199aaaa-2222-7222-8222-222222222222',
  scope_kind: 'tenant', tenant_id: '0199aaaa-2222-7222-8222-222222222222',
  username: 'tenant-user', display_name: '示例客户', roles: ['tenant_owner'], permissions: ['sites.read', 'sites.manage'],
}
const opID = '0199bbbb-5555-7555-8555-555555555555'
const node = (id, display, state, targets, progress) => ({
  node_id: id, node_display_id: display, state, attempt: 1, progress, targets, updated_at: '2026-10-28T08:00:00Z',
})
const operation = {
  id: opID, display_id: '1024', site_id: '0199cccc-3333-7333-8333-333333333333', site_display_id: '36',
  action: 'purge', target_type: 'exact_url', state: 'partial_failed', max_attempts: 4, auto_nodes: true,
  progress: { total: 6, completed: 5, succeeded: 3, failed: 1, cancelled: 1 },
  targets: [
    { ordinal: 1, display_url: 'https://www.example.com/assets/app.js?v=1', canonical_path: '/assets/app.js?v=1', target_sha256: 'a'.repeat(64), query_redacted: false },
    { ordinal: 2, display_url: 'https://www.example.com/assets/app.js?v=2', canonical_path: '/assets/app.js?v=2', target_sha256: 'b'.repeat(64), query_redacted: false },
    { ordinal: 3, display_url: 'https://www.example.com/download?token=redacted', canonical_path: '/download?token=redacted', target_sha256: 'c'.repeat(64), query_redacted: true },
  ],
  nodes: [
    node('0199dddd-7777-7777-8777-777777777777', '7', 'partial_failed', [
      { target_ordinal: 1, state: 'succeeded', attempt: 1, sequence: 1 },
      { target_ordinal: 2, state: 'failed', attempt: 1, sequence: 2, error_code: 'cache_delete_failed' },
      { target_ordinal: 3, state: 'cancelled', attempt: 1, sequence: 3, error_code: 'cancelled' },
    ], { total: 3, completed: 3, succeeded: 1, failed: 1, cancelled: 1 }),
    node('0199dddd-8888-7888-8888-888888888888', '8', 'running', [
      { target_ordinal: 1, state: 'succeeded', attempt: 1, sequence: 1 },
      { target_ordinal: 3, state: 'succeeded', attempt: 1, sequence: 2 },
    ], { total: 3, completed: 2, succeeded: 2, failed: 0, cancelled: 0 }),
  ],
  created_at: '2026-10-28T07:59:00Z', updated_at: '2026-10-28T08:00:00Z',
}
const { targets, nodes, ...facts } = operation
const summary = { ...facts, target_count: targets.length, node_count: nodes.length, first_target: targets[0] }
const counts = { queued: 0, running: 0, succeeded: 4, partial_failed: 1, failed: 0, cancelled: 0 }

const browser = await chromium.launch({ channel: 'chrome', headless: true })
for (const [scene, width, height] of [['detail', 1440, 900], ['detail', 390, 844], ['fail', 1440, 900], ['denied', 1440, 900]]) {
  const page = await browser.newPage({ viewport: { width, height }, locale: 'zh-CN' })
  await page.route('**/v1/**', (route) => {
    const p = new URL(route.request().url()).pathname
    const json = (body, s = 200) => route.fulfill({ status: s, contentType: 'application/json', body: JSON.stringify(body) })
    if (p === '/v1/auth/refresh') return json({ access_token: token, token_type: 'Bearer', expires_in: 3600, principal: tenant })
    if (p === '/v1/auth/me') return json(tenant)
    if (p === '/v1/modules') return json({ status: 'active', lease_serial: 1, modules: [] })
    if (p === '/v1/runtime-features') return json({ features: { cache_control: true, custom_rbac: false, plugin_webhooks: false, approval_center: false, market: false, package_auto_renew: false, origin_auth: false } })
    if (p === '/v1/cache-operations') {
      if (scene === 'fail') return json({ error: { code: 'service_unavailable', message: 'down' } }, 503)
      if (scene === 'denied') return json({ error: { code: 'permission_denied', message: 'denied' } }, 403)
      return json({ items: [summary], state_counts: counts })
    }
    if (p === `/v1/cache-operations/${opID}`) return json(operation)
    return json({ data: [], items: [], total: 0, page: 1, page_size: 20 })
  })
  await page.goto(`${base}/site/cache-clean/history`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(600)
  if (scene === 'detail') {
    await page.getByRole('button', { name: '查看详情' }).first().click()
    await page.getByText('逐项结果').first().waitFor({ timeout: 15000 })
    await page.waitForTimeout(500)
  }
  if (scene === 'fail') {
    const ack = page.getByRole('button', { name: '知道了' })
    if (await ack.count()) await ack.first().click()
    await page.waitForTimeout(500)
  }
  await page.screenshot({ path: `${out}/history-${scene}-${width}.png`, fullPage: false })
  const info = await page.evaluate(() => {
    const doc = document.scrollingElement
    return { document: doc.scrollWidth, client: doc.clientWidth, pageOverflow: doc.scrollWidth > doc.clientWidth + 1 }
  })
  console.log(scene, width, JSON.stringify(info))
  await page.close()
}
await browser.close()
