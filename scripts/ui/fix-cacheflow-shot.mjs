// 管理员刷新预热页截图（mock 接口，不连真实主控）。
// 用法：node scripts/ui/fix-cacheflow-shot.mjs <base> <outDir> <tag>
// 需要可解析的 playwright-core。1440 与 390 各一张，
// 并打印管理区几何（宽高、透明度）与整页是否横向溢出。
import { chromium } from 'playwright-core'

const [base, out, tag] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const platform = {
  user_id: '0199aaaa-1111-7111-8111-111111111111', scope_id: '0199aaaa-2222-7222-8222-222222222222', scope_kind: 'platform', tenant_id: null,
  username: 'admin', display_name: 'admin', roles: ['platform_owner'], permissions: ['sites.read', 'sites.manage', 'users.read'],
}
const browser = await chromium.launch({ channel: 'chrome', headless: true })
for (const [width, height] of [[1440, 900], [390, 844]]) {
  const page = await browser.newPage({ viewport: { width, height }, locale: 'zh-CN' })
  await page.route('**/v1/**', (route) => {
    const p = new URL(route.request().url()).pathname
    const json = (body, s = 200) => route.fulfill({ status: s, contentType: 'application/json', body: JSON.stringify(body) })
    if (p === '/v1/auth/refresh') return json({ access_token: token, token_type: 'Bearer', expires_in: 3600, principal: platform })
    if (p === '/v1/auth/me') return json(platform)
    if (p === '/v1/modules') return json({ status: 'active', lease_serial: 1, modules: [] })
    return json({ data: [], items: [], total: 0, page: 1, page_size: 20 })
  })
  await page.goto(`${base}/dashboard/site/cache-clean`, { waitUntil: 'networkidle' })
  await page.locator('.cache-baseline-layout').waitFor({ timeout: 15000 })
  await page.waitForTimeout(500)
  await page.screenshot({ path: `${out}/${tag}-admin-${width}.png`, fullPage: true })
  const info = await page.evaluate(() => {
    const el = document.querySelector('.cache-operations-management')
    const r = el?.getBoundingClientRect()
    const create = [...document.querySelectorAll('button')].find((b) => b.textContent?.includes('创建任务'))
    const c = create?.getBoundingClientRect()
    const doc = document.scrollingElement
    return {
      management: r ? { w: Math.round(r.width), h: Math.round(r.height), opacity: getComputedStyle(el).opacity } : null,
      createButton: c ? { w: Math.round(c.width), h: Math.round(c.height), visible: c.width > 1 && c.height > 1 } : null,
      pageOverflow: doc.scrollWidth > doc.clientWidth + 1,
    }
  })
  console.log(tag, width, JSON.stringify(info))
  await page.close()
}
await browser.close()
