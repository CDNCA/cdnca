// 代登录横幅 390px 整页越界截图（mock 接口，不连真实主控）。
// 用法：node scripts/ui/fix-cacheflow2-shot.mjs <base> <outDir> <tag>
// 需要可解析的 playwright-core（ESM 不读 NODE_PATH：复制到装有它的目录下运行）。
// 320/390/1440 各一张，打印 .app-main 下横幅外层的几何
// 与整页是否横向溢出。用账户概览页（无宽表格），避免历史页表格横滚干扰判断。
import { chromium } from 'playwright-core'

const [base, out, tag] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const tenant = {
  user_id: '0199aaaa-3333-7333-8333-333333333333', scope_id: '0199aaaa-2222-7222-8222-222222222222',
  scope_kind: 'tenant', tenant_id: '0199aaaa-1111-7111-8111-111111111111',
  username: 'tenant-user', display_name: '示例客户', roles: ['tenant_owner'], permissions: ['sites.read', 'sites.manage'],
  impersonation: {
    grant_id: '0199aaaa-4444-7444-8444-444444444444', actor_user_id: '0199aaaa-5555-7555-8555-555555555555',
    actor_display_name: '平台管理员', subject_user_id: '0199aaaa-3333-7333-8333-333333333333',
    subject_display_name: '示例客户', tenant_id: '0199aaaa-1111-7111-8111-111111111111',
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
  },
}
const browser = await chromium.launch({ channel: 'chrome', headless: true })
for (const [width, height] of [[320, 720], [390, 844], [1440, 900]]) {
  const page = await browser.newPage({ viewport: { width, height }, locale: 'zh-CN' })
  await page.route('**/v1/**', (route) => {
    const p = new URL(route.request().url()).pathname
    const json = (body, s = 200) => route.fulfill({ status: s, contentType: 'application/json', body: JSON.stringify(body) })
    if (p === '/v1/auth/refresh') return json({ access_token: token, token_type: 'Bearer', expires_in: 3600, principal: tenant })
    if (p === '/v1/auth/me') return json(tenant)
    if (p === '/v1/modules') return json({ status: 'active', lease_serial: 1, modules: [] })
    return json({ data: [], items: [], total: 0, page: 1, page_size: 20 })
  })
  await page.goto(`${base}/account/user`, { waitUntil: 'networkidle' })
  await page.locator('.app-main > [role="status"]').first().waitFor({ timeout: 15000 })
  await page.waitForTimeout(500)
  await page.screenshot({ path: `${out}/${tag}-impersonation-${width}.png`, fullPage: false })
  const info = await page.evaluate(() => {
    const banner = document.querySelector('.app-main > [role="status"]')
    const r = banner?.getBoundingClientRect()
    const doc = document.scrollingElement
    return {
      banner: r ? { left: Math.round(r.left), right: Math.round(r.right), width: Math.round(r.width) } : null,
      document: doc.scrollWidth, client: doc.clientWidth, pageOverflow: doc.scrollWidth > doc.clientWidth + 1,
    }
  })
  console.log(tag, width, JSON.stringify(info))
  await page.close()
}
await browser.close()
