// fix-cachedlg 刷新预热截图（mock 接口，不连真实主控）。
//   node scripts/ui/fix-cachedlg-shot.mjs <baseURL> <输出目录>
// 租户 /dashboard/site/cache-clean：主区预检计数与未匹配、创建弹窗（URL 匹配 / 整站选网站 / 节点多选）；
// 管理员：不选租户直接提交，按网站拆到各租户。1440 与 390 两种宽度。
import { chromium } from 'playwright-core'

const [base, out] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const tenantScope = '22222222-2222-4222-8222-222222222222'
const principals = {
  tenant: {
    user_id: '11111111-1111-4111-8111-111111111111', scope_id: tenantScope, scope_kind: 'tenant', tenant_id: tenantScope,
    username: 'jason', display_name: 'jason', roles: ['tenant_owner'], permissions: ['sites.read', 'sites.manage'],
  },
  admin: {
    user_id: '11111111-1111-4111-8111-111111111112', scope_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', scope_kind: 'platform', tenant_id: null,
    username: 'admin', display_name: 'admin', roles: ['platform_admin'], permissions: ['platform.admin'],
  },
}
const sites = [
  { id: '33333333-3333-4333-8333-333333333333', scope_id: tenantScope, display_id: '3', domain: 'www.example.com', domains: ['www.example.com', '*.example.com'] },
  { id: '44444444-4444-4444-8444-444444444444', scope_id: '77777777-7777-4777-8777-777777777777', display_id: '9', domain: 'shop.example.net', domains: ['shop.example.net'] },
]
const nodes = [
  { id: '55555555-5555-4555-8555-555555555551', display_id: '1', name: 'hk-edge-01', ipv4: '203.0.113.11' },
  { id: '55555555-5555-4555-8555-555555555552', display_id: '2', name: 'sg-edge-02', ipv4: '203.0.113.12' },
]
const host = (raw) => { try { return new URL(raw.replace('://*.', '://wildcard.')).hostname } catch { return '' } }
const serves = (site, h) => site.domains.some((name) => name === h || (name.startsWith('*.') && h.endsWith(name.slice(1))))

function resolve(kind, body) {
  const visible = kind === 'tenant' ? sites.filter((site) => site.scope_id === tenantScope) : sites
  const groups = new Map()
  const unmatched = []
  body.targets.forEach((raw, index) => {
    const h = host(raw)
    const site = h && visible.find((candidate) => serves(candidate, h))
    if (!site) { unmatched.push({ target_ordinal: index + 1, reason: h ? 'target_site_not_found' : 'target_url_invalid' }); return }
    const group = groups.get(site.id) ?? { site_id: site.id, scope_id: site.scope_id, site_display_id: site.display_id, domain: site.domain, target_ordinals: [] }
    group.target_ordinals.push(index + 1)
    groups.set(site.id, group)
  })
  return { groups: [...groups.values()], unmatched }
}

const browser = await chromium.launch({ channel: 'chrome', headless: true })
for (const kind of ['tenant', 'admin']) {
  const principal = principals[kind]
  const auth = { access_token: token, token_type: 'Bearer', expires_in: 3600, principal }
  for (const [label, viewport] of [['1440', { width: 1440, height: 900 }], ['390', { width: 390, height: 844 }]]) {
    const context = await browser.newContext({ viewport, locale: 'zh-CN', timezoneId: 'Asia/Shanghai' })
    const page = await context.newPage()
    await page.route('**/v1/**', async (route) => {
      const url = new URL(route.request().url())
      const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
      const p = url.pathname
      if (p === '/v1/auth/refresh') return json(auth)
      if (p === '/v1/auth/me') return json(principal)
      if (p.endsWith('/cache-operations/target-sites')) return json(resolve(kind, route.request().postDataJSON()))
      if (p.endsWith('/cache-operations/carrying-nodes')) return json({ items: nodes })
      if (p === '/v1/nodes') return json({ items: [] })
      if (p.endsWith('/cache-operations') && route.request().method() === 'GET') return json({ items: [] })
      if (p === '/v1/sites') {
        const items = sites.filter((site) => kind === 'admin' || site.scope_id === tenantScope).map((site) => ({
          ...site, version: 1, owner: null, listen_ports: ['80'], origins: [], cname: '', lock: { locked: false, reason: null, locked_at: null, operator: null },
        }))
        return json({ items, total: items.length, page: 1, limit: 50 })
      }
      return json({ error: { code: 'not_found', message: 'mock' } }, 404)
    })
    await page.goto(`${base}/dashboard/site/cache-clean`, { waitUntil: 'networkidle' })
    await page.getByRole('textbox', { name: 'URL 列表' }).waitFor({ timeout: 30000 })
    if (kind === 'tenant') {
      await page.getByRole('textbox', { name: 'URL 列表' }).fill(
        'https://www.example.com/app.js\nhttps://img.example.com/logo.png\nhttps://shop.example.net/a.css')
      await page.waitForTimeout(1200)
      await page.screenshot({ path: `${out}/${kind}-${label}-1-main-precheck.png`, fullPage: label === '390' })
    }
    await page.getByRole('button', { name: '创建任务' }).dispatchEvent('click')
    const dialog = page.getByRole('dialog', { name: '创建刷新预热任务' })
    await dialog.waitFor()
    await dialog.getByLabel('目标 URL').fill(kind === 'tenant'
      ? 'https://www.example.com/app.js\nhttps://cdn.example.com/x.png'
      : 'https://www.example.com/app.js\nhttps://shop.example.net/a.css')
    await page.waitForTimeout(1200)
    await page.screenshot({ path: `${out}/${kind}-${label}-2-dialog-urls.png` })
    await dialog.locator('.ant-select', { has: page.getByRole('combobox', { name: '节点（可选）' }) }).locator('.ant-select-selector').click()
    await page.waitForTimeout(500)
    await page.screenshot({ path: `${out}/${kind}-${label}-3-dialog-nodes.png` })
    await page.keyboard.press('Escape')
    await dialog.locator('.ant-select', { has: page.getByRole('combobox', { name: '目标范围' }) }).locator('.ant-select-selector').click()
    await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option-content', { hasText: '整站' }).click()
    await dialog.locator('.ant-select', { has: page.getByRole('combobox', { name: '网站' }) }).locator('.ant-select-selector').click()
    await page.waitForTimeout(600)
    await page.screenshot({ path: `${out}/${kind}-${label}-4-dialog-whole-site.png` })
    const audit = await page.evaluate(() => ({
      overflowX: document.documentElement.scrollWidth > window.innerWidth,
      siteIdInput: Boolean([...document.querySelectorAll('label')].find((item) => item.textContent === '站点 ID' && item.closest('.cache-operation-modal'))),
    }))
    console.log(kind, label, JSON.stringify(audit))
    await context.close()
  }
}
await browser.close()
