// fix-finrefund2 在途退款预留的余额显示截图（mock 接口，不连真实主控）。
//   node scripts/ui/fix-finrefund2-shot.mjs <baseURL> <输出目录>
// ① 租户 /account/balance：余额 ¥123.45，可用 ¥23.45（含退款处理中 100元）
// ② 管理员 /finance/recharge：账户列表余额列副行、流水抽屉头。1440 与 390 两种宽度。
import { chromium } from 'playwright-core'

const [base, out] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const scopeID = '22222222-2222-4222-8222-222222222222'
const account = {
  id: scopeID, scope_id: scopeID, tenant_id: '33333333-3333-4333-8333-333333333333', tenant_name: 'Alpha Tenant',
  currency: 'CNY', balance_minor: 12345, available_minor: 2345, refunding_minor: 10000, revision: 3,
  created_at: '2026-10-28T01:00:00Z', updated_at: '2026-10-28T02:00:00Z',
}
const other = { ...account, id: '55555555-5555-4555-8555-555555555555', scope_id: '55555555-5555-4555-8555-555555555555',
  tenant_name: 'Beta Tenant', balance_minor: 50000, available_minor: 50000, refunding_minor: 0 }
const tenant = {
  user_id: '66666666-6666-4666-8666-666666666666', scope_id: scopeID, scope_kind: 'tenant', tenant_id: scopeID,
  username: 'alpha', display_name: 'alpha', roles: ['tenant_owner'], permissions: ['billing.account.read'],
}
const admin = {
  user_id: '77777777-7777-4777-8777-777777777777', scope_id: '99999999-9999-4999-8999-999999999999', scope_kind: 'platform',
  tenant_id: null, username: 'admin', display_name: 'admin', roles: ['platform_admin'], permissions: ['platform.admin'],
}

const browser = await chromium.launch({ channel: 'chrome', headless: true })
for (const [label, viewport] of [['1440', { width: 1440, height: 900 }], ['390', { width: 390, height: 844 }]]) {
  for (const [name, principal, path] of [['tenant', tenant, '/account/balance'], ['admin', admin, '/finance/recharge']]) {
    const context = await browser.newContext({ viewport, locale: 'zh-CN', timezoneId: 'Asia/Shanghai' })
    const page = await context.newPage()
    const auth = { access_token: token, token_type: 'Bearer', expires_in: 3600, principal }
    await page.route('**/v1/**', async (route) => {
      const p = new URL(route.request().url()).pathname
      const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
      if (p === '/v1/auth/refresh') return json(auth)
      if (p === '/v1/auth/me') return json(principal)
      if (p === '/v1/account/balance') return json(account)
      if (p === '/v1/admin/billing/accounts') return json({ items: [account, other], total: 2, page: 1, limit: 20 })
      if (p.startsWith('/v1/admin/billing/accounts/') && p.endsWith('/ledger')) return json({ items: [], total: 0, page: 1, limit: 20 })
      if (p === '/v1/admin/billing/adjustments') return json({ items: [], total: 0, page: 1, limit: 20 })
      if (p === '/v1/admin/users') return json({ items: [], total: 0, page: 1, limit: 20 })
      return json({ code: 'not_found' }, 404)
    })
    await page.goto(`${base}/dashboard${path}`, { waitUntil: 'networkidle' })
    const expected = name === 'tenant' ? '可用 ¥23.45（含退款处理中 100元）' : '可用 ¥23.45（含退款处理中 ¥100.00）'
    await page.getByText(expected).first().waitFor({ timeout: 30000 })
    await page.waitForTimeout(300)
    await page.screenshot({ path: `${out}/${label}-${name}-balance.png`, fullPage: label === '390' })
    if (name === 'admin') {
      await page.getByRole('button', { name: '查看流水' }).first().click()
      await page.locator('.billing-ledger-summary').getByText(expected).waitFor({ timeout: 15000 })
      await page.waitForTimeout(400)
      await page.screenshot({ path: `${out}/${label}-admin-ledger.png` })
    }
    await context.close()
  }
}
await browser.close()
console.log('fix-finrefund2 screenshots written to', out)
