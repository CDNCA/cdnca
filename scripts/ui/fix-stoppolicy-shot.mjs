// 主控锁定横幅截图（mock 接口，不连真实主控）。
//   NODE_PATH=<playwright-core 所在 node_modules> node scripts/ui/fix-stoppolicy-shot.mjs <baseURL> <输出目录>
// 三种原因：安全封禁（停流量）、服务凭证过期（冻结）、租约过期（冻结）；1440 与 390 两种宽度。
import { createRequire } from 'node:module'
import path from 'node:path'

const require = createRequire(path.join(process.env.NODE_PATH ?? '', 'x.js'))
const { chromium } = require('playwright-core')

const [base, out] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const principal = {
  user_id: '11111111-1111-4111-8111-111111111112', scope_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', scope_kind: 'platform', tenant_id: null,
  username: 'admin', display_name: 'admin', roles: ['platform_admin'], permissions: ['platform.admin'],
}
const auth = { access_token: token, token_type: 'Bearer', expires_in: 3600, principal }
const locks = {
  banned: { locked: true, reason: 'installation_banned', ban_id: '0b0b0b0b-0b0b-40b0-80b0-0b0b0b0b0b0b', reason_code: 'abuse',
    reason_text: '违规转售', until: new Date((now + 2 * 86400) * 1000).toISOString() },
  frozen: { locked: true, reason: 'service_ticket_expired' },
  lease: { locked: true, reason: 'lease_expired' },
}

const browser = await chromium.launch({ channel: 'chrome', headless: true })
for (const [name, lock] of Object.entries(locks)) {
  for (const [label, viewport] of [['1440', { width: 1440, height: 900 }], ['390', { width: 390, height: 844 }]]) {
    const context = await browser.newContext({ viewport, locale: 'zh-CN', timezoneId: 'Asia/Shanghai' })
    const page = await context.newPage()
    await page.route('**/v1/**', async (route) => {
      const p = new URL(route.request().url()).pathname
      const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
      if (p === '/v1/auth/refresh') return json(auth)
      if (p === '/v1/auth/me') return json(principal)
      if (p === '/v1/installation-lock') return json(lock)
      return json({ error: { code: 'not_found', message: 'mock' } }, 404)
    })
    await page.goto(`${base}/dashboard/`, { waitUntil: 'networkidle' })
    await page.getByRole('alert').filter({ hasText: '本主控授权已被锁定' }).waitFor({ timeout: 30000 })
    await page.waitForTimeout(500)
    await page.screenshot({ path: `${out}/banner-${name}-${label}.png` })
    const audit = await page.evaluate(() => ({ overflowX: document.documentElement.scrollWidth > window.innerWidth }))
    console.log(name, label, JSON.stringify(audit))
    await context.close()
  }
}
await browser.close()
