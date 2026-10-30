// fix-finrefund 充值订单退款执行截图（mock 接口，不连真实主控、不调用任何支付渠道）。
//   node scripts/ui/fix-finrefund-shot.mjs <baseURL> <输出目录>
// 管理员 /finance/recharge-orders：订单行“查询渠道状态”、执行退款弹窗的
// ①处理中待确认（同一请求再查，无需验证码）②渠道拒绝（原因+请求编号）③退款尚未发往渠道。1440 与 390 两种宽度。
import { chromium } from 'playwright-core'

const [base, out] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const orderID = '11111111-1111-4111-8111-111111111111'
const tenantScopeID = '22222222-2222-4222-8222-222222222222'
const approvalID = '88888888-8888-4888-8888-888888888888'
const principal = {
  user_id: '66666666-6666-4666-8666-666666666666', scope_id: '99999999-9999-4999-8999-999999999999', scope_kind: 'platform', tenant_id: null,
  username: 'admin', display_name: 'admin', roles: ['platform_admin'],
  permissions: ['billing.recharges.read', 'billing.recharges.compensate', 'billing.recharges.approve', 'billing.recharges.reconcile'],
}
const order = {
  id: orderID, display_id: '31', tenant_scope_id: tenantScopeID, tenant_id: '33333333-3333-4333-8333-333333333333',
  user_id: '44444444-4444-4444-8444-444444444444', user_display_id: '41', channel: 'alipay', provider: 'alipay',
  amount_minor: 10000, captured_minor: 10000, refunded_minor: 0, net_minor: 10000, currency: 'CNY', state: 'paid', revision: 3,
  created_at: '2026-10-28T01:00:00Z', updated_at: '2026-10-28T01:00:01Z',
}
const approval = {
  id: approvalID, order_id: orderID, tenant_scope_id: tenantScopeID, kind: 'refund', amount_minor: 2000, currency: 'CNY',
  expected_order_revision: 3, reason: '客户申请退回误充金额', state: 'approved', revision: 2,
  proposed_by_scope_id: principal.scope_id, proposed_by_user_id: '77777777-7777-4777-8777-777777777777',
  proposed_at: '2026-10-28T01:10:00Z', expires_at: '2030-10-28T01:25:00Z', decided_by_scope_id: principal.scope_id,
  decided_by_user_id: principal.user_id, decided_at: '2026-10-28T01:12:00Z', replayed: false,
}
const result = (status, reason) => ({
  compensation_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', approval_id: approvalID, order_id: orderID, tenant_scope_id: tenantScopeID,
  kind: 'refund', amount_minor: 2000, currency: 'CNY', status, reason_code: reason, attempt: 1,
  provider_request_id: 'rf019a2b3c4d5e6f708192a3b4c5d6e7f8', order_state: 'paid', order_revision: 3,
  retryable: status === 'pending' || status === 'unknown', replayed: false,
})

const browser = await chromium.launch({ channel: 'chrome', headless: true })
const auth = { access_token: token, token_type: 'Bearer', expires_in: 3600, principal }
for (const [label, viewport] of [['1440', { width: 1440, height: 900 }], ['390', { width: 390, height: 844 }]]) {
  for (const scenario of ['pending', 'failed', 'not_sent']) {
    const context = await browser.newContext({ viewport, locale: 'zh-CN', timezoneId: 'Asia/Shanghai' })
    const page = await context.newPage()
    await page.route('**/v1/**', async (route) => {
      const url = new URL(route.request().url())
      const p = url.pathname
      const json = (body, status = 200, headers = {}) => route.fulfill({ status, contentType: 'application/json', headers, body: JSON.stringify(body) })
      if (p === '/v1/auth/refresh') return json(auth)
      if (p === '/v1/auth/me') return json(principal)
      if (p === '/v1/admin/recharges/orders') return json({ items: [order], total: 1, page: 1, limit: 20, snapshot_at: '2026-10-28T02:00:00Z' })
      if (p === '/v1/admin/recharge-payment-approvals') return json({ items: [approval], total: 1, page: 1, limit: 20, snapshot_at: '2026-10-28T02:00:00Z' })
      if (p === '/v1/account/mfa/step-up-proofs') {
        return json({ proof_id: 'abababab-abab-4bab-8bab-abababababab', token: 'S'.repeat(43), method: 'totp', issued_at: '2026-10-28T02:00:00Z',
          expires_at: '2030-01-01T00:00:00Z', max_uses: 1, replayed: false }, 201)
      }
      if (p === `/v1/admin/recharge-payments/orders/${orderID}/refunds`) {
        if (scenario === 'not_sent') return json({ code: 'recharge_payment_compensation_not_sent' }, 503)
        if (scenario === 'failed') return json(result('failed', 'PROVIDER_REJECTED'), 200, { ETag: '"3"' })
        return json(result('pending', 'COMPENSATION_PENDING'), 202, { ETag: '"3"' })
      }
      return json({ code: 'not_found' }, 404)
    })
    await page.goto(`${base}/finance/recharge-orders`, { waitUntil: 'networkidle' })
    await page.getByRole('button', { name: `执行 ${approvalID}` }).waitFor({ timeout: 30000 })
    if (scenario === 'pending') {
      await page.screenshot({ path: `${out}/${label}-0-list.png`, fullPage: label === '390' })
    }
    await page.getByRole('button', { name: `执行 ${approvalID}` }).click()
    const dialog = page.getByRole('dialog', { name: '执行退款：订单 31' })
    await dialog.getByLabel('身份验证码').fill('123456')
    await dialog.getByRole('button', { name: '确认' }).click()
    const expected = { pending: '退款处理中，到账结果待确认。', failed: '退款尚未完成，渠道未接受本次请求，资金未退出。',
      not_sent: '退款尚未发往渠道，系统执行失败，请联系管理员。' }[scenario]
    await dialog.getByText(expected).waitFor({ timeout: 15000 })
    await page.waitForTimeout(400)
    const index = { pending: 1, failed: 2, not_sent: 3 }[scenario]
    await page.screenshot({ path: `${out}/${label}-${index}-execute-${scenario}.png` })
    await context.close()
  }
}
await browser.close()
console.log('fix-finrefund screenshots written to', out)
