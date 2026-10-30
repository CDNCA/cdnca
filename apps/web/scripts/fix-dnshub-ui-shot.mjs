// fix-dnshub-ui 本地 mock 截图：用户端 网站管理 → 域名解析（ADR 0020 §3.4，不连真实主控）。
// 场景：records（选中域名看记录与「本平台在用」标记）、managed（修改本平台在用记录的二次确认）、
//       readonly（无 dns.manage）、empty（没有自有 DNS 账号）。
// 依赖 playwright-core 与系统 Chrome；先起 vite dev，再：
//   node fix-dnshub-ui-shot.mjs <baseURL 如 http://127.0.0.1:5891/dashboard> <输出目录>
import { chromium } from 'playwright-core'

const [base, out] = process.argv.slice(2)
const now = Math.floor(Date.now() / 1000)
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url')
const token = `${b64({ alg: 'none' })}.${b64({ exp: now + 3600 })}.x`
const tenant = (permissions) => ({
  user_id: '0199aaaa-1111-7111-8111-111111111111', scope_id: '0199aaaa-2222-7222-8222-222222222222', scope_kind: 'tenant',
  tenant_id: '0199aaaa-3333-7333-8333-333333333333', username: 'shop-owner', display_name: '商城运维', roles: ['tenant_owner'],
  permissions: ['identity.self.read', 'sites.read', 'dns.read', ...permissions],
})
const features = { cache_control: true, custom_rbac: false, plugin_webhooks: false, approval_center: false, market: false, package_auto_renew: false, origin_auth: false }
const provider = (id, name, type, status = 'verified') => ({
  id, scope_id: tenant([]).scope_id, name, provider_type: type, credentials_configured: true, status, managed_by: 'tenant',
  version: 1, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
})
const ali = '0199cccc-0000-7000-8000-000000000001'
const cf = '0199cccc-0000-7000-8000-000000000002'
const hw = '0199cccc-0000-7000-8000-000000000003'
const providers = [provider(ali, '阿里云主账号', 'aliyun'), provider(cf, '海外 Cloudflare', 'cloudflare'), provider(hw, '华为云备用', 'huawei', 'unverified')]
const domains = [
  { provider_id: ali, provider_name: '阿里云主账号', provider_type: 'aliyun', apex: 'shop-demo.cn', record_count: 6, last_listed_at: '2026-10-29T01:12:00Z' },
  { provider_id: ali, provider_name: '阿里云主账号', provider_type: 'aliyun', apex: 'static-demo.cn', record_count: 3, last_listed_at: '2026-10-29T01:12:00Z' },
  { provider_id: cf, provider_name: '海外 Cloudflare', provider_type: 'cloudflare', apex: 'shop-demo.com', record_count: 4, last_listed_at: '2026-10-29T01:10:00Z' },
  { provider_id: hw, provider_name: '华为云备用', provider_type: 'huawei', apex: 'backup-demo.cn', record_count: null, list_error: 'credentials_rejected' },
]
const records = [
  { record_ref: 'r1', name: 'www', fqdn: '', type: 'CNAME', value: 'k3x9.cdnca.com', ttl: 600, line: '默认', weight: 0, managed: { kind: 'site_cname', site_id: '', site_domain: 'www.shop-demo.cn' } },
  { record_ref: 'r2', name: '@', fqdn: '', type: 'A', value: '192.0.2.10', ttl: 600, line: '默认', weight: 0, managed: null },
  { record_ref: 'r3', name: '@', fqdn: '', type: 'A', value: '198.51.100.20', ttl: 600, line: '电信', weight: 0, managed: null },
  { record_ref: 'r4', name: 'api', fqdn: '', type: 'AAAA', value: '2001:db8::20', ttl: 300, line: '默认', weight: 0, managed: null },
  { record_ref: 'r5', name: '_acme-challenge.www', fqdn: '', type: 'TXT', value: 'Qm9vdHN0cmFwLWRjdi10b2tlbi1leGFtcGxlLXZhbHVl', ttl: 120, line: '默认', weight: 0, managed: { kind: 'cdn_validation', site_id: '', site_domain: 'www.shop-demo.cn' } },
  { record_ref: 'r6', name: '@', fqdn: '', type: 'TXT', value: 'v=spf1 include:spf.mail.example -all', ttl: 600, line: '默认', weight: 0, managed: null },
]
const scenes = {
  records: { principal: tenant(['dns.manage']), providers },
  managed: { principal: tenant(['dns.manage']), providers },
  readonly: { principal: tenant([]), providers },
  empty: { principal: tenant(['dns.manage']), providers: [] },
}

const browser = await chromium.launch({ channel: 'chrome' })
for (const [name, scene] of Object.entries(scenes)) {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({ viewport: { width, height: width > 600 ? 900 : 844 }, locale: 'zh-CN' })
    await page.route('**/v1/**', (route) => {
      const url = new URL(route.request().url())
      const json = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
      if (url.pathname === '/v1/auth/refresh') return json({ access_token: token, token_type: 'Bearer', expires_in: 3600, principal: scene.principal })
      if (url.pathname === '/v1/auth/me') return json(scene.principal)
      if (url.pathname === '/v1/runtime-features') return json({ features })
      if (url.pathname === '/v1/dns/providers') return json({ items: scene.providers })
      if (url.pathname === '/v1/dns/hub/domains') {
        const id = url.searchParams.get('provider_id')
        const accounts = scene.providers.filter((item) => !id || item.id === id).map((item) => ({ provider_id: item.id, name: item.name, provider_type: item.provider_type,
          status: item.status, last_listed_at: null, list_error: '', domain_count: 0, supported_lines: item.provider_type === 'aliyun' ? ['默认', '电信', '联通', '移动', '境外'] : ['默认'],
          supports_weight: false, record_types: ['A', 'AAAA', 'CNAME', 'TXT'] }))
        return json({ accounts, items: domains.filter((item) => !id || item.provider_id === id), next_cursor: '' })
      }
      if (url.pathname.startsWith('/v1/dns/hub/domains/') && url.pathname.endsWith('/records')) {
        return json({ provider_id: ali, apex: 'shop-demo.cn', skipped: 0, items: records })
      }
      return json({ error: { code: 'not_found', message: 'mock' } }, 404)
    })
    const fail = async (error) => { await page.screenshot({ path: `${out}/debug-${name}-${width}.png` }); throw error }
    await page.goto(`${base}/site/dns-hub`)
    if (name === 'empty') {
      await page.getByText('还没有 DNS 账号').waitFor({ timeout: 20000 }).catch(fail)
    } else {
      await page.getByRole('button', { name: /shop-demo\.cn/ }).first().waitFor({ timeout: 20000 }).catch(fail)
      await page.getByRole('button', { name: /shop-demo\.cn/ }).first().click()
      await page.getByText('k3x9.cdnca.com').waitFor({ timeout: 10000 }).catch(fail)
      if (name === 'managed') {
        await page.getByRole('button', { name: '修改 www CNAME' }).click()
        await page.getByRole('dialog').waitFor({ timeout: 10000 }).catch(fail)
      }
    }
    await page.waitForTimeout(800)
    await page.screenshot({ path: `${out}/${name}-${width}.png`, fullPage: name !== 'managed' })
    const facts = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > window.innerWidth,
      title: document.querySelector('.shell-breadcrumb-current')?.textContent ?? '',
      selected: document.querySelector('.ant-menu-item-selected')?.textContent ?? '',
    }))
    console.log(name, width, facts.overflow ? 'HORIZONTAL_OVERFLOW' : 'ok', `title=${facts.title}`, `selected=${facts.selected}`)
    await page.close()
  }
}
await browser.close()
