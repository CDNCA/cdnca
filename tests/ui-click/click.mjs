// 本机四端逐页逐按钮点击巡检（ui-click）。
// 浏览器：CDNCA_PW（默认当前目录）下 node_modules 的 playwright-core 驱动系统 Chrome（channel chrome），
// 独立配置目录 tests/ui-click/out/profile/<身份>（out/ 不入库），无头；不连用户日常 Chrome、不读其登录态。
//
// 用法：node click.mjs --identity <身份> [--only <正则>] [--limit N] [--no-click] [--no-en]
//   身份见 IDENTITIES；页面清单 = state/pages.json（gen-pages.mjs 生成）。
// 输出：tests/ui-click/out/run/<身份>/results.jsonl；截图 docs/ui/click-1035/<端>/<身份>/<页>.{zh,en}.png
//
// 每页：打开 → 断言（不跳登录、布局容器可见、无错误结果块、无 console error、本站接口无 ≥400、无“未开放/未实现”占位）
// → 中文截图 → 枚举主区域可见按钮/开关/标签页逐个点击：
//   * 记录点击后 2.5 秒内本站接口请求与响应码、DOM 变化（弹窗/抽屉/消息/URL/文本）；
//   * 打开的弹窗/抽屉里有表单：按字段类型填最小合法值并点主按钮（只在测试库上执行创建/保存），记结果后关闭；
//   * 危险操作（删除/吊销/停用/重置/退出/卸载/升级/迁移/恢复等）：只点到二次确认出现为止，然后取消——
//     记“需确认”，不执行，避免破坏种子数据导致后续页面无数据；
//   * 无请求且无 DOM 变化 = “点击无效果”。
// → 切英文刷新后截图 → 切回中文。
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { createRequire } from 'node:module'

const HERE = path.dirname(new URL(import.meta.url).pathname)
const ROOT = path.resolve(HERE, '../..')
const PW = process.env.CDNCA_PW ?? process.cwd()
const { chromium } = createRequire(`${PW}/package.json`)('playwright-core')
const STATE = process.env.UICLICK_STATE ?? '/tmp/uiclick-state'

const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i < 0 ? d : process.argv[i + 1] }
const has = (n) => process.argv.includes(`--${n}`)

const ORIGIN = { web: 'http://localhost:55101', 'operator-console': 'http://localhost:55102', 'license-portal': 'http://localhost:55102', 'seller-portal': 'http://localhost:55103' }
const BASE = { web: '/dashboard', 'operator-console': '/operator', 'license-portal': '/console', 'seller-portal': '' }
const SHELL = { web: 'main.app-main', 'operator-console': 'main.operator-main', 'license-portal': '.portal-shell', 'seller-portal': '.portal-shell' }
const LOCALE_KEY = { web: 'cdnca.locale', 'operator-console': 'operator_locale', 'license-portal': 'cdnca-portal-locale', 'seller-portal': 'cdnca-seller-locale' }
const API = /^\/(v1|operator\/v1|portal\/v1|auth\/v1|seller\/v1|payments\/v1)\//
// 身份 → 巡哪个端、web 用 admin 还是 user 菜单、登录方式。
const IDENTITIES = {
  'platform-admin': { app: 'web', role: 'admin', user: 'admin', login: 'web' },
  'tenant-admin': { app: 'web', role: 'user', user: 'tenant1', login: 'web' },
  'tenant-user': { app: 'web', role: 'user', user: 'member1', login: 'web', limited: true },
  owner: { app: 'operator-console', user: 'owner', login: 'unified' },
  operator: { app: 'operator-console', user: 'operator1', login: 'unified', totp: true, limited: true },  // user 由 identities.json operatorUser 覆盖
  seller: { app: 'license-portal', user: 'seller1', login: 'unified' },
  'seller-site': { app: 'seller-portal', user: 'seller1', login: 'seller' },
}
const identity = arg('identity')
const who = IDENTITIES[identity]
if (!who) { console.error(`--identity 取值：${Object.keys(IDENTITIES).join(' ')}`); process.exit(2) }
const app = who.app
const ids = JSON.parse(fs.readFileSync(`${STATE}/identities.json`, 'utf8'))
if (identity === 'operator' && ids.operatorUser) who.user = ids.operatorUser
const PASSWORD = identity === 'tenant-user' && ids.memberPassword ? ids.memberPassword : ids.password

const DANGER = /删除|移除|吊销|撤销|撤回|停用|禁用|作废|注销|退出登录|退出|登出|重置|清空|清除|卸载|升级|迁移|恢复|回滚|降级|解绑|驳回|拒绝|终止|下架|冻结|封禁|拉黑|强制|轮换|踢出|delete|remove|revoke|disable|deactivate|reset|clear|purge|uninstall|upgrade|migrate|restore|rollback|downgrade|unbind|reject|terminate|suspend|freeze|ban|block|logout|log out|sign out|rotate|kick/i
const SKIP = /^(中文|English|简体中文|EN|ZH|繁體中文)$|语言|Language|帮助文档|文档中心/i
const PLACEHOLDER = /(?<!平台)未开放|未实现|暂未开放|即将上线|敬请期待|功能开发中|暂无可用的真实后端契约|尚未提供.{0,12}接口|Coming soon|Not implemented|not yet available|no available real backend contract/i
// 本地栈与生产的已知差异（up.sh 头注释）：这些响应记 env，不算产品失败。
//   品牌资源/错误页（需对象存储 + clamd）、ACME 证书资产（需 ACME 账户与证书信封密钥）、主控市场（需 85 市场 mTLS）
//   在本机不启用 → 这些路由 404 page not found（Go 默认 mux 文本，非产品 JSON 错误）；授权刷新需授权端 URL；
//   实时监控需节点采集证据。
const ENV = [/\/v1\/(admin\/)?brand-assets(\/\w+)? → 404/, /\/v1\/admin\/entitlement\/refresh → 404/, /analytics_realtime_evidence_unavailable/,
  /\/v1\/(admin\/)?certificate-assets[^ ]* → 404 404 page not found/, /\/v1\/(admin\/)?error-pages[^ ]* → 404 404 page not found/,
  /\/v1\/(admin\/|tenant\/)?market\/[^ ]* → 404 404 page not found/]
// 页面跳转时浏览器中断的上报请求（status 0，frontend-events）是巡检导航造成的，不计。
const NOISE = /\/v1\/observability\/frontend-events → 0/
const isEnv = (s) => ENV.some((re) => re.test(s)) || NOISE.test(s)
const NEUTRAL = /^(查询|搜索|清除|清空筛选|重置|重置筛选|筛选|刷新|\d+|上一页|下一页|Search|Query|Reset|Clear|Refresh|Filter)$/i
const SUCCESS = /成功|已保存|已创建|已提交|已更新|已发送|已复制|success|saved|created|updated|submitted|copied/i

const pagesFile = JSON.parse(fs.readFileSync(arg('pages', `${STATE}/pages.json`), 'utf8'))
const only = arg('only') ? new RegExp(arg('only')) : null
let pages = pagesFile.pages.filter((p) => p.app === app && (!who.role || p.roles.includes(who.role)) && (!only || only.test(p.path)))
  .filter((p, i, a) => a.findIndex((q) => q.path === p.path) === i)
pages = pages.slice(Number(arg('skip', 0)), Number(arg('skip', 0)) + Number(arg('limit', 1e9)))

const runDir = path.join(HERE, 'out', 'run', identity)
const shotDir = path.join(ROOT, 'docs/ui/click-1035', app, identity)
fs.mkdirSync(runDir, { recursive: true }); fs.mkdirSync(shotDir, { recursive: true })
const resultsPath = path.join(runDir, 'results.jsonl')
if (!has('append')) fs.writeFileSync(resultsPath, '')

const context = await chromium.launchPersistentContext(path.join(HERE, 'out', 'profile', identity), {
  channel: 'chrome', headless: !has('headed'), viewport: { width: 1440, height: 900 }, locale: 'zh-CN', timezoneId: 'Asia/Shanghai',
  args: ['--no-first-run', '--no-default-browser-check', '--disable-extensions'],
})
context.setDefaultTimeout(8000)
const page = context.pages()[0] ?? await context.newPage()
const origin = ORIGIN[app]
const base = BASE[app]

// ---------- 网络与 console 采集 ----------
let net = []; let consoleErrors = []
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 300)) })
page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${String(e).slice(0, 300)}`))
page.on('response', async (res) => {
  const u = new URL(res.url())
  if (!API.test(u.pathname)) return
  const item = { method: res.request().method(), path: u.pathname + (u.search.length < 80 ? u.search : ''), status: res.status(), t: Date.now() }
  if (res.status() >= 400) item.body = (await res.text().catch(() => '')).slice(0, 240)
  net.push(item)
})
page.on('requestfailed', (req) => { const u = new URL(req.url()); if (API.test(u.pathname)) net.push({ method: req.method(), path: u.pathname, status: 0, error: req.failure()?.errorText, t: Date.now() }) })

const settle = async (ms = 1200) => { await page.waitForLoadState('networkidle', { timeout: 6000 }).catch(() => {}); await page.waitForTimeout(ms) }
const shell = () => page.locator(SHELL[app]).first()

// ---------- 登录 ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const totp = (secret) => {
  let bits = ''; for (const c of secret) bits += B32.indexOf(c).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const d = crypto.createHmac('sha1', key).update(counter).digest(); const o = d[d.length - 1] & 15
  return String((d.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0')
}
async function login() {
  await page.goto(`${origin}${base}/`, { waitUntil: 'domcontentloaded' }); await settle(800)
  if (await shell().isVisible().catch(() => false)) return true
  if (who.login === 'web') {
    await page.goto(`${origin}/dashboard/login`, { waitUntil: 'domcontentloaded' }); await settle(500)
    await page.locator('input[autocomplete="username"]').first().fill(who.user)
    await page.locator('input[autocomplete="current-password"]').first().fill(PASSWORD)
    await page.locator('button[type="submit"]').first().click()
  } else if (who.login === 'unified' || who.login === 'seller') {
    await page.goto(`${ORIGIN['license-portal']}/`, { waitUntil: 'domcontentloaded' }); await settle(2500)
    // 已有会话时统一登录页会自动跳回应用：再确认一次布局。
    if (await shell().isVisible().catch(() => false)) return true
    await page.locator('input[type=password]').first().waitFor({ timeout: 15000 })
    const inputs = page.locator('form input:not([type=hidden])')
    await inputs.nth(0).fill(who.user); await page.locator('input[type=password]').first().fill(PASSWORD)
    await page.locator('form button[type="submit"]').first().click()
    await settle(800)
    if (who.totp) {
      await page.locator('input[autocomplete="one-time-code"], input[inputmode="numeric"]').first().fill(totp(ids.operatorTOTP))
      await page.locator('form button[type="submit"]').first().click()
    }
    if (who.login === 'seller') {
      await settle(800)
      await page.goto(`${origin}/`, { waitUntil: 'domcontentloaded' }); await settle(800)
      // 卖家站未登录时有“登录”按钮 → 跳门户 /console/seller-login → 带令牌跳回。
      const btn = page.locator('button, a').filter({ hasText: /登录|Sign in/ }).first()
      if (await btn.isVisible().catch(() => false)) await btn.click()
    }
  }
  await settle(2000)
  if (who.login !== 'web') await page.goto(`${origin}${base}/`, { waitUntil: 'domcontentloaded' }).catch(() => {})
  await settle(1500)
  return shell().isVisible().catch(() => false)
}

// ---------- 页面状态指纹 ----------
async function snapshot() {
  return page.evaluate(() => {
    const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
    const overlays = [...document.querySelectorAll('.ant-modal-wrap, .ant-drawer-open, .ant-popover:not(.ant-popover-hidden), .ant-dropdown:not(.ant-dropdown-hidden), .ant-popconfirm, .ant-select-dropdown:not(.ant-select-dropdown-hidden)')].filter(visible).length
    const msgs = [...document.querySelectorAll('.ant-message-notice, .ant-notification-notice, .ant-alert')].filter(visible).map((n) => n.innerText.trim()).join(' | ').slice(0, 300)
    const text = (document.querySelector('main, .portal-shell, #root')?.innerText ?? '').slice(0, 20000)
    let h = 0; for (let i = 0; i < text.length; i++) h = (h * 31 + text.charCodeAt(i)) | 0
    return { url: location.pathname + location.search, overlays, msgs, hash: h, len: text.length }
  })
}

// 弹窗/抽屉里的表单：给每个可见空字段填最小合法值。
async function fillForm(scope) {
  const filled = []
  const fields = scope.locator('input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=file]):not([readonly]):not([disabled]), textarea:not([disabled])')
  const n = Math.min(await fields.count(), 20)
  for (let i = 0; i < n; i++) {
    const f = fields.nth(i)
    if (!(await f.isVisible().catch(() => false))) continue
    if ((await f.inputValue().catch(() => 'x')) !== '') continue
    const meta = await f.evaluate((el) => ({ type: el.type, name: el.name || el.id || '', ph: el.placeholder || '', role: el.getAttribute('role') || '', cls: el.className, label: el.closest('.ant-form-item')?.querySelector('label')?.innerText ?? '' }))
    if (meta.role === 'combobox' || /ant-select-selection-search-input/.test(meta.cls)) {
      await f.click().catch(() => {}); await page.waitForTimeout(300)
      const opt = page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option').first()
      if (await opt.isVisible().catch(() => false)) { await opt.click().catch(() => {}); filled.push(`${meta.label || meta.name}=选第一项`) }
      else await page.keyboard.press('Escape')
      continue
    }
    if (/ant-picker/.test(meta.cls)) continue
    const key = `${meta.name} ${meta.ph} ${meta.label}`.toLowerCase()
    let v = 'uiclick-test'
    const numeric = meta.type === 'number' || /ant-input-number/.test(meta.cls) || /端口|port|数量|次数|秒|分钟|天|大小|限制|阈值|count|limit|seconds|days|size|max|min|weight|权重|价|price|金额|amount|实际支付|费用|余额/.test(key) && !/方式|渠道|名称|单号|交易号|method|channel|name/.test(key)
    if (/mail|邮箱/.test(key)) v = 'uiclick@example.test'
    if (/域名|domain|host|cname/.test(key)) v = 'uiclick-test.example.com'
    if (/(^|[^a-z])ip([^a-z]|$)|ip地址|源站地址|回源地址|address|源站|origin/.test(key) && !/价|金额|amount|price/.test(key)) v = '192.0.2.10'
    if (/url|链接|网址|endpoint|回调/.test(key)) v = 'https://uiclick.example.com/'
    if (/phone|手机/.test(key)) v = '13800000000'
    if (meta.type === 'password' || /密码|password/.test(key)) v = PASSWORD
    if (numeric && !/密码|password/.test(key)) v = '10'
    if (/cidr|网段/.test(key)) v = '192.0.2.0/24'
    await f.fill(v).catch(() => {})
    filled.push(`${meta.label || meta.name || meta.ph}=${v === PASSWORD ? '***' : v}`)
  }
  return filled
}

async function closeOverlays() {
  for (let i = 0; i < 3; i++) {
    const cancel = page.locator('.ant-modal-wrap:visible .ant-modal-footer button:not(.ant-btn-primary), .ant-drawer-open .ant-drawer-close, .ant-modal-wrap:visible .ant-modal-close, .ant-popover:visible .ant-btn:not(.ant-btn-primary)').first()
    if (await cancel.isVisible().catch(() => false)) await cancel.click({ timeout: 2000 }).catch(() => {})
    await page.keyboard.press('Escape').catch(() => {})
    await page.waitForTimeout(250)
  }
}

// ---------- 单页 ----------
async function visit(p) {
  const r = { app, identity, path: p.path, label: p.label, group: p.group ?? null, permission: p.permission ?? null, module: p.module ?? null, issues: [], clicks: [] }
  if (p.needsId) { r.status = 'manual'; r.issues.push({ level: 'info', what: '详情页需要 id，未巡' }); return r }
  net = []; consoleErrors = []
  const url = `${origin}${base}${p.path}`
  try { await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }); await settle(1500) }
  catch (e) { r.issues.push({ level: 'error', what: `打开失败：${String(e).slice(0, 160)}` }) }
  const here = new URL(page.url()).pathname
  if (/\/login$|^\/$/.test(here) && here !== `${base}${p.path}`) r.issues.push({ level: 'error', what: `跳到登录页 ${here}` })
  else if (here !== `${base}${p.path}`) r.issues.push({ level: 'info', what: `重定向到 ${here}` })
  if (!(await shell().isVisible().catch(() => false))) r.issues.push({ level: 'error', what: `布局容器 ${SHELL[app]} 不可见` })
  const resultBlocks = await page.locator('.ant-result').evaluateAll((els) => els.filter((e) => e.offsetHeight).map((e) => `${[...e.classList].find((c) => /ant-result-(\d+|error|warning|info|success)$/.test(c)) ?? ''} ${e.querySelector('.ant-result-title')?.textContent ?? ''}`.trim()))
  for (const b of resultBlocks) {
    const forbidden = /403/.test(b)
    r.issues.push({ level: forbidden && who.limited ? 'warn' : /success|info/.test(b) ? 'info' : 'error', what: `结果块：${b}` })
  }
  const body = (await shell().innerText().catch(() => '')) ?? ''
  r.textLength = body.trim().length
  const ph = body.match(PLACEHOLDER); if (ph) r.issues.push({ level: 'error', what: `占位文案：${ph[0]}` })
  if (r.textLength < 30) r.issues.push({ level: 'warn', what: '页面几乎为空' })
  // "Failed to load resource" 是浏览器对 ≥400 响应的镜像，接口本身已逐条记录，这里不重复计。
  for (const c of [...new Set(consoleErrors)].filter((x) => !/^Failed to load resource/.test(x))) r.issues.push({ level: 'error', what: `console：${c}` })
  for (const n of net.filter((x) => x.status >= 400 || x.status === 0)) {
    if (isEnv(`${n.method} ${n.path} → ${n.status} ${n.body ?? ''}`)) { r.issues.push({ level: 'env', what: `本地环境：${n.method} ${n.path} → ${n.status}` }); continue }
    const lvl = n.status === 403 && who.limited ? 'warn' : n.status === 401 ? 'error' : n.status >= 500 || [0, 404, 405, 501].includes(n.status) ? 'error' : 'warn'
    r.issues.push({ level: lvl, what: `打开即请求 ${n.method} ${n.path} → ${n.status}${n.body ? ' ' + n.body.slice(0, 120) : ''}` })
  }
  r.loadRequests = net.length
  const file = (p.path.replace(/^\//, '').replace(/[/:?=&]+/g, '_') || 'root')
  await page.screenshot({ path: path.join(shotDir, `${file}.zh.png`), fullPage: true }).catch(() => {})
  r.shot = path.relative(path.join(ROOT, 'docs/ui/click-1035'), path.join(shotDir, `${file}.zh.png`))

  if (!has('no-click')) await clickAll(r, url)

  if (!has('no-en')) {
    await page.evaluate(([k]) => localStorage.setItem(k, 'en-US'), [LOCALE_KEY[app]])
    await page.goto(url, { waitUntil: 'domcontentloaded' }).catch(() => {}); await settle(1200)
    await page.screenshot({ path: path.join(shotDir, `${file}.en.png`), fullPage: true }).catch(() => {})
    const enBody = (await shell().innerText().catch(() => '')) ?? ''
    // 英文界面残留中文（排除用户数据里常见的中文显示名/备注）。
    const han = (enBody.match(/[一-龥]{2,}/g) ?? []).filter((w) => !/测试|运营负责人|平台管理员|uiclick/.test(w))
    if (han.length > 3) r.issues.push({ level: 'warn', what: `英文界面残留中文 ${han.length} 处：${[...new Set(han)].slice(0, 6).join('、')}` })
    await page.evaluate(([k]) => localStorage.setItem(k, 'zh-CN'), [LOCALE_KEY[app]])
  }
  r.status = r.issues.some((i) => i.level === 'error') || r.clicks.some((c) => c.level === 'error') ? 'error'
    : r.issues.some((i) => i.level === 'warn') || r.clicks.some((c) => c.level === 'warn') ? 'warn' : 'ok'
  return r
}

async function clickAll(r, url) {
  // 主区域内可见控件（不含侧栏菜单/顶栏），按文字去重；每页最多 25 个。
  const sel = `${SHELL[app]} button:visible, ${SHELL[app]} [role="switch"]:visible, ${SHELL[app]} .ant-tabs-tab:visible, ${SHELL[app]} .ant-segmented-item:visible`
  const targets = await page.locator(sel).evaluateAll((els) => els.map((el, i) => {
    const t = (el.innerText || el.getAttribute('aria-label') || el.title || '').trim().replace(/\s+/g, ' ').slice(0, 40)
    // 已选中的标签页/分段/单选式按钮：再点一次本就不变。
    const active = el.classList.contains('ant-tabs-tab-active') || el.classList.contains('ant-segmented-item-selected') ||
      el.getAttribute('aria-pressed') === 'true' || el.getAttribute('aria-selected') === 'true' || el.getAttribute('aria-checked') === 'true' && el.getAttribute('role') !== 'switch' ||
      (el.classList.contains('ant-btn-primary') && el.parentElement && [...el.parentElement.children].filter((c) => c.tagName === 'BUTTON').length > 2)
    return { i, text: t, active, kind: el.getAttribute('role') === 'switch' ? 'switch' : el.classList.contains('ant-tabs-tab') ? 'tab' : 'button', disabled: el.disabled || el.getAttribute('aria-disabled') === 'true' || el.classList.contains('ant-btn-disabled') }
  }))
  const seen = new Set()
  const list = targets.filter((t) => { const k = `${t.kind}:${t.text}`; if (seen.has(k) || (!t.text && t.kind !== 'switch')) return false; seen.add(k); return true }).slice(0, 25)
  for (const t of list) {
    const c = { text: t.text || '(开关)', kind: t.kind }
    if (t.disabled) { c.result = '禁用（不可点）'; c.level = 'info'; r.clicks.push(c); continue }
    if (SKIP.test(t.text)) { c.result = '跳过（语言/外链）'; c.level = 'info'; r.clicks.push(c); continue }
    // 每次点击前回到干净页面状态
    if (new URL(page.url()).pathname !== new URL(url).pathname) { await page.goto(url, { waitUntil: 'domcontentloaded' }).catch(() => {}); await settle(800) }
    await closeOverlays()
    const el = page.locator(sel).filter({ hasText: t.text || undefined }).nth(0)
    const target = t.text ? el : page.locator(sel).nth(t.i)
    if (!(await target.isVisible().catch(() => false))) { c.result = '重新定位不到'; c.level = 'info'; r.clicks.push(c); continue }
    const before = await snapshot(); net = []; consoleErrors = []
    const danger = DANGER.test(t.text)
    if (t.kind === 'switch' && danger) { c.result = '危险开关，未点'; c.level = 'info'; r.clicks.push(c); continue }
    try { await target.click({ timeout: 4000 }) } catch (e) { c.result = `点击失败：${String(e).split('\n')[0].slice(0, 120)}`; c.level = 'warn'; r.clicks.push(c); continue }
    await page.waitForTimeout(1500); await settle(600)
    let after = await snapshot()
    // 弹出的确认框：危险操作一律取消；非危险的确认框（如“确定提交”）点确定。
    const confirm = page.locator('.ant-popover:visible .ant-btn-primary, .ant-modal-confirm:visible .ant-btn-primary').first()
    if (await confirm.isVisible().catch(() => false)) {
      if (danger) { c.result = '危险操作：出现二次确认，已取消（未执行）'; c.level = 'info'; await closeOverlays(); r.clicks.push(c); continue }
      await confirm.click().catch(() => {}); await page.waitForTimeout(1500); await settle(600); after = await snapshot()
    }
    // 弹窗/抽屉表单：填最小值并提交（危险操作只看弹窗出现，不提交）。
    const dialog = page.locator('.ant-modal-wrap:visible .ant-modal-content, .ant-drawer-open .ant-drawer-content').last()
    if (await dialog.isVisible().catch(() => false)) {
      c.opened = (await dialog.locator('.ant-modal-title, .ant-drawer-title').first().innerText().catch(() => '')).slice(0, 60) || '弹窗'
      const ok = dialog.locator('.ant-modal-footer .ant-btn-primary, .ant-drawer-footer .ant-btn-primary, button[type=submit]').last()
      if (!danger && await ok.isVisible().catch(() => false) && await dialog.locator('form, .ant-form').count()) {
        c.filled = await fillForm(dialog)
        net = []; consoleErrors = []
        await ok.click({ timeout: 3000 }).catch(() => {})
        await page.waitForTimeout(2000); await settle(600)
        const formErrors = await dialog.locator('.ant-form-item-explain-error').allInnerTexts().catch(() => [])
        c.submit = { requests: net.map((n) => `${n.method} ${n.path} → ${n.status}${n.body ? ' ' + n.body.slice(0, 160) : ''}`), formErrors: formErrors.slice(0, 4), msgs: (await snapshot()).msgs }
      }
      await closeOverlays()
    }
    c.requests = (c.requests ?? []).concat(net.filter((n) => !c.submit || !c.submit.requests.includes(`${n.method} ${n.path} → ${n.status}`)).map((n) => `${n.method} ${n.path} → ${n.status}${n.body ? ' ' + n.body.slice(0, 160) : ''}`))
    c.msgs = after.msgs
    c.changed = before.url !== after.url ? `跳转 ${after.url}` : after.overlays > before.overlays ? '弹层' : before.hash !== after.hash ? '内容变化' : after.msgs && after.msgs !== before.msgs ? '提示' : ''
    c.console = [...new Set(consoleErrors)].filter((x) => !/^Failed to load resource/.test(x)).slice(0, 3)
    const all = [...(c.requests ?? []), ...(c.submit?.requests ?? [])].filter((x) => !isEnv(x))
    const bad = all.filter((s) => / → (0|404|405|501|5\d\d)\b/.test(s))
    const soft = all.filter((s) => / → (4\d\d)\b/.test(s) && !bad.includes(s))
    if (bad.length) c.level = 'error'
    else if (c.console.length) c.level = 'error'
    else if (soft.some((s) => / → 403\b/.test(s)) && who.limited) c.level = 'warn'
    else if (soft.length && !(c.submit?.formErrors?.length)) c.level = 'warn'
    // 查询/清除/重置/分页这类按钮在空列表、空筛选下本就无变化：记 info 不算无效果。
    else if (!all.length && !c.changed && !c.opened) c.level = t.active || NEUTRAL.test(t.text) ? 'info' : 'warn'
    else c.level = 'ok'
    if (!all.length && !c.changed && !c.opened) c.result = t.active ? '已是当前选中项' : '点击无效果（无请求、无界面变化）'
    if (c.msgs && !SUCCESS.test(c.msgs) && /失败|错误|error|failed/i.test(c.msgs) && c.level === 'ok') c.level = 'warn'
    // 点击后弹出“X 暂不可用 / 未实现”这类占位提示 = 按钮无真实功能。
    const placeholder = (c.msgs ?? '').match(PLACEHOLDER) ?? (after.msgs !== before.msgs && /暂不可用/.test(after.msgs) ? ['暂不可用'] : null)
    if (placeholder && !all.length) { c.level = 'error'; c.result = `占位按钮：${c.msgs.slice(0, 80)}` }
    r.clicks.push(c)
    if (new URL(page.url()).pathname !== new URL(url).pathname) { await page.goto(url, { waitUntil: 'domcontentloaded' }).catch(() => {}); await settle(800) }
  }
}

// ---------- 主流程 ----------
const started = Date.now()
const loggedIn = await login()
console.log(`[${identity}] 登录 ${loggedIn ? 'ok' : '失败'} 页面 ${pages.length}`)
if (!loggedIn) await page.screenshot({ path: path.join(runDir, 'login-failed.png'), fullPage: true }).catch(() => {})
const tally = {}
for (const p of pages) {
  if (Date.now() - started > Number(arg('budget-min', 55)) * 60000) { console.log('时间预算用完，停止'); break }
  let r
  try { r = await visit(p) } catch (e) { r = { app, identity, path: p.path, label: p.label, status: 'error', issues: [{ level: 'error', what: `巡检异常：${String(e).slice(0, 200)}` }], clicks: [] } }
  tally[r.status] = (tally[r.status] ?? 0) + 1
  fs.appendFileSync(resultsPath, JSON.stringify(r) + '\n')
  const bad = [...r.issues.filter((i) => i.level !== 'info').map((i) => i.what), ...r.clicks.filter((c) => c.level === 'error' || c.level === 'warn').map((c) => `[${c.text}] ${c.result ?? (c.requests ?? []).concat(c.submit?.requests ?? []).join(',')}`)]
  console.log(`${r.status.padEnd(6)} ${p.path} 点击${r.clicks.length}${bad.length ? '  ' + bad.join(' | ').slice(0, 220) : ''}`)
}
console.log(`[${identity}] ${JSON.stringify(tally)} ${Math.round((Date.now() - started) / 1000)}s`)
await context.close()
