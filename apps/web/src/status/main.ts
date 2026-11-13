import '@cdnca/ui/status.css'
import { closeDayCard, snapshotCard, type Snapshot } from '@cdnca/ui/status/daycard'
import { incidentTitle, renderIncident, renderNotFound } from '@cdnca/ui/status/detail'
import { el } from '@cdnca/ui/status/dom'
import { fill, messages } from '@cdnca/ui/status/i18n'
import { chooseView, findIncident, parseRoute, parseView, pickLang, type View } from '@cdnca/ui/status/model'
import { hideTip, renderView } from '@cdnca/ui/status/render'

// 公开状态页 /status/。外观与交互来自共用模块 packages/cdnca-ui/src/status，
// 这里只负责取数和客户自己的品牌：logo、标题、说明、语言切换。
// 只读 GET /v1/status-page/public；服务端 30 秒快照、按来源 IP 限速，这里每 60 秒刷新一次，
// 页面不可见时不刷新。失败时保留上次数据并标「稍后自动重试」。
// 路由用 hash：#/incident/<id> 是事件详情，其余是列表。
const endpoint = '/v1/status-page/public'
const REFRESH_MS = 60_000
const RETRY_MS = 30_000
const FETCH_TIMEOUT_MS = 8000
const lang = pickLang(window.location.search, navigator.languages ?? [navigator.language])
const m = messages(lang)
const root = document.getElementById('status-main')!
const titleNode = document.getElementById('status-title')!
const logo = document.getElementById('status-logo') as HTMLImageElement
const switcher = document.getElementById('status-lang') as HTMLAnchorElement
const footer = document.getElementById('status-footer')!
const expanded = new Map<string, boolean>()
let last: View | null = null
let flags = { stale: false, failed: false }
let loaded = false
let disabled = false
let etag = ''
let timer = 0
let mode: '' | 'list' | 'incident' = ''
let shown = ''
/** 进入详情前的列表现场：滚动位置和打开的当天卡片，返回时恢复。 */
let saved: { scrollY: number; card: Snapshot | null } | null = null

document.documentElement.lang = lang === 'en' ? 'en' : 'zh-CN'
switcher.textContent = m.language
switcher.href = `?lang=${m.languageHref}`
switcher.lang = lang === 'en' ? 'zh-CN' : 'en'
titleNode.textContent = m.defaultTitle
document.title = m.defaultTitle
logo.addEventListener('error', () => { logo.hidden = true })

function brand(view: View | null) {
  const title = view?.title || m.defaultTitle
  titleNode.textContent = title
  titleNode.title = view?.description || ''
  logo.hidden = !view?.show_logo
  if (view?.show_logo && !logo.getAttribute('src')) logo.src = '/v1/brand-assets/logo'
  footer.textContent = fill(m.poweredBy, { title })
  return title
}

function message(title: string, body: string, retry: boolean) {
  const button = retry ? el('button', { type: 'button', class: 'st-button' }, m.retry) : null
  button?.addEventListener('click', () => { void load() })
  root.replaceChildren(el('section', { class: 'st-empty', role: 'status' }, el('h2', {}, title), body ? el('p', { class: 'st-muted' }, body) : null, button))
}

function focusHeading() {
  document.getElementById('st-detail-title')?.focus({ preventScroll: true })
  window.scrollTo(0, 0)
}

/** 按当前 hash 画页面。navigated 表示这次是路由变化（需要处理焦点与滚动），否则是每分钟的数据刷新。 */
function paint(navigated: boolean) {
  if (!loaded) return
  if (disabled) {
    brand(null)
    document.title = m.disabledTitle
    message(m.disabledTitle, m.disabledBody, false)
    return
  }
  const title = brand(last)
  const route = parseRoute(window.location.hash)
  if (route.name === 'incident') {
    if (navigated && mode === 'list') saved = { scrollY: window.scrollY, card: snapshotCard() }
    hideTip(); closeDayCard()
    if (!last) {
      message(m.errorTitle, '', true)
      document.title = title
      mode = 'incident'; shown = 'unavailable'
      return
    }
    const item = findIncident(last, route.id)
    const key = item ? `${route.id}|${last.generated_at}|${flags.failed}` : `missing|${route.id}`
    if (!navigated && shown === key) return
    if (item) {
      renderIncident(root, last, item, lang)
      document.title = `${incidentTitle(item, lang)} · ${title}`
    } else {
      renderNotFound(root, lang)
      document.title = `${m.notFoundTitle} · ${title}`
    }
    mode = 'incident'; shown = key
    if (navigated) focusHeading()
    return
  }
  const back = navigated && mode === 'incident' ? saved : null
  mode = 'list'; shown = ''
  document.title = title
  if (!last) {
    message(m.errorTitle, '', true)
    return
  }
  renderView(root, last, lang, { ...flags, expanded, restore: back?.card ?? null })
  if (back) { window.scrollTo(0, back.scrollY); saved = null }
}

async function fetchView(): Promise<{ view: View | null; disabled: boolean }> {
  const controller = new AbortController()
  const abort = window.setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  try {
    const response = await fetch(endpoint, { headers: { Accept: 'application/json', ...(etag && last ? { 'If-None-Match': etag } : {}) }, signal: controller.signal })
    if (response.status === 304 && last) return { view: last, disabled: false }
    if (response.status === 404) return { view: null, disabled: true }
    if (!response.ok) return { view: null, disabled: false }
    const view = parseView(await response.json())
    etag = response.headers.get('ETag') ?? ''
    return { view, disabled: false }
  } catch {
    return { view: null, disabled: false }
  } finally {
    window.clearTimeout(abort)
  }
}

async function load() {
  window.clearTimeout(timer)
  const result = await fetchView()
  const picked = chooseView(result.view, Date.now())
  disabled = result.disabled
  if (disabled) last = null
  else if (picked) last = picked.view
  flags = { stale: picked?.stale ?? false, failed: !picked && !disabled }
  const first = !loaded
  loaded = true
  paint(first)
  root.setAttribute('aria-busy', 'false')
  if (!document.hidden) timer = window.setTimeout(() => { void load() }, picked && !picked.stale ? REFRESH_MS : RETRY_MS)
}

root.setAttribute('aria-busy', 'true')
root.setAttribute('aria-label', m.loading)
window.addEventListener('hashchange', () => paint(true))
document.addEventListener('visibilitychange', () => {
  if (document.hidden) window.clearTimeout(timer)
  else void load()
})
void load()
