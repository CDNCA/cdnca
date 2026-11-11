import './status.css'
import { fill, messages, pickLang } from './i18n'
import { el, renderView, type View } from './render'

// 公开状态页 /status/。
// 只读 GET /v1/status-page/public；服务端 30 秒快照、按来源 IP 限速，这里每 60 秒刷新一次，
// 页面不可见时不刷新。失败时保留上次数据并标「数据可能已过期」。
const endpoint = '/v1/status-page/public'
const refreshMs = 60_000
const lang = pickLang(window.location.search, navigator.languages ?? [navigator.language])
const m = messages(lang)
const root = document.getElementById('status-main')!
const titleNode = document.getElementById('status-title')!
const logo = document.getElementById('status-logo') as HTMLImageElement
const switcher = document.getElementById('status-lang') as HTMLAnchorElement
const footer = document.getElementById('status-footer')!
let last: View | null = null
let etag = ''
let timer = 0

document.documentElement.lang = lang === 'en' ? 'en' : 'zh-CN'
switcher.textContent = m.language
switcher.href = `?lang=${m.languageHref}`
switcher.lang = lang === 'en' ? 'zh-CN' : 'en'
titleNode.textContent = m.defaultTitle
logo.addEventListener('error', () => { logo.hidden = true })

function message(title: string, body: string, retry: boolean) {
  const button = retry ? el('button', { type: 'button', class: 'st-button' }, m.retry) : null
  button?.addEventListener('click', () => { void load() })
  root.replaceChildren(el('section', { class: 'st-empty', role: 'status' }, el('h2', {}, title), el('p', { class: 'st-muted' }, body), button))
}

function apply(view: View, stale: boolean) {
  const title = view.title || m.defaultTitle
  titleNode.textContent = title
  document.title = title
  logo.hidden = !view.show_logo
  if (view.show_logo && !logo.getAttribute('src')) logo.src = '/v1/brand-assets/logo'
  footer.textContent = fill(m.poweredBy, { title })
  if (view.description) titleNode.title = view.description
  renderView(root, view, lang, stale)
}

async function load() {
  window.clearTimeout(timer)
  try {
    const response = await fetch(endpoint, { headers: { Accept: 'application/json', ...(etag ? { 'If-None-Match': etag } : {}) } })
    if (response.status === 304 && last) {
      apply(last, false)
    } else if (response.status === 404) {
      last = null
      message(m.disabledTitle, m.disabledBody, false)
    } else if (response.ok) {
      const view = await response.json() as View
      if (view.schema !== 'cdnca.status-page/v1') throw new Error('schema')
      last = view
      etag = response.headers.get('ETag') ?? ''
      apply(view, false)
    } else {
      throw new Error(String(response.status))
    }
  } catch {
    if (last) apply(last, true)
    else message(m.errorTitle, '', true)
  }
  if (!document.hidden) timer = window.setTimeout(() => { void load() }, refreshMs)
}

document.addEventListener('visibilitychange', () => {
  if (document.hidden) window.clearTimeout(timer)
  else void load()
})
void load()
