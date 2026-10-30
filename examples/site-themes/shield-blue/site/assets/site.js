// 读官网内容接口，把 content_schema 声明的字段填进页面。
// 页面包只能请求两个公开接口：/v1/control-site/content 与 /v1/control-site/assets/<sha256>；
// 登录 / 注册 / 找回密码直接链到平台的 /dashboard/login、/dashboard/register、/dashboard/forgot-password。
// 以 <script type="module"> 加载：页面包内的模块、字体、JSON 都可以按相对路径正常引用。
import { features as defaultFeatures } from './defaults.mjs'

const CONTENT = '/v1/control-site/content'
const AUTH = { '#login': '/dashboard/login', '#register': '/dashboard/register' }

function imageURL(ref) {
  const m = /^asset:([0-9a-f]{64})$/.exec(ref || '')
  return m ? `/v1/control-site/assets/${m[1]}` : ''
}

function el(tag, className, text) {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text) node.textContent = text
  return node
}

function list(name, items, build) {
  const host = document.querySelector(`[data-list="${name}"]`)
  if (!host || !Array.isArray(items) || items.length === 0) return
  host.textContent = ''
  for (const item of items) host.appendChild(build(item || {}))
}

// 链接字段 {label, href}：站内路径、https、平台登录注册占位（#login / #register）。
function safeHref(href) {
  if (AUTH[href]) return AUTH[href]
  return /^(\/(?!\/)|https:\/\/|#)/.test(href || '') ? href : '#'
}

function render(doc) {
  const values = doc.plugin_content || {}
  for (const node of document.querySelectorAll('[data-bind]')) {
    const key = node.getAttribute('data-bind')
    const value = key === 'brand_name' ? doc.brand && doc.brand.name : values[key]
    if (typeof value === 'string' && value) node.textContent = value
  }
  if (doc.brand && doc.brand.title) document.title = doc.brand.title

  list('stats', values.stats, (item) => {
    const box = el('div')
    box.appendChild(el('dt', '', item.label))
    box.appendChild(el('dd', '', item.value))
    return box
  })
  list('features', values.features, (item) => {
    const li = el('li')
    const src = imageURL(item.icon)
    if (src) {
      const img = el('img')
      img.src = src
      img.alt = ''
      li.appendChild(img)
    }
    li.appendChild(el('h3', '', item.title))
    li.appendChild(el('p', '', item.body))
    return li
  })
  list('plans', values.plans, (item) => {
    const li = el('li', item.featured === 'yes' ? 'is-featured' : '')
    li.appendChild(el('h3', '', item.name))
    const price = el('div', 'sb-price hb-price', item.price)
    if (item.unit) price.appendChild(el('small', '', ` ${item.unit}`))
    li.appendChild(price)
    const points = el('ul')
    for (const p of String(item.points || '').split('\n').filter(Boolean)) points.appendChild(el('li', '', p))
    li.appendChild(points)
    const cta = el('a', 'sb-button hb-button', (item.action && item.action.label) || '立即购买')
    cta.href = safeHref(item.action && item.action.href)
    cta.target = '_top'
    li.appendChild(cta)
    return li
  })
  list('faq', values.faq, (item) => {
    const box = el('details', 'sb-faq hb-faq')
    box.appendChild(el('summary', '', item.question))
    box.appendChild(el('p', '', item.answer))
    return box
  })
}

// 内容接口不可用或客户还没填时，用包内默认文案。
render({ plugin_content: { features: defaultFeatures } })
fetch(CONTENT, { credentials: 'omit', headers: { Accept: 'application/json' } })
  .then((response) => (response.ok ? response.json() : null))
  .then((doc) => { if (doc && doc.enabled) render(doc) })
  .catch(() => { /* 保留默认文案 */ })
