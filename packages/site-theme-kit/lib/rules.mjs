// 本地预检：与 libs/sitetheme（市场上传、授权端、主控安装三处共用的 Go 校验库）同一套规则和
// 错误码（site_theme.*）。权威仍是 Go 库：test/sitetheme-go.test.mjs 用库本身复核脚手架和示例。
// 与库不同的是这里一次列出全部问题（库遇到第一个就返回），方便开发时一次改完。
import { createHash } from 'node:crypto'

export const SCHEMA_V2 = 'cdnca.site-theme/v2'
export const CONSOLE_SCHEMA = 'cdnca.theme/v1'
export const MAX_CONTENT_BYTES = 8 << 20
export const BUNDLE_MAX_FILES = 2000
export const DEFAULT_ENTRY = 'index.html'
export const IMAGE_MAX_BYTES = 2 << 20
export const AUTH_STYLE_MAX_CSS = 256 << 10
export const AUTH_STYLE_MAX_IMAGES = 32
/** 预览图（主题卡片首页截图）：png/jpeg/webp，按内容嗅探，单张上限 512 KiB，建议 1200×750。 */
export const PREVIEW_MAX_BYTES = 512 << 10
export const PREVIEW_SLOT = 'preview'
export const CONTENT_SCHEMA_MAX_FIELDS = 100
export const CONTENT_SCHEMA_MAX_LIST_FIELDS = 30
export const FIELD_TYPES = ['text', 'textarea', 'richtext', 'image', 'link', 'list']
export const THIRD_PARTY_SCOPES = ['user+site', 'user', 'site']
export const BUNDLE_EXTENSIONS = ['html', 'css', 'js', 'mjs', 'json', 'svg', 'png', 'jpg', 'jpeg', 'webp', 'gif', 'ico',
  'woff', 'woff2', 'ttf', 'txt', 'map']
export const TEXT_EXTENSIONS = ['html', 'css', 'js', 'mjs', 'json', 'svg', 'txt', 'map']
/** 页面包只能引用的两个公开接口。 */
export const PUBLIC_API = ['/v1/control-site/content', '/v1/control-site/assets/']

const MARKET_ID = /^market\.[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$/
const VERSION = /^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$/
const SEGMENT = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/
const SHA = /^[0-9a-f]{64}$/
const SLOT = /^[a-z0-9][a-z0-9-]{0,47}$/
const FIELD_KEY = /^[a-z][a-z0-9_]{0,63}$/
const LOCALES = ['zh-CN', 'zh-TW', 'en-US']
const MARKUP = /[<>]/
const ADMIN_ROLE_SELECTOR = /data-cdnca-role\s*[~|^$*]?=\s*["']?\s*admin\b/i
const ADMIN_WORD = /(?:^|[^a-z0-9_])admin(?:$|[^a-z0-9_])/i
const SCOPE_KEYS = ['scope', 'scopes', 'role', 'roles', 'applies_to']
const BASE_TAG = /<\s*base[\s/>]/i
const EXTERNAL_IMPORT = /\bimport\b[^;"'`]{0,200}?["'`]\s*(?:[a-z][a-z0-9+.-]*:|\/\/|\\\\)/i
const FORBIDDEN_CSS = ['</style', '<script', '@import', 'expression(', 'javascript:', 'vbscript:', 'behavior:', '-moz-binding',
  'image-set(', 'src(']
const DATA_IMAGE = /^data:image\/(?:png|jpeg|webp|gif|svg\+xml)(?:;base64)?,/

export class Findings {
  constructor() { this.items = [] }
  add(code, field = '', detail = '') { this.items.push({ code: `site_theme.${code}`, field, detail }) }
  get ok() { return this.items.length === 0 }
}

export function validBundlePath(p) {
  if (typeof p !== 'string' || p === '' || p.length > 256 || p.startsWith('/')) return false
  const segments = p.split('/')
  return segments.every((s) => SEGMENT.test(s) && s !== '.' && s !== '..')
}

export function extension(p) {
  const base = p.slice(p.lastIndexOf('/') + 1)
  const dot = base.lastIndexOf('.')
  return dot <= 0 ? '' : base.slice(dot + 1).toLowerCase()
}

function normalizeText(text) {
  return text.toLowerCase().replaceAll('\\/', '/').replaceAll('\\x2f', '/').replaceAll('\\u002f', '/').replaceAll('%2f', '/')
    .replaceAll('&#47;', '/').replaceAll('&#x2f;', '/').replaceAll('&sol;', '/')
}

const isWord = (c) => /[a-z0-9_]/.test(c)
const isPath = (c) => isWord(c) || '-./%~'.includes(c)

/** 页面包只能链接的三个平台页面：登录、注册、找回密码（后面只能跟 ?query 或 #hash）。 */
export const AUTH_LINKS = ['/dashboard/login', '/dashboard/register', '/dashboard/forgot-password']

function forbiddenDashboard(text) {
  let rest = text
  for (;;) {
    const index = rest.indexOf('/dashboard')
    if (index < 0) return false
    const tail = rest.slice(index)
    rest = rest.slice(index + '/dashboard'.length)
    const route = AUTH_LINKS.find((r) => tail.startsWith(r))
    if (!route) return true
    const after = tail.slice(route.length)
    if (after !== '' && isPath(after[0])) return true
  }
}

function forbiddenV1(text) {
  let rest = text
  for (;;) {
    const index = rest.indexOf('/v1')
    if (index < 0) return false
    const tail = rest.slice(index)
    rest = rest.slice(index + 3)
    if (tail.length > 3 && isWord(tail[3])) continue
    if (!allowedV1Ref(tail)) return true
  }
}

function allowedV1Ref(tail) {
  for (const prefix of PUBLIC_API) {
    if (!tail.startsWith(prefix)) continue
    const after = tail.slice(prefix.length)
    if (prefix.endsWith('/')) {
      const end = after.search(/["'` ()<>?#\n\r\t]/)
      const ref = end < 0 ? after : after.slice(0, end)
      return !ref.includes('..') && !ref.includes('/')
    }
    return after === '' || !isPath(after[0])
  }
  return false
}

/** 同源相对地址：没有 scheme、不是 //、没有反斜线。 */
export function relativeRef(value) {
  const v = value.trim()
  if (v.startsWith('//') || v.includes('\\')) return false
  const colon = v.indexOf(':')
  if (colon >= 0) {
    const slash = v.search(/[/?#]/)
    if (slash < 0 || colon < slash) return false
  }
  return true
}

function attributes(tag) {
  const out = {}
  for (const m of tag.matchAll(/([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*("[^"]*"|'[^']*'|[^\s"'=<>`]+))?/g)) {
    out[m[1].toLowerCase()] = (m[2] ?? '').replace(/^["']|["']$/g, '')
  }
  return out
}

function scanHTML(text) {
  for (const m of text.matchAll(/<\s*([a-zA-Z][a-zA-Z0-9-]*)\b([^>]*)>/g)) {
    const name = m[1].toLowerCase()
    const attrs = attributes(m[2])
    if (name === 'base') return 'bundle_base'
    if (name === 'script' && 'src' in attrs && !relativeRef(attrs.src)) return 'bundle_external_script'
    if (name === 'link') {
      const loadsScript = (attrs.rel ?? '').toLowerCase().includes('modulepreload') || (attrs.as ?? '').trim().toLowerCase() === 'script'
      if (loadsScript && 'href' in attrs && !relativeRef(attrs.href)) return 'bundle_external_script'
    }
  }
  return ''
}

/** 一个页面包文件的第一个违规码（不带前缀），没有返回 ''。 */
export function scanFile(ext, data) {
  if (!TEXT_EXTENSIONS.includes(ext)) return ''
  const raw = Buffer.from(data).toString('utf8')
  const text = normalizeText(raw)
  if (forbiddenDashboard(text)) return 'bundle_dashboard'
  if (forbiddenV1(text)) return 'bundle_api'
  if (text.includes('serviceworker')) return 'bundle_service_worker'
  if (ADMIN_ROLE_SELECTOR.test(text)) return 'bundle_admin'
  if (ext === 'html') {
    const code = scanHTML(raw)
    if (code) return code
  }
  if (ext === 'html' || ext === 'js' || ext === 'mjs') {
    if (BASE_TAG.test(text)) return 'bundle_base'
    if (EXTERNAL_IMPORT.test(text)) return 'bundle_external_script'
  }
  return ''
}

function checkI18n(f, text, max, required, field) {
  if (text === undefined || text === null || (typeof text === 'object' && Object.keys(text).length === 0)) {
    if (required) f.add('i18n_required', field)
    return
  }
  if (typeof text !== 'object' || Array.isArray(text)) return f.add('package_json', field)
  if (!text['zh-CN']) return f.add('i18n_required', `${field}.zh-CN`)
  for (const [locale, value] of Object.entries(text)) {
    if (!LOCALES.includes(locale) || typeof value !== 'string' || value === '' || [...value].length > max ||
      value.trim() !== value || MARKUP.test(value) || /\p{Cc}/u.test(value)) f.add('i18n_value', `${field}.${locale}`)
  }
}

function scopesKey(values) {
  return ['admin', 'user', 'site'].filter((s) => values.includes(s)).join('+')
}

function walkAdmin(value, field, scopeKey) {
  if (Array.isArray(value)) {
    for (const [i, item] of value.entries()) {
      const found = walkAdmin(item, `${field}[${i}]`, scopeKey)
      if (found) return found
    }
  } else if (value && typeof value === 'object') {
    for (const key of Object.keys(value).sort()) {
      const found = walkAdmin(value[key], `${field}.${key}`, SCOPE_KEYS.includes(key))
      if (found) return found
    }
  } else if (typeof value === 'string') {
    if ((scopeKey && ADMIN_WORD.test(value)) || ADMIN_ROLE_SELECTOR.test(value)) return field
  }
  return ''
}

export function checkAuthCSS(css) {
  if (typeof css !== 'string') return 'auth_style_css'
  if (Buffer.byteLength(css) > AUTH_STYLE_MAX_CSS) return 'auth_style_size'
  if (css.includes('\\') || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(css)) return 'auth_style_css'
  const lower = css.toLowerCase()
  if (FORBIDDEN_CSS.some((x) => lower.includes(x))) return 'auth_style_css'
  if (ADMIN_ROLE_SELECTOR.test(lower)) return 'admin_forbidden'
  let rest = lower
  for (;;) {
    const index = rest.indexOf('url(')
    if (index < 0) break
    rest = rest.slice(index + 4)
    const end = rest.indexOf(')')
    if (end < 0) return 'auth_style_url'
    const arg = rest.slice(0, end).trim().replace(/^["']|["']$/g, '').trim()
    const ok = arg !== '' && (arg.startsWith('data:') ? DATA_IMAGE.test(arg)
      : !arg.startsWith('//') && !arg.includes('..') && !/["']/.test(arg) && relativeRef(arg))
    if (!ok) return 'auth_style_url'
    rest = rest.slice(end + 1)
  }
  if (lower.includes('://') || lower.includes('"//') || lower.includes("'//")) return 'auth_style_url'
  return ''
}

/** 识别图片类型（与库 SniffImage 一致；SVG 只做粗检，库里另有完整的安全 SVG 检查）。 */
export function sniffImage(body) {
  const b = Buffer.from(body)
  if (b.length === 0 || b.length > IMAGE_MAX_BYTES) return ''
  if (b.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))) return 'image/png'
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg'
  if (b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP') return 'image/webp'
  if (b[0] === 0 && b[1] === 0 && b[2] === 1 && b[3] === 0) return 'image/x-icon'
  const text = b.toString('utf8').toLowerCase()
  if (text.includes('<svg') && !/<script|\bon[a-z]+\s*=|javascript:|<foreignobject|href\s*=\s*["']\s*(?!#)/.test(text)) return 'image/svg+xml'
  return ''
}

function checkFields(f, fields, field, top) {
  const max = top ? CONTENT_SCHEMA_MAX_FIELDS : CONTENT_SCHEMA_MAX_LIST_FIELDS
  if (!Array.isArray(fields) || fields.length === 0 || fields.length > max) return f.add('content_schema', field)
  const keys = new Set()
  for (const [i, value] of fields.entries()) {
    const at = `${field}[${i}]`
    if (!FIELD_KEY.test(value?.key ?? '')) { f.add('content_key', `${at}.key`); continue }
    if (keys.has(value.key)) { f.add('content_key_duplicate', `${at}.key`); continue }
    keys.add(value.key)
    if (!FIELD_TYPES.includes(value.type)) { f.add('content_type', `${at}.type`); continue }
    if (value.type === 'list' && !top) { f.add('content_nesting', `${at}.type`); continue }
    checkI18n(f, value.label, 64, true, `${at}.label`)
    checkI18n(f, value.help, 256, false, `${at}.help`)
    const textual = ['text', 'textarea', 'richtext'].includes(value.type)
    const maxLength = value.max_length ?? 0
    if (!Number.isInteger(maxLength) || maxLength < 0 || maxLength > 20000 || (maxLength !== 0 && !textual)) f.add('content_max_length', `${at}.max_length`)
    const maxItems = value.max_items ?? 0
    if (!Number.isInteger(maxItems) || maxItems < 0 || maxItems > 200 || (maxItems !== 0 && value.type !== 'list')) f.add('content_max_items', `${at}.max_items`)
    if (value.type !== 'list') {
      if (value.fields !== undefined) f.add('content_fields', `${at}.fields`)
      continue
    }
    checkFields(f, value.fields, `${at}.fields`, false)
  }
}

/**
 * 预检打包后的 v2 content（JSON 字节）。返回 Findings。
 * pluginID 给出时额外检查 id = market.<pluginID>（市场审核同样检查）。
 */
export function checkContent(raw, { pluginID } = {}) {
  const f = new Findings()
  const bytes = Buffer.from(raw)
  if (bytes.length === 0 || bytes.length > MAX_CONTENT_BYTES) f.add('package_size', '', `${bytes.length} bytes, limit ${MAX_CONTENT_BYTES}`)
  let pkg
  try {
    pkg = JSON.parse(bytes.toString('utf8'))
  } catch {
    f.add('package_json')
    return f
  }
  const allowed = ['schema', 'id', 'version', 'name', 'description', 'applies_to', 'console_theme', 'site_bundle', 'auth_style', 'content_schema', 'preview']
  for (const key of Object.keys(pkg)) if (!allowed.includes(key)) f.add('package_json', key, 'unknown field')
  if (pkg.schema !== SCHEMA_V2) f.add('schema', 'schema')
  if (typeof pkg.id !== 'string' || pkg.id.length > 128 || !MARKET_ID.test(pkg.id)) f.add('id', 'id', 'third-party themes are market.<plugin id>')
  else if (pluginID && pkg.id !== `market.${pluginID}`) f.add('id', 'id', `must be market.${pluginID}`)
  if (!VERSION.test(pkg.version ?? '')) f.add('version', 'version')
  checkI18n(f, pkg.name, 64, true, 'name')
  checkI18n(f, pkg.description, 512, false, 'description')

  const scopes = Array.isArray(pkg.applies_to) ? pkg.applies_to : []
  if (!Array.isArray(pkg.applies_to) || scopes.some((s) => !['admin', 'user', 'site'].includes(s)) || new Set(scopes).size !== scopes.length) {
    f.add('applies_to', 'applies_to')
  } else if (scopes.includes('admin')) {
    f.add('admin_forbidden', 'applies_to', 'only the official publisher io.cdnca may theme the admin console')
  } else if (!THIRD_PARTY_SCOPES.includes(scopesKey(scopes))) {
    f.add('applies_to', 'applies_to')
  }
  const user = scopes.includes('user')
  const site = scopes.includes('site')
  if (user && pkg.console_theme === undefined) f.add('console_theme_required', 'console_theme')
  if (!user && pkg.console_theme !== undefined) f.add('console_theme_unexpected', 'console_theme')
  if (site && pkg.site_bundle === undefined) f.add('site_bundle_required', 'site_bundle')
  if (!site && pkg.site_bundle !== undefined) f.add('site_bundle_unexpected', 'site_bundle')
  if (!site && pkg.content_schema !== undefined) f.add('content_schema_unexpected', 'content_schema')

  if (user && pkg.console_theme !== undefined) {
    const c = pkg.console_theme
    if (!c || typeof c !== 'object' || Array.isArray(c)) f.add('console_theme', 'console_theme')
    else {
      if (c.schema !== CONSOLE_SCHEMA) f.add('console_theme_schema', 'console_theme.schema')
      if (c.tokens_by_role && typeof c.tokens_by_role === 'object' && 'admin' in c.tokens_by_role) f.add('admin_forbidden', 'console_theme.tokens_by_role.admin')
      else {
        const found = walkAdmin(c, 'console_theme', false)
        if (found) f.add('admin_forbidden', found)
      }
    }
  }

  if (site && pkg.site_bundle !== undefined) {
    const bundle = pkg.site_bundle
    const files = Array.isArray(bundle?.files) ? bundle.files : []
    if (files.length === 0 || files.length > BUNDLE_MAX_FILES) f.add('bundle_files', 'site_bundle.files')
    const seen = new Set()
    for (const [i, file] of files.entries()) {
      const field = `site_bundle.files[${i}]`
      if (!validBundlePath(file.path)) { f.add('bundle_path', `${field}.path`, String(file.path)); continue }
      const ext = extension(file.path)
      if (!BUNDLE_EXTENSIONS.includes(ext)) { f.add('bundle_extension', `${field}.path`, file.path); continue }
      if (seen.has(file.path.toLowerCase())) { f.add('bundle_duplicate', `${field}.path`, file.path); continue }
      seen.add(file.path.toLowerCase())
      if (!SHA.test(file.sha256 ?? '')) { f.add('bundle_sha256', `${field}.sha256`); continue }
      const data = Buffer.from(file.data_base64 ?? '', 'base64')
      if (data.toString('base64') !== file.data_base64) { f.add('bundle_data', `${field}.data_base64`); continue }
      const sum = sha256Hex(data)
      if (sum !== file.sha256) { f.add('bundle_sha256_mismatch', `${field}.sha256`); continue }
      const code = scanFile(ext, data)
      if (code) f.add(code, `${field}.data_base64`, file.path)
    }
    const entry = bundle?.entry ?? DEFAULT_ENTRY
    if (!validBundlePath(entry) || extension(entry) !== 'html' || !files.some((x) => x.path === entry)) f.add('bundle_entry', 'site_bundle.entry', entry)
  }

  if (pkg.auth_style !== undefined) {
    const style = pkg.auth_style
    const code = checkAuthCSS(style?.css)
    if (code) f.add(code, 'auth_style.css')
    const images = style?.images ?? {}
    if (Object.keys(images).length > AUTH_STYLE_MAX_IMAGES) f.add('auth_style_images', 'auth_style.images')
    for (const slot of Object.keys(images).sort()) {
      const field = `auth_style.images.${slot}`
      if (!SLOT.test(slot) || slot === PREVIEW_SLOT) { f.add('image_slot', field); continue }
      const body = Buffer.from(images[slot], 'base64')
      if (body.toString('base64') !== images[slot] || !sniffImage(body)) f.add('image_body', field)
    }
  }
  if (site && pkg.content_schema !== undefined) checkFields(f, pkg.content_schema, 'content_schema', true)
  if (pkg.preview !== undefined) {
    const code = checkPreview(pkg.preview)
    if (code) f.add(code, 'preview')
  }
  return f
}

/** 预检 v2 顶层 preview（base64）：返回错误码或 ''。与库 parsePreview 一致。 */
export function checkPreview(encoded) {
  if (typeof encoded !== 'string' || encoded === '') return 'preview'
  const body = Buffer.from(encoded, 'base64')
  if (body.toString('base64') !== encoded) return 'preview'
  if (body.length > PREVIEW_MAX_BYTES) return 'preview_size'
  return ['image/png', 'image/jpeg', 'image/webp'].includes(sniffImage(body)) ? '' : 'preview'
}

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex')
}
