// 本地预览：起一个只监听 127.0.0.1 的静态服务，按主控线上的方式提供页面包——
//   - 页面包挂在 /site/t/<id>/<version>/ 下（根路径 302 过去）；这个前缀上的响应带 CSP sandbox
//     （不含 allow-same-origin）和 Access-Control-Allow-Origin: *（只 GET/HEAD、不带凭据），
//     页面 origin 是 null，读不到 Cookie / localStorage，包内的 module 脚本、字体、JSON 照常加载；
//   - 只开放两个公开接口的 mock：GET /v1/control-site/content（含 plugin_content）与
//     GET /v1/control-site/assets/<sha256>，对 Origin: null 只放行 GET / HEAD / OPTIONS，不带凭据；
//   - 其他 /v1/ 与 /dashboard 一律 403，并在终端打印“违规请求”；CSP 违规报告也打印到终端；
//   - /dashboard/login、/dashboard/register、/dashboard/forgot-password 是模拟的平台表单，
//     套上 auth_style（经 /v1/theme/auth-style 下发，与线上 auth_style_url 同形）。
// 每次请求都从源码目录重新打包，改完刷新即可；内容与 pack 输出的 theme.json 完全一致。
import { createServer } from 'node:http'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { extname, join } from 'node:path'

import { buildContent } from './pack.mjs'
import { checkContent, sha256Hex, sniffImage } from './rules.mjs'
import { MOCK_CONTENT } from './scaffold.mjs'

/** 主控对页面包使用的 CSP（预览与线上一致；线上以主控 nginx 配置为准）。 */
export const SANDBOX_CSP = [
  'sandbox allow-scripts allow-forms allow-popups allow-top-navigation-by-user-activation',
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ')

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif',
  '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
}

/** 页面包所在前缀（线上 /site/t/<id>/<version>/）。 */
export const SITE_PREFIX = '/site/t/'
/** 平台登录页样式接口（线上为主题渲染文档里的 auth_style_url）。 */
export const AUTH_STYLE_PATH = '/v1/theme/auth-style'
/** 平台登录 / 注册 / 找回页地址，页面包里的按钮直接链到这里。 */
export const AUTH_PAGES = { '/dashboard/login': 'login', '/dashboard/register': 'register', '/dashboard/forgot-password': 'forgot' }
const AUTH_TITLES = { login: '登录', register: '注册', forgot: '找回密码' }

const AUTH_PAGE = (kind, css, images) => `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${AUTH_TITLES[kind]}（本地预览）</title>
<style>
:root { ${Object.entries(images).map(([slot, url]) => `--cdnca-auth-image-${slot}: url("${url}");`).join(' ')} }
body { margin: 0; font-family: system-ui, sans-serif; }
.cdnca-auth { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #f5f7fa; }
.cdnca-auth-card { width: 375px; max-width: calc(100% - 32px); padding: 28px 30px; background: #fff; border: 1px solid #e5e7eb; border-radius: 6px; }
.cdnca-auth-brand { height: 40px; margin-bottom: 16px; }
.cdnca-auth-title { margin: 0 0 20px; font-size: 22px; }
.cdnca-auth-field { display: block; margin-bottom: 14px; }
.cdnca-auth-field input { width: 100%; height: 40px; box-sizing: border-box; padding: 0 12px; border: 1px solid #d0d5dd; border-radius: 4px; }
.cdnca-auth-submit { width: 100%; height: 40px; border: 0; border-radius: 4px; background: #2563eb; color: #fff; }
</style>
<style id="auth-style">${css.replaceAll('</', '<\\/')}</style></head>
<body><main class="cdnca-auth" data-cdnca-auth="${kind}"><div class="cdnca-auth-card">
<div class="cdnca-auth-brand" aria-hidden="true"></div>
<h1 class="cdnca-auth-title">${AUTH_TITLES[kind]}</h1>
<form class="cdnca-auth-form" action="#" method="get">
<label class="cdnca-auth-field">账号<input name="account" autocomplete="username"></label>
${kind === 'forgot' ? '' : '<label class="cdnca-auth-field">密码<input name="password" type="password" autocomplete="current-password"></label>'}
<button class="cdnca-auth-submit" type="button">${AUTH_TITLES[kind]}</button>
</form></div></main></body></html>`

/** preview/assets 下的每个文件按 sha256 提供（content.json 里写 asset:<sha256> 引用）。 */
function loadAssets(root) {
  const dir = join(root, 'preview/assets')
  const map = new Map()
  if (!existsSync(dir)) return map
  for (const name of readdirSync(dir)) {
    const data = readFileSync(join(dir, name))
    map.set(sha256Hex(data), { name, data, type: TYPES[extname(name).toLowerCase()] ?? 'application/octet-stream' })
  }
  return map
}

function mockContent(root, contentFile) {
  const path = contentFile ?? join(root, 'preview/content.json')
  return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : MOCK_CONTENT
}

/** 创建预览服务（不监听）。log 接收一行文本。 */
export function createPreviewServer(root, { contentFile, log = console.log } = {}) {
  const reportFindings = (findings) => {
    for (const item of findings) log(`[预检] ${item.code} ${item.field}${item.detail ? ` (${item.detail})` : ''}`)
  }
  let lastReport = null
  return createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const path = decodeURIComponent(url.pathname)
    const send = (status, type, body, headers = {}) => {
      res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers })
      res.end(body)
    }
    if (path === '/__preview/csp-report' && req.method === 'POST') {
      let body = ''
      req.on('data', (chunk) => { body += chunk })
      req.on('end', () => {
        try {
          const report = JSON.parse(body)['csp-report'] ?? {}
          log(`[CSP 违规] ${report['violated-directive'] ?? report['effective-directive'] ?? '?'} 阻止了 ${report['blocked-uri'] ?? '?'}`)
        } catch { log('[CSP 违规] (无法解析报告)') }
        send(204, 'text/plain', '')
      })
      return
    }
    // 两个公开接口：只放行 GET / OPTIONS，不带凭据。
    if (path === '/v1/control-site/content' || path.startsWith('/v1/control-site/assets/')) {
      const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, HEAD', 'Vary': 'Origin' }
      if (req.method === 'OPTIONS') return send(204, 'text/plain', '', { ...cors, 'Access-Control-Max-Age': '600' })
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        log(`[违规请求] ${req.method} ${path}：公开接口只允许 GET`)
        return send(405, 'application/json', '{"error":"method_not_allowed"}', { Allow: 'GET' })
      }
      if (path === '/v1/control-site/content') {
        return send(200, 'application/json; charset=utf-8', JSON.stringify(mockContent(root, contentFile)), cors)
      }
      const asset = loadAssets(root).get(path.slice('/v1/control-site/assets/'.length))
      return asset ? send(200, asset.type, asset.data, cors) : send(404, 'application/json', '{"error":"not_found"}', cors)
    }
    const authPage = AUTH_PAGES[path.replace(/\/$/, '')]
    if (!authPage && (path.startsWith('/v1/') || path === '/v1' || path.startsWith('/dashboard')) && path !== AUTH_STYLE_PATH &&
      !path.startsWith(`${AUTH_STYLE_PATH}/assets/`)) {
      log(`[违规请求] ${req.method} ${path}：页面包只能请求 /v1/control-site/content 与 /v1/control-site/assets/`)
      return send(403, 'application/json', '{"error":"forbidden_in_site_bundle"}')
    }
    let built
    try {
      built = buildContent(root)
    } catch (error) {
      return send(500, 'text/plain; charset=utf-8', `打包失败：${error.message}`)
    }
    const raw = Buffer.from(`${JSON.stringify(built.content)}\n`)
    const findings = checkContent(raw).items
    const report = findings.map((x) => `${x.code}:${x.field}`).join(',')
    if (report !== lastReport) {
      lastReport = report
      if (findings.length) reportFindings(findings)
      else log('[预检] 通过')
    }
    if (path === '/__preview/check') return send(200, 'application/json; charset=utf-8', JSON.stringify({ findings }))
    // 平台登录 / 注册 / 找回页（线上是主控 /dashboard/login 等，表单属于平台），套上 auth_style。
    const style = built.content.auth_style ?? { css: '' }
    const images = Object.keys(style.images ?? {}).sort()
    if (path === AUTH_STYLE_PATH) {
      // 线上由主题渲染文档里的 auth_style_url 下发，形状 {css, images: {槽位: 同源图片地址}}。
      const body = { css: style.css ?? '', images: Object.fromEntries(images.map((slot) => [slot,
        `${AUTH_STYLE_PATH}/assets/${sha256Hex(Buffer.from(style.images[slot], 'base64'))}`])) }
      return send(200, 'application/json; charset=utf-8', JSON.stringify(body))
    }
    if (path.startsWith(`${AUTH_STYLE_PATH}/assets/`)) {
      const sha = path.slice(`${AUTH_STYLE_PATH}/assets/`.length)
      const slot = images.find((s) => sha256Hex(Buffer.from(style.images[s], 'base64')) === sha)
      if (!slot) return send(404, 'application/json', '{"error":"not_found"}')
      const data = Buffer.from(style.images[slot], 'base64')
      return send(200, sniffImage(data) || 'application/octet-stream', data)
    }
    if (authPage) {
      const urls = Object.fromEntries(images.map((slot) => [slot,
        `${AUTH_STYLE_PATH}/assets/${sha256Hex(Buffer.from(style.images[slot], 'base64'))}`]))
      return send(200, 'text/html; charset=utf-8', AUTH_PAGE(authPage, style.css ?? '', urls))
    }
    const bundle = built.content.site_bundle
    const base = `${SITE_PREFIX}${built.content.id}/${built.content.version}/`
    if (!bundle) return send(404, 'text/plain; charset=utf-8', '这个主题没有官网页面包（applies_to 不含 site）；打开 /dashboard/login 查看登录页样式。')
    // 线上：页面包挂在 /site/t/<id>/<version>/ 下，站点根路径与站内路径落到入口页。
    if (!path.startsWith(SITE_PREFIX) && extname(path) !== '') return send(404, 'text/plain; charset=utf-8', 'not found')
    if (!path.startsWith(SITE_PREFIX)) {
      res.writeHead(302, { Location: `${base}${path === '/' ? '' : path.replace(/^\//, '')}` })
      return res.end()
    }
    if (!path.startsWith(base)) return send(404, 'text/plain; charset=utf-8', `当前预览的页面包在 ${base}`)
    const rel = path.slice(base.length)
    const file = bundle.files.find((f) => f.path === (rel === '' || rel.endsWith('/') ? `${rel}${bundle.entry}` : rel))
      ?? (extname(rel) === '' ? bundle.files.find((f) => f.path === bundle.entry) : undefined)
    // 沙箱 CSP 与 ACAO 只加在 /site/t/ 前缀：页面 origin 为 null，包内的 module 脚本、字体、JSON 照常加载。
    const headers = { 'Content-Security-Policy': `${SANDBOX_CSP}; report-uri /__preview/csp-report`, 'Referrer-Policy': 'no-referrer',
      'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, HEAD' }
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(405, 'text/plain', '', { ...headers, Allow: 'GET, HEAD' })
    if (!file) return send(404, 'text/plain; charset=utf-8', 'not found', headers)
    return send(200, TYPES[extname(file.path).toLowerCase()] ?? 'application/octet-stream', Buffer.from(file.data_base64, 'base64'), headers)
  })
}
