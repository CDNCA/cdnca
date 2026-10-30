// 本机 UI 巡检用前端服务：按生产前置的路由把四端 dist 与接口代理放到三个本机端口。
//   web（主控）            :WEB_PORT     /dashboard/* 静态（SPA 回落 index.html），/v1/ 等 → control-api
//   运营后台 + 客户门户      :AUTH_PORT    /operator/* 与 /console/* 静态，/operator/v1、/portal/v1、/auth/v1 → license-service
//   卖家站                  :SELLER_PORT  / 静态，/seller/v1 → market-service 卖家监听
// 路由依据：apps/web/nginx.conf（/v1/ → control-api，/dashboard/ SPA）、services/management-web/main.go isAPIPath、
// apps/seller-portal/vite.config.ts（/seller/v1）。只监听 127.0.0.1，仅供本机巡检，无鉴权层（鉴权由后端完成）。
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..')
const env = (k, d) => process.env[k] ?? d
const CONTROL = env('UICLICK_CONTROL', 'http://127.0.0.1:58080')
const LICENSE = env('UICLICK_LICENSE', 'http://127.0.0.1:58081')
const SELLER = env('UICLICK_SELLER', 'http://127.0.0.1:59445')

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.woff': 'font/woff', '.map': 'application/json', '.webp': 'image/webp' }

function serveStatic(res, dir, rel) {
  let file = path.join(dir, rel)
  if (!file.startsWith(dir)) { res.writeHead(400).end(); return }
  // 资源文件不存在 → 404；页面路由 → index.html（SPA）。
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    if (path.extname(rel) && rel !== '/') { res.writeHead(404).end('not found'); return }
    file = path.join(dir, 'index.html')
  }
  res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' })
  fs.createReadStream(file).pipe(res)
}

function proxy(req, res, target) {
  const t = new URL(target)
  const headers = { ...req.headers, host: req.headers.host, 'x-forwarded-for': '127.0.0.1', 'x-forwarded-proto': 'http' }
  const up = http.request({ hostname: t.hostname, port: t.port, method: req.method, path: req.url, headers }, (r) => {
    res.writeHead(r.statusCode ?? 502, r.headers)
    r.pipe(res)
  })
  up.on('error', (e) => { if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' }); res.end(`upstream error: ${e.message}`) })
  req.pipe(up)
}

const listen = (port, handler) => http.createServer(handler).listen(port, '127.0.0.1', () => console.log(`front :${port}`))

const webDist = path.join(root, 'apps/web/dist')
listen(Number(env('UICLICK_WEB_PORT', 55101)), (req, res) => {
  const u = new URL(req.url, 'http://x')
  if (/^\/(v1|api|auth|control|installation|public|activation|downloads|_cdnca)\//.test(u.pathname) || u.pathname === '/health/ready') return proxy(req, res, CONTROL)
  if (u.pathname === '/' ) { res.writeHead(302, { Location: '/dashboard/' }).end(); return }
  if (u.pathname === '/runtime-config.js') return serveStatic(res, webDist, '/runtime-config.js')
  if (u.pathname.startsWith('/dashboard')) return serveStatic(res, webDist, u.pathname.slice('/dashboard'.length) || '/')
  return serveStatic(res, webDist, u.pathname)
})

const operatorDist = path.join(root, 'apps/operator-console/dist')
const portalDist = path.join(root, 'apps/license-portal/dist')
listen(Number(env('UICLICK_AUTH_PORT', 55102)), (req, res) => {
  const u = new URL(req.url, 'http://x')
  if (/^\/(operator\/v1|portal\/v1|auth\/v1|payments\/v1|service\/v1|public)(\/|$)/.test(u.pathname)) return proxy(req, res, LICENSE)
  if (u.pathname.startsWith('/operator')) return serveStatic(res, operatorDist, u.pathname.slice('/operator'.length) || '/')
  // 门户 bundle 的 base 是 /console/；统一登录页在 /（同一 index.html，apps/license-portal/src/main.tsx:13）。
  if (u.pathname.startsWith('/console/')) return serveStatic(res, portalDist, u.pathname.slice('/console'.length))
  return serveStatic(res, portalDist, path.extname(u.pathname) ? u.pathname : '/')
})

const sellerDist = path.join(root, 'apps/seller-portal/dist')
listen(Number(env('UICLICK_SELLER_PORT', 55103)), (req, res) => {
  const u = new URL(req.url, 'http://x')
  if (u.pathname.startsWith('/seller/v1')) return proxy(req, res, SELLER)
  return serveStatic(res, sellerDist, u.pathname)
})
