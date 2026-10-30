#!/usr/bin/env node
// 构建产物静态检查（Lighthouse 类 SEO/可访问性基础项，不跑浏览器）：
// 每个 HTML 有 lang、唯一 <title>、description、canonical、hreflang、viewport、恰好一个 <h1>、
// 正文非空（预渲染生效）；所有 <img> 有 alt；内联 <svg role="img"> 有可访问名称；
// 站内链接都能落到 dist 里的文件；没有外部脚本/样式；sitemap 与页面一致；
// 市场接口（site.ts）是同源路径且 scripts/install-site.sh 有它的反代段；官网内容接口是同源路径，且
// nginx-www.conf 与 scripts/install-site.sh 都把它反代到授权端（CSP 不为它放宽）。
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = join(root, process.argv[2] || 'dist')
const errors = []
const fail = (file, msg) => errors.push(`${file}: ${msg}`)

function walk(dir) {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n)
    return statSync(p).isDirectory() ? walk(p) : [p]
  })
}

function urlToFile(u) {
  const path = u.split('#')[0].split('?')[0]
  if (path === '' ) return null
  const rel = path.replace(/^\//, '')
  const candidates = [join(dist, rel), join(dist, rel, 'index.html')]
  return candidates.find((c) => existsSync(c) && statSync(c).isFile()) || null
}

const files = walk(dist)
const htmlFiles = files.filter((f) => f.endsWith('.html'))
const titles = new Map()
for (const file of htmlFiles) {
  const rel = relative(dist, file)
  const s = readFileSync(file, 'utf8')
  const is404 = rel === '404.html'
  if (!/<html lang="(zh-CN|en)">/.test(s)) fail(rel, 'missing <html lang>')
  if (!/<meta name="viewport"/.test(s)) fail(rel, 'missing viewport')
  const t = s.match(/<title>([^<]+)<\/title>/g) || []
  if (t.length !== 1) fail(rel, `expected 1 <title>, got ${t.length}`)
  else if (!is404) {
    if (titles.has(t[0])) fail(rel, `duplicate title with ${titles.get(t[0])}`)
    titles.set(t[0], rel)
  }
  if (!is404) {
    const d = s.match(/<meta name="description" content="([^"]*)"/)
    if (!d || d[1].length < 20) fail(rel, 'missing or short description')
    if (!/<link rel="canonical" href="https:\/\/www\.cdnca\.com\//.test(s)) fail(rel, 'missing canonical')
    if (!/hreflang="zh-CN"/.test(s) || !/hreflang="en"/.test(s)) fail(rel, 'missing hreflang')
  }
  const h1 = (s.match(/<h1[\s>]/g) || []).length
  if (h1 !== 1) fail(rel, `expected 1 <h1>, got ${h1}`)
  if (!/<main id="main"[^>]*>[\s\S]{120,}<\/main>/.test(s)) fail(rel, 'main content not prerendered')
  if (/\sstyle="/.test(s)) fail(rel, 'inline style attribute (CSP style-src self)')
  for (const m of s.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) if (!/\bsrc="/.test(m[1]) || m[2].trim()) fail(rel, 'inline script (CSP script-src self)')
  for (const img of s.match(/<img\b[^>]*>/g) || []) if (!/\balt="/.test(img)) fail(rel, `img without alt: ${img.slice(0, 80)}`)
  for (const svg of s.match(/<svg\b[^>]*role="img"[^>]*>/g) || []) {
    if (!/aria-labelledby="|aria-label="/.test(svg)) fail(rel, `svg role=img without name: ${svg.slice(0, 80)}`)
  }
  for (const m of s.matchAll(/<(script|link)\b[^>]*(src|href)="(https?:)?\/\/[^"]+"[^>]*>/g)) {
    if (m[1] === 'script' || /rel="stylesheet"/.test(m[0])) fail(rel, `external resource: ${m[0].slice(0, 100)}`)
  }
  for (const m of s.matchAll(/<a\b[^>]*href="(\/[^"]*)"/g)) {
    if (m[1].startsWith('//')) continue
    if (!urlToFile(m[1])) fail(rel, `broken internal link ${m[1]}`)
  }
}

const sitemap = readFileSync(join(dist, 'sitemap.xml'), 'utf8')
const locs = [...sitemap.matchAll(/<loc>https:\/\/www\.cdnca\.com([^<]*)<\/loc>/g)].map((m) => m[1])
for (const l of locs) if (!urlToFile(l)) fail('sitemap.xml', `loc without page ${l}`)
if (locs.length !== htmlFiles.length - 1) fail('sitemap.xml', `has ${locs.length} locs, dist has ${htmlFiles.length - 1} pages`)
if (!existsSync(join(dist, 'robots.txt'))) fail('dist', 'missing robots.txt')

const conf = join(root, 'nginx-www.conf')
if (existsSync(conf)) {
  const site = readFileSync(join(root, 'src/site.ts'), 'utf8')
  const api = site.match(/MARKET_PUBLIC_API = '([^']+)'/)
  const csp = readFileSync(conf, 'utf8').match(/connect-src ([^;]*);/)
  if (!api || !/^\/public\/v1$/.test(api[1])) fail('site.ts', 'MARKET_PUBLIC_API must be the same-origin path /public/v1 (CSP connect-src self)')
  if (!csp || csp[1].trim() !== "'self'") fail('nginx-www.conf', "CSP connect-src must be 'self' only")
  const installer = join(root, '../../scripts/install-site.sh')
  if (existsSync(installer) && !readFileSync(installer, 'utf8').includes('location ^~ /public/v1/ {')) fail('scripts/install-site.sh', 'missing location ^~ /public/v1/ { reverse proxy to the market public listener')
  const content = readFileSync(join(root, 'src/content/siteContent.ts'), 'utf8').match(/SITE_CONTENT_PATH = '([^']+)'/)
  if (!content || !/^\/public\/v1\/[a-z-]+$/.test(content[1])) fail('siteContent.ts', 'SITE_CONTENT_PATH must be a same-origin path (CSP connect-src self)')
  else {
    const proxy = `location ^~ ${content[1]} {`
    if (!readFileSync(conf, 'utf8').includes(proxy)) fail('nginx-www.conf', `missing ${proxy} reverse proxy to the licensing service`)
    const site = join(root, '../../scripts/install-site.sh')
    if (existsSync(site) && !readFileSync(site, 'utf8').includes(proxy)) fail('scripts/install-site.sh', `missing ${proxy} reverse proxy to the licensing service`)
  }
}

if (errors.length) {
  console.error(errors.join('\n'))
  console.error(`check-dist: ${errors.length} problem(s)`)
  process.exit(1)
}
console.log(`check-dist: ${htmlFiles.length} html files OK`)
