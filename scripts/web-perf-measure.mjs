#!/usr/bin/env node
// 量前端构建产物首屏体积：index.html 引用的入口 JS 及其静态 import 闭包、首屏 CSS，
// 输出原始字节与 gzip -9 字节，以及整个 dist 的总量。
// 用法：node scripts/web-perf-measure.mjs <dist 目录> [--json]
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join, dirname, resolve, relative } from 'node:path'
import { gzipSync } from 'node:zlib'

const dist = resolve(process.argv[2] || 'dist')
const asJson = process.argv.includes('--json')
const html = readFileSync(join(dist, 'index.html'), 'utf8')

// HTML 中的 /base/assets/x.js -> dist/assets/x.js；按文件名在 dist 里找，避免依赖 base。
function locate(ref) {
  const clean = ref.split('?')[0]
  const parts = clean.split('/').filter(Boolean)
  for (let i = 0; i < parts.length; i++) {
    const p = join(dist, ...parts.slice(i))
    if (existsSync(p) && statSync(p).isFile()) return p
  }
  return null
}

const gz = (buf) => gzipSync(buf, { level: 9 }).length
const entries = [...html.matchAll(/<script[^>]+type="module"[^>]+src="([^"]+)"/g)].map((m) => m[1])
const preloads = [...html.matchAll(/<link[^>]+rel="modulepreload"[^>]+href="([^"]+)"/g)].map((m) => m[1])
const css = [...html.matchAll(/<link[^>]+rel="stylesheet"[^>]+href="([^"]+)"/g)].map((m) => m[1])

// 静态 import 闭包（import ... from "./x.js" / import "./x.js"），不跟随 import()。
const seen = new Set()
function walk(file) {
  if (!file || seen.has(file)) return
  seen.add(file)
  const src = readFileSync(file, 'utf8')
  const re = /(?:^|[;}\s])import\s*(?:[\w*{}\s,$]+from\s*)?["']([^"']+\.js)["']/g
  for (const m of src.matchAll(re)) {
    if (m[1].startsWith('.')) walk(resolve(dirname(file), m[1]))
  }
}
for (const e of [...entries, ...preloads]) walk(locate(e))

let jsRaw = 0, jsGz = 0
const jsFiles = [...seen].map((f) => {
  const b = readFileSync(f)
  jsRaw += b.length
  jsGz += gz(b)
  return { file: relative(dist, f), raw: b.length, gzip: gz(b) }
}).sort((a, b) => b.gzip - a.gzip)

let cssRaw = 0, cssGz = 0
for (const c of css) {
  const f = locate(c)
  if (!f) continue
  const b = readFileSync(f)
  cssRaw += b.length
  cssGz += gz(b)
}

let totalRaw = 0, totalGz = 0, count = 0
function sum(dir) {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) { sum(p); continue }
    if (/\.(br|gz)$/.test(n)) continue
    const b = readFileSync(p)
    count++
    totalRaw += b.length
    totalGz += /\.(js|css|html|svg|json|txt|map)$/.test(n) ? gz(b) : b.length
  }
}
sum(dist)

const out = {
  dist,
  firstLoadJs: { files: jsFiles.length, raw: jsRaw, gzip: jsGz },
  firstLoadCss: { files: css.length, raw: cssRaw, gzip: cssGz },
  total: { files: count, raw: totalRaw, gzipText: totalGz },
  top: jsFiles.slice(0, 12),
}
if (asJson) {
  console.log(JSON.stringify(out, null, 2))
} else {
  const k = (n) => (n / 1024).toFixed(1) + ' KiB'
  console.log(`dist: ${dist}`)
  console.log(`首屏 JS: ${jsFiles.length} 个，原始 ${k(jsRaw)}，gzip ${k(jsGz)}`)
  console.log(`首屏 CSS: ${css.length} 个，原始 ${k(cssRaw)}，gzip ${k(cssGz)}`)
  console.log(`总产物: ${count} 个文件，原始 ${k(totalRaw)}（文本 gzip 后合计 ${k(totalGz)}）`)
  for (const f of out.top) console.log(`  ${k(f.gzip).padStart(10)}  ${k(f.raw).padStart(10)}  ${f.file}`)
}
