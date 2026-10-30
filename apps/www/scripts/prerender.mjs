#!/usr/bin/env node
// 预渲染：读 vite 客户端产物 dist/index.html 作模板，用 dist-ssr/entry-server.js
// 逐路由 renderToString，写 dist/<路径>/index.html；另写 404.html、sitemap.xml、robots.txt。
// 不引入新框架（www-design.md §5.2）。
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = join(root, 'dist')
const ssrDir = join(root, 'dist-ssr')
const template = readFileSync(join(dist, 'index.html'), 'utf8')
const { render, urls, SITE_ORIGIN } = await import(pathToFileURL(join(ssrDir, 'entry-server.js')).href)

function fill(r) {
  return template
    // 替换值用函数：内容里的 $' $& 等不会被 String.replace 当作特殊模式展开（教程正文含 $'）。
    .replace('<!--app-lang-->', () => r.lang)
    .replace('<!--app-head-->', () => r.head)
    .replace('<!--app-html-->', () => r.html)
}

function outFile(url) {
  const clean = url.replace(/^\/+|\/+$/g, '')
  return clean === '' ? join(dist, 'index.html') : join(dist, clean, 'index.html')
}

const list = urls()
for (const url of list) {
  const file = outFile(url)
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, fill(render(url)))
}
writeFileSync(join(dist, '404.html'), fill(render('/__not_found__')))

const today = new Date().toISOString().slice(0, 10)
const sitemap = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
  ...list.map((u) => `  <url><loc>${SITE_ORIGIN}${u}</loc><lastmod>${today}</lastmod></url>`),
  '</urlset>',
  '',
].join('\n')
writeFileSync(join(dist, 'sitemap.xml'), sitemap)
writeFileSync(join(dist, 'robots.txt'), `User-agent: *\nAllow: /\nSitemap: ${SITE_ORIGIN}/sitemap.xml\n`)

rmSync(ssrDir, { recursive: true, force: true })
console.log(`prerendered ${list.length} pages + 404.html, sitemap.xml, robots.txt`)
