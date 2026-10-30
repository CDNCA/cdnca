// 生成本地可打开的 UI 浏览索引：docs/ui/click-1035/index.html（按端 → 菜单分组 → 页面，缩略图 + 红绿标记）。
// 输入：tests/ui-click/out/run/<身份>/results.jsonl（click.mjs 输出）；同时写 docs/ui/click-1035/results.json 汇总。
// 用法：node index.mjs
import fs from 'node:fs'
import path from 'node:path'
import { reclassify } from './classify.mjs'

const HERE = path.dirname(new URL(import.meta.url).pathname)
const ROOT = path.resolve(HERE, '../..')
const OUT = path.join(ROOT, 'docs/ui/click-1035')
const runs = path.join(HERE, 'out/run')
const APP_NAME = { web: '主控（web）', 'operator-console': '运营后台', 'license-portal': '客户门户', 'seller-portal': '卖家站' }
const WHO = { 'platform-admin': '平台管理员', 'tenant-admin': '租户主账号', 'tenant-user': '租户成员', owner: '运营 owner', operator: '受限运营员', seller: '门户客户', 'seller-site': '卖家' }
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))

const rows = []
for (const who of fs.existsSync(runs) ? fs.readdirSync(runs) : []) {
  const f = path.join(runs, who, 'results.jsonl')
  if (!fs.existsSync(f)) continue
  for (const line of fs.readFileSync(f, 'utf8').split('\n')) if (line.trim()) rows.push(reclassify(JSON.parse(line)))
}
// 中文 label 从 i18n key 退回路径；分组用 gen-pages 的 group。
const label = (r) => (r.label && !/^[a-z]+:/.test(r.label) ? r.label : r.path)
fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify(rows, null, 1))

const counts = rows.reduce((m, r) => ({ ...m, [r.status]: (m[r.status] ?? 0) + 1 }), {})
const badClicks = (r) => (r.clicks ?? []).filter((c) => c.level === 'error' || c.level === 'warn')
const issueText = (r) => [
  ...(r.issues ?? []).filter((i) => i.level === 'error' || i.level === 'warn').map((i) => `${i.level === 'error' ? '✖' : '!'} ${i.what}`),
  ...badClicks(r).map((c) => `${c.level === 'error' ? '✖' : '!'} [${c.text}] ${c.result ?? ''} ${[...(c.requests ?? []), ...(c.submit?.requests ?? [])].join('；')} ${(c.console ?? []).join('；')} ${c.submit?.formErrors?.length ? '表单校验：' + c.submit.formErrors.join('、') : ''}`),
]

let html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>cdnca 1.0.35 本机 UI 点击巡检</title>
<style>
body{font:14px/1.5 -apple-system,"PingFang SC",sans-serif;margin:0;background:#f5f6f8;color:#1f2329}
header{background:#fff;padding:16px 24px;border-bottom:1px solid #e5e6eb;position:sticky;top:0;z-index:2}
h1{font-size:18px;margin:0 0 6px} h2{font-size:16px;margin:24px 24px 8px} h3{font-size:14px;margin:16px 24px 8px;color:#4e5969}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px;padding:0 24px}
.card{background:#fff;border:1px solid #e5e6eb;border-radius:6px;overflow:hidden;border-top:4px solid #00b42a}
.card.warn{border-top-color:#ff7d00}.card.error{border-top-color:#f53f3f}.card.manual{border-top-color:#86909c}
.card img{width:100%;height:160px;object-fit:cover;object-position:top;display:block;border-bottom:1px solid #f2f3f5}
.card .b{padding:8px 10px}.card .t{font-weight:600}.card .p{color:#86909c;font-size:12px;word-break:break-all}
.card .l a{margin-right:8px;font-size:12px}.card ul{margin:6px 0 0;padding-left:16px;font-size:12px;color:#4e5969;max-height:120px;overflow:auto}
.tag{display:inline-block;padding:0 6px;border-radius:3px;font-size:12px;color:#fff;margin-left:6px}
.ok{background:#00b42a}.warnb{background:#ff7d00}.errb{background:#f53f3f}.man{background:#86909c}
nav a{margin-right:12px} .legend span{margin-right:12px}
</style></head><body><header><h1>cdnca 1.0.35 本机 UI 点击巡检</h1>
<div class="legend">页面 ${rows.length}：<span class="tag ok">通过 ${counts.ok ?? 0}</span><span class="tag warnb">告警 ${counts.warn ?? 0}</span><span class="tag errb">失败 ${counts.error ?? 0}</span><span class="tag man">未巡 ${counts.manual ?? 0}</span>
 　绿=打开与点击均正常；橙=有无效果按钮/4xx/英文残留等；红=错误结果块、5xx/404/405/501、console 错误、占位页。点击缩略图看中文整页截图，“英文”看英文版。</div>
<nav>${Object.keys(APP_NAME).map((a) => `<a href="#${a}">${APP_NAME[a]}</a>`).join('')}</nav></header>`

for (const app of Object.keys(APP_NAME)) {
  const ofApp = rows.filter((r) => r.app === app)
  if (!ofApp.length) continue
  html += `<h2 id="${app}">${APP_NAME[app]}</h2>`
  for (const who of [...new Set(ofApp.map((r) => r.identity))]) {
    const list = ofApp.filter((r) => r.identity === who)
    const groups = [...new Set(list.map((r) => r.group ?? '其他'))]
    html += `<h3>身份：${esc(WHO[who] ?? who)}（${list.length} 页）</h3>`
    for (const g of groups) {
      html += `<h3 style="margin-left:36px">菜单：${esc(g)}</h3><div class="grid">`
      for (const r of list.filter((x) => (x.group ?? '其他') === g)) {
        const zh = r.shot ?? ''; const en = zh.replace(/\.zh\.png$/, '.en.png')
        const st = r.status === 'ok' ? '' : r.status
        const issues = issueText(r)
        html += `<div class="card ${st}">${zh ? `<a href="${esc(zh)}" target="_blank"><img loading="lazy" src="${esc(zh)}" alt="${esc(label(r))} 截图"></a>` : ''}
<div class="b"><div class="t">${esc(label(r))}<span class="tag ${r.status === 'ok' ? 'ok' : r.status === 'warn' ? 'warnb' : r.status === 'error' ? 'errb' : 'man'}">${esc(r.status)}</span></div>
<div class="p">${esc(r.path)} · 点击 ${(r.clicks ?? []).length} 个控件${r.permission ? ' · ' + esc(r.permission) : ''}</div>
<div class="l">${zh ? `<a href="${esc(zh)}" target="_blank">中文</a>` : ''}${fs.existsSync(path.join(OUT, en)) ? `<a href="${esc(en)}" target="_blank">英文</a>` : ''}</div>
${issues.length ? `<ul>${issues.slice(0, 12).map((t) => `<li>${esc(t.slice(0, 260))}</li>`).join('')}</ul>` : ''}</div></div>`
      }
      html += '</div>'
    }
  }
}
html += '</body></html>\n'
fs.writeFileSync(path.join(OUT, 'index.html'), html)
console.log(`index → ${path.join(OUT, 'index.html')}  ${JSON.stringify(counts)}`)
