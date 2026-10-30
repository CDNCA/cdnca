// 汇总 click.mjs 结果：按“页面问题 / 按钮问题”逐条列出（非 env、非 info），供写报告。
// 用法：node summarize.mjs [身份...]   （默认全部）
import fs from 'node:fs'
import path from 'node:path'
import { reclassify } from './classify.mjs'

const HERE = path.dirname(new URL(import.meta.url).pathname)
const runs = path.join(HERE, 'out/run')
const who = process.argv.slice(2)
const ids = who.length ? who : fs.readdirSync(runs)
for (const id of ids) {
  const f = path.join(runs, id, 'results.jsonl')
  if (!fs.existsSync(f)) continue
  const rows = fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => reclassify(JSON.parse(l)))
  const t = rows.reduce((m, r) => ({ ...m, [r.status]: (m[r.status] ?? 0) + 1 }), {})
  console.log(`\n#### ${id} ${rows.length} 页 ${JSON.stringify(t)}`)
  for (const r of rows) {
    const issues = (r.issues ?? []).filter((i) => i.level === 'error' || i.level === 'warn')
    const clicks = (r.clicks ?? []).filter((c) => c.level === 'error' || c.level === 'warn')
    if (!issues.length && !clicks.length) continue
    console.log(`## ${r.status} ${r.path} (${r.label ?? ''}) 文字${r.textLength ?? '-'}`)
    for (const i of issues) console.log(`  P ${i.level} ${i.what.replace(/\s+/g, ' ').slice(0, 260)}`)
    for (const c of clicks) {
      const reqs = [...(c.requests ?? []), ...(c.submit?.requests ?? [])].map((s) => s.replace(/\s+/g, ' ').slice(0, 200))
      console.log(`  B ${c.level} [${c.text}] ${c.result ?? ''}${c.opened ? ' 弹窗:' + c.opened : ''}${c.filled?.length ? ' 填:' + c.filled.join(',').slice(0, 120) : ''} ${reqs.join(' ; ')} ${c.submit?.formErrors?.length ? '校验:' + c.submit.formErrors.join('/') : ''} ${c.console?.length ? 'console:' + c.console.join('/').slice(0, 200) : ''} ${c.msgs ? '提示:' + c.msgs.slice(0, 100) : ''}`)
    }
  }
}
