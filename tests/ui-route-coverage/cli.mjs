#!/usr/bin/env node
// 四端 UI ↔ 后端路由静态对账。
// 用法：
//   node tests/ui-route-coverage/cli.mjs [--repo <dir>] [--json out.json] [--markdown out.md] [--check]
//   --check：与 allowlist.json 比对，有新增缺口、白名单过期或理由缺失时退出 1
//   --write-allowlist <file>：把当前全部缺口写成白名单骨架（理由取默认值，须人工补齐）
import { writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runAudit } from './lib/audit.mjs'
import { KEYS, compare, loadAllowlist } from './lib/allowlist.mjs'
import { renderMarkdown } from './lib/report.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const args = process.argv.slice(2)
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined }
const repo = resolve(opt('--repo') ?? join(here, '../..'))
const result = runAudit(repo)

const summary = {
  backendRoutes: result.backend.length,
  frontendCalls: result.calls.length,
  table1: result.table1.length,
  table2: result.table2.length,
  table3: result.table3.length,
  table4: result.table4.length,
  table5: result.table5.length,
  excludedNonUI: result.excluded.length,
  proxyGaps: result.proxyGaps.length,
  openapi: { operations: result.openapiCheck.operations, notServed: result.openapiCheck.notServed.length, permissionMismatch: result.openapiCheck.permMismatch.length, undocumentedRoutes: result.openapiCheck.undocumented },
}

if (opt('--json')) {
  const { backend, calls, menuItems, routes, ...rest } = result
  writeFileSync(opt('--json'), JSON.stringify({ summary, ...rest }, null, 2) + '\n')
}
if (opt('--markdown')) writeFileSync(opt('--markdown'), renderMarkdown(result, summary))
if (opt('--write-allowlist')) {
  const out = {}
  const tables = { table1: result.table1, table2: result.table2, table3: result.table3, table4: result.table4, table5: result.table5, proxyGaps: result.proxyGaps, openapiNotServed: result.openapiCheck.notServed }
  for (const [name, rows] of Object.entries(tables)) {
    out[name] = Object.fromEntries(rows.map((r) => [KEYS[name](r), { reason: 'TODO', owner: '' }]).sort(([a], [b]) => a.localeCompare(b)))
  }
  writeFileSync(opt('--write-allowlist'), JSON.stringify(out, null, 2) + '\n')
}

console.log(JSON.stringify(summary))
if (args.includes('--check')) {
  const { fresh, stale, invalid } = compare(result, loadAllowlist(join(here, 'allowlist.json')))
  let failed = false
  for (const [name, rows] of Object.entries(fresh)) {
    if (!rows.length) continue
    failed = true
    console.error(`新增缺口 ${name}（${rows.length}）：`)
    for (const r of rows.slice(0, 40)) console.error(`  ${KEYS[name](r)}  ${r.evidence ?? ''}`)
  }
  for (const [name, keys] of Object.entries(stale)) {
    if (!keys.length) continue
    failed = true
    console.error(`白名单过期 ${name}（缺口已消失，请删除）：`)
    for (const k of keys.slice(0, 40)) console.error(`  ${k}`)
  }
  for (const line of invalid) { failed = true; console.error(line) }
  process.exit(failed ? 1 : 0)
}
