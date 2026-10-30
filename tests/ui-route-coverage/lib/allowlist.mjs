// 白名单：现存缺口逐条登记（带理由与承接任务），新出现的缺口不在白名单里就让测试失败；
// 白名单里有、但缺口已消失的条目（已修好）也报出来，提示删掉，避免白名单只增不减。
import { readFileSync, existsSync } from 'node:fs'

// 每张表的条目稳定键（不含行号，避免改代码挪行就失败）
export const KEYS = {
  table1: (r) => `${r.service} ${r.method} ${r.path}`,
  table2: (r) => `${r.kind} ${r.app} ${r.method} ${r.path}`,
  table3: (r) => r.kind === 'unknown_permission' || r.kind === 'permission_never_gated' ? `${r.kind} ${r.app} ${r.code}` : `${r.kind} ${r.app} ${r.page} ${r.route}`,
  table4: (r) => `${r.app} ${r.path}`,
  table5: (r) => `${r.kind} ${r.app} ${r.member} ${r.evidence.split(':')[0]}`,
  proxyGaps: (r) => `${r.side} ${r.method} ${r.path}`,
  openapiNotServed: (r) => `${r.method} ${r.path}`,
}

export function loadAllowlist(file) {
  if (!existsSync(file)) return {}
  return JSON.parse(readFileSync(file, 'utf8'))
}

// 返回 { fresh: {表: [条目]}, stale: {表: [键]}, invalid: [说明] }
export function compare(result, allowlist) {
  const fresh = {}
  const stale = {}
  const invalid = []
  const tables = {
    table1: result.table1, table2: result.table2, table3: result.table3, table4: result.table4, table5: result.table5,
    proxyGaps: result.proxyGaps, openapiNotServed: result.openapiCheck.notServed,
  }
  for (const [name, rows] of Object.entries(tables)) {
    const listed = allowlist[name] ?? {}
    for (const [key, entry] of Object.entries(listed)) {
      if (!entry || typeof entry.reason !== 'string' || entry.reason.trim().length < 4) invalid.push(`${name} ${key}：缺少理由（reason）`)
    }
    const keys = new Set(rows.map(KEYS[name]))
    fresh[name] = rows.filter((r) => !listed[KEYS[name](r)])
    stale[name] = Object.keys(listed).filter((k) => !keys.has(k))
  }
  return { fresh, stale, invalid }
}
