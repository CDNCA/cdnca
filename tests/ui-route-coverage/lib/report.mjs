// 机器生成的明细表（Markdown）。人工报告引用它并补充判断与落点。
const esc = (s) => String(s ?? '').replace(/\|/g, '\\|')

export function renderMarkdown(result, summary) {
  const out = []
  out.push('# UI ↔ 路由静态对账明细（tests/ui-route-coverage 生成，勿手改）', '')
  out.push('```json', JSON.stringify(summary, null, 2), '```', '')

  out.push('## 表① 后端有、四端都没调用', '')
  const byMod = new Map()
  for (const r of result.table1) {
    const k = `${r.service} · ${r.module}`
    byMod.set(k, [...(byMod.get(k) ?? []), r])
  }
  for (const [mod, rows] of [...byMod].sort(([a], [b]) => a.localeCompare(b))) {
    out.push(`### ${mod}（${rows.length}）`, '', '| 方法 | 路径 | 权限码 | 证据 |', '|---|---|---|---|')
    for (const r of rows) out.push(`| ${r.method} | ${esc(r.path)} | ${esc(r.permissions.join(', '))} | ${esc(r.evidence)} |`)
    out.push('')
  }

  out.push('## 表①附 市场上游无代理放行', '', '| 侧 | 方法 | 路径 | 证据 | 说明 |', '|---|---|---|---|---|')
  for (const r of result.proxyGaps) out.push(`| ${r.side} | ${r.method} | ${esc(r.path)} | ${esc(r.evidence)} | ${esc(r.detail)} |`)
  out.push('')

  out.push('## 表② 前端调用了、后端不存在/方法不符（点了不生效）', '', '| 类型 | 端 | 方法 | 路径 | 证据 | 页面引用 | 说明 |', '|---|---|---|---|---|---|---|')
  for (const r of result.table2) out.push(`| ${r.kind} | ${r.app} | ${r.method} | ${esc(r.path)} | ${esc(r.evidence)} | ${esc(r.referenced ?? '-')} | ${esc(r.detail)} |`)
  out.push('')

  out.push('## 表③ 权限码 ↔ 菜单/按钮显示条件', '')
  const kinds = { unknown_permission: '③a 前端引用了不存在的权限码', read_forbidden: '③b 页面可见但读接口必 403', write_ungated: '③b 写按钮未按权限隐藏', permission_never_gated: '③c 接口权限码在前端从未作为显示条件' }
  for (const [kind, title] of Object.entries(kinds)) {
    const rows = result.table3.filter((r) => r.kind === kind)
    out.push(`### ${title}（${rows.length}）`, '')
    if (kind === 'unknown_permission' || kind === 'permission_never_gated') {
      out.push('| 端 | 权限码 | 证据 | 说明 |', '|---|---|---|---|')
      for (const r of rows) out.push(`| ${r.app} | ${esc(r.code)} | ${esc(r.evidence)} | ${esc(r.detail)}${r.routes ? '：' + esc(r.routes.join('; ')) : ''} |`)
    } else {
      out.push('| 端 | 页面 | 接口 | 页面可见条件 | 接口要求 | 证据 |', '|---|---|---|---|---|---|')
      for (const r of rows) out.push(`| ${r.app} | ${esc(r.page)} | ${esc(r.route)} | ${esc(r.visible.join(', '))} | ${esc(r.required.join(', '))} | ${esc(r.evidence)} |`)
    }
    out.push('')
  }

  out.push('## 表④ 孤儿页面（有 <Route> 无入口）', '', '| 端 | 路径 | 组件 | 证据 |', '|---|---|---|---|')
  for (const r of result.table4) out.push(`| ${r.app} | ${esc(r.path)} | ${esc(r.components.join(', '))} | ${esc(r.evidence)} |`)
  out.push('')

  out.push('## 表⑤ 页面接假数据/本地拒绝（按钮不发请求）', '', '| 类型 | 端 | 成员 | 证据 | 说明 |', '|---|---|---|---|---|')
  for (const r of result.table5) out.push(`| ${r.kind} | ${r.app} | ${esc(r.member)} | ${esc(r.evidence)} | ${esc(r.detail)} |`)
  out.push('')

  out.push('## OpenAPI 交叉校验', '')
  out.push(`OpenAPI 操作 ${result.openapiCheck.operations} 条；代码未提供 ${result.openapiCheck.notServed.length} 条；权限码不一致 ${result.openapiCheck.permMismatch.length} 条；代码有而 OpenAPI 未登记 ${result.openapiCheck.undocumented} 条（只计数）。`, '')
  out.push('| 方法 | 路径 | 证据 |', '|---|---|---|')
  for (const r of result.openapiCheck.notServed) out.push(`| ${r.method} | ${esc(r.path)} | ${esc(r.evidence)} |`)
  for (const r of result.openapiCheck.permMismatch) out.push(`| ${r.method} | ${esc(r.path)} | 权限码 OpenAPI ${esc(r.openapi.join(','))} ≠ 代码 ${esc(r.code.join(','))}：${esc(r.evidence)} |`)
  out.push('')

  out.push('## 已排除的非 UI 路由（按类）', '', '| 类 | 条数 | 理由 |', '|---|---|---|')
  const cls = new Map()
  for (const e of result.excluded) cls.set(e.class, { n: (cls.get(e.class)?.n ?? 0) + 1, reason: e.reason })
  for (const [k, v] of cls) out.push(`| ${k} | ${v.n} | ${esc(v.reason)} |`)
  out.push('')
  return out.join('\n')
}
