// 对账核心：后端路由 × 前端调用 × 页面模型 → 四张表。
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { backendInventory, normPath, permissionCatalog } from './backend.mjs'
import { extractFrontendCalls, APPS, PREFIX_SERVICE } from './frontend.mjs'
import { openapiOperations } from './openapi.mjs'
import { menus, routeTables, linkTargets, importGraph, reachable, routeAliases } from './pages.mjs'
import { nonUIClass, moduleOf } from './classify.mjs'
import { rel } from './util.mjs'

const segs = (p) => p.split('/').filter(Boolean)

// 后端模式段 {} 匹配任意段；前端 {} 匹配任意后端段。subtree 挂载按前缀匹配。
export function pathMatches(backend, front) {
  const b = segs(normPath(backend.path))
  // 前端 {}{} / {}/x{} 这类插值拼接段：{} 可以吞掉若干后端段（如 `${id}${suffix}` = "{id}/approve"）
  if (/\{\}\{\}/.test(front)) {
    const re = new RegExp('^/' + segs(front).map((x) => x.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{\}/g, '[^]*')).join('/') + '$')
    if (re.test('/' + b.join('/'))) return true
    // 子树挂载（/v1/x/sites/）：前端拼接段落在挂载前缀之下即命中（`${id}${suffix}` = "{id}/events"）
    if (backend.mount !== 'subtree') return false
    const f = segs(front)
    const seg = (x) => new RegExp('^' + x.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{\}/g, '.*') + '$')
    return f.length > b.length && b.every((s, i) => s === '{}' || seg(f[i]).test(s))
  }
  const f = segs(front)
  if (backend.mount === 'subtree') return f.length >= b.length && b.every((s, i) => s === '{}' || f[i] === '{}' || s === f[i])
  if (b.length !== f.length) return false
  return b.every((s, i) => s === '{}' || f[i] === '{}' || s === f[i] || f[i].includes('{}') && new RegExp('^' + f[i].replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{\}/g, '.*') + '$').test(s))
}
const methodMatches = (bm, fm) => bm === '*' || fm === '*' || bm === fm

export function serviceForCall(call) {
  for (const [prefix, service] of PREFIX_SERVICE) if (call.path.startsWith(prefix) || call.path + '/' === prefix) return service
  return APPS[call.app].service
}

export function runAudit(repo) {
  const backend = backendInventory(repo)
  const calls = extractFrontendCalls(repo)
  const catalog = permissionCatalog(repo)
  const openapi = openapiOperations(repo)
  const menuItems = menus(repo)
  const aliases = routeAliases(repo)
  const routes = [...routeTables(repo), ...aliases.map((a) => ({ app: a.app, path: a.from, to: a.to, redirect: true, components: [], files: [], guards: [], evidence: 'apps/web/src/routes/routePolicy.ts' }))]
  const links = linkTargets(repo)

  // ---- 调用 ↔ 路由匹配 ----
  const byService = {}
  for (const r of backend) (byService[r.service] ??= []).push(r)
  const callMatches = new Map()
  for (const c of calls) {
    const pool = byService[serviceForCall(c)] ?? []
    const pathHits = pool.filter((r) => pathMatches(r, c.path))
    const exact = pathHits.filter((r) => r.mount !== 'subtree')
    let exactMethod = exact.filter((r) => methodMatches(r.method, c.method))
    // Go ServeMux 语义：字面量段优先于 {param}；同时有精确 method 的命中时丢弃 method=* 的挂载
    if (exactMethod.length > 1) {
      // 逐段打分：双方字面量相等 2；双方都是参数 1；后端字面量对前端插值 0（前端值未知，不应优先命中 /export 之类字面量）
      const fs = segs(c.path)
      const score = (r) => segs(normPath(r.path)).reduce((n, x, i) => n + (x !== '{}' && x === fs[i] ? 2 : x === '{}' && fs[i] === '{}' ? 1 : x === '{}' ? 1 : 0), 0)
      const best = Math.max(...exactMethod.map(score))
      exactMethod = exactMethod.filter((r) => score(r) === best)
      if (c.method !== '*' && exactMethod.some((r) => r.method === c.method)) exactMethod = exactMethod.filter((r) => r.method === c.method)
      else if (exactMethod.some((r) => r.method !== '*')) exactMethod = exactMethod.filter((r) => r.method !== '*')
    }
    const subtree = pathHits.filter((r) => r.mount === 'subtree' && methodMatches(r.method, c.method))
    callMatches.set(c, { pathHits, exactMethod, subtree })
    for (const r of [...exactMethod, ...(exactMethod.length ? [] : subtree)]) (r.callers ??= []).push(c)
  }

  // ---- 表①：后端有、四端都没调用 ----
  const table1 = []
  const excluded = []
  for (const r of backend) {
    if (r.callers?.length) continue
    const cls = nonUIClass(r)
    if (cls) { excluded.push({ key: r.key, class: cls.id, reason: cls.reason }); continue }
    // 代理白名单里 pending 的行（市场侧未实现）单列，不算"没按钮"
    if (r.proxy === 'marketadminproxy' && !r.forwarded) { excluded.push({ key: r.key, class: 'proxy-pending', reason: `代理白名单 pending（owner ${r.owner}），市场侧未提供，浏览器调用会被代理拒绝` }); continue }
    // 无 method 的挂载/分发条目：与精确路由重复、或其下已有精确路由/前端调用（只是前缀挂载）时不单列
    if (r.method === '*') {
      const base = normPath(r.path).replace(/\/$/, '')
      const under = (p) => normPath(p) === base || normPath(p).startsWith(base + '/') || pathMatches({ path: r.path, mount: 'subtree' }, p)
      if (backend.some((o) => o !== r && o.method !== '*' && o.service === r.service && under(o.path))) continue
      if (calls.some((c) => serviceForCall(c) === r.service && under(c.path))) continue
    }
    table1.push({ key: r.key, service: r.service, method: r.method, path: r.path, module: moduleOf(r), permissions: r.permissions, evidence: r.evidences[0], mount: r.mount })
  }

  // 代理缺口：市场 /admin/v1 上游路由在授权端代理里没有 forwarded 行；市场 /v1 成员路由在主控 member.go 无映射
  const proxyGaps = marketProxyGaps(repo, backend)

  // ---- 表②：前端调用了、后端不存在或方法不匹配 ----
  // 同一调用点因三元/可选段展开出多个变体时，任一变体命中即视为该调用点有效
  const siteHit = new Set()
  for (const c of calls) {
    const m = callMatches.get(c)
    if (m.exactMethod.length || m.subtree.length) for (const e of c.evidences) siteHit.add(`${c.app}|${e}|${c.method}`)
  }
  const table2 = []
  for (const c of calls) {
    const m = callMatches.get(c)
    if (!(m.exactMethod.length || m.subtree.length) && c.evidences.every((e) => siteHit.has(`${c.app}|${e}|${c.method}`))) continue
    if (c.kind === 'literal' && /^\/(v1|operator\/v1|portal\/v1|seller\/v1|auth\/v1)$/.test(c.path)) continue
    if (m.exactMethod.length || m.subtree.length) {
      const pending = m.exactMethod.find((r) => r.proxy === 'marketadminproxy' && !r.forwarded)
      if (pending && m.exactMethod.every((r) => r.proxy === 'marketadminproxy' && !r.forwarded)) table2.push(row2(repo, c, 'proxy_pending', `代理白名单行 owner=${pending.owner} 未放行（${pending.evidences[0]}）`))
      continue
    }
    if (m.pathHits.length) table2.push(row2(repo, c, 'method_mismatch', `路径存在但方法只有 ${[...new Set(m.pathHits.map((r) => r.method))].join('/')}（${m.pathHits[0].evidences[0]}）`))
    else table2.push(row2(repo, c, 'no_route', `${serviceForCall(c)} 无此路由`))
  }
  // 菜单/跳转目标指向不存在的前端路由（点了 404）
  const routeIndex = routes.map((r) => ({ ...r, segs: segs(r.path.replace(/:[^/]+/g, '{}')) }))
  const frontRouteExists = (app, path) => {
    const p = segs(path.split('?')[0].split('#')[0])
    return routeIndex.some((r) => r.app === app && (r.path === '*' ? false : r.segs.length === p.length && r.segs.every((s, i) => s === '{}' || p[i] === '{}' || s === p[i])))
  }
  for (const mi of menuItems) if (!frontRouteExists(mi.app, mi.path)) table2.push({ kind: mi.kind === 'direct' ? 'direct_route_no_page' : 'menu_no_page', app: mi.app, method: '-', path: mi.path, evidence: mi.evidence,
    detail: mi.kind === 'direct' ? 'directRouteDefinitions 登记了该路径（面包屑/选中态），但 App.tsx 没有对应 <Route>，任何跳转到这里都会 404' : '菜单项在路由表里没有对应 <Route>，点击会落到 404/重定向' })
  // 站内跳转目标指向不存在的前端路由
  for (const l of links) {
    const p = l.path.split('?')[0].split('#')[0].replace(/([^/{}])\{\}$/, '$1')
    if (!p || p === '/' || /^\/(v1|operator|portal|seller|auth)\//.test(p) || p.includes('{}') && segs(p)[0] === '{}') continue
    if (table2.some((x) => x.app === l.app && x.path === p)) continue
    if (!frontRouteExists(l.app, p) && /^\/[a-z]/.test(p) && !/^\/(console|dashboard|operator)(\/|$)/.test(p) && !/\.(png|svg|ico|json|txt|html)$/.test(p)) table2.push({ kind: 'link_no_page', app: l.app, method: '-', path: p, evidence: l.evidence, detail: '站内跳转目标在路由表里不存在' })
  }

  // ---- OpenAPI 交叉校验（顺带用 x-required-permissions 补全静态解析不到的路由权限码）----
  const openapiCheck = crossOpenAPI(openapi, backend)

  // ---- 表③：权限码一致性 ----
  const table3 = permissionTable(repo, { backend, calls, callMatches, catalog, menuItems, routes })

  // ---- 表④：孤儿页面 ----
  const table4 = orphanPages(repo, { routes, menuItems, links })

  // ---- 表⑤：页面接的是假数据/本地拒绝（mock 客户端、notImplemented 占位），按钮看着能点但不发请求 ----
  const table5 = placeholders(repo)

  return { backend, calls, table1, table2, table3, table4, table5, excluded, proxyGaps, openapiCheck, menuItems, routes }
}

function row2(repo, c, kind, detail) {
  return { kind, app: c.app, method: c.method, path: c.path, evidence: c.evidence, detail, referenced: referencedOutside(repo, c) }
}

// 调用所属的导出成员在同端其它源码里是否被引用（未引用 = 死代码，影响低；被引用 = 页面上点了不生效）
const refCache = new Map()
function referencedOutside(repo, c) {
  const { top, member } = c.owner ?? {}
  if (!top) return undefined
  const callFile = c.evidence.split(':')[0]
  const key = `${c.app}|${callFile}|${top}|${member}`
  if (refCache.has(key)) return refCache.get(key)
  const re = member ? new RegExp(`\\b${top}\\s*\\.\\s*${member}\\b`) : new RegExp(`\\b${top}\\b`)
  const hit = sourceFilesOf(repo, c.app).find((f) => !f.endsWith(callFile) && re.test(readFileSync(f, 'utf8')))
  const out = hit ? rel(repo, hit) : null
  refCache.set(key, out)
  return out
}

// 市场上游 → 代理覆盖：/admin/v1/* 是否有授权端代理 forwarded 行；/v1/* 成员接口是否有主控 member.go 映射或主控 marketclient 直调。
function marketProxyGaps(repo, backend) {
  const proxyRows = backend.filter((r) => r.proxy === 'marketadminproxy')
  const memberSrc = readFileSync(join(repo, 'services/control-api/internal/marketsubscribehttp/member.go'), 'utf8')
  const upstreams = [...memberSrc.matchAll(/"(GET|POST|PUT|PATCH|DELETE) (\/v1\/admin\/market\/[^"]*)":\s*\{upstream:\s*"([^"]+)"/g)].map((m) => ({ method: m[1], path: m[3] }))
  const clientCalls = []
  for (const dir of ['marketclient', 'marketsupply', 'marketruntime', 'marketprobe', 'marketsubscribe', 'marketsubscribehttp']) {
    let files = []
    try { files = readdirSyncSafe(join(repo, 'services/control-api/internal', dir)) } catch { /* none */ }
    for (const f of files) for (const m of readFileSync(f, 'utf8').matchAll(/"(\/v1\/[a-z][^"?]*)/g)) clientCalls.push(m[1].replace(/\/$/, ''))
  }
  const gaps = []
  for (const r of backend.filter((x) => x.service === 'market-service')) {
    if (r.path.startsWith('/admin/v1/')) {
      const rest = r.path.slice('/admin/v1/'.length)
      const covered = proxyRows.some((p) => p.forwarded && methodMatchesLoose(p.method, r.method) && pathMatches({ path: '/x/' + rest }, normPath('/x/' + p.path.slice('/operator/v1/market/'.length))))
      if (!covered) gaps.push({ key: r.key, side: '运营端代理', method: r.method, path: r.path, evidence: r.evidences[0], detail: '授权端 marketadminproxy 无 forwarded 行，运营后台无法调用' })
    } else if (r.path.startsWith('/v1/')) {
      const covered = upstreams.some((u) => methodMatchesLoose(u.method, r.method) && pathMatches(r, normPath(u.path))) ||
        clientCalls.some((c) => pathMatches(r, normPath(c)) || pathMatches({ path: r.path, mount: 'exact' }, normPath(c)) || normPath(r.path).startsWith(normPath(c) + '/'))
      if (!covered) gaps.push({ key: r.key, side: '主控代理/直调', method: r.method, path: r.path, evidence: r.evidences[0], detail: '主控 member.go 无 upstream 映射且 marketclient 未直调' })
    }
  }
  return gaps
}
const methodMatchesLoose = (a, b) => a === '*' || b === '*' || a === b
function readdirSyncSafe(dir) {
  return readdirSync(dir).filter((f) => f.endsWith('.go') && !f.endsWith('_test.go')).map((f) => join(dir, f))
}

const PERM_RE = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/
const APP_SERVICE = { web: 'control-api', 'operator-console': 'license-service' }

// 前端权限判断里出现的权限码（严格上下文），带证据：
//   hasPermission(x, 'a.b') / can('a.b') / canAny(p, ['a.b']) / permissions.includes('a.b') / has('a.b')
//   permission: 'a.b' / requiredPermission(s): … / adminPermission= / userPermission= / permission="a.b"
//   const xxxPermission = 'a.b'
const STRICT_CTX = [
  /\b(?:hasPermission|hasAnyPermission|hasAllPermissions|can|canAny|canAll|mayOpen|allowed|includes|has|some|every|market|requirePermission|permitted|holds)\w*\(\s*(?:[\w.?]+\s*,\s*)?\[?\s*(?:'[^']*'\s*,\s*)*$/,
  /\b\w*[Pp]ermissions?\w*\s*[:=]\s*\[?\s*(?:'[^']*'\s*,\s*)*$/,
  /\b\w*[Pp]ermission\w*=\{?\[?\s*(?:'[^']*'\s*,\s*)*$/,
]
function frontendPermissionLiterals(repo, app) {
  const out = []
  for (const file of sourceFilesOf(repo, app)) {
    if (/\/i18n\//.test(file) || /I18n\.tsx?$/.test(file)) continue
    const text = readFileSync(file, 'utf8')
    for (const m of text.matchAll(/['"]([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)['"]/g)) {
      const before = text.slice(Math.max(0, m.index - 160), m.index).replace(/\s+/g, ' ')
      if (!STRICT_CTX.some((re) => re.test(before))) continue
      if (/^(module|feature|pack|theme|quota|plan)\./.test(m[1])) continue
      const line = text.slice(0, m.index).split('\n').length
      out.push({ code: m[1], evidence: `${rel(repo, file)}:${line}` })
    }
  }
  return out
}
import { sourceFiles as sourceFilesOf } from './frontend.mjs'

function permissionTable(repo, { backend, calls, callMatches, catalog, menuItems, routes }) {
  const rows = []
  // ③a 前端引用了目录里不存在的权限码：按钮/菜单永远隐藏（或守卫永远 403）
  for (const app of Object.keys(APP_SERVICE)) {
    const known = catalog[APP_SERVICE[app]]
    const seen = new Set()
    const lits = [...frontendPermissionLiterals(repo, app), ...menuItems.filter((m) => m.app === app).flatMap((m) => m.permissions.map((code) => ({ code, evidence: m.evidence })))]
    for (const { code, evidence } of lits) {
      if (known.has(code) || seen.has(code)) continue
      // 主控前端也会读模块码 module.*、套餐功能码，不是权限
      if (/^(module|feature|pack|theme|quota|plan)\./.test(code)) continue
      seen.add(code)
      rows.push({ kind: 'unknown_permission', app, code, evidence, detail: `${APP_SERVICE[app]} 迁移权限目录无此码：持有任何角色都不会显示/通过` })
    }
  }
  // ③b 页面可见条件 ↔ 页面调用接口的权限码。
  //   read_forbidden：页面调用的 GET 接口所需权限与页面可见条件不相交，且页面作用域里没有该权限码的判断 → 只持有菜单权限的账号打开即 403
  //   write_ungated：写接口所需权限与可见条件不相交，且页面作用域里从未出现这些权限码（没有按权限隐藏按钮）→ 按钮可点但必失败
  const graphs = {}
  for (const page of routes.filter((r) => !r.redirect && r.files.length && APP_SERVICE[r.app])) {
    const vis = new Set([...menuItems.filter((m) => m.app === page.app && samePath(m.path, page.path)).flatMap((m) => m.permissions), ...page.guards])
    if (!vis.size || vis.has('platform.admin')) continue
    graphs[page.app] ??= importGraph(repo, page.app)
    const scope = pageScope(repo, page, graphs[page.app])
    const used = usedCalls(calls.filter((c) => c.app === page.app), scope)
    const flagged = new Map()
    for (const c of used) {
      for (const r of callMatches.get(c).exactMethod) {
        if (!r.permissions.length || SESSION_ROUTE.test(`${r.method} ${r.path}`)) continue
        if (r.permissions.some((q) => vis.has(q))) continue
        const read = r.method === 'GET'
        // 页面作用域里出现了所需权限码（hasPermission/enabled: can… 等条件）视为已按权限门控
        if (r.permissions.some((q) => scope.text.includes(`'${q}'`) || scope.text.includes(`"${q}"`))) continue
        // 运营端市场：菜单含旧码 licensing.platform_policies.manage，代理按路由新码鉴权（licensing/market_admin.go）
        flagged.set(r.key, { kind: read ? 'read_forbidden' : 'write_ungated', app: page.app, page: page.path, route: `${r.method} ${r.path}`,
          visible: [...vis], required: r.permissions, evidence: `${c.evidence} → ${r.evidences[0]}`,
          detail: read ? `页面按 ${[...vis].join('|')} 显示，加载即调用的接口需要 ${r.permissions.join('|')}` : `写操作需要 ${r.permissions.join('|')}，页面未按该权限隐藏按钮（可见条件 ${[...vis].join('|')}）` })
      }
    }
    rows.push(...flagged.values())
  }
  // ③c 后端路由要求的权限码在该端前端任何显示条件里都没出现：只有该权限的账号没有入口
  for (const app of Object.keys(APP_SERVICE)) {
    const front = new Set([...frontendPermissionLiterals(repo, app).map((x) => x.code), ...menuItems.filter((m) => m.app === app).flatMap((m) => m.permissions), ...routes.filter((r) => r.app === app).flatMap((r) => r.guards)])
    const need = new Map()
    for (const r of backend.filter((x) => x.service === APP_SERVICE[app] && x.callers?.some((c) => c.app === app))) {
      for (const p of r.permissions) if (p !== 'platform.admin' && !front.has(p)) (need.get(p) ?? need.set(p, []).get(p)).push(`${r.method} ${r.path}`)
    }
    for (const [code, list] of need) rows.push({ kind: 'permission_never_gated', app, code, routes: list.slice(0, 5), count: list.length, evidence: backend.find((r) => `${r.method} ${r.path}` === list[0])?.evidences[0],
      detail: `接口要求 ${code}，前端无任何菜单/按钮以它为显示条件（只持有该码的账号看不到入口；持有其它码时按钮显示但 403）` })
  }
  return rows
}

function samePath(a, b) {
  const x = segs(a.replace(/:[^/]+/g, '{}')), y = segs(b.replace(/:[^/]+/g, '{}'))
  return x.length === y.length && x.every((s, i) => s === y[i] || s === '{}' || y[i] === '{}')
}

// 页面作用域：页面组件（多页面模块按 pick 的导出名）的函数体 + 其引用的同文件函数，
// 再沿 import 只走作用域里实际用到的绑定名，遇到其它 *Page.tsx 停止。
function pageScope(repo, page, graph) {
  const files = new Set()
  const texts = []
  const visit = (file, names, depth) => {
    if (!file || depth > 6) return
    const key = `${file}#${names ? [...names].sort().join(',') : '*'}`
    if (files.has(key)) return
    files.add(key)
    const src = readFileSync(file, 'utf8')
    const text = names ? scopeText(src, names) : src
    texts.push({ file, text })
    for (const m of src.matchAll(/import\s+(?:type\s+)?(?:(\w+)\s*,?\s*)?(?:\{([^}]*)\})?\s*from\s*'(\.[^']+)'/g)) {
      const bound = [m[1], ...(m[2] ?? '').split(',').map((x) => x.trim().split(/\s+as\s+/).pop())].filter(Boolean)
      const usedNames = bound.filter((n) => new RegExp(`\\b${n}\\b`).test(text))
      if (!usedNames.length) continue
      const dep = [...(graph.get(file) ?? [])].find((d) => d.replace(/\.(tsx?|ts)$/, '').replace(/\/index$/, '').endsWith(m[3].replace(/^\.+\//, '').replace(/\/$/, '')))
      if (!dep || (/Page\.tsx$/.test(dep) && !page.files.includes(dep))) continue
      visit(dep, /\/api\//.test(dep) ? undefined : new Set(usedNames), depth + 1)
    }
  }
  for (const f of page.files.filter((x) => /\/pages\//.test(x))) visit(f, page.components.length ? new Set(page.components) : undefined, 0)
  return { files: texts.map((t) => t.file), texts, text: texts.map((t) => t.text).join('\n') }
}

// 从源码里截取 names 指名的顶层声明及其传递引用的同文件顶层声明。
function scopeText(src, names) {
  const decls = new Map()
  const re = /^(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let)\s+(\w+)\s*[=:])/gm
  const starts = [...src.matchAll(re)].map((m) => ({ name: m[1] ?? m[2], index: m.index }))
  starts.forEach((d, i) => decls.set(d.name, src.slice(d.index, starts[i + 1]?.index ?? src.length)))
  if (![...names].some((n) => decls.has(n))) return src
  const out = new Set()
  const stack = [...names].filter((n) => decls.has(n))
  while (stack.length) {
    const n = stack.pop()
    if (out.has(n)) continue
    out.add(n)
    const body = decls.get(n)
    for (const [other] of decls) if (!out.has(other) && new RegExp(`\\b${other}\\b`).test(body)) stack.push(other)
  }
  return [...out].map((n) => decls.get(n)).join('\n')
}

// 页面作用域里实际引用到的调用：调用所在文件在作用域内，且（非定义文件里）出现 `对象.成员` 或 `函数名` 引用。
function usedCalls(calls, scope) {
  return calls.filter((c) => {
    const callFile = c.evidence.split(':')[0]
    if (!scope.files.some((f) => f.endsWith(callFile))) return false
    const { top, member } = c.owner ?? {}
    if (!top) return false
    const esc = (x) => x.replace(/[$]/g, '\\$')
    const re = member ? new RegExp(`\\b${esc(top)}\\s*\\.\\s*${esc(member)}\\b`) : new RegExp(`\\b${esc(top)}\\b`)
    return scope.texts.some((t) => !t.file.endsWith(callFile) && re.test(t.text))
  })
}

// 每次登录都会调用的会话/自身接口，所有已登录身份都有，不参与③b
const SESSION_ROUTE = /^(GET|DELETE|POST) \/(v1\/auth\/(me|refresh|logout)|v1\/modules|operator\/v1\/session(\/reauthenticate)?)$/

const PUBLIC_PAGES = /^\/(login|register|forgot-password|reset-password|forget-password|accept-invitation|auth\/callback|checkout(\/|$)|callback|403$|404$|500$)/

// 不经菜单/站内跳转、由运行时或外部系统生成入口的页面（逐条理由，静态扫描看不到）
export const EXTERNAL_ENTRIES = {
  'web /plugin-ui/:pluginId/:pageId': 'ui_page 插件页：菜单项运行时由 usePluginUIPages() 按已安装插件生成（apps/web/src/pluginui/usePluginUIPages.ts:29）',
  'license-portal /seller-login': '卖家站未登录时跳转的统一登录交接页：入口是 market-service seller_site.go 返回的 login_url（/console/seller-login?state=…）',
  'license-portal /seller-identity': '卖家站「去实名」跳转页：入口是 market-service seller_site.go 返回的 identity_url（/console/seller-identity），卖家站按钮 href 指向它',
}

function orphanPages(repo, { routes, menuItems, links }) {
  const rows = []
  const entryPaths = (app) => [
    ...menuItems.filter((m) => m.app === app).map((m) => m.path),
    ...links.filter((l) => l.app === app).map((l) => l.path.split('?')[0].split('#')[0].replace(/([^/{}])\{\}$/, '$1')),
    ...routes.filter((r) => r.app === app && r.to).map((r) => r.to.split('?')[0]),
  ]
  for (const app of Object.keys(APPS)) {
    const entries = entryPaths(app)
    // AliasRedirect/Navigate to= 也是入口（取 routePolicy 别名）
    for (const r of routes.filter((x) => x.app === app && !x.redirect && x.files.length && x.path !== '*')) {
      if (PUBLIC_PAGES.test(r.path) || EXTERNAL_ENTRIES[`${app} ${r.path}`]) continue
      if (entries.some((e) => samePath(e, r.path))) continue
      rows.push({ kind: 'orphan_route', app, path: r.path, components: r.components.filter((c) => !/Boundary|Suspense|Route$/.test(c)), evidence: r.evidence, detail: '定义了 <Route> 与页面组件，但无菜单项、站内跳转或重定向指向它' })
    }
  }
  return rows
}

function crossOpenAPI(openapi, backend) {
  const served = backend.filter((r) => r.service !== 'market-service')
  const notServed = []
  for (const op of openapi) {
    const hit = served.some((r) => methodMatchesLoose(r.method, op.method) && pathMatches(r, normPath(op.path)))
    if (!hit) notServed.push({ method: op.method, path: op.path, evidence: `${op.file}:${op.line}` })
  }
  const permMismatch = []
  for (const op of openapi.filter((o) => o.permissions.length)) {
    const r = served.find((x) => x.method === op.method && normPath(x.path) === normPath(op.path))
    if (!r) continue
    if (!r.permissions.length) { r.permissions = op.permissions.slice(); r.permissionSource = 'openapi'; continue }
    if (!op.permissions.some((p) => r.permissions.includes(p))) permMismatch.push({ method: op.method, path: op.path, openapi: op.permissions, code: r.permissions, evidence: `${op.file}:${op.line} ↔ ${r.evidences[0]}` })
  }
  const documented = (r) => openapi.some((op) => methodMatchesLoose(r.method, op.method) && pathMatches(r, normPath(op.path)))
  const undocumented = served.filter((r) => r.method !== '*' && /^\/(v1|operator\/v1|portal\/v1)\//.test(r.path) && !documented(r)).length
  return { operations: openapi.length, notServed, permMismatch, undocumented }
}

function placeholders(repo) {
  const rows = []
  for (const app of Object.keys(APPS)) {
    for (const file of sourceFilesOf(repo, app)) {
      const lines = readFileSync(file, 'utf8').split('\n')
      lines.forEach((line, i) => {
        if (/^\s*(\/\/|\*)/.test(line)) return
        let m
        if ((m = line.match(/^\s*(\w+)\s*:\s*\([^)]*\)\s*=>\s*notImplemented\b/))) rows.push({ kind: 'not_implemented', app, member: m[1], evidence: `${rel(repo, file)}:${i + 1}`, detail: '前端 API 成员直接返回 501，不发请求' })
        if ((m = line.match(/<UnavailableAction\b[^>]*>\{t\('([^']+)'\)\}/))) rows.push({ kind: 'disabled_placeholder', app, member: m[1], evidence: `${rel(repo, file)}:${i + 1}`, detail: '按钮常驻禁用并提示"后端未提供"' })
        if ((m = line.match(/\bcreateMock\w*\(\)/)) && !/export function/.test(line)) rows.push({ kind: 'mock_client', app, member: m[0], evidence: `${rel(repo, file)}:${i + 1}`, detail: '生产页面使用内存 mock 客户端，展示假数据，操作不落库' })
      })
    }
  }
  return rows
}
