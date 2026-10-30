// 页面模型：菜单（导航定义）、路由表（App.tsx <Route path element>）、站内跳转（navigate/Link/to/href），
// 以及每个页面组件经 import 图可达的 API 调用（用于表③：按钮/菜单显示条件 ↔ 路由权限码）。
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { loadTS } from './ts.mjs'
import { APPS, sourceFiles } from './frontend.mjs'
import { rel } from './util.mjs'

function parse(ts, file) {
  return ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
}
const strip = (ts, n) => { while (n && (ts.isAsExpression(n) || ts.isParenthesizedExpression(n) || ts.isSatisfiesExpression?.(n))) n = n.expression; return n }

function topDecls(ts, sf) {
  const out = {}
  for (const st of sf.statements) {
    if (!ts.isVariableStatement(st)) continue
    for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name) && d.initializer) out[d.name.text] = strip(ts, d.initializer)
  }
  return out
}

// 对象字面量属性（展开 ...gate 同文件常量）
function props(ts, sf, obj, decls) {
  const out = {}
  for (const p of obj.properties) {
    if (ts.isSpreadAssignment(p) && ts.isIdentifier(p.expression) && decls[p.expression.text]) Object.assign(out, props(ts, sf, decls[p.expression.text], decls))
    else if (ts.isPropertyAssignment(p)) out[p.name.getText(sf)] = p.initializer
    else if (ts.isShorthandPropertyAssignment(p)) out[p.name.text] = p.name
  }
  return out
}

// 权限表达式 → 权限码列表（字符串、数组、常量、market(MP.x, ...)、对象成员 MP.x）
function permList(ts, sf, node, decls, imported) {
  node = strip(ts, node)
  if (!node) return []
  if (ts.isStringLiteralLike(node)) return [node.text]
  if (ts.isArrayLiteralExpression(node)) return node.elements.flatMap((e) => permList(ts, sf, e, decls, imported))
  if (ts.isIdentifier(node)) {
    if (decls[node.text]) return permList(ts, sf, decls[node.text], decls, imported)
    if (imported[node.text]) return imported[node.text]
    return []
  }
  if (ts.isPropertyAccessExpression(node)) {
    const k = node.getText(sf)
    return imported[k] ?? []
  }
  if (ts.isCallExpression(node)) {
    const extra = imported[`${node.expression.getText(sf)}()`] ?? []
    return [...node.arguments.flatMap((a) => permList(ts, sf, a, decls, imported)), ...extra]
  }
  return []
}

// 常量导入表：从同端源码里收集 export const X = '...' / ['...'] 与 export const MP = { k: '...' }
function exportedConstants(ts, repo, app) {
  const out = {}
  for (const file of sourceFiles(repo, app)) {
    const text = readFileSync(file, 'utf8')
    if (!/export const/.test(text)) continue
    const sf = parse(ts, file)
    const decls = topDecls(ts, sf)
    for (const [name, init] of Object.entries(decls)) {
      if (ts.isStringLiteralLike(init) && /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/.test(init.text)) out[name] = [init.text]
      else if (ts.isArrayLiteralExpression(init) && init.elements.every((e) => ts.isStringLiteralLike(strip(ts, e)))) out[name] = init.elements.map((e) => strip(ts, e).text)
      else if (ts.isObjectLiteralExpression(init)) {
        for (const p of init.properties) if (ts.isPropertyAssignment(p) && ts.isStringLiteralLike(strip(ts, p.initializer))) out[`${name}.${p.name.getText(sf)}`] = [strip(ts, p.initializer).text]
      }
    }
  }
  // market(...) 会附加旧权限码
  if (out.LEGACY_MARKET_PERMISSION) out['market()'] = out.LEGACY_MARKET_PERMISSION
  return out
}

// ---- 菜单 ----
export function menus(repo) {
  const ts = loadTS(repo)
  const out = []
  {
    const file = join(repo, 'apps/web/src/routes/navigation.ts')
    const sf = parse(ts, file)
    const decls = topDecls(ts, sf)
    const imported = exportedConstants(ts, repo, 'web')
    const walk = (arr, role) => {
      if (!ts.isArrayLiteralExpression(arr)) {
        const m = arr.getText(sf).match(/item\.key === '([^']+)'/)
        const src = m && decls.adminNavigation.elements.map((e) => props(ts, sf, e, decls)).find((o) => o.key?.text === m[1])
        if (!src) return
        arr = src.children
      }
      for (const el of arr.elements) {
        const o = props(ts, sf, el, decls)
        if (o.children) walk(strip(ts, o.children), role)
        const key = o.key && ts.isStringLiteralLike(o.key) ? o.key.text : undefined
        if (!key?.startsWith('/')) continue
        out.push({ app: 'web', role, path: key, kind: 'menu', evidence: `${rel(repo, file)}:${sf.getLineAndCharacterOfPosition(el.getStart(sf)).line + 1}`,
          permissions: [...permList(ts, sf, o.requiredPermission, decls, imported), ...permList(ts, sf, o.requiredPermissions, decls, imported)],
          module: o.requiredModule && ts.isStringLiteralLike(o.requiredModule) ? o.requiredModule.text : undefined,
          platformAdminFallback: !(o.platformAdminFallback && o.platformAdminFallback.kind === ts.SyntaxKind.FalseKeyword),
          implemented: o.implemented ? o.implemented.kind !== ts.SyntaxKind.FalseKeyword : false })
      }
    }
    walk(decls.adminNavigation, 'admin')
    walk(decls.userNavigation, 'user')
    for (const el of decls.directRouteDefinitions?.elements ?? []) {
      const o = props(ts, sf, el, decls)
      out.push({ app: 'web', role: (o.roles?.elements ?? []).map((e) => e.text).join('|'), path: o.path.text, kind: 'direct',
        evidence: `${rel(repo, file)}:${sf.getLineAndCharacterOfPosition(el.getStart(sf)).line + 1}`,
        permissions: [...permList(ts, sf, o.requiredPermission, decls, imported), ...permList(ts, sf, o.requiredPermissions, decls, imported)],
        platformAdminFallback: !(o.platformAdminFallback && o.platformAdminFallback.kind === ts.SyntaxKind.FalseKeyword), implemented: true })
    }
  }
  {
    const file = join(repo, 'apps/operator-console/src/navigation.tsx')
    const sf = parse(ts, file)
    const decls = topDecls(ts, sf)
    const imported = exportedConstants(ts, repo, 'operator-console')
    for (const g of decls.navGroups.elements) {
      const go = props(ts, sf, g, decls)
      for (const it of go.items.elements) {
        const o = props(ts, sf, it, decls)
        out.push({ app: 'operator-console', role: 'operator', path: o.path.text, kind: 'menu', evidence: `${rel(repo, file)}:${sf.getLineAndCharacterOfPosition(it.getStart(sf)).line + 1}`,
          permissions: permList(ts, sf, o.permission, decls, imported), platformAdminFallback: false, implemented: true })
      }
    }
  }
  for (const [app, relPath] of [['license-portal', 'apps/license-portal/src/layout/PortalLayout.tsx'], ['seller-portal', 'apps/seller-portal/src/layout/SellerLayout.tsx']]) {
    const file = join(repo, relPath)
    const sf = parse(ts, file)
    const decls = topDecls(ts, sf)
    for (const it of decls.MENU.elements) {
      const o = props(ts, sf, it, decls)
      out.push({ app, role: 'customer', path: o.path.text, kind: 'menu', evidence: `${relPath}:${sf.getLineAndCharacterOfPosition(it.getStart(sf)).line + 1}`, permissions: [], platformAdminFallback: false, implemented: true })
    }
  }
  return out
}

// ---- 路由表：<Route path="..." element={...}> 以及 [path, Component] 数组 ----
const APP_FILES = {
  web: 'apps/web/src/App.tsx',
  'operator-console': 'apps/operator-console/src/App.tsx',
  'license-portal': 'apps/license-portal/src/App.tsx',
  'seller-portal': 'apps/seller-portal/src/App.tsx',
}

// 组件名 → 源文件（lazy(() => import('./pages/X'))、const f = () => import(...)、import { X } from './pages/X'）
function componentFiles(ts, sf, file) {
  const out = {}
  const dir = dirname(file)
  const lazyMods = {}
  for (const st of sf.statements) {
    if (ts.isImportDeclaration(st) && st.importClause) {
      const spec = st.moduleSpecifier.text
      const names = []
      if (st.importClause.name) names.push(st.importClause.name.text)
      const nb = st.importClause.namedBindings
      if (nb && ts.isNamedImports(nb)) for (const e of nb.elements) names.push(e.name.text)
      for (const n of names) out[n] = resolveModule(dir, spec)
    }
    if (!ts.isVariableStatement(st)) continue
    for (const d of st.declarationList.declarations) {
      if (!ts.isIdentifier(d.name) || !d.initializer) continue
      const text = d.initializer.getText(sf)
      const m = text.match(/import\('([^']+)'\)/)
      if (m) {
        if (/^\(\) => import/.test(text)) lazyMods[d.name.text] = resolveModule(dir, m[1])
        else out[d.name.text] = resolveModule(dir, m[1])
        continue
      }
      const m2 = text.match(/lazy\(\(\) => (\w+)\(\)/)
      if (m2 && lazyMods[m2[1]]) out[d.name.text] = lazyMods[m2[1]]
    }
  }
  return { out, lazyMods }
}

function resolveModule(dir, spec) {
  if (!spec.startsWith('.')) return undefined
  const base = resolve(dir, spec)
  for (const cand of [base, `${base}.tsx`, `${base}.ts`, join(base, 'index.tsx'), join(base, 'index.ts')]) if (existsSync(cand) && !cand.endsWith('/')) {
    try { if (readFileSync(cand)) return cand } catch { /* directory */ }
  }
  return undefined
}

export function routeTables(repo) {
  const ts = loadTS(repo)
  const out = []
  for (const [app, relPath] of Object.entries(APP_FILES)) {
    const file = join(repo, relPath)
    const sf = parse(ts, file)
    const { out: comps, lazyMods } = componentFiles(ts, sf, file)
    const decls = topDecls(ts, sf)
    const at = (n) => `${relPath}:${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}`
    const localFns = {}
    for (const st of sf.statements) if (ts.isFunctionDeclaration(st) && st.name) localFns[st.name.text] = st
    const elementComponents = (expr, depth = 0) => {
      const names = new Set()
      const visit = (n) => {
        if ((ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) && ts.isIdentifier(n.tagName)) {
          const tag = n.tagName.text
          names.add(tag)
          // 同文件包装组件（SecurityRulesRoute 等）：展开其函数体里的 JSX
          if (!comps[tag] && localFns[tag] && depth < 2) for (const x of elementComponents(localFns[tag].body, depth + 1)) names.add(x)
        }
        ts.forEachChild(n, visit)
      }
      if (expr) visit(expr)
      return [...names]
    }
    const guards = (expr) => {
      const perms = []
      const guardSeen = new Set()
      const visit = (n) => {
        if ((ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) && localFns[n.tagName.getText(sf)] && !/^(PermissionRoute|RoleRoute)$/.test(n.tagName.getText(sf))) {
          const body = localFns[n.tagName.getText(sf)].body
          if (body && !guardSeen.has(body)) { guardSeen.add(body); for (const m of body.getText(sf).matchAll(/hasPermission\([^,]*,\s*'([a-z][\w.]+)'/g)) perms.push(m[1]) }
        }
        if ((ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) && /Permission|Route$/.test(n.tagName.getText(sf))) {
          for (const a of n.attributes.properties) {
            if (!ts.isJsxAttribute(a) || !/^permissions?$/.test(a.name.getText(sf)) || !a.initializer) continue
            const init = ts.isJsxExpression(a.initializer) ? a.initializer.expression : a.initializer
            perms.push(...permList(ts, sf, init, decls, exportedConstants(ts, repo, app)))
          }
        }
        ts.forEachChild(n, visit)
      }
      if (expr) visit(expr)
      return perms
    }
    const visit = (n) => {
      if ((ts.isJsxSelfClosingElement(n) || ts.isJsxOpeningElement(n)) && n.tagName.getText(sf) === 'Route') {
        let path, element
        for (const a of n.attributes.properties) {
          if (!ts.isJsxAttribute(a) || !a.initializer) continue
          const name = a.name.getText(sf)
          const init = ts.isJsxExpression(a.initializer) ? a.initializer.expression : a.initializer
          if (name === 'path' && init && ts.isStringLiteralLike(init)) path = init.text
          if (name === 'element') element = init
        }
        if (path) {
          const names = elementComponents(element)
          const redirect = names.some((x) => /Navigate|Redirect/.test(x)) && !names.some((x) => comps[x] && /pages\//.test(comps[x]))
          const pageNames = names.filter((x) => comps[x])
          out.push({ app, path, evidence: at(n), components: pageNames, files: pageNames.map((x) => comps[x]).filter(Boolean), redirect, guards: guards(element) })
        }
      }
      ts.forEachChild(n, visit)
    }
    visit(sf)
    // {path: '/x', ...} 对象数组经 .map(({ path }) => <Route path={path} …>) 渲染（web systemConfigurationRoutes）
    for (const [name, init] of Object.entries(decls)) {
      if (!ts.isArrayLiteralExpression(init) || !new RegExp(`\\b${name}\\.map\\(`).test(sf.text)) continue
      const mapAt = sf.text.indexOf(`${name}.map(`)
      const body = sf.text.slice(mapAt, mapAt + 3000)
      if (!/<Route\b[^>]*path=\{/.test(body)) continue
      const names = [...body.matchAll(/<([A-Z]\w+)/g)].map((m) => m[1]).filter((x) => comps[x])
      for (const el of init.elements) {
        if (!ts.isObjectLiteralExpression(el)) continue
        const pp = el.properties.find((q) => ts.isPropertyAssignment(q) && q.name.getText(sf) === 'path')
        if (!pp || !ts.isStringLiteralLike(pp.initializer)) continue
        out.push({ app, path: pp.initializer.text, evidence: at(el), components: names, files: names.map((x) => comps[x]), redirect: false, guards: [], fromArray: name })
      }
    }
    // [path, Component] 元组数组（运营端 marketplaceRoutes、legacyMarketRedirects）
    for (const [name, init] of Object.entries(decls)) {
      if (!ts.isArrayLiteralExpression(init)) continue
      for (const el of init.elements) {
        if (!ts.isArrayLiteralExpression(el) || el.elements.length !== 2 || !ts.isStringLiteralLike(el.elements[0])) continue
        const path = el.elements[0].text
        if (!path.startsWith('/')) continue
        const second = el.elements[1]
        if (ts.isStringLiteralLike(second)) { out.push({ app, path, evidence: at(el), components: [], files: [], redirect: true, to: second.text, guards: [] }); continue }
        const t = second.getText(sf)
        const pick = t.match(/^pick\((\w+), '(\w+)'\)$/)
        const f = pick ? lazyMods[pick[1]] : comps[t]
        out.push({ app, path, evidence: at(el), components: [pick ? pick[2] : t], files: f ? [f] : [], redirect: false, guards: [], fromArray: name })
      }
    }
  }
  return out
}

// ---- 站内跳转目标：navigate('/x')、<Link to="/x">、to: '/x'、href="/x"、window.location ----
// 路由别名（web routePolicy.observedRouteAliases {from,to}）：from 是可达入口（重定向到 to）
export function routeAliases(repo) {
  const file = join(repo, 'apps/web/src/routes/routePolicy.ts')
  const text = existsSync(file) ? readFileSync(file, 'utf8') : ''
  return [...text.matchAll(/\{\s*from:\s*'([^']+)',\s*to:\s*'([^']+)'/g)].map((m) => ({ app: 'web', from: m[1], to: m[2] }))
}

export function linkTargets(repo) {
  const ts = loadTS(repo)
  const out = []
  for (const app of Object.keys(APPS)) {
    for (const file of sourceFiles(repo, app)) {
      const text = readFileSync(file, 'utf8')
      if (!/navigate\(|to[=:]|href|Navigate|location|path:/.test(text)) continue
      const sf = parse(ts, file)
      const visit = (n) => {
        let target
        if (ts.isCallExpression(n) && /(^|\.)(navigate|push|replace|assign|open)$/.test(n.expression.getText(sf)) && n.arguments[0]) target = n.arguments[0]
        if (ts.isJsxAttribute(n) && /^(to|href)$/.test(n.name.getText(sf)) && n.initializer) target = ts.isJsxExpression(n.initializer) ? n.initializer.expression : n.initializer
        if (ts.isPropertyAssignment(n) && /^(to|href|path|key|target|link|route)$/.test(n.name.getText(sf))) target = n.initializer
        if (target) {
          for (const v of linkValues(ts, target)) if (v.startsWith('/') && !/^\/(v1|operator\/v1|portal\/v1|seller\/v1|auth\/v1)\//.test(v)) out.push({ app, path: v, evidence: `${rel(repo, file)}:${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}` })
        }
        ts.forEachChild(n, visit)
      }
      visit(sf)
    }
  }
  return out
}
function linkValues(ts, n) {
  n = strip(ts, n)
  if (!n) return []
  if (ts.isStringLiteralLike(n)) return [n.text]
  if (ts.isTemplateExpression(n)) return [n.head.text + n.templateSpans.map((s) => '{}' + s.literal.text).join('')]
  if (ts.isConditionalExpression(n)) return [...linkValues(ts, n.whenTrue), ...linkValues(ts, n.whenFalse)]
  if (ts.isBinaryExpression(n)) return [...linkValues(ts, n.left), ...linkValues(ts, n.right)]
  return []
}

// ---- import 图：从页面文件出发可达的同端源码文件 ----
export function importGraph(repo, app) {
  const ts = loadTS(repo)
  const graph = new Map()
  for (const file of sourceFiles(repo, app)) {
    const text = readFileSync(file, 'utf8')
    const deps = new Set()
    for (const m of text.matchAll(/(?:from\s+|import\s*\(\s*)'(\.[^']+)'/g)) {
      const r = resolveModule(dirname(file), m[1])
      if (r) deps.add(r)
    }
    graph.set(file, deps)
  }
  return graph
}
export function reachable(graph, starts, stopAt = () => false) {
  const seen = new Set()
  const stack = [...starts]
  while (stack.length) {
    const f = stack.pop()
    if (seen.has(f)) continue
    seen.add(f)
    for (const d of graph.get(f) ?? []) if (!seen.has(d) && !stopAt(d)) stack.push(d)
  }
  return seen
}
