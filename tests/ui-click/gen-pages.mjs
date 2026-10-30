// 从出包提交的前端源码生成全站巡检页面清单（只读，不连任何服务器）。
// 用法：node gen-pages.mjs [集成工作树] > pages.json
// 来源（apps/*/src 的导航与路由定义）：
//   web             apps/web/src/routes/navigation.ts（adminNavigation/userNavigation/directRouteDefinitions）
//   operator-console apps/operator-console/src/navigation.tsx（navGroups）
//   license-portal  apps/license-portal/src/layout/PortalLayout.tsx（MENU）
//   seller-portal   apps/seller-portal/src/layout/SellerLayout.tsx（MENU）
// 每页输出 app、path、角色、权限/模块门控；带 :参数 的详情页标为 needsId（巡检时从列表页取第一条）。
import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'

const repo = process.argv[2] ?? process.cwd()
const tsDir = fs.readdirSync(path.join(repo, 'node_modules/.pnpm')).find((d) => d.startsWith('typescript@'))
if (!tsDir) throw new Error(`${repo}/node_modules/.pnpm 没有 typescript（先 pnpm install）`)
const ts = createRequire(import.meta.url)(path.join(repo, 'node_modules/.pnpm', tsDir, 'node_modules/typescript'))

const parse = (rel) => {
  const file = path.join(repo, rel)
  return ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
}
const topConst = (sf, name) => {
  for (const st of sf.statements) {
    if (!ts.isVariableStatement(st)) continue
    for (const d of st.declarationList.declarations) if (d.name.getText(sf) === name) return d.initializer
  }
  throw new Error(`${sf.fileName} 没有 ${name}`)
}
// 对象字面量 -> { 属性名: 源码文本/字符串值 }；展开（...gate）按同文件常量并入。
const props = (sf, obj) => {
  const out = {}
  for (const p of obj.properties) {
    if (ts.isSpreadAssignment(p)) {
      let init = topConst(sf, p.expression.getText(sf))
      while (init && (ts.isAsExpression(init) || ts.isSatisfiesExpression?.(init))) init = init.expression
      Object.assign(out, props(sf, init))
      continue
    }
    if (!ts.isPropertyAssignment(p)) continue
    const k = p.name.getText(sf)
    const v = p.initializer
    out[k] = ts.isStringLiteralLike(v) ? v.text : v
  }
  return out
}
const text = (sf, v) => (v === undefined ? undefined : typeof v === 'string' ? v : v.getText(sf))
const arrayOf = (sf, v) => (v && ts.isArrayLiteralExpression(v) ? v.elements.map((e) => (ts.isStringLiteralLike(e) ? e.text : e.getText(sf))) : undefined)

const pages = []
const add = (p) => pages.push({ ...p, needsId: /:[A-Za-z]/.test(p.path) })

// ---- web（73 主控 /dashboard）----
{
  const sf = parse('apps/web/src/routes/navigation.ts')
  const walk = (arr, role, group) => {
    // 用户端四层菜单复用 admin 的 children（adminNavigation.find(... 'stream')?.children）。
    if (!ts.isArrayLiteralExpression(arr)) {
      const m = arr.getText(sf).match(/^adminNavigation\.find\(\(item\) => item\.key === '([^']+)'\)\?\.children$/)
      if (!m) throw new Error(`无法解析 children：${arr.getText(sf)}`)
      const src = topConst(sf, 'adminNavigation').elements.map((e) => props(sf, e)).find((o) => text(sf, o.key) === m[1])
      arr = src.children
    }
    for (const el of arr.elements) {
      const o = props(sf, el)
      const key = text(sf, o.key)
      if (o.children) walk(o.children, role, key)
      else if (key?.startsWith('/')) add({
        app: 'web', host: 'cdnca.com', base: '/dashboard', path: key, roles: [role], group,
        label: text(sf, o.labelKey), permission: text(sf, o.requiredPermission),
        permissions: arrayOf(sf, o.requiredPermissions), module: text(sf, o.requiredModule),
        platformAdminFallback: o.platformAdminFallback ? text(sf, o.platformAdminFallback) !== 'false' : true,
        // implemented 可能是运行时开关（packageCommerceFeatureEnabled），记源码文本，巡检时页面在才访问。
        implemented: o.implemented ? (text(sf, o.implemented) === 'true' ? true : text(sf, o.implemented)) : false, source: 'nav',
      })
    }
  }
  walk(topConst(sf, 'adminNavigation'), 'admin', null)
  walk(topConst(sf, 'userNavigation'), 'user', null)
  for (const el of topConst(sf, 'directRouteDefinitions').elements) {
    const o = props(sf, el)
    add({
      app: 'web', host: 'cdnca.com', base: '/dashboard', path: text(sf, o.path), roles: arrayOf(sf, o.roles),
      group: text(sf, o.parentKey), label: text(sf, o.labelKey), permission: text(sf, o.requiredPermission),
      permissions: arrayOf(sf, o.requiredPermissions), module: text(sf, o.requiredModule),
      platformAdminFallback: o.platformAdminFallback ? text(sf, o.platformAdminFallback) !== 'false' : true,
      implemented: true, source: 'direct',
    })
  }
}

// ---- operator-console（68 运营后台 /operator）----
{
  const sf = parse('apps/operator-console/src/navigation.tsx')
  for (const g of topConst(sf, 'navGroups').elements) {
    const go = props(sf, g)
    for (const it of go.items.elements) {
      const o = props(sf, it)
      add({ app: 'operator-console', host: 'auth.cdnca.com', base: '/operator', path: o.path, roles: ['operator'],
        group: go.key, label: o.label, permission: text(sf, o.permission) })
    }
  }
}

// ---- license-portal（68 客户门户 /console）、seller-portal（85 卖家站 developer.cdnca.com）----
for (const [app, rel, host, base] of [
  ['license-portal', 'apps/license-portal/src/layout/PortalLayout.tsx', 'auth.cdnca.com', '/console'],
  ['seller-portal', 'apps/seller-portal/src/layout/SellerLayout.tsx', 'developer.cdnca.com', ''],
]) {
  const sf = parse(rel)
  for (const it of topConst(sf, 'MENU').elements) {
    const o = props(sf, it)
    add({ app, host, base, path: o.path, roles: ['customer'], label: o.label,
      onboarded: o.onboarded ? text(sf, o.onboarded) === 'true' : false })
  }
}

// 路由表里有、菜单里没有的页面（只列出，供人工核对是否漏巡）。
// App.tsx 的 <Route> 多数写成多行，只按 path="/..." 取。
const routePaths = (rel) => [...new Set([...fs.readFileSync(path.join(repo, rel), 'utf8').matchAll(/\bpath="(\/[^"*]*)"/g)].map((m) => m[1]))]
const known = new Set(pages.map((p) => `${p.app}${p.path}`))
const unlisted = []
for (const [app, rel] of [['web', 'apps/web/src/App.tsx'], ['operator-console', 'apps/operator-console/src/App.tsx'],
  ['license-portal', 'apps/license-portal/src/App.tsx'], ['seller-portal', 'apps/seller-portal/src/App.tsx']]) {
  for (const p of routePaths(rel)) if (!known.has(`${app}${p}`)) unlisted.push({ app, path: p })
}

const counts = pages.reduce((m, p) => ({ ...m, [p.app]: (m[p.app] ?? 0) + 1 }), {})
process.stdout.write(JSON.stringify({ repo, generatedAt: new Date().toISOString(), counts, pages, unlisted }, null, 2) + '\n')
