// 前端调用清单：TypeScript AST 解析四端 src（排除测试），找出所有以接口前缀开头的路径字面量，
// 还原 method（同一调用实参里的 method: 'X'，或 send('X', ...) 首参），得到 method + path + 证据行号。
// 模板插值记为 {}，查询串丢弃；同文件的字符串常量（const base = '/operator/v1/market'）会展开。
import { readFileSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { listFiles, rel } from './util.mjs'
import { loadTS } from './ts.mjs'

// 端 → 源码目录、后端服务、相对路径默认前缀（门户/卖家站 request('/x') 由客户端补前缀）。
export const APPS = {
  web: { src: 'apps/web/src', service: 'control-api' },
  'operator-console': { src: 'apps/operator-console/src', service: 'license-service' },
  'license-portal': { src: 'apps/license-portal/src', service: 'license-service', relativePrefix: '/portal/v1' },
  'seller-portal': { src: 'apps/seller-portal/src', service: 'market-service', relativePrefix: '/seller/v1' },
}

export const PREFIX_SERVICE = [
  ['/operator/v1/', 'license-service'],
  ['/portal/v1/', 'license-service'],
  ['/auth/v1/', 'license-service'],
  ['/seller/v1/', 'market-service'],
  ['/v1/', 'control-api'],
]
const prefixRe = /^\/(v1|operator\/v1|portal\/v1|auth\/v1|seller\/v1)(\/|$)/
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])

const isTestFile = (f) => /\.(test|spec)\.[tj]sx?$/.test(f) || /\/(test|tests|__tests__|__mocks__)\//.test(f) || /fixtures?\./.test(f) || f.endsWith('.d.ts')

export function sourceFiles(repo, app) {
  const root = join(repo, APPS[app].src)
  return listFiles(root, (f) => /\.(ts|tsx)$/.test(f) && !isTestFile(f.slice(root.length)))
}

const MAX_VARIANTS = 24
const uniq = (a) => [...new Set(a)].slice(0, MAX_VARIANTS)
const product = (a, b) => uniq(a.flatMap((x) => b.map((y) => x + y)))
const ROOT_IDENT = /^(apiRoot|apiBase|API_ROOT|API_BASE|baseURL|apiBaseURL|apiBaseUrl|root|origin)$/

// 单文件上下文：顶层声明、函数表。
function fileContext(ts, sf) {
  const top = {}
  const funcs = {}
  for (const st of sf.statements) {
    if (ts.isFunctionDeclaration(st) && st.name) funcs[st.name.text] = st
    const list = ts.isVariableStatement(st) ? st.declarationList.declarations : []
    for (const d of list) {
      if (!ts.isIdentifier(d.name) || !d.initializer) continue
      let init = d.initializer
      while (ts.isAsExpression(init) || ts.isParenthesizedExpression(init)) init = init.expression
      if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) funcs[d.name.text] = init
      else top[d.name.text] = d.initializer
    }
  }
  return { ts, sf, top, funcs }
}

function strip(ts, n) {
  while (n && (ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isNonNullExpression(n) || ts.isSatisfiesExpression?.(n))) n = n.expression
  return n
}

function returnExprs(ts, fn) {
  if (!fn.body) return []
  if (!ts.isBlock(fn.body)) return [fn.body]
  const out = []
  const visit = (n) => {
    if (n !== fn.body && (ts.isFunctionLike(n))) return
    if (ts.isReturnStatement(n) && n.expression) out.push(n.expression)
    ts.forEachChild(n, visit)
  }
  visit(fn.body)
  return out
}

// 在 usage 所在作用域链里找 name 的所有赋值来源（声明初始值 + 后续赋值）。
function localSources(ts, usage, name) {
  for (let p = usage.parent; p; p = p.parent) {
    if (ts.isFunctionLike(p)) {
      const param = p.parameters?.find((x) => ts.isIdentifier(x.name) && x.name.text === name)
      if (param) return { param, fn: p }
    }
    if (ts.isBlock(p) || ts.isSourceFile(p) || ts.isFunctionLike(p)) {
      const found = []
      const scan = (n) => {
        if (n !== p && ts.isFunctionLike(n)) return
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name && n.initializer) found.push(n.initializer)
        if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left) && n.left.text === name) found.push(n.right)
        ts.forEachChild(n, scan)
      }
      if (!ts.isSourceFile(p)) scan(p)
      if (found.length) return { exprs: found }
    }
  }
  return undefined
}

// 表达式 → 可能的字符串集合；undefined 表示不是字符串表达式。env：形参名 → 变体。
function variants(ctx, node, env = {}, depth = 0) {
  const { ts } = ctx
  node = strip(ts, node)
  if (!node || depth > 8) return undefined
  if (ts.isStringLiteralLike(node)) return [node.text]
  if (ts.isTemplateExpression(node)) {
    let acc = [node.head.text]
    for (const span of node.templateSpans) acc = product(product(acc, part(ctx, span.expression, env, depth)), [span.literal.text])
    return acc
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const l = variants(ctx, node.left, env, depth + 1)
    if (l === undefined) return undefined
    return product(l, part(ctx, node.right, env, depth))
  }
  if (ts.isConditionalExpression(node)) {
    const a = variants(ctx, node.whenTrue, env, depth + 1)
    const b = variants(ctx, node.whenFalse, env, depth + 1)
    if (a === undefined && b === undefined) return undefined
    return uniq([...(a ?? ['{}']), ...(b ?? ['{}'])])
  }
  if (ts.isIdentifier(node)) return identVariants(ctx, node, env, depth)
  if (ts.isCallExpression(node)) return callVariants(ctx, node, env, depth)
  return undefined
}

function identVariants(ctx, node, env, depth) {
  const { ts } = ctx
  const name = node.text
  if (env[name]) return env[name]
  // apiRoot 等取 import.meta.env 的根地址视为空串；同名但值是接口路径的（const root = '/v1/admin/x'）照常展开
  if (ROOT_IDENT.test(name)) {
    // 部署根（import.meta.env…）视为空；若其值本身拼了接口前缀（root = `${env}/v1/admin/x`），保留前缀
    const init = ctx.top[name]
    const vs = init ? variants(ctx, init, env, depth + 1) : undefined
    if (vs?.some((v) => prefixRe.test(v))) return vs
    return ['']
  }
  const local = localSources(ts, node, name)
  if (local?.param) return local.param.initializer ? uniq([...(variants(ctx, local.param.initializer, env, depth + 1) ?? []), '{}']) : factoryArgVariants(ctx, local, depth)
  if (local?.exprs) {
    const vs = local.exprs.map((e) => variants(ctx, e, env, depth + 1)).filter(Boolean)
    if (vs.length) return uniq(vs.flat())
    return undefined
  }
  const init = ctx.top[name]
  if (init) {
    if (/import\.meta\.env/.test(init.getText(ctx.sf))) return ['']
    return variants(ctx, init, env, depth + 1)
  }
  return undefined
}

// 工厂函数的接口前缀形参（function inboxApi(base) { return { list: () => call(`${base}/x`) } }，
// 同文件 inboxApi('/v1/admin/inbox')）：形参无默认值时取同文件全部调用点的实参。只认返回对象字面量的
// 顶层函数，普通请求函数（call(token, path)）的 path 形参不展开，避免把所有调用路径灌进它体内的 fetch。
function factoryArgVariants(ctx, { param, fn }, depth) {
  const { ts, sf } = ctx
  const name = Object.entries(ctx.funcs).find(([, f]) => f === fn)?.[0]
  if (!name) return undefined
  const rs = returnExprs(ts, fn)
  if (!rs.length || !rs.every((r) => ts.isObjectLiteralExpression(strip(ts, r)))) return undefined
  const index = fn.parameters.indexOf(param)
  const out = []
  const scan = (n) => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === name && n.arguments[index]) {
      out.push(...(variants(ctx, n.arguments[index], {}, depth + 1) ?? []))
    }
    ts.forEachChild(n, scan)
  }
  scan(sf)
  return out.length ? uniq(out) : undefined
}

function callVariants(ctx, node, env, depth) {
  const { ts } = ctx
  const callee = node.expression
  // x.toString() / encodeURIComponent(x) / String(x) 不是路径
  if (!ts.isIdentifier(callee)) return undefined
  const fn = ctx.funcs[callee.text]
  if (!fn || (ctx.stack ??= new Set()).has(callee.text)) return undefined
  ctx.stack.add(callee.text)
  try {
    const bound = {}
    fn.parameters.forEach((p, i) => {
      if (!ts.isIdentifier(p.name)) return
      const arg = node.arguments[i]
      const v = arg ? variants(ctx, arg, env, depth + 1) : p.initializer ? variants(ctx, p.initializer, env, depth + 1) : ['']
      bound[p.name.text] = v ?? ['{}']
    })
    const outs = returnExprs(ts, fn).map((e) => variants(ctx, e, bound, depth + 1)).filter(Boolean)
    if (!outs.length) return undefined
    const flat = uniq(outs.flat())
    return flat.some((s) => prefixRe.test(s)) ? flat : undefined
  } finally {
    ctx.stack.delete(callee.text)
  }
}

function part(ctx, expr, env, depth) {
  // `${(import.meta.env.VITE_API_BASE_URL ?? '').replace(...)}`：部署根地址，视为空
  if (/import\.meta\.env/.test(expr.getText(ctx.sf))) return ['']
  const v = variants(ctx, expr, env, depth + 1)
  if (v === undefined) return ['{}']
  return v
}

export function normalizeFrontPath(p) {
  let s = p.split('?')[0].split('#')[0].split('&')[0]
  s = s.replace(/\/+$/, '')
  s = s.replace(/([^/{}])\{\}$/, '$1')
  s = s.replace(/\/\/+/g, '/')
  return s || '/'
}

function findMethodProp(ts, node, depth = 0) {
  node = strip(ts, node)
  if (depth > 3 || !node || !ts.isObjectLiteralExpression(node)) return undefined
  for (const p of node.properties) {
    if (ts.isPropertyAssignment(p) && p.name.getText() === 'method') {
      const v = strip(ts, p.initializer)
      if (ts.isStringLiteralLike(v)) return [v.text.toUpperCase()]
      if (ts.isConditionalExpression(v)) {
        const a = strip(ts, v.whenTrue), b = strip(ts, v.whenFalse)
        if (ts.isStringLiteralLike(a) && ts.isStringLiteralLike(b)) return [a.text.toUpperCase(), b.text.toUpperCase()]
      }
      return ['*']
    }
    if (ts.isShorthandPropertyAssignment(p) && p.name.text === 'method') return ['*']
    if (ts.isPropertyAssignment(p)) {
      const r = findMethodProp(ts, p.initializer, depth + 1)
      if (r) return r
    }
  }
  return undefined
}

function methodOfCall(ctx, call) {
  const { ts } = ctx
  const callee = ts.isIdentifier(call.expression) ? call.expression.text : ts.isPropertyAccessExpression(call.expression) ? call.expression.name.text : ''
  if (callee === 'open' && call.arguments[0] && ts.isStringLiteralLike(call.arguments[0])) return [call.arguments[0].text.toUpperCase()]
  for (const arg of call.arguments) {
    const m = findMethodProp(ts, arg)
    if (m) return m
    // init 由同文件辅助函数构造：json('POST', body) / post(body) / withBody('PUT', …)
    const a = strip(ts, arg)
    if (a && ts.isCallExpression(a) && ts.isIdentifier(a.expression)) {
      for (const x of a.arguments) {
        const lit = strip(ts, x)
        if (lit && ts.isStringLiteralLike(lit) && METHODS.has(lit.text)) return [lit.text]
        // json(t.id ? 'PUT' : 'POST', body)：两支都是方法字面量
        if (lit && ts.isConditionalExpression(lit)) {
          const l = strip(ts, lit.whenTrue), r = strip(ts, lit.whenFalse)
          if (ts.isStringLiteralLike(l) && ts.isStringLiteralLike(r) && METHODS.has(l.text) && METHODS.has(r.text)) {
            return Object.assign([l.text, r.text], { cond: lit.condition.getText() })
          }
        }
      }
      const helper = ctx.funcs[a.expression.text]
      if (helper) {
        for (const r of returnExprs(ts, helper)) {
          const hm = findMethodProp(ts, r)
          if (hm && hm[0] !== '*') return hm
        }
      }
      if (nameMethod[a.expression.text]) return [nameMethod[a.expression.text]]
    }
  }
  // 位置实参里的方法字面量：send('POST', …)、idempotent(path, 'PUT', …)
  for (const a of call.arguments) {
    const x = strip(ts, a)
    if (x && ts.isStringLiteralLike(x) && METHODS.has(x.text)) return [x.text]
  }
  if (ctx.wrappers[callee]) return [ctx.wrappers[callee]]
  if (nameMethod[callee]) return [nameMethod[callee]]
  return undefined
}

const nameMethod = { post: 'POST', create: 'POST', put: 'PUT', patch: 'PATCH', del: 'DELETE', remove: 'DELETE', destroy: 'DELETE', postJSON: 'POST', putJSON: 'PUT' }

function wrapperMethods(ts, sf, funcs) {
  const out = {}
  for (const [name, fn] of Object.entries(funcs)) {
    const found = new Set([...(fn.body?.getText(sf) ?? '').matchAll(/method:\s*['"](GET|POST|PUT|PATCH|DELETE)['"]/g)].map((m) => m[1]))
    if (found.size === 1) out[name] = [...found][0]
  }
  return out
}

// 返回 API 路径的同文件函数（路径构造器）：所有 return 都能展开成字符串且至少一个是接口路径。
// 其调用点不是"发请求"，由外层调用记录。
function pathBuilders(ctx) {
  const out = new Set()
  for (const [name, fn] of Object.entries(ctx.funcs)) {
    const rs = returnExprs(ctx.ts, fn)
    if (!rs.length) continue
    const env = Object.fromEntries(fn.parameters.filter((p) => ctx.ts.isIdentifier(p.name)).map((p) => [p.name.text, ['{}']]))
    const vs = rs.map((r) => variants(ctx, r, env))
    if (vs.every(Boolean) && vs.flat().some((v) => prefixRe.test(v))) out.add(name)
  }
  return out
}

const GET_DEFAULT = /^(fetch|request|call|send|read|json|fetchJSON|jsonRequest|requestJSON|get|readPage|fetchResponse|getJSON|load)$/

// 转发函数：函数体内把某个形参拼进接口路径再发请求（const get = (path) => request(`${base}/${path}`)）。
// 返回 { pathParam 序号, methodParam 序号|undefined, template 变体（形参处留占位 \u0000）, fixedMethod }。
function forwarders(ctx) {
  const { ts } = ctx
  const out = {}
  for (const [name, fn] of Object.entries(ctx.funcs)) {
    const params = fn.parameters.map((p) => (ts.isIdentifier(p.name) ? p.name.text : undefined))
    if (!fn.body) continue
    let found
    const visit = (n) => {
      if (found) return
      if (ts.isCallExpression(n)) {
        for (const arg of n.arguments) {
          for (let i = 0; i < params.length; i++) {
            if (!params[i]) continue
            const env = Object.fromEntries(params.map((q, j) => [q, j === i ? ['\u0000'] : ['{}']]).filter(([q]) => q))
            const vs = variants(ctx, arg, env)
            // 形参必须接在常量接口前缀之后（`${base}/${path}`），整条路径就是形参的（request(path)）不算转发
            const hits = (vs ?? []).filter((v) => v.includes('\u0000') && prefixRe.test(v.slice(0, v.indexOf('\u0000'))))
            // 形参须直接出现在模板/拼接里（不是经 query(params) 之类调用间接进入）
            const direct = new RegExp(`\\$\\{\\s*${params[i]}\\s*\\}|\\+\\s*${params[i]}\\b`).test(arg.getText(ctx.sf))
            // 转发形参是路径尾部（`${base}/${path}`）或名字像路径；`/x/${id}/release` 里的 id 是普通参数
            // 名字像路径（path/suffix/…），或模板形如"固定前缀/形参"且前缀不含其它插值（`${base}/${path}`）
            const nameLike = /^(path|suffix|sub|rest|endpoint|resource|url|route|relative|action|segment)\w*$/i.test(params[i])
            const tail = nameLike ||
              hits.every((v) => /\u0000(\?.*|\{\})?$/.test(v) && !v.slice(0, v.indexOf('\u0000')).includes('{}'))
            // 形参经局部变量（const path = `${base}${suffix}`）进入请求时 direct 为假，名字像路径即可
            if (hits.length && (direct || nameLike) && tail) {
              const m = methodOfCall(ctx, n)
              const methodParam = params.findIndex((q) => q && fn.body.getText(ctx.sf).match(new RegExp(`\\bmethod\\s*[,}]|method:\\s*${q}\\b`)) && /method/i.test(q))
              found = { pathParam: i, templates: hits, fixedMethod: m && m[0] !== '*' ? m : undefined, methodParam: methodParam >= 0 ? methodParam : undefined, nameLike, inner: n }
              return
            }
          }
        }
      }
      ts.forEachChild(n, visit)
    }
    visit(fn.body)
    if (found) out[name] = found
  }
  return out
}

export function extractFrontendCalls(repo) {
  const ts = loadTS(repo)
  const calls = []
  for (const app of Object.keys(APPS)) {
    for (const file of sourceFiles(repo, app)) {
      const text = readFileSync(file, 'utf8')
      const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
      const ctx = fileContext(ts, sf)
      ctx.wrappers = wrapperMethods(ts, sf, ctx.funcs)
      const builders = pathBuilders(ctx)
      const fwd = forwarders(ctx)
      const at = (n) => `${rel(repo, file)}:${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}`
      const local = []
      const literalSites = []
      const recordedSpans = []
      const record = (method, raw, node, kind) => {
        recordedSpans.push([node.pos, node.end])
        const owner = ownerOf(ts, node, sf)
        for (const m of method) local.push({ app, method: m, raw, path: normalizeFrontPath(raw), evidence: at(node), kind, owner })
      }
      const fwdBodies = Object.keys(fwd).map((k) => ctx.funcs[k])
      const insideForwarder = (n) => fwdBodies.some((fn) => n.pos >= fn.pos && n.end <= fn.end)
      const visit = (n) => {
        if (ts.isCallExpression(n) && !insideForwarder(n)) {
          const callee = ts.isIdentifier(n.expression) ? n.expression.text : ts.isPropertyAccessExpression(n.expression) ? n.expression.name.text : ''
          // 门户/卖家站的 request(path) 由下方相对前缀规则处理（支持 prefix 选项），不当转发函数
          const f = ts.isIdentifier(n.expression) && !(APPS[app].relativePrefix && callee === 'request') ? fwd[callee] : undefined
          if (f && n.arguments[f.pathParam]) {
            const sub = variants(ctx, n.arguments[f.pathParam]) ?? ['{}']
            let method = f.fixedMethod
            if (f.methodParam !== undefined) {
              const ma = strip(ts, n.arguments[f.methodParam])
              if (ma && ts.isStringLiteralLike(ma) && METHODS.has(ma.text)) method = [ma.text]
            }
            method ??= methodOfCall(ctx, n) ?? ['GET']
            for (const t of f.templates) for (const v of sub) record(method, t.replace('\u0000', v), n, 'call')
          } else if (!builders.has(callee) && !/^(encodeURIComponent|String|startsWith|endsWith|includes|replace|test|match|push|set|append|t|log|warn|error)$/.test(callee)) {
            for (const arg of n.arguments) {
              const vs = variants(ctx, arg)
              const hits = (vs ?? []).filter((v) => prefixRe.test(v))
              if (!hits.length) continue
              let method = methodOfCall(ctx, n) ?? (GET_DEFAULT.test(callee) || ctx.funcs[callee] ? ['GET'] : ['*'])
              // fetch(path, { ...init }) 且 init 是外层函数形参：方法由外层函数的调用点给出，合并它们
              const outer = enclosingFunction(ts, n)
              const spread = n.arguments.some((a) => ts.isObjectLiteralExpression(strip(ts, a)) && strip(ts, a).properties.some((pp) => ts.isSpreadAssignment(pp) && ts.isIdentifier(pp.expression) && outer?.params.includes(pp.expression.text)))
              if (outer?.name && (spread || n.arguments.some((a) => ts.isIdentifier(a) && outer.params.includes(a.text) && /init|options|opts/i.test(a.text)))) {
                const fromCallers = callerMethods(ctx, sf, outer.name)
                if (fromCallers.size) method = [...new Set([...method.filter((x) => x !== '*'), ...fromCallers])]
              }
              // 路径与方法是同一条件的三元（c ? '/x/{id}' : '/x' 配 json(c ? 'PUT' : 'POST')）：按分支配对，不做笛卡尔积
              const pa = strip(ts, arg)
              if (method.cond && ts.isConditionalExpression(pa) && pa.condition.getText() === method.cond) {
                const branch = (e, m) => { for (const h of (variants(ctx, e) ?? []).filter((v) => prefixRe.test(v))) record([m], h, n, 'call') }
                branch(pa.whenTrue, method[0])
                branch(pa.whenFalse, method[1])
                break
              }
              for (const h of hits) record(method, h, n, 'call')
              break
            }
            // 门户/卖家站相对路径 request('/x', { prefix })
            if (APPS[app].relativePrefix && callee === 'request' && n.arguments[0]) {
              let arg = strip(ts, n.arguments[0])
              let vs
              if (ts.isCallExpression(arg) && ts.isIdentifier(arg.expression) && arg.expression.text === 'seller') vs = (variants(ctx, arg.arguments[0]) ?? ['{}']).map((v) => '/' + v)
              else vs = variants(ctx, arg)
              const rels = (vs ?? []).filter((v) => v.startsWith('/') && !prefixRe.test(v))
              if (rels.length) {
                let prefixes = [APPS[app].relativePrefix]
                const opts = strip(ts, n.arguments[1])
                if (opts && ts.isObjectLiteralExpression(opts)) {
                  const pp = opts.properties.find((p) => ts.isPropertyAssignment(p) && p.name.getText() === 'prefix')
                  if (pp) prefixes = variants(ctx, pp.initializer) ?? prefixes
                }
                const method = methodOfCall(ctx, n) ?? ['GET']
                for (const pre of prefixes) for (const r of rels) record(method, pre + r, n, 'call')
              }
            }
          }
        }
        if ((ts.isStringLiteralLike(n) || ts.isTemplateExpression(n)) && prefixRe.test(ts.isStringLiteralLike(n) ? n.text : n.head.text)) literalSites.push(n)
        ts.forEachChild(n, visit)
      }
      visit(sf)
      // 形参是普通 id（`/x/${approvalId}`）的转发函数若本文件没有直接调用点（只经导出对象被外部调用），
      // 它体内的请求会被上面跳过；按 {} 记入，避免漏判"有调用"。路径名形参（path/suffix…）是通用转发，不记
      const directCalls = new Set()
      const scanCalls = (n) => { if (ts.isCallExpression(n) && ts.isIdentifier(n.expression)) directCalls.add(n.expression.text); ts.forEachChild(n, scanCalls) }
      scanCalls(sf)
      for (const [name, f] of Object.entries(fwd)) {
        if (f.nameLike || directCalls.has(name)) continue
        const method = f.fixedMethod ?? methodOfCall(ctx, f.inner) ?? ['GET']
        for (const t of f.templates) record(method, t.replace('\u0000', '{}'), f.inner, 'call')
      }
      // 兜底：没被任何调用点覆盖的接口字面量（如端点映射表）按 method=* 记入，避免漏判"有调用"。
      // 只跳过已被某个调用点覆盖的字面量（在其 span 内），以及仅作前缀用的常量（其下有更长调用）
      const covered = new Set(local.map((c) => c.path))
      for (const n of literalSites) {
        if (recordedSpans.some(([a, b]) => n.pos >= a && n.end <= b)) continue
        const vs = variants(ctx, n) ?? []
        for (const v of vs) {
          const p = normalizeFrontPath(v)
          if (!prefixRe.test(v) || [...covered].some((c) => c.startsWith(p + '/'))) continue
          covered.add(p)
          local.push({ app, method: '*', raw: v, path: p, evidence: at(n), kind: 'literal', owner: ownerOf(ts, n, sf) })
        }
      }
      const exportAlias = {}
      for (const st of sf.statements) {
        if (!ts.isVariableStatement(st) || !st.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) continue
        for (const d of st.declarationList.declarations) {
          const init = strip(ts, d.initializer)
          if (!init || !ts.isObjectLiteralExpression(init) || !ts.isIdentifier(d.name)) continue
          for (const pr of init.properties) {
            if (ts.isShorthandPropertyAssignment(pr)) exportAlias[pr.name.text] = { top: d.name.text, member: pr.name.text }
            else if (ts.isPropertyAssignment(pr) && ts.isIdentifier(strip(ts, pr.initializer))) exportAlias[strip(ts, pr.initializer).text] = { top: d.name.text, member: pr.name.getText(sf) }
          }
        }
      }
      for (const c of local) if (c.owner && !c.owner.exported && c.owner.top && exportAlias[c.owner.top]) c.owner = { ...exportAlias[c.owner.top], exported: true }
      calls.push(...local)
    }
  }
  return dedupeCalls(calls)
}

function dedupeCalls(calls) {
  const map = new Map()
  for (const c of calls) {
    const k = `${c.app} ${c.method} ${c.path}`
    const prev = map.get(k)
    if (prev) prev.evidences.push(c.evidence)
    else map.set(k, { ...c, evidences: [c.evidence] })
  }
  return [...map.values()]
}

// 调用点所属：顶层声明名 + 对象字面量成员名（fooApi.list）。用于判断页面是否真的用到这条调用。
function ownerOf(ts, node, sf) {
  let member
  for (let p = node.parent; p; p = p.parent) {
    if (!member && (ts.isPropertyAssignment(p) || ts.isMethodDeclaration(p) || ts.isShorthandPropertyAssignment(p)) && p.name) member = p.name.getText(sf)
    if (p.parent && ts.isSourceFile(p.parent)) {
      let top
      if (ts.isFunctionDeclaration(p) && p.name) top = p.name.text
      if (ts.isVariableStatement(p)) top = p.declarationList.declarations[0]?.name.getText(sf)
      if (ts.isClassDeclaration(p) && p.name) top = p.name.text
      const exported = !!p.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
      return { top, member: top && ts.isVariableStatement(p) ? member : undefined, exported }
    }
  }
  return { top: undefined, member: undefined, exported: false }
}

function enclosingFunction(ts, node) {
  for (let p = node.parent; p; p = p.parent) {
    if (ts.isFunctionDeclaration(p) && p.name) return { name: p.name.text, params: p.parameters.map((x) => x.name.getText()) }
    if ((ts.isArrowFunction(p) || ts.isFunctionExpression(p)) && ts.isVariableDeclaration(p.parent)) return { name: p.parent.name.getText(), params: p.parameters.map((x) => x.name.getText()) }
    if (ts.isFunctionLike(p)) return undefined
  }
  return undefined
}

// 同文件里调用 name(...) 的地方给出的 method
function callerMethods(ctx, sf, name) {
  const out = new Set()
  const visit = (n) => {
    if (ctx.ts.isCallExpression(n) && ctx.ts.isIdentifier(n.expression) && n.expression.text === name) {
      const m = methodOfCall(ctx, n)
      if (m) for (const x of m) if (x !== '*') out.add(x)
      else out.add('GET')
    }
    ctx.ts.forEachChild(n, visit)
  }
  visit(sf)
  return out
}
