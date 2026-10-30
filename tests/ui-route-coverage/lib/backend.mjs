// 后端路由清单：从 Go 源码（非测试文件）静态提取 method + path + 权限码 + 证据行号。
// 只读解析，不编译、不运行 Go。覆盖写法：
//   1. "METHOD /path" 字面量（mux.HandleFunc / router.Handle / 路由 map 键 / Patterns 数组）
//   2. "METHOD "+var+"/x"、var+"/x" 拼接：var 取最近的 for _, var := range []string{...} 或同包常量
//   3. 无 method 的挂载（patterns 列表、mux.Handle("/v1/x/")）：method="*"；以 / 结尾记为子树挂载
//   4. 表驱动：autodefensehttp routes 表、marketadminproxy rt(...) 行、marketsubscribehttp upstream 映射
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { listFiles, lineOf, rel } from './util.mjs'

const METHODS = 'GET|POST|PUT|PATCH|DELETE|HEAD'
const exactRe = new RegExp(`"(${METHODS}) (/[^"\\s]*)"`, 'g')
const pathLit = /^\/(v1|operator\/v1|portal\/v1|seller\/v1|auth\/v1|admin\/v1|service\/v1|installation\/v1|activation\/v1|control\/v1|payments\/v1|public\/v1|catalog\/v1|billing-provider\/v1|health|healthz|workload)\b/

// 服务 → 扫描目录（cmd 只取服务自身入口，其它 cmd 是独立工具）。
export const SERVICES = {
  'control-api': ['services/control-api/internal', 'services/control-api/cmd/control-api'],
  'license-service': ['services/license-service/internal', 'services/license-service/cmd'],
  'market-service': ['services/market-service/internal', 'services/market-service/cmd'],
}

function goFiles(repo, dirs) {
  // 排除测试桩包（如 dnspupprobe/dnspuptest：模拟第三方的假服务器）
  return dirs.flatMap((d) => {
    const root = join(repo, d)
    return listFiles(root, (f) => f.endsWith('.go') && !f.endsWith('_test.go') && !/\/testdata\//.test(f.slice(root.length)) && !/\/\w+test\//.test(f.slice(root.length)))
  })
}

function stripComments(src) {
  return src.split('\n').map((l) => (/^\s*\/\//.test(l) ? '' : l)).join('\n')
}

// 包级字符串常量（含 const ( ... ) 块里的 Name = "..."）。
function packageConsts(files) {
  const out = {}
  for (const { src } of files) {
    for (const m of src.matchAll(/^\s*(?:const\s+)?([A-Za-z_]\w*)\s*(?:string\s*)?(?::?=)\s*"([^"]*)"\s*$/gm)) out[m[1]] ??= m[2]
  }
  return out
}

// 在 idx 之前 40 行内找 for _, name := range []string{...}，返回列表。
function rangeValues(src, idx, name) {
  const before = src.slice(Math.max(0, src.lastIndexOf('\n', idx - 1) - 4000), idx)
  const re = new RegExp(`for _, ${name} := range \\[\\]string\\{([\\s\\S]*?)\\}\\s*\\{|for ${name}(?:, \\w+)? := range map\\[string\\]\\w+\\{([\\s\\S]*?)\\}\\s*\\{`, 'g')
  let last
  for (const m of before.matchAll(re)) last = m
  if (!last) return undefined
  if (last[1] !== undefined) return [...last[1].matchAll(/"([^"]*)"/g)].map((m) => m[1])
  return [...last[2].matchAll(/"([^"]*)"\s*:/g)].map((m) => m[1])
}

// 同函数内（向前到最近的 func 关键字，最多 3000 字符）对 name 的全部字符串赋值；
// name 若是外层闭包/函数形参（如 payoutAction(action string, …)），说明值来自调用点，再收集调用点的首个字符串实参。
function localConst(src, idx, name) {
  const start = Math.max(0, idx - 3000)
  const before = src.slice(start, idx)
  const vals = [...before.matchAll(new RegExp(`\\b(?:const\\s+)?${name}\\s*(?::=|=)\\s*"([^"]*)"`, 'g'))].map((m) => m[1])
  if (vals.length) return [...new Set(vals)]
  const fn = [...before.matchAll(new RegExp(`(\\w+)\\s*:?=\\s*func\\(${name} string`, 'g'))].pop()
  if (fn) {
    const calls = [...src.matchAll(new RegExp(`\\b${fn[1]}\\(\\s*"([^"]+)"`, 'g'))].map((m) => m[1])
    if (calls.length) return [...new Set(calls)]
  }
  return undefined
}

// 取离使用点最近的绑定：range 循环变量或局部赋值，谁的位置更靠后用谁。
function nearestBinding(src, idx, name) {
  const before = src.slice(Math.max(0, idx - 3000), idx)
  const rangeAt = Math.max(before.lastIndexOf(`for _, ${name} := range`), before.lastIndexOf(`for ${name} := range`), before.lastIndexOf(`for ${name}, `))
  const assignAt = before.search(new RegExp(`\\b${name}\\s*(?::=|=)\\s*"[^"]*"(?![\\s\\S]*\\b${name}\\s*(?::=|=)\\s*")`))
  if (assignAt > rangeAt) return localConst(src, idx, name)
  return rangeValues(src, idx, name) ?? localConst(src, idx, name)
}

// 拼接表达式（"a"+x+"b"）展开为全部可能的字符串。
function expandConcat(src, start, consts) {
  const expr = src.slice(start).match(/^((?:"[^"]*"|[A-Za-z_][\w.]*)(?:\s*\+\s*(?:"[^"]*"|[A-Za-z_][\w.]*))+)/)
  if (!expr) return []
  let acc = ['']
  for (const part of expr[1].split(/\s*\+\s*/)) {
    let values
    if (part.startsWith('"')) values = [part.slice(1, -1)]
    else values = nearestBinding(src, start, part) ?? (consts[part.split('.').pop()] !== undefined ? [consts[part.split('.').pop()]] : undefined)
    if (!values) return []
    acc = acc.flatMap((a) => values.map((v) => a + v))
  }
  return acc
}

function handlerPermissions(src, after, handlerBodies, file) {
  const pkg = file.slice(0, file.lastIndexOf('/'))
  // 注册行剩余部分（到行尾）里所有 x.method 引用，取第一个有权限的处理器（跳过 requireSession 等包装）。
  const line = src.slice(after, src.indexOf('\n', after))
  for (const m of line.matchAll(/\b(?:api|s|h|handler)\.([A-Za-z_]\w*)/g)) {
    if (/^(require\w*|with\w*|router|mux|serve)$/.test(m[1])) continue
    const perms = handlerBodies.get(`${pkg}|${m[1]}`)
    if (perms) return perms
  }
  return []
}

const PERM_LIT = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/
// 权限检查调用：require*Permission(w, r, X) / Authorize(p, X) / has(X, ...) / Permission: X / readOperation(X, ...)
const permCallRe = /(?:require\w*Permission|Authorize|authorize\w*|hasPermission|\.has|readOperation|Permission:)\s*\(?\s*((?:[\w.]+\s*,\s*)*)((?:"[a-z][a-z0-9_.]*"|[A-Z]\w*|\w+\.[A-Z]\w*)(?:\s*,\s*(?:"[a-z][a-z0-9_.]*"|[A-Z]\w*|\w+\.[A-Z]\w*))*)/g
function permsIn(body, consts) {
  const out = new Set()
  for (const m of body.matchAll(/\b[pP]ermission\w*\s*(?::=|=)\s*"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)"/g)) out.add(m[1])
  for (const m of body.matchAll(permCallRe)) {
    for (const tok of (m[1] + m[2]).split(/\s*,\s*/).filter(Boolean)) {
      const v = tok.startsWith('"') ? tok.slice(1, -1) : consts[tok.split('.').pop()]
      if (v && PERM_LIT.test(v) && !/^(application|text|http|net|installation_client_certificate)\./.test(v) && !/\.(list|json|go|sql)$/.test(v)) out.add(v)
    }
  }
  return out
}
// 处理器名 → 权限码。只在同一 Go 包内跟踪调用（包内方法名唯一时），最多 3 层；跨包同名方法（List/Get）不跟，避免串味。
// licensing 包（授权端业务层）单独作为 httpapi 的下游：api.licensing.X → (service *Service) X → (store *Store) X。
function collectHandlerBodies(files, consts) {
  const byPkg = new Map()
  for (const { file, src } of files) {
    const pkg = file.slice(0, file.lastIndexOf('/'))
    const raw = byPkg.get(pkg) ?? byPkg.set(pkg, new Map()).get(pkg)
    for (const m of src.matchAll(/^func \((?:\w+) \*?(\w+)\) ([A-Za-z_]\w*)\(/gm)) {
      const end = src.indexOf('\n}\n', m.index)
      const body = src.slice(m.index, end < 0 ? undefined : end)
      const list = raw.get(m[2]) ?? raw.set(m[2], []).get(m[2])
      list.push({ recv: m[1], body })
    }
  }
  const licensing = [...byPkg.entries()].find(([k]) => k.endsWith('/license-service/internal/licensing'))?.[1]
  const map = new Map()
  const callRe = /\b(?:s|api|h|handler|service|server|store)\.(?:(licensing|store|service)\.)?([A-Z_a-z]\w*)\(/g
  for (const [pkg, raw] of byPkg) {
    for (const [name, defs] of raw) {
      if (defs.length !== 1) continue
      const perms = permsIn(defs[0].body, consts)
      const seen = new Set([name])
      let frontier = [{ body: defs[0].body, pool: raw }]
      for (let depth = 0; depth < 3 && !perms.size; depth++) {
        const next = []
        for (const { body, pool } of frontier) for (const c of body.matchAll(callRe)) {
          const target = c[1] === 'licensing' && licensing ? licensing : pool
          const key = `${target === licensing ? 'L' : 'P'}:${c[2]}`
          if (seen.has(key)) continue
          seen.add(key)
          const subs = target.get(c[2])
          if (!subs) continue
          // 同名多定义时只取 Service/Store 接收者（授权端业务层惯例）
          const picked = subs.length === 1 ? subs : subs.filter((d) => /^(Service|Store)$/.test(d.recv))
          if (!picked.length || picked.length > 2) continue
          for (const d of picked) {
            for (const q of permsIn(d.body, consts)) perms.add(q)
            next.push({ body: d.body, pool: target })
          }
        }
        frontier = next
      }
      if (perms.size) map.set(`${pkg}|${name}`, [...perms])
    }
  }
  return map
}

export function extractBackend(repo) {
  const routes = []
  const add = (r) => routes.push(r)
  for (const [service, dirs] of Object.entries(SERVICES)) {
    const files = goFiles(repo, dirs).map((f) => ({ file: f, src: stripComments(readFileSync(f, 'utf8')) }))
      // internal/ 下的 package main 是离线工具（如 urlauthpolicyhttp/reviewcmd），不属于服务路由
      .filter(({ file, src }) => !(file.includes('/internal/') && /^package main\b/m.test(src)))
    const consts = packageConsts(files)
    const bodies = collectHandlerBodies(files, consts)
    for (const { file, src } of files) {
      const where = (i) => `${rel(repo, file)}:${lineOf(src, i)}`
      for (const m of src.matchAll(exactRe)) {
        const tail = src.slice(m.index + m[0].length, m.index + m[0].length + 3)
        if (/^\s*\+/.test(tail)) {
          for (const v of expandConcat(src, m.index, consts)) {
            const mm = v.match(new RegExp(`^(${METHODS}) (/\\S*)$`))
            if (mm) add({ service, method: mm[1], path: mm[2], evidence: where(m.index), permissions: [] })
          }
          continue
        }
        add({ service, method: m[1], path: m[2], evidence: where(m.index), permissions: handlerPermissions(src, m.index + m[0].length - 1, bodies, file) })
      }
      // "METHOD "+x 形式
      for (const m of src.matchAll(new RegExp(`"(${METHODS}) "\\s*\\+`, 'g'))) {
        for (const v of expandConcat(src, m.index, consts)) {
          const mm = v.match(new RegExp(`^(${METHODS}) (/\\S*)$`))
          if (mm) add({ service, method: mm[1], path: mm[2], evidence: where(m.index), permissions: [] })
        }
      }
      collectBareMounts(service, src, where, add)
      for (const m of src.matchAll(/\.(?:Handle|HandleFunc)\(\s*([A-Za-z_]\w*)\s*,/g)) {
        const v = consts[m[1]] ?? localConst(src, m.index, m[1])?.[0]
        const mm = v?.match(new RegExp(`^(${METHODS}) (/\\S*)$`))
        if (mm) add({ service, method: mm[1], path: mm[2], evidence: where(m.index), permissions: handlerPermissions(src, m.index + m[0].length - 2, bodies, file) })
      }
      for (const m of src.matchAll(new RegExp(`\\b(?:get|write|read|handle|route|register|reg|on)\\(\\s*(?:"(${METHODS})"\\s*,\\s*)?"(\\/(?:seller|admin|operator|portal|v1)[^"\\s]*)"`, 'g'))) {
        const pathStart = m.index + m[0].length - m[2].length - 2
        const tail = src.slice(m.index + m[0].length, m.index + m[0].length + 3)
        if (/^\s*\+/.test(tail)) {
          for (const v of expandConcat(src, pathStart, consts)) add({ service, method: m[1] ?? 'GET', path: v, evidence: where(m.index), permissions: [] })
          continue
        }
        add({ service, method: m[1] ?? 'GET', path: m[2], evidence: where(m.index), permissions: [] })
      }
    }
  }
  return dedupe(routes)
}

// 无 method 的挂载：Handle/HandleFunc 首参字面量，或挂载用的 []string{...} 列表里的路径。
function collectBareMounts(service, src, where, add) {
  // 处理器内部分发：URL.Path == "/v1/x"、case "/v1/x"、map 键 "/v1/x": {…}、CutPrefix/HasPrefix(path, "/v1/x/")
  for (const m of src.matchAll(/(?:[Pp]ath\s*[!=]=\s*|case\s+|^\s*)"(\/(?:v1|operator\/v1|portal\/v1|seller\/v1|admin\/v1)\/[^"\s]*)"\s*[:,]?/gm)) {
    const lit = m[1]
    const ctxt = m[0]
    if (!/(==|!=|case|":)/.test(ctxt + src.slice(m.index + m[0].length - 1, m.index + m[0].length + 1))) continue
    add({ service, method: '*', path: lit, evidence: where(m.index), permissions: [], mount: lit.endsWith('/') ? 'subtree' : 'exact', dispatch: true })
  }
  for (const m of src.matchAll(/(?:CutPrefix|HasPrefix|TrimPrefix)\(\s*[\w.]+\s*,\s*"(\/(?:v1|operator\/v1|portal\/v1|seller\/v1|admin\/v1)\/[^"\s]*)"/g)) {
    add({ service, method: '*', path: m[1].endsWith('/') ? m[1] : m[1] + '/', evidence: where(m.index), permissions: [], mount: 'subtree', dispatch: true })
  }
  // 路径常量 + == 比较（accountRecoveryRequestPath 等）
  for (const m of src.matchAll(/^\s*(\w+Path\w*|\w*[Pp]refix\w*)\s*=\s*"(\/(?:v1|operator\/v1|portal\/v1|seller\/v1|admin\/v1)\/[^"\s]*)"/gm)) {
    add({ service, method: '*', path: m[2], evidence: where(m.index), permissions: [], mount: m[2].endsWith('/') ? 'subtree' : 'exact', dispatch: true })
  }
  for (const m of src.matchAll(/\.(?:Handle|HandleFunc)\(\s*"(\/[^"\s]*)"/g)) {
    if (m[1] === '/' || !pathLit.test(m[1])) continue
    add({ service, method: '*', path: m[1], evidence: where(m.index), permissions: [], mount: m[1].endsWith('/') ? 'subtree' : 'exact' })
  }
  for (const block of src.matchAll(/(?:patterns:\s*\[\]string\{|range \[\]string\{|Routes\s*=\s*\[\]string\{|Patterns\s*=\s*\[\]string\{)((?:"[^"]*"|[^"}])*)\}/g)) {
    for (const lit of block[1].matchAll(/"(\/[^"\s]*)"/g)) {
      if (!pathLit.test(lit[1])) continue
      const at = block.index + block[0].indexOf(lit[0])
      add({ service, method: '*', path: lit[1], evidence: where(at), permissions: [], mount: lit[1].endsWith('/') ? 'subtree' : 'exact' })
    }
  }
}

// autodefensehttp：segments 表 + Tenant/Admin 前缀；权限按 write/wafAdapt/platform 推导。
export function extractAutodefense(repo) {
  const file = join(repo, 'services/control-api/internal/autodefensehttp/routes.go')
  const src = readFileSync(file, 'utf8')
  const out = []
  for (const m of src.matchAll(/\{method: http\.Method(\w+), segments: \[\]string\{((?:"[^"]*"\s*,?\s*)*)\}([^\n]*)\}/g)) {
    const method = m[1].toUpperCase()
    const segs = [...m[2].matchAll(/"([^"]*)"/g)].map((s) => s[1])
    const flags = m[3]
    const sub = segs.join('/')
    const write = /write: true/.test(flags)
    const waf = /wafAdapt: true/.test(flags)
    const platform = /platform: true/.test(flags)
    const perm = platform ? ['platform.admin'] : waf ? [write ? 'waf_adapt.manage' : 'waf_adapt.read'] : [write ? 'security_policies.manage' : 'security_policies.read']
    const prefixes = /admin: true/.test(flags) ? ['/v1/admin/security/autodefense'] : ['/v1/security/autodefense', '/v1/admin/security/autodefense']
    for (const p of prefixes) out.push({ service: 'control-api', method, path: `${p}/${sub}`, evidence: `${rel(repo, file)}:${lineOf(src, m.index)}`, permissions: perm })
  }
  return out
}

// license-service marketadminproxy：rt("METHOD", "path", owner, forwarded|pending, q, perms...)。
export function extractMarketAdminProxy(repo) {
  const file = join(repo, 'services/license-service/internal/marketadminproxy/routes.go')
  const src = readFileSync(file, 'utf8')
  const consts = Object.fromEntries([...src.matchAll(/^\s*(Perm\w+)\s*=\s*"([^"]+)"/gm)].map((m) => [m[1], m[2]]))
  const out = []
  for (const m of src.matchAll(/^\s*rt\("(\w+)",\s*"([^"]*)",\s*"([^"]*)",\s*(forwarded|pending),\s*[^,]*(?:\([^)]*\))?\s*((?:,\s*\w+)*)\),?/gm)) {
    const perms = m[5].split(',').map((s) => s.trim()).filter(Boolean).map((p) => consts[p] ?? p)
    out.push({ service: 'license-service', method: m[1], path: `/operator/v1/market/${m[2]}`, evidence: `${rel(repo, file)}:${lineOf(src, m.index)}`,
      permissions: perms, proxy: 'marketadminproxy', forwarded: m[4] === 'forwarded', owner: m[3] })
  }
  return out
}

// 主控市场代理 member.go：access 级别 → 权限码（marketsubscribehttp/handler.go allows）。
const MARKET_ACCESS = {
  accessBrowse: ['marketplace.browse', 'marketplace.purchase', 'marketplace.sell', 'sites.manage'],
  accessPurchase: ['marketplace.purchase', 'sites.manage'],
  accessSell: ['marketplace.sell', 'sites.manage'],
  accessSites: ['sites.manage'],
  accessAdvisoryRead: ['marketplace.browse', 'marketplace.purchase', 'marketplace.sell', 'sites.manage', 'plugin_installations.read', 'plugin_installations.manage'],
  accessPluginRead: ['marketplace.browse', 'marketplace.purchase', 'marketplace.sell', 'sites.manage', 'plugin_installations.read', 'plugin_installations.manage'],
  accessAdvisoryAck: ['marketplace.purchase', 'sites.manage', 'plugin_installations.manage'],
}
export function applyMarketAccess(repo, routes) {
  for (const f of ['member.go', 'buyer.go', 'supply.go', 'handler.go']) {
    const file = join(repo, 'services/control-api/internal/marketsubscribehttp', f)
    const src = readFileSync(file, 'utf8')
    for (const m of src.matchAll(new RegExp(`"(${METHODS}) (/v1/admin/[^"]*)":\\s*\\{[^}]*access:\\s*(access\\w+)`, 'g'))) {
      const r = routes.find((x) => x.method === m[1] && x.path === m[2])
      if (r && !r.permissions.length) r.permissions = MARKET_ACCESS[m[3]] ?? [m[3]]
    }
  }
}

export function normPath(p) {
  // Go mux 的 {name} 与 {name...} → {}；":upload" 这类自定义动词保持原样
  return p.replace(/\{[^}]*\}/g, '{}')
}

function dedupe(routes) {
  const map = new Map()
  for (const r of routes) {
    const key = `${r.service} ${r.method} ${normPath(r.path)}`
    const prev = map.get(key)
    if (!prev) map.set(key, { ...r, key, evidences: [r.evidence] })
    else {
      prev.evidences.push(r.evidence)
      prev.permissions = [...new Set([...prev.permissions, ...r.permissions])]
    }
  }
  return [...map.values()]
}

// 迁移里登记过的权限码：control-api permissions(name)，license-service operator_permissions(code)。
export function permissionCatalog(repo) {
  const out = { 'control-api': new Set(['platform.admin']), 'license-service': new Set(), 'market-service': new Set() }
  for (const [service, table] of [['control-api', 'permissions'], ['license-service', 'operator_permissions']]) {
    const dir = join(repo, 'services', service, 'migrations')
    for (const f of listFiles(dir, (x) => x.endsWith('.up.sql'))) {
      const sql = readFileSync(f, 'utf8')
      for (const m of sql.matchAll(new RegExp(`INSERT INTO\\s+(?:\\w+\\.)?${table}\\s*\\([^)]*\\)\\s*VALUES([\\s\\S]*?);`, 'gi'))) {
        for (const v of m[1].matchAll(/\(\s*'([a-z][a-z0-9_.]*)'/g)) out[service].add(v[1])
      }
      for (const v of sql.matchAll(/'([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)'/g)) if (/permission/i.test(sql.slice(Math.max(0, v.index - 400), v.index))) out[service].add(v[1])
    }
  }
  return out
}

export function backendInventory(repo) {
  const base = extractBackend(repo)
  applyMarketAccess(repo, base)
  const extra = [...extractAutodefense(repo), ...extractMarketAdminProxy(repo)]
  const catalog = permissionCatalog(repo)
  const routes = dedupe([...base, ...extra])
  for (const r of routes) {
    const known = catalog[r.service]
    r.permissions = r.permissions.filter((p) => known.has(p))
  }
  return routes
}
