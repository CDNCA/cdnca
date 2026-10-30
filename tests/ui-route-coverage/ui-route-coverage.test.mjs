// node --test tests/ui-route-coverage/ui-route-coverage.test.mjs
// 1) 夹具：各提取器与四张表的判定规则；2) 仓库：当前缺口必须全部在 allowlist.json 里且有理由，白名单不得有已修复的过期条目。
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { runAudit, pathMatches } from './lib/audit.mjs'
import { compare, loadAllowlist, KEYS } from './lib/allowlist.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const mini = join(here, 'fixtures/mini')
const repo = join(here, '../..')
const fixture = runAudit(mini)
const keys = (rows, name) => rows.map(KEYS[name]).sort()

test('后端：精确路由、range 拼接、子树挂载、表驱动（autodefense/代理白名单）都进清单', () => {
  const routes = fixture.backend.map((r) => `${r.service} ${r.method} ${r.path}`)
  for (const want of [
    'control-api GET /v1/widgets',
    'control-api DELETE /v1/widgets/{id}',
    'control-api GET /v1/bans',
    'control-api GET /v1/admin/bans',
    'control-api * /v1/reports/',
    'control-api GET /v1/security/autodefense/sites',
    'license-service GET /operator/v1/market/sellers',
    'market-service GET /seller/v1/me',
  ]) assert.ok(routes.includes(want), want)
})

test('后端：处理器权限码按包解析，并按迁移权限目录过滤', () => {
  const byKey = Object.fromEntries(fixture.backend.map((r) => [`${r.method} ${r.path}`, r.permissions]))
  assert.deepEqual(byKey['GET /v1/widgets'], ['widgets.read'])
  assert.deepEqual(byKey['POST /v1/widgets'], ['widgets.manage'])
  assert.deepEqual(byKey['GET /operator/v1/market/sellers'], ['marketplace.overview.view'])
})

test('前端：三元前缀、路径构造函数、门户相对路径与 seller() 包装都还原为完整路径', () => {
  const calls = fixture.calls.map((c) => `${c.app} ${c.method} ${c.path}`)
  for (const want of [
    'web GET /v1/widgets',
    'web POST /v1/widgets',
    'web PATCH /v1/widgets/{}',
    'web GET /v1/admin/bans',
    'web GET /v1/bans',
    'operator-console GET /operator/v1/customers',
    'license-portal GET /portal/v1/plans',
    'seller-portal GET /seller/v1/me',
    'web PUT /v1/widgets/{}',
    'web GET /v1/gadgets/{}',
    'web GET /v1/things/count',
  ]) assert.ok(calls.includes(want), want)
  // json(c ? 'PUT' : 'POST') 与 c ? 路径A : 路径B 同条件：按分支配对，不是 GET，也不交叉
  for (const bad of ['web GET /v1/widgets/{}', 'web POST /v1/widgets/{}', 'web PUT /v1/widgets']) assert.ok(!calls.includes(bad), bad)
})

test('表①：没有任何前端调用的业务路由入表；健康检查/安装实例/市场上游排除并写理由', () => {
  const t1 = keys(fixture.table1, 'table1')
  assert.ok(t1.includes('control-api DELETE /v1/widgets/{id}'))
  assert.ok(t1.includes('control-api GET /v1/gadgets'))
  assert.ok(!t1.includes('control-api GET /v1/gadgets/{id}'), '只经导出对象调用的 id 型函数声明也算调用')
  assert.ok(!t1.includes('control-api GET /v1/widgets'))
  assert.ok(!t1.includes('control-api * /v1/reports/'), '子树挂载被前端调用覆盖')
  const excluded = Object.fromEntries(fixture.excluded.map((e) => [e.key, e.class]))
  assert.equal(excluded['control-api GET /health/live'], 'health')
  assert.equal(excluded['license-service POST /activation/v1/activations'], 'installation')
  assert.equal(excluded['market-service GET /admin/v1/sellers'], 'market-upstream')
  // 代理 pending 行有前端调用 → 进表②（proxy_pending）而非表①
  assert.ok(!t1.includes('license-service GET /operator/v1/market/future'))
  for (const e of fixture.excluded) assert.ok(e.reason.length > 4)
})

test('表①附：市场上游 /admin/v1 无 forwarded 代理行即报缺口', () => {
  assert.deepEqual(fixture.proxyGaps.map((r) => r.path), ['/admin/v1/unproxied'])
})

test('表②：不存在的路由、方法不符、代理 pending、菜单无页面', () => {
  const t2 = keys(fixture.table2, 'table2')
  assert.ok(t2.includes('no_route web GET /v1/nope'))
  assert.ok(t2.includes('method_mismatch web PATCH /v1/widgets/{}'))
  assert.ok(t2.includes('proxy_pending operator-console GET /operator/v1/market/future'))
  assert.ok(t2.includes('menu_no_page web - /ghost-menu'))
  const nope = fixture.table2.find((r) => r.path === '/v1/nope')
  assert.equal(nope.referenced, 'apps/web/src/pages/WidgetsPage.tsx', '页面确实引用了这条调用')
})

test('表③：菜单按 gadgets.read 显示，但页面读写 widgets.* → 读 403 与写按钮未门控', () => {
  const t3 = keys(fixture.table3, 'table3')
  assert.ok(t3.includes('read_forbidden web /widgets GET /v1/widgets'))
  assert.ok(t3.includes('write_ungated web /widgets POST /v1/widgets'))
  // 运营端 /customers 的菜单与接口都是 licensing.customers.manage，一致
  assert.ok(!t3.some((k) => k.includes('/operator/v1/customers')))
})

test('表④：有 <Route> 无菜单/跳转/别名的页面是孤儿；登录等公共页不算', () => {
  assert.deepEqual(fixture.table4.map((r) => `${r.app} ${r.path}`), ['web /orphan'])
})

test('OpenAPI：契约里有、代码没提供的操作被列出，x-required-permissions 参与权限补全', () => {
  assert.deepEqual(fixture.openapiCheck.notServed.map((r) => `${r.method} ${r.path}`), ['GET /v1/ghost'])
})

test('路径匹配：{} 对任意段、子树前缀、插值拼接段', () => {
  assert.ok(pathMatches({ path: '/v1/a/{id}' }, '/v1/a/{}'))
  assert.ok(pathMatches({ path: '/v1/a/', mount: 'subtree' }, '/v1/a/{}/b'))
  assert.ok(pathMatches({ path: '/v1/a/{id}/approve' }, '/v1/a/{}{}'))
  assert.ok(!pathMatches({ path: '/v1/a/{id}' }, '/v1/b/{}'))
  assert.ok(pathMatches({ path: '/v1/a/', mount: 'subtree' }, '/v1/a/{}{}'), '插值拼接段落在子树挂载下')
  assert.ok(!pathMatches({ path: '/v1/b/', mount: 'subtree' }, '/v1/a/{}{}'))
})

test('仓库：当前缺口全部登记在 allowlist.json（带理由），且白名单没有已修复的过期条目', () => {
  const result = runAudit(repo)
  const { fresh, stale, invalid } = compare(result, loadAllowlist(join(here, 'allowlist.json')))
  const msg = []
  for (const [name, rows] of Object.entries(fresh)) for (const r of rows) msg.push(`新增缺口 ${name}: ${KEYS[name](r)}  ${r.evidence ?? ''}`)
  for (const [name, list] of Object.entries(stale)) for (const k of list) msg.push(`白名单过期 ${name}: ${k}`)
  msg.push(...invalid)
  assert.deepEqual(msg, [], `\n${msg.slice(0, 60).join('\n')}\n修复缺口，或在 tests/ui-route-coverage/allowlist.json 登记理由（node tests/ui-route-coverage/cli.mjs --check 看全量）`)
})
