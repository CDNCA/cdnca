import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import Ajv2020 from 'ajv/dist/2020.js'

const root = fileURLToPath(new URL('../', import.meta.url))
const temporaryDir = mkdtempSync(join(tmpdir(), 'cdnca-site-groups-contract-'))
let document
try {
  const output = join(temporaryDir, 'site-groups.json')
  execFileSync('pnpm', ['--package=@redocly/cli@1.34.5', 'dlx', 'redocly', 'bundle',
    join(root, 'api/control-site-groups.openapi.yaml'), '--output', output], { cwd: root, stdio: 'pipe' })
  document = JSON.parse(readFileSync(output, 'utf8'))
} finally {
  rmSync(temporaryDir, { recursive: true, force: true })
}
const schemas = document.components.schemas
const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false })
const group = {
  id: '11111111-1111-7111-8111-111111111111', scope_id: '22222222-2222-7222-8222-222222222222',
  name: 'contract fixture', revision: 1, created_at: '2026-10-10T00:00:00Z', updated_at: '2026-10-10T00:00:00Z',
}
function assertSiteGroupContract(name, value, expected) {
  assert.ok(schemas[name], `missing schema ${name}`)
  const validate = ajv.compile({ ...schemas[name], components: { schemas } })
  assert.equal(validate(value), expected, `${name}: ${JSON.stringify(validate.errors)}`)
}

test('platform global read retains both IAM permissions, explicit scope kind and ten-row default', () => {
  const operation = document.paths['/v1/admin/site-groups'].get
  assert.deepEqual(operation['x-required-permissions'], ['sites.read', 'identity.users.manage'])
  assert.equal(operation['x-required-scope-kind'], 'platform')
  assert.deepEqual(operation.parameters.map((parameter) => parameter.name), ['page', 'limit'])
  assert.deepEqual(operation.parameters[1].schema, { type: 'integer', minimum: 1, maximum: 100, default: 10 })
  assert.deepEqual(document.security, [{ bearerAuth: [] }, { cdncaKey: [] }])
  for (const status of ['400', '401', '403', '503']) assert.ok(operation.responses[status])
})

test('scoped writes preserve idempotency and revision headers instead of adding an admin bypass', () => {
  const collection = document.paths['/v1/site-groups']
  const resource = document.paths['/v1/site-groups/{id}']
  assert.deepEqual(collection.post['x-required-permissions'], ['sites.manage'])
  assert.deepEqual(resource.get['x-required-permissions'], ['sites.read'])
  assert.equal(document.components.parameters.ScopeID.required, true)
  for (const method of ['patch', 'delete']) {
    assert.deepEqual(resource[method]['x-required-permissions'], ['sites.manage'])
    assert.deepEqual(resource[method].parameters.map((parameter) => parameter.$ref), ['#/components/parameters/IfMatch', '#/components/parameters/IdempotencyKey'])
  }
  assert.equal(collection.post.responses['201'].headers.ETag.$ref, '#/components/headers/ETag')
  assert.equal(resource.get.responses['200'].content['application/json'].schema.$ref, '#/components/schemas/CurrentSiteGroup')
  assert.ok(resource.delete.responses['204'])
  assert.deepEqual(Object.keys(document.components.responses.Conflict), ['description'])
})

test('immutable legacy write receipts stay valid while current reads require real metadata', () => {
  assertSiteGroupContract('SiteGroup', group, true)
  assertSiteGroupContract('CurrentSiteGroup', group, false)
  assertSiteGroupContract('CurrentSiteGroup', { ...group, display_id: '1', remark: '' }, true)
  for (const display_id of ['0', '-1', '1.5', 1, null]) {
    assertSiteGroupContract('CurrentSiteGroup', { ...group, display_id, remark: '' }, false)
  }
})

test('global owner states never allow a fabricated or ambiguous user', () => {
  const item = { ...group, display_id: '1', remark: '', user_state: 'resolved', user: { id: group.id, display_id: '2', username: 'owner' } }
  assertSiteGroupContract('AdminSiteGroup', item, true)
  assertSiteGroupContract('AdminSiteGroup', { ...item, user: null }, false)
  for (const user_state of ['missing', 'ambiguous']) {
    assertSiteGroupContract('AdminSiteGroup', { ...item, user_state, user: null }, true)
    assertSiteGroupContract('AdminSiteGroup', { ...item, user_state }, false)
  }
  assertSiteGroupContract('AdminSiteGroup', { ...item, user_state: 'inferred' }, false)
  assertSiteGroupContract('AdminSiteGroupList', { items: [item], total: 1, page: 1, limit: 10 }, true)
  assertSiteGroupContract('AdminSiteGroupList', { items: [item], total: -1, page: 1, limit: 10 }, false)
})

test('optional remark preserves legacy omission and distinguishes explicit clearing from null', () => {
  for (const [name, request] of [
    ['CreateSiteGroupRequest', { target_scope_id: group.scope_id, name: group.name }],
    ['RenameSiteGroupRequest', { expected_revision: 1, name: group.name }],
  ]) {
    assertSiteGroupContract(name, request, true)
    for (const remark of ['', '第一行\n第二行\t备注', 'x'.repeat(1024)]) assertSiteGroupContract(name, { ...request, remark }, true)
    for (const remark of [null, 1, 'x'.repeat(1025), '\u0001', '\u007f', '\u0080']) assertSiteGroupContract(name, { ...request, remark }, false)
    assertSiteGroupContract(name, { ...request, display_id: '1' }, false)
  }
})
