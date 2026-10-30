import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const apiDir = dirname(fileURLToPath(import.meta.url))
const root = resolve(apiDir, '..')
const aggregatePath = join(apiDir, 'openapi/v1/control.yaml')
const aggregateSource = readFileSync(aggregatePath, 'utf8')
const temporaryDir = mkdtempSync(join(tmpdir(), 'cdnca-regions-openapi-'))

try {
  const bundlePath = join(temporaryDir, 'regions.json')
  execFileSync('pnpm', [
    '--package=@redocly/cli@1.34.5', 'dlx', 'redocly', 'bundle',
    join(apiDir, 'control-regions.openapi.yaml'), '--output', bundlePath,
  ], { cwd: root, stdio: 'pipe' })
  const document = JSON.parse(readFileSync(bundlePath, 'utf8'))
  const collection = document.paths['/v1/regions']
  assert.deepEqual(Object.keys(collection), ['get', 'post'])
  assert.equal(collection.get.operationId, 'listPlatformRegions')
  assert.deepEqual(collection.get['x-required-permissions'], ['regions.read'])
  assert.deepEqual(collection.get.parameters.map((parameter) => parameter.name), ['limit', 'page', 'page_size', 'search'])
  assert.equal(collection.get.parameters.some((parameter) => parameter.name.includes('tenant')), false)
  assert.equal(collection.post.operationId, 'createPlatformRegion')
  assert.deepEqual(collection.post['x-required-permissions'], ['regions.manage'])
  assert.equal(collection.post.parameters[0].$ref, '#/components/parameters/IdempotencyKey')
  assert.equal(document.components.parameters.IdempotencyKey.name, 'Idempotency-Key')
  assert.ok(collection.post.responses['201'] && collection.post.responses['409'] && collection.post.responses['503'])

  const item = document.paths['/v1/regions/{id}']
  assert.deepEqual(Object.keys(item), ['parameters', 'get', 'patch', 'put', 'delete'])
  assert.equal(item.parameters[0].$ref, '#/components/parameters/RegionID')
  assert.equal(document.components.parameters.RegionID.name, 'id')
  assert.equal(item.get.operationId, 'getPlatformRegion')
  assert.equal(item.patch.operationId, 'updatePlatformRegion')
  assert.equal(item.put.operationId, 'replacePlatformRegion')
  assert.equal(item.delete.operationId, 'deletePlatformRegion')
  for (const operation of [item.patch, item.put, item.delete]) {
    assert.deepEqual(operation['x-required-permissions'], ['regions.manage'])
    assert.deepEqual(operation.parameters.map((parameter) => parameter.$ref), [
      '#/components/parameters/IfMatch', '#/components/parameters/IdempotencyKey',
    ])
    assert.ok(operation.responses['412'] && operation.responses['428'])
  }

  assert.deepEqual(document.components.schemas.Region.required, [
    'id', 'name', 'code', 'country_code', 'province_code', 'description', 'l2_check_port', 'sort', 'revision', 'created_at', 'updated_at',
  ])
  assert.deepEqual(Object.keys(document.components.schemas.RegionInput.properties), [
    'name', 'country_code', 'province_code', 'description', 'l2_check_port', 'sort',
  ])
  assert.equal(document.components.schemas.PositiveDisplayID.pattern, '^[1-9][0-9]{0,18}$')
  assert.match(document.components.schemas.RegionList.properties.count.description, /before pagination or limit/i)
  assert.ok(aggregateSource.includes("../../control-regions.openapi.yaml#/paths/~1v1~1regions'"))
  assert.ok(aggregateSource.includes("../../control-regions.openapi.yaml#/paths/~1v1~1regions~1{id}'"))
} finally {
  rmSync(temporaryDir, { recursive: true, force: true })
}

console.log('platform region management OpenAPI contract: passed')
