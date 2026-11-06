import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// The control plugin library routes (PA-27) are registered in the control
// OpenAPI and match the handler: route, access, and the LibraryItem fields.
const apiDir = dirname(fileURLToPath(import.meta.url))
const root = resolve(apiDir, '..')
const aggregateSource = readFileSync(join(apiDir, 'openapi/v1/control.yaml'), 'utf8')
const buyerSource = readFileSync(join(root, 'services/control-api/internal/marketsubscribehttp/buyer.go'), 'utf8')
const memberSource = readFileSync(join(root, 'services/control-api/internal/marketsubscribehttp/member.go'), 'utf8')
const handlerSource = readFileSync(join(root, 'services/control-api/internal/marketsubscribehttp/handler.go'), 'utf8')
const temporaryDir = mkdtempSync(join(tmpdir(), 'cdnca-market-plugins-openapi-'))

try {
  const bundlePath = join(temporaryDir, 'market-plugins.json')
  execFileSync('pnpm', [
    '--package=@redocly/cli@1.34.5', 'dlx', 'redocly', 'bundle',
    join(apiDir, 'control-market-plugins.openapi.yaml'), '--output', bundlePath,
  ], { cwd: root, stdio: 'pipe' })
  const document = JSON.parse(readFileSync(bundlePath, 'utf8'))

  assert.match(buyerSource, /libraryPattern = "GET \/v1\/admin\/market\/plugin-library"/)
  assert.match(buyerSource, /h\.handle\(libraryPattern, accessBrowse,/)
  const library = document.paths['/v1/admin/market/plugin-library']
  assert.deepEqual(Object.keys(library), ['get'])
  assert.equal(library.get.operationId, 'getMarketPluginLibrary')
  assert.deepEqual(library.get['x-required-any-permission'], ['marketplace.browse', 'marketplace.purchase', 'marketplace.sell'])
  assert.equal(library.get.parameters, undefined)
  const goFields = [...buyerSource.match(/type LibraryItem struct \{([\s\S]*?)\n\}/)[1].matchAll(/json:"([a-z_]+)"/g)].map((m) => m[1])
  assert.deepEqual(document.components.schemas.LibraryItem.required, goFields)
  assert.deepEqual(Object.keys(document.components.schemas.LibraryItem.properties), goFields)

  assert.match(memberSource, /"POST \/v1\/admin\/market\/plugin-downloads": \{upstream: "\/v1\/plugin-downloads", access: accessPurchase\}/)
  const download = document.paths['/v1/admin/market/plugin-downloads']
  assert.deepEqual(Object.keys(download), ['post'])
  assert.equal(download.post.operationId, 'downloadMarketPlugin')
  assert.deepEqual(download.post['x-required-permissions'], ['marketplace.purchase'])
  // Not keyed in member.go: no Idempotency-Key parameter.
  assert.equal(download.post.parameters, undefined)
  assert.deepEqual(document.components.schemas.PluginDownloadInput.required, ['plugin_id'])
  for (const code of ['200', '400', '402', '403', '501', '502']) assert.ok(download.post.responses[code], `downloads ${code}`)
  assert.deepEqual(document.components.schemas.ControlError.required, ['error'])

  // local stop / enable, platform administrators with an Idempotency-Key.
  for (const [op, operationId] of [['disable', 'disableMarketPluginLocally'], ['enable', 'enableMarketPluginLocally']]) {
    assert.match(buyerSource, new RegExp(`${op}Pattern += "POST /v1/admin/market/plugin-library/\\{plugin_id\\}/${op}"`))
    assert.match(buyerSource, new RegExp(`h\\.handle\\(${op}Pattern, accessPluginSwitch,`))
    const route = document.paths[`/v1/admin/market/plugin-library/{plugin_id}/${op}`]
    assert.deepEqual(Object.keys(route), ['post'])
    assert.equal(route.post.operationId, operationId)
    assert.deepEqual(route.post['x-required-any-permission'], ['plugin_installations.platform.manage', 'platform.admin'])
    const resolve = (p) => (p.$ref ? document.components.parameters[p.$ref.split('/').pop()] : p)
    assert.deepEqual(route.post.parameters.map(resolve).map((p) => `${p.in}:${p.name}:${p.required}`), ['path:plugin_id:true', 'header:Idempotency-Key:true'])
    for (const code of ['200', '400', '403', '409']) assert.ok(route.post.responses[code], `${op} ${code}`)
    assert.ok(aggregateSource.includes(`../../control-market-plugins.openapi.yaml#/paths/~1v1~1admin~1market~1plugin-library~1{plugin_id}~1${op}'`))
  }
  const switchFields = [...handlerSource.match(/case accessPluginSwitch:\n\t\treturn ([^\n]+)/)[1].matchAll(/"([a-z_.]+)"/g)].map((m) => m[1])
  assert.deepEqual(switchFields.slice(1), ['plugin_installations.platform.manage', 'platform.admin'])
  // The stop takes the feature code only, and answers no reason.
  assert.deepEqual(document.components.schemas.LocalDisableInput.required, ['feature_code'])
  assert.deepEqual(Object.keys(document.components.schemas.LocalDisableInput.properties), ['feature_code'])
  assert.equal(document.components.schemas.LocalDisable.properties.reason, undefined)
  assert.ok(aggregateSource.includes("../../control-market-plugins.openapi.yaml#/paths/~1v1~1admin~1market~1plugin-library'"))
  assert.ok(aggregateSource.includes("../../control-market-plugins.openapi.yaml#/paths/~1v1~1admin~1market~1plugin-downloads'"))
} finally {
  rmSync(temporaryDir, { recursive: true, force: true })
}

console.log('control market plugin library OpenAPI contract: passed')
