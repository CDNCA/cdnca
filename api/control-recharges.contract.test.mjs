import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const apiDir = dirname(fileURLToPath(import.meta.url))
const root = resolve(apiDir, '..')
const temporaryDir = mkdtempSync(join(tmpdir(), 'cdnca-recharges-openapi-'))

try {
  const bundlePath = join(temporaryDir, 'recharges.json')
  execFileSync('pnpm', [
    '--package=@redocly/cli@1.34.5', 'dlx', 'redocly', 'bundle',
    join(apiDir, 'control-recharges.openapi.yaml'), '--output', bundlePath,
  ], { cwd: root, stdio: 'pipe' })
  const document = JSON.parse(readFileSync(bundlePath, 'utf8'))
  const displayID = document.components.schemas.PositiveDisplayID
  assert.deepEqual(displayID, {
    type: 'string',
    pattern: '^[1-9][0-9]{0,18}$',
    readOnly: true,
  })
  for (const schemaName of ['RechargeOrder', 'RechargeStatistic']) {
    const schema = document.components.schemas[schemaName]
    assert.ok(schema.required.includes('display_id'), `${schemaName}.display_id must be required`)
    assert.ok(schema.required.includes('user_display_id'), `${schemaName}.user_display_id must be required`)
    assert.equal(schema.properties.display_id.$ref, '#/components/schemas/PositiveDisplayID')
    assert.equal(schema.properties.user_display_id.$ref, '#/components/schemas/PositiveDisplayID')
  }
} finally {
  rmSync(temporaryDir, { recursive: true, force: true })
}

console.log('recharge OpenAPI short-ID contract: passed')
