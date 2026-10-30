import assert from 'node:assert/strict'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import Ajv from 'ajv'
import addFormats from 'ajv-formats'

const repositoryRoot = new URL('../../../', import.meta.url)
const argumentsList = process.argv.slice(2)
let controlAPIVersion = ''
const positional = []

for (let index = 0; index < argumentsList.length; index += 1) {
  if (argumentsList[index] === '--control-api-version') {
    controlAPIVersion = argumentsList[index + 1] ?? ''
    index += 1
  } else {
    positional.push(argumentsList[index])
  }
}

assert.equal(positional.length, 2,
  'usage: node validate-plugin-manifest.mjs --control-api-version <semver> <plugin.json> <publisher-public-key.json>')
assert.notEqual(controlAPIVersion, '', '--control-api-version is required')

async function readJSON(url) {
  return JSON.parse(await readFile(url, 'utf8'))
}

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
}

function canonicalBase64url(value, length) {
  assert.match(value, /^[A-Za-z0-9_-]+$/)
  const decoded = Buffer.from(value, 'base64url')
  assert.equal(decoded.length, length)
  assert.equal(decoded.toString('base64url'), value)
  return decoded
}

function parseSemver(value) {
  const match = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$/.exec(value)
  assert.ok(match, `non-canonical SemVer: ${value}`)
  return { core: match.slice(1, 4).map(BigInt), prerelease: match[4]?.split('.') ?? [] }
}

function compareIdentifiers(left, right) {
  const leftNumeric = /^[0-9]+$/.test(left)
  const rightNumeric = /^[0-9]+$/.test(right)
  if (leftNumeric && rightNumeric) {
    const leftValue = BigInt(left)
    const rightValue = BigInt(right)
    return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0
  }
  if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1
  return left < right ? -1 : left > right ? 1 : 0
}

function compareSemver(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left.core[index] !== right.core[index]) return left.core[index] < right.core[index] ? -1 : 1
  }
  if (!left.prerelease.length || !right.prerelease.length) {
    return left.prerelease.length === right.prerelease.length ? 0 : left.prerelease.length ? -1 : 1
  }
  for (let index = 0; index < Math.max(left.prerelease.length, right.prerelease.length); index += 1) {
    if (left.prerelease[index] === undefined) return -1
    if (right.prerelease[index] === undefined) return 1
    const compared = compareIdentifiers(left.prerelease[index], right.prerelease[index])
    if (compared !== 0) return compared
  }
  return 0
}

function evaluateCompatibility(constraint, version) {
  assert.ok(constraint.length >= 1 && constraint.length <= 128, 'compatibility constraint length is invalid')
  const comparators = constraint.split(' ')
  assert.ok(comparators.length >= 1 && comparators.length <= 8 && comparators.join(' ') === constraint,
    'compatibility constraint must use one ASCII space between 1..8 comparators')
  const current = parseSemver(version)
  return comparators.every((comparator) => {
    const match = /^(=|>=|<=|>|<)(.+)$/.exec(comparator)
    assert.ok(match, `invalid compatibility comparator: ${comparator}`)
    const compared = compareSemver(current, parseSemver(match[2]))
    return match[1] === '=' ? compared === 0
      : match[1] === '>=' ? compared >= 0
        : match[1] === '<=' ? compared <= 0
          : match[1] === '>' ? compared > 0 : compared < 0
  })
}

const manifestURL = pathToFileURL(resolve(process.cwd(), positional[0]))
const publisherURL = pathToFileURL(resolve(process.cwd(), positional[1]))
const [schema, catalog, matrix, manifest, publisher] = await Promise.all([
  readJSON(new URL('api/schemas/marketplace/v1/plugin-manifest.schema.json', repositoryRoot)),
  readJSON(new URL('api/schemas/marketplace/v1/extension-catalog.json', repositoryRoot)),
  readJSON(new URL('docs/developer/examples/plugin-compatibility-v1.json', repositoryRoot)),
  readJSON(manifestURL),
  readJSON(publisherURL),
])

const ajv = new Ajv({ allErrors: true, strict: true })
addFormats(ajv)
assert.equal(ajv.validateSchema(schema), true, JSON.stringify(ajv.errors))
const validate = ajv.compile(schema)
assert.equal(validate(manifest), true, JSON.stringify(validate.errors))
assert.equal(matrix.schema, 'cdnca.plugin-compatibility-matrix/v1')
assert.ok(matrix.rows.some((row) => row.surface === 'control_api'))

const permissionByName = new Map(catalog.permissions.map((entry) => [entry.name, entry]))
const eventByType = new Map(catalog.events.map((entry) => [entry.type, entry]))
for (const permission of manifest.spec.permissions) assert.ok(permissionByName.has(permission), `unknown permission: ${permission}`)
for (const eventType of manifest.spec.subscriptions ?? []) assert.ok(eventByType.has(eventType), `unknown event: ${eventType}`)

const unsigned = structuredClone(manifest)
delete unsigned.integrity
const digest = createHash('sha256').update(canonicalize(unsigned), 'utf8').digest()
assert.equal(digest.toString('hex'), manifest.integrity.payload_sha256, 'manifest digest mismatch')
assert.equal(publisher.key_id, manifest.integrity.key_id, 'publisher key ID mismatch')
assert.equal(publisher.algorithm, 'Ed25519', 'unsupported publisher algorithm')
assert.equal(manifest.integrity.algorithm, 'Ed25519', 'unsupported manifest algorithm')
const publicKey = createPublicKey({
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), canonicalBase64url(publisher.public_key_base64url, 32)]),
  format: 'der',
  type: 'spki',
})
assert.equal(verify(null, Buffer.concat([Buffer.from('cdnca-plugin-manifest/v1\n'), digest]), publicKey,
  canonicalBase64url(manifest.integrity.signature, 64)), true, 'manifest signature mismatch')

const compatible = evaluateCompatibility(manifest.spec.compatibility.control_api, controlAPIVersion)
assert.equal(compatible, true,
  `control-api ${controlAPIVersion} is outside ${manifest.spec.compatibility.control_api}; preserve LKG and deny install/upgrade`)
const capabilitiesAvailable = manifest.spec.permissions.every((name) => permissionByName.get(name).status === 'available') &&
  (manifest.spec.subscriptions ?? []).every((type) => eventByType.get(type).status === 'available')

console.log(JSON.stringify({
  schema: manifest.api_version,
  manifest: `${manifest.metadata.id}@${manifest.metadata.version}`,
  digest: manifest.integrity.payload_sha256,
  signature_valid: true,
  control_api_version: controlAPIVersion,
  compatibility_constraint: manifest.spec.compatibility.control_api,
  compatible,
  capabilities_available: capabilitiesAvailable,
  installable: compatible && capabilitiesAvailable,
}, null, 2))
