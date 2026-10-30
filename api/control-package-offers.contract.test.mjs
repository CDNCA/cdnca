import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const source = await readFile(new URL('./openapi/v1/control.yaml', import.meta.url), 'utf8')

for (const operationId of [
  'publishPackageOffer',
  'withdrawPackageOffer',
  'listPublishedPackageOffers',
]) {
  assert.match(source, new RegExp(`operationId:\\s+${operationId}\\b`))
}

assert.match(source, /packages\.manage/)
assert.match(source, /package_subscriptions\.manage/)
