import assert from 'node:assert/strict'
import { readFileSync, realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import test from 'node:test'

// Reuse the locked Web lint dependency; do not download a parser during tests.
const require = createRequire(realpathSync(new URL('../apps/web/node_modules/eslint/package.json', import.meta.url)))
const { load } = require('js-yaml')
const fragment = load(readFileSync(new URL('./openapi/v1/node-inventory-order.yaml', import.meta.url), 'utf8'))

test('additive node order retains the original UUID mode and strict descending mode', () => {
  const { parameters, schemas } = fragment.components
  assert.deepEqual(Object.keys(parameters), ['NodeInventoryOrder', 'NodeInventoryCursor'])
  assert.deepEqual(parameters.NodeInventoryOrder.schema, { type: 'string', enum: ['management_sort_desc'] })
  assert.equal(parameters.NodeInventoryOrder.required, false)
  assert.deepEqual(parameters.NodeInventoryCursor.schema.oneOf, [
    { type: 'string', format: 'uuid' }, { $ref: '#/components/schemas/NodeInventoryOrderCursor' },
  ])
  const response = schemas.NodeInventoryOrderedListResponse
  assert.equal(response.additionalProperties, false)
  assert.deepEqual(response.required, ['order', 'items'])
  assert.deepEqual(Object.keys(response.properties), ['order', 'items', 'next_cursor'])
  assert.deepEqual(response.properties.order.enum, ['management_sort_desc'])
  assert.equal(response.properties.items.maxItems, 300)
  assert.equal(response.properties.items.items.$ref, './control.yaml#/components/schemas/NodeInventory')
  assert.equal(schemas.NodeInventoryOrderCursor.maxLength, 2048)
  assert.ok(new RegExp(schemas.NodeInventoryOrderCursor.pattern).test('nso1.eyJ2ZXJzaW9uIjoxfQ'))
  assert.ok(!new RegExp(schemas.NodeInventoryOrderCursor.pattern).test('nso1.eyJ2ZXJzaW9uIjoxfQ=='))
  for (const fact of ['UUID-ascending', 'nodes.read', 'sort DESC', 'display_id DESC', '1..300']) assert.ok(parameters.NodeInventoryOrder.description.includes(fact), fact)
  for (const fact of ['not a snapshot', 'untrusted bookmarks', 'scope/filter/order']) assert.ok(parameters.NodeInventoryCursor.description.includes(fact), fact)
  for (const fact of ['9223372036854775807', 'no duplicate/unknown', 'not looked up again']) assert.ok(schemas.NodeInventoryOrderCursor.description.includes(fact), fact)
})
