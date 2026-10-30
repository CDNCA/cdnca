import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const spec = readFileSync(new URL('./control-observability-logs.openapi.yaml', import.meta.url), 'utf8')
for (const path of ['/v1/observability/logs:', '/v1/observability/logs/export:', '/v1/observability/frontend-events:']) assert.ok(spec.includes(path), `missing ${path}`)
for (const field of ['reason_code:', 'result_code:', 'geo_code:', 'next_cursor:', 'snapshot_at:']) assert.ok(spec.includes(field), `missing ${field}`)
for (const forbidden of ['password:', 'body:', 'subject:', 'stack:', 'payload:']) assert.ok(!spec.includes(forbidden), `sensitive schema ${forbidden}`)
assert.match(spec, /Limit: \{name: limit, in: query, schema: \{type: integer, minimum: 1, maximum: 300, default: 50\}\}/)
assert.match(spec, /items: \{type: array, maxItems: 300, items: \{\$ref: '#\/components\/schemas\/LogFact'\}\}/)
