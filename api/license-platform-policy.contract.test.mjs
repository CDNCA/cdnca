import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

const root = fileURLToPath(new URL('../', import.meta.url))
const document = JSON.parse(execFileSync('pnpm', [
  '--package=yaml@2.8.1', 'dlx', 'node',
  fileURLToPath(new URL('../tools/contract-doc-check/parse-yaml.cjs', import.meta.url)), '2.8.1',
], { cwd: root, input: readFileSync(new URL('./openapi/v1/license.yaml', import.meta.url)), encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }))
const schemas = document.components.schemas
const ajv = new Ajv2020({ allErrors: true, strict: false })
addFormats(ajv)
const validatePolicy = ajv.compile({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $ref: '#/components/schemas/PlatformPolicy', components: { schemas },
})

function assertPolicyContract(value, expected, label) {
  assert.equal(validatePolicy(value), expected, `${label}: ${JSON.stringify(validatePolicy.errors)}`)
}

const legacy = {
  schema: 'platform-policy/v1', minimum_control_version: '1.0.0', blocked_control_versions: [],
  allowed_release_channels: ['stable'], plugin_market: { enabled: false, trusted_catalog_ids: [] },
}
const ccRule = { id: '1', key: 'cc.system.00001', name: '验证', sort: 1, filter: { type: 'off', parameters: {} } }
const wafRule = {
  id: '00000000-0000-7000-8000-000000000101', name: '请求路径', priority: 1, enabled: true,
  conditions: [{ field: 'path', operator: 'prefix', values: ['/admin'] }], action: 'block', flow: 'stop',
}
const library = {
  id: '00000000-0000-7000-8000-000000000100', name: '规则库', description: '', revision: 1, enabled: true, rules: [wafRule],
}

test('legacy five-field policies remain valid and strict', () => {
  assert.deepEqual(schemas.PlatformPolicy.required, Object.keys(legacy))
  assertPolicyContract(legacy, true, 'legacy policy')
  assertPolicyContract({ ...legacy, extra: true }, false, 'unknown policy field')
  for (const key of Object.keys(legacy)) {
    const value = { ...legacy }
    delete value[key]
    assertPolicyContract(value, false, `missing legacy ${key}`)
  }
})

test('optional CC and WAF fields retain omitted, null and empty request semantics', () => {
  assertPolicyContract({ ...legacy, cc_protection: null, cc_system_rules: null, waf_rule_libraries: null }, true, 'null extensions')
  assertPolicyContract({ ...legacy, cc_system_rules: [], waf_rule_libraries: [] }, true, 'explicit empty extensions')
  assertPolicyContract({ ...legacy, cc_protection: { white_time: 600 }, cc_system_rules: [ccRule], waf_rule_libraries: [library] }, true, 'extended policy')
  for (const key of ['cc_system_rules', 'waf_rule_libraries']) {
    assertPolicyContract({ ...legacy, [key]: {} }, false, `${key} must be an array or null`)
    assertPolicyContract({ ...legacy, [key]: [null] }, false, `${key} rejects null entries`)
  }
})

test('CC protection documents zero defaults, nested strictness and byte limits', () => {
  assertPolicyContract({ ...legacy, cc_protection: {
    white_time: 600, cc_enable: null, block_time: null, tmp_white_total_limit: null,
    tmp_white_per_limit: null, default_page_rule: null, auto_switch: null, templates: null,
  } }, true, 'null zero-value fields')
  assertPolicyContract({ ...legacy, cc_protection: {
    white_time: 600, default_page_rule: 'x'.repeat(128),
    auto_switch: { enable: null, qps_50x: 0, qps_total: 0, rule: 'x'.repeat(128), seconds: 0 },
    templates: { slider_html: 'x'.repeat(8192), captcha_html: null },
  } }, true, 'CC protection scalar boundaries')
  assertPolicyContract({ ...legacy, cc_protection: { white_time: 9007199254740992 } }, true, 'Go int64 is not limited to JavaScript safe integers')
  for (const [label, value] of [
    ['missing white time', {}], ['white time null', { white_time: null }], ['white time minimum', { white_time: 599 }],
    ['negative block time', { white_time: 600, block_time: -1 }], ['fractional time', { white_time: 600.5 }],
    ['unknown field', { white_time: 600, extra: true }],
    ['unknown auto switch field', { white_time: 600, auto_switch: { extra: true } }],
    ['negative auto switch threshold', { white_time: 600, auto_switch: { qps_50x: -1 } }],
    ['unknown template', { white_time: 600, templates: { raw_html: '' } }],
    ['oversized template', { white_time: 600, templates: { slider_html: 'x'.repeat(8193) } }],
    ['oversized default rule', { white_time: 600, default_page_rule: 'x'.repeat(129) }],
  ]) assertPolicyContract({ ...legacy, cc_protection: value }, false, label)
  assert.equal(schemas.PlatformCCSystemRule.properties.name['x-max-utf8-bytes'], 128)
  assert.equal(schemas.PlatformCCTemplates.properties.slider_html['x-max-utf8-bytes'], 8192)
})

test('CC rules keep the actual filter and arbitrary legacy matcher contracts', () => {
  const types = ['off', 'relaxed', 'js', 'five_second', 'click', 'slider', 'captcha', 'rotate_image', 'simple_click', 'simple_slider']
  assert.deepEqual(schemas.PlatformCCSystemFilter.properties.type.enum, types)
  for (const type of types) assertPolicyContract({ ...legacy, cc_system_rules: [{ ...ccRule, filter: { type, parameters: { arbitrary: null } } }] }, true, type)
  for (const values of [undefined, null, [], [''], ['z', 'a', 'a'], [null]]) {
    assertPolicyContract({ ...legacy, cc_system_rules: [{ ...ccRule, filter: null,
      matcher: { field: 'legacy_field', operator: 'arbitrary operator', key: null, ...(values === undefined ? {} : { values }) },
    }] }, true, `legacy matcher values ${JSON.stringify(values)}`)
  }
  for (const [label, value] of [
    ['both alternatives', { ...ccRule, matcher: { field: 'x', operator: 'y' } }],
    ['neither alternative', { ...ccRule, filter: null }],
    ['missing parameters', { ...ccRule, filter: { type: 'off' } }],
    ['null parameters', { ...ccRule, filter: { type: 'off', parameters: null } }],
    ['array parameters', { ...ccRule, filter: { type: 'off', parameters: [] } }],
    ['unknown filter', { ...ccRule, filter: { type: 'unknown', parameters: {} } }],
    ['unknown nested field', { ...ccRule, filter: { type: 'off', parameters: {}, extra: true } }],
    ['missing matcher operator', { ...ccRule, filter: null, matcher: { field: 'x' } }],
    ['too many matcher values', { ...ccRule, filter: null, matcher: { field: 'x', operator: 'y', values: Array(101).fill('') } }],
    ['unknown rule field', { ...ccRule, extra: true }], ['sort minimum', { ...ccRule, sort: 0 }],
    ['sort maximum', { ...ccRule, sort: 10001 }], ['name maximum', { ...ccRule, name: 'x'.repeat(129) }],
    ['ID maximum', { ...ccRule, id: '1'.repeat(33) }], ['invalid key', { ...ccRule, key: 'UPPER' }],
  ]) assertPolicyContract({ ...legacy, cc_system_rules: [value] }, false, label)
  for (const key of ['id', 'key', 'name', 'sort']) {
    const value = { ...ccRule }
    delete value[key]
    assertPolicyContract({ ...legacy, cc_system_rules: [value] }, false, `missing CC ${key}`)
  }
  const rules = Array.from({ length: 32 }, (_, index) => ({ ...ccRule, key: `cc.system.${String(index).padStart(5, '0')}` }))
  assertPolicyContract({ ...legacy, cc_system_rules: rules }, true, '32 CC rules')
  assertPolicyContract({ ...legacy, cc_system_rules: [...rules, ccRule] }, false, '33 CC rules')
})

test('WAF libraries and rules use runtime limits rather than the old editor limits', () => {
  const libraries = Array.from({ length: 64 }, (_, index) => ({ ...library,
    id: `00000000-0000-7000-8000-${String(index + 1).padStart(12, '0')}`, name: `规则库${index}`,
  }))
  assertPolicyContract({ ...legacy, waf_rule_libraries: libraries }, true, '64 libraries')
  assertPolicyContract({ ...legacy, waf_rule_libraries: [...libraries, library] }, false, '65 libraries')
  const rules = Array.from({ length: 100 }, (_, index) => ({ ...wafRule,
    id: `00000000-0000-7000-8000-${String(index + 1).padStart(12, '0')}`, name: `规则${index}`,
  }))
  assertPolicyContract({ ...legacy, waf_rule_libraries: [{ ...library, name: '汉'.repeat(128), description: '字'.repeat(1000), revision: 9007199254740991, rules }] }, true, 'WAF Unicode and count boundaries')
  const { description: _description, enabled: _enabled, ...minimalLibrary } = library
  const { enabled: _ruleEnabled, ...minimalRule } = wafRule
  assertPolicyContract({ ...legacy, waf_rule_libraries: [{ ...minimalLibrary, rules: [minimalRule] }] }, true, 'WAF omitted zero-value fields')
  assertPolicyContract({ ...legacy, waf_rule_libraries: [{ ...library, description: null, enabled: null, rules: [{ ...wafRule, enabled: null }] }] }, true, 'WAF null zero-value fields')
  for (const [label, value] of [
    ['library name maximum', { ...library, name: 'x'.repeat(129) }], ['description maximum', { ...library, description: 'x'.repeat(1001) }],
    ['revision minimum', { ...library, revision: 0 }], ['revision maximum', { ...library, revision: 9007199254740992 }],
    ['nil library UUID', { ...library, id: '00000000-0000-0000-0000-000000000000' }], ['bad UUID', { ...library, id: 'bad' }],
    ['empty rules', { ...library, rules: [] }], ['101 rules', { ...library, rules: [...rules, wafRule] }],
    ['unknown library field', { ...library, extra: true }],
    ['rule priority minimum', { ...library, rules: [{ ...wafRule, priority: 0 }] }],
    ['rule priority maximum', { ...library, rules: [{ ...wafRule, priority: 1000001 }] }],
    ['rule name maximum', { ...library, rules: [{ ...wafRule, name: 'x'.repeat(129) }] }],
    ['unknown rule field', { ...library, rules: [{ ...wafRule, action_config: {} }] }],
    ['unsupported rule action', { ...library, rules: [{ ...wafRule, action: 'challenge' }] }],
    ['unsupported rule flow', { ...library, rules: [{ ...wafRule, flow: 'next' }] }],
  ]) assertPolicyContract({ ...legacy, waf_rule_libraries: [value] }, false, label)
  for (const [target, fields] of [[library, ['id', 'name', 'revision', 'rules']], [wafRule, ['id', 'name', 'priority', 'conditions', 'action', 'flow']]]) {
    for (const key of fields) {
      const value = { ...target }
      delete value[key]
      assertPolicyContract({ ...legacy, waf_rule_libraries: [target === library ? value : { ...library, rules: [value] }] }, false, `missing WAF ${key}`)
    }
  }
})

test('WAF condition field/operator/key/value combinations match Go', () => {
  for (const condition of [
    { field: 'client_ip', operator: 'ip_in_cidr', values: ['192.0.2.0/24'] },
    { field: 'header', operator: 'equals', key: 'x-check', values: ['yes'] },
    { field: 'method', operator: 'equals', key: null, values: ['GET', 'POST'] },
    { field: 'path', operator: 'equals', key: '', values: ['/path'] },
    { field: 'path', operator: 'prefix', values: ['/path'] },
    { field: 'port', operator: 'number_eq', values: ['65535'] },
  ]) assertPolicyContract({ ...legacy, waf_rule_libraries: [{ ...library, rules: [{ ...wafRule, conditions: [condition] }] }] }, true, condition.field)
  for (const [label, conditions] of [
    ['empty conditions', []], ['five conditions', Array(5).fill(wafRule.conditions[0])],
    ['unsupported regex', [{ field: 'path', operator: 'regex', values: ['x'] }]],
    ['missing header key', [{ field: 'header', operator: 'equals', values: ['x'] }]],
    ['uppercase header', [{ field: 'header', operator: 'equals', key: 'X-Check', values: ['x'] }]],
    ['non-header key', [{ field: 'path', operator: 'prefix', key: 'x', values: ['/'] }]],
    ['unknown condition field', [{ ...wafRule.conditions[0], extra: true }]],
    ['empty values', [{ ...wafRule.conditions[0], values: [] }]],
    ['65 values', [{ ...wafRule.conditions[0], values: Array(65).fill('x') }]],
    ['null value', [{ ...wafRule.conditions[0], values: [null] }]],
    ['oversized value', [{ ...wafRule.conditions[0], values: ['x'.repeat(257)] }]],
    ['lowercase method', [{ field: 'method', operator: 'equals', values: ['get'] }]],
    ['long method', [{ field: 'method', operator: 'equals', values: ['A'.repeat(17)] }]],
    ['multiple ports', [{ field: 'port', operator: 'number_eq', values: ['80', '443'] }]],
    ['port leading zero', [{ field: 'port', operator: 'number_eq', values: ['080'] }]],
    ['port zero', [{ field: 'port', operator: 'number_eq', values: ['0'] }]],
    ['port overflow', [{ field: 'port', operator: 'number_eq', values: ['65536'] }]],
  ]) assertPolicyContract({ ...legacy, waf_rule_libraries: [{ ...library, rules: [{ ...wafRule, conditions }] }] }, false, label)
})

test('canonical and publication differences are explicitly documented, not fake schema guarantees', () => {
  assert.equal(schemas.PlatformPolicy['x-max-canonical-utf8-bytes'], 65536)
  assert.match(schemas.PlatformPolicy.description, /preflight does not/i)
  assert.match(schemas.PlatformPolicy.description, /ordinary publish.*10/s)
  assert.match(schemas.PlatformPolicy.description, /rollback.*stored canonical/is)
  assert.match(schemas.PlatformPolicy.description, /explicit.*\[\]/i)
  assert.match(schemas.PlatformPolicy.description, /x-.*not.*JSON Schema/s)
  assert.deepEqual(schemas.PlatformPolicy.properties.cc_system_rules['x-order-by'], ['key'])
  assert.deepEqual(schemas.PlatformPolicy.properties.waf_rule_libraries['x-unique-by'], ['id', 'name'])
  assert.deepEqual(schemas.PlatformPolicyWAFRuleLibrary.properties.rules['x-order-by'], ['priority', 'id'])
  assert.deepEqual(schemas.PlatformPolicyWAFRule.properties.conditions['x-order-by'], ['field'])
  assert.match(schemas.PlatformPolicyWAFRuleCondition.description, /masked.*canonical.*CIDR/s)
  assert.match(schemas.PlatformCCSystemMatcher.description, /not.*whitelist/s)
  assert.match(schemas.PlatformCCProtection.description, /9223372036854775807/)
  assert.match(schemas.PlatformCCProtection.description, /JavaScript clients may reject/s)
})

test('public schema fields and limits remain bound to the current Go model', () => {
  const source = readFileSync(new URL('../services/license-service/internal/licensing/platform_policy.go', import.meta.url), 'utf8')
  for (const [schemaName, goName] of [
    ['PlatformPolicy', 'PlatformPolicy'], ['PlatformCCProtection', 'PlatformCCProtection'],
    ['PlatformCCAutoSwitch', 'PlatformCCAutoSwitch'], ['PlatformCCTemplates', 'PlatformCCTemplates'],
    ['PlatformCCSystemRule', 'CCSystemRule'], ['PlatformCCSystemMatcher', 'CCSystemMatcher'], ['PlatformCCSystemFilter', 'CCSystemFilter'],
    ['PlatformPolicyWAFRuleLibrary', 'PlatformPolicyWAFRuleLibrary'], ['PlatformPolicyWAFRule', 'PlatformPolicyWAFRule'], ['PlatformPolicyWAFRuleCondition', 'PlatformPolicyWAFRuleCondition'],
  ]) {
    const body = source.match(new RegExp(`type ${goName} struct \\{([\\s\\S]*?)\\n\\}`))?.[1]
    assert.ok(body, `missing Go model ${goName}`)
    const fields = [...body.matchAll(/json:"([^",]+)/g)].map((match) => match[1]).sort()
    assert.deepEqual(Object.keys(schemas[schemaName]?.properties ?? {}).sort(), fields, `${schemaName} field drift`)
  }
  assert.match(source, /maxWAFRuleLibraries\s*= 64/)
  assert.match(source, /maxWAFRulesPerLibrary\s*= 100/)
  assert.match(source, /if candidate\.CCSystemRules == nil \{\s*candidate\.CCSystemRules = DefaultCCSystemRules\(\)/)
  assert.match(source, /utf8\.RuneCountInString\(value\)/)
})

test('contract CI installs frozen root dependencies and runs policy checks after index drift', () => {
  const source = readFileSync(new URL('../scripts/ci-check.sh', import.meta.url), 'utf8')
  const body = source.match(/^check_contracts\(\) \{\n([\s\S]*?)^\}/m)?.[1]
  assert.ok(body, 'missing contracts gate')
  const driftAt = body.indexOf('node tools/contract-doc-check/openapi-index.mjs --check')
  const installAt = body.indexOf('pnpm --filter cdnca install --frozen-lockfile --ignore-scripts')
  const testAt = body.indexOf('node --test api/license-platform-policy.contract.test.mjs')
  assert.ok(driftAt >= 0 && installAt > driftAt && testAt > installAt, 'policy gate must run with locked root dependencies after index drift')
  assert.ok(body.indexOf('  check_proto') > testAt, 'policy failures must stop subsequent contracts gates')
})
