import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

const apiDir = dirname(fileURLToPath(import.meta.url))
const root = resolve(apiDir, '..')
const fragmentPath = join(apiDir, 'control-system-configuration.openapi.yaml')
const temporaryDir = mkdtempSync(join(tmpdir(), 'cdnca-system-default-openapi-'))
const controlFreePattern = '^[^\\u0000-\\u001f\\u007f-\\u009f]*$'
const recommendedCipherSuites = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
const legacyTLS12CipherSuites = `${recommendedCipherSuites}:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA`

function expectValid(validate, value, label) {
  assert.equal(validate(value), true, `${label}: ${JSON.stringify(validate.errors)}`)
}

function expectInvalid(validate, value, label) {
  assert.equal(validate(value), false, `${label}: expected schema rejection`)
}

try {
  const bundlePath = join(temporaryDir, 'system-configuration.json')
  execFileSync('pnpm', [
    '--package=@redocly/cli@1.34.5', 'dlx', 'redocly', 'bundle',
    fragmentPath, '--output', bundlePath,
  ], { cwd: root, stdio: 'pipe' })

  const document = JSON.parse(readFileSync(bundlePath, 'utf8'))
  const schemas = document.components.schemas

  const ssl = schemas.DefaultSSL
  assert.equal(ssl.type, 'object')
  assert.equal(ssl.additionalProperties, false)
  assert.deepEqual(ssl.required, ['mode', 'protocols', 'cipher_suites', 'prefer_server_ciphers'])
  assert.deepEqual(ssl.properties.mode.enum, ['recommended', 'legacy_tls12', 'legacy_full'])
  assert.equal(ssl.properties.protocols.$ref, '#/components/schemas/TLSProtocols')
  assert.deepEqual(ssl.properties.cipher_suites, {
    type: 'string', maxLength: 4096, pattern: controlFreePattern,
  })
  assert.equal(ssl.properties.prefer_server_ciphers.type, 'boolean')
  assert.deepEqual(schemas.TLSProtocols, {
    type: 'array', minItems: 1, maxItems: 6, uniqueItems: true,
    items: { type: 'string', enum: ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] },
  })
  assert.equal(ssl.oneOf.length, 3)
  assert.deepEqual(ssl.oneOf.map((branch) => branch.properties.mode.const), [
    'recommended', 'legacy_tls12', 'legacy_full',
  ])
  assert.deepEqual(ssl.oneOf[0].properties.protocols.const, ['TLSv1.2', 'TLSv1.3'])
  assert.equal(ssl.oneOf[0].properties.cipher_suites.const, recommendedCipherSuites)
  assert.equal(ssl.oneOf[0].properties.prefer_server_ciphers.const, false)
  assert.deepEqual(ssl.oneOf[1].properties.protocols.const, ['TLSv1.2', 'TLSv1.3'])
  assert.equal(ssl.oneOf[1].properties.cipher_suites.const, legacyTLS12CipherSuites)
  assert.equal(ssl.oneOf[1].properties.prefer_server_ciphers.const, true)
  assert.deepEqual(ssl.oneOf[2].properties.protocols.const, ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'])
  assert.equal(ssl.oneOf[2].properties.cipher_suites.const, 'DEFAULT:@SECLEVEL=0')
  assert.equal(ssl.oneOf[2].properties.prefer_server_ciphers.const, true)

  const origin = schemas.DefaultWebsite.properties.origin
  assert.equal(origin.type, 'object')
  assert.equal(origin.additionalProperties, false)
  assert.deepEqual(origin.required, [
    'scheme', 'http_port', 'https_port', 'response_timeout_seconds', 'connect_timeout_seconds',
    'ssl_protocols', 'http_version', 'keepalive_enabled', 'post_body_limit_bytes',
  ])
  assert.deepEqual(Object.keys(origin.properties), origin.required)
  assert.deepEqual(origin.properties.scheme.enum, ['http', 'https', 'follow', 'follow_with_port'])
  assert.deepEqual(origin.properties.http_port, { type: 'integer', minimum: 1, maximum: 65535 })
  assert.deepEqual(origin.properties.https_port, { type: 'integer', minimum: 1, maximum: 65535 })
  assert.deepEqual(origin.properties.response_timeout_seconds, { type: 'integer', minimum: 1, maximum: 3600 })
  assert.deepEqual(origin.properties.connect_timeout_seconds, { type: 'integer', minimum: 1, maximum: 75 })
  assert.equal(origin.properties.ssl_protocols.$ref, '#/components/schemas/TLSProtocols')
  assert.deepEqual(origin.properties.http_version.enum, ['1.0', '1.1'])
  assert.equal(origin.properties.keepalive_enabled.type, 'boolean')
  assert.deepEqual(origin.properties.post_body_limit_bytes, {
    type: 'integer', format: 'int64', minimum: 1024, maximum: 10737418240,
  })

  const cacheRule = schemas.DefaultCacheRule
  assert.equal(cacheRule.type, 'object')
  assert.equal(cacheRule.additionalProperties, false)
  assert.deepEqual(cacheRule.required, [
    'id', 'match', 'content', 'ttl_seconds', 'ignore_query', 'force_cache', 'range', 'ignore_vary',
    'no_cache', 'enabled', 'position',
  ])
  assert.deepEqual(Object.keys(cacheRule.properties), cacheRule.required)
  assert.equal(cacheRule.properties.id.$ref, '#/components/schemas/ShortConfigurationID')
  assert.deepEqual(cacheRule.properties.match, {
    type: 'string', minLength: 1, maxLength: 64, pattern: controlFreePattern,
  })
  assert.deepEqual(cacheRule.properties.content, {
    type: ['string', 'null'], maxLength: 2048, pattern: controlFreePattern,
  })
  assert.deepEqual(cacheRule.properties.ttl_seconds, {
    type: 'integer', minimum: 0, maximum: 31536000,
  })
  assert.equal(cacheRule.properties.ignore_query.type, 'boolean')
  assert.equal(cacheRule.properties.force_cache.type, 'boolean')
  assert.equal(cacheRule.properties.range.type, 'boolean')
  assert.equal(cacheRule.properties.ignore_vary.type, 'boolean')
  assert.equal(cacheRule.properties.no_cache.type, 'array')
  assert.equal(cacheRule.properties.no_cache.maxItems, 100)
  assert.equal(
    cacheRule.properties.no_cache.items.$ref,
    '#/components/schemas/DefaultCacheNoCacheCondition',
  )
  assert.equal(cacheRule.properties.enabled.type, 'boolean')
  assert.deepEqual(cacheRule.properties.position, {
    type: 'integer', minimum: 0, maximum: 99,
  })

  const condition = schemas.DefaultCacheNoCacheCondition
  assert.equal(condition.type, 'object')
  assert.equal(condition.additionalProperties, false)
  assert.deepEqual(condition.required, ['variable', 'string'])
  assert.deepEqual(Object.keys(condition.properties), condition.required)
  assert.deepEqual(condition.properties.variable, {
    type: 'string', minLength: 1, maxLength: 256, pattern: controlFreePattern,
  })
  assert.deepEqual(condition.properties.string, {
    type: 'string', minLength: 1, maxLength: 2048, pattern: controlFreePattern,
  })

  const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false })
  const compile = (schema) => ajv.compile({
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    ...schema,
    components: { schemas },
  })
  const validateSSL = compile(ssl)
  const validateOrigin = compile(origin)
  const validateCacheRule = compile(cacheRule)
  const validateCondition = compile(condition)

  const recommendedSSL = {
    mode: 'recommended', protocols: ['TLSv1.2', 'TLSv1.3'],
    cipher_suites: recommendedCipherSuites, prefer_server_ciphers: false,
  }
  expectValid(validateSSL, recommendedSSL, 'recommended SSL preset')
  expectValid(validateSSL, {
    mode: 'legacy_tls12', protocols: ['TLSv1.2', 'TLSv1.3'],
    cipher_suites: legacyTLS12CipherSuites, prefer_server_ciphers: true,
  }, 'legacy TLS 1.2 SSL preset')
  expectValid(validateSSL, {
    mode: 'legacy_full', protocols: ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'],
    cipher_suites: 'DEFAULT:@SECLEVEL=0', prefer_server_ciphers: true,
  }, 'legacy full SSL preset')
  // ge-tls 9532d64cf：系统 SSL 去掉无法校验的 custom 模式（Go 侧 systemconfig/schema_test.go:346 同样拒绝）
  expectInvalid(validateSSL, {
    mode: 'custom', protocols: ['TLSv1.3'], cipher_suites: 'CUSTOM', prefer_server_ciphers: true,
  }, 'custom SSL settings')
  expectInvalid(validateSSL, { ...recommendedSSL, protocols: ['TLSv1.2'] }, 'preset protocol drift')
  expectInvalid(validateSSL, { ...recommendedSSL, cipher_suites: 'CUSTOM' }, 'preset cipher drift')
  expectInvalid(validateSSL, { ...recommendedSSL, prefer_server_ciphers: true }, 'preset preference drift')
  expectInvalid(validateSSL, {
    mode: 'custom', protocols: [], cipher_suites: 'CUSTOM', prefer_server_ciphers: true,
  }, 'custom SSL protocol minimum')
  expectInvalid(validateSSL, {
    mode: 'custom', protocols: ['TLSv1.3', 'TLSv1.3'], cipher_suites: 'CUSTOM', prefer_server_ciphers: true,
  }, 'custom SSL protocol uniqueness')
  expectInvalid(validateSSL, {
    mode: 'custom', protocols: ['TLSv1.4'], cipher_suites: 'CUSTOM', prefer_server_ciphers: true,
  }, 'custom SSL unknown protocol')
  expectInvalid(validateSSL, {
    mode: 'custom', protocols: ['TLSv1.3'], cipher_suites: 'C'.repeat(4097), prefer_server_ciphers: true,
  }, 'custom SSL cipher maximum')
  expectInvalid(validateSSL, {
    mode: 'custom', protocols: ['TLSv1.3'], cipher_suites: 'CUSTOM\u0085', prefer_server_ciphers: true,
  }, 'SSL control character')
  expectInvalid(validateSSL, { ...recommendedSSL, extra: true }, 'SSL additional property')
  expectInvalid(validateSSL, { ...recommendedSSL, mode: 'unknown' }, 'SSL mode enum')
  const { mode: _omittedSSLMode, ...sslWithoutMode } = recommendedSSL
  expectInvalid(validateSSL, sslWithoutMode, 'SSL required fields')

  const minimumOrigin = {
    scheme: 'http', http_port: 1, https_port: 1, response_timeout_seconds: 1,
    connect_timeout_seconds: 1, ssl_protocols: ['SSLv2'], http_version: '1.0',
    keepalive_enabled: false, post_body_limit_bytes: 1024,
  }
  const maximumOrigin = {
    scheme: 'follow_with_port', http_port: 65535, https_port: 65535,
    response_timeout_seconds: 3600, connect_timeout_seconds: 75,
    ssl_protocols: ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'], http_version: '1.1',
    keepalive_enabled: true, post_body_limit_bytes: 10737418240,
  }
  expectValid(validateOrigin, minimumOrigin, 'minimum origin boundaries')
  expectValid(validateOrigin, maximumOrigin, 'maximum origin boundaries')
  for (const [label, value] of [
    ['origin scheme', { ...minimumOrigin, scheme: 'ftp' }],
    ['origin HTTP port minimum', { ...minimumOrigin, http_port: 0 }],
    ['origin HTTPS port maximum', { ...minimumOrigin, https_port: 65536 }],
    ['origin response timeout', { ...minimumOrigin, response_timeout_seconds: 3601 }],
    ['origin connect timeout', { ...minimumOrigin, connect_timeout_seconds: 76 }],
    ['origin SSL unknown protocol', { ...minimumOrigin, ssl_protocols: ['TLSv1.4'] }],
    ['origin SSL duplicate protocol', { ...minimumOrigin, ssl_protocols: ['SSLv3', 'SSLv3'] }],
    ['origin HTTP version', { ...minimumOrigin, http_version: '2' }],
    ['origin keepalive type', { ...minimumOrigin, keepalive_enabled: 'true' }],
    ['origin body limit minimum', { ...minimumOrigin, post_body_limit_bytes: 1023 }],
    ['origin body limit maximum', { ...minimumOrigin, post_body_limit_bytes: 10737418241 }],
    ['origin required fields', (() => { const { scheme: _scheme, ...value } = minimumOrigin; return value })()],
    ['origin additional property', { ...minimumOrigin, extra: true }],
  ]) expectInvalid(validateOrigin, value, label)

  const cacheRuleValue = {
    id: 'cache001', match: 'suffix', content: 'css|js', ttl_seconds: 0,
    ignore_query: false, force_cache: false, range: false, ignore_vary: false,
    no_cache: [{ variable: '$http_cookie', string: 'wordpress_logged_in' }],
    enabled: true, position: 0,
  }
  expectValid(validateCacheRule, cacheRuleValue, 'cache rule minimum boundaries')
  expectValid(validateCacheRule, { ...cacheRuleValue, content: null }, 'nullable cache content')
  expectValid(validateCacheRule, {
    ...cacheRuleValue, match: 'm'.repeat(64), content: 'c'.repeat(2048),
    ttl_seconds: 31536000, no_cache: [], position: 99,
  }, 'cache rule maximum boundaries')
  for (const [label, value] of [
    ['cache ID reference', { ...cacheRuleValue, id: 'bad' }],
    ['cache match minimum', { ...cacheRuleValue, match: '' }],
    ['cache match maximum', { ...cacheRuleValue, match: 'm'.repeat(65) }],
    ['cache match control', { ...cacheRuleValue, match: 'suffix\n' }],
    ['cache content maximum', { ...cacheRuleValue, content: 'c'.repeat(2049) }],
    ['cache content control', { ...cacheRuleValue, content: 'css\u0085js' }],
    ['cache TTL minimum', { ...cacheRuleValue, ttl_seconds: -1 }],
    ['cache TTL maximum', { ...cacheRuleValue, ttl_seconds: 31536001 }],
    ['cache boolean type', { ...cacheRuleValue, ignore_vary: 'false' }],
    ['cache no-cache maximum', { ...cacheRuleValue, no_cache: Array(101).fill({ variable: 'v', string: 's' }) }],
    ['cache position minimum', { ...cacheRuleValue, position: -1 }],
    ['cache position maximum', { ...cacheRuleValue, position: 100 }],
    ['cache additional property', { ...cacheRuleValue, extra: true }],
  ]) expectInvalid(validateCacheRule, value, label)

  expectValid(validateCondition, { variable: 'v'.repeat(256), string: 's'.repeat(2048) }, 'no-cache boundaries')
  for (const [label, value] of [
    ['no-cache variable minimum', { variable: '', string: 's' }],
    ['no-cache variable maximum', { variable: 'v'.repeat(257), string: 's' }],
    ['no-cache variable control', { variable: 'v\n', string: 's' }],
    ['no-cache string minimum', { variable: 'v', string: '' }],
    ['no-cache string maximum', { variable: 'v', string: 's'.repeat(2049) }],
    ['no-cache string control', { variable: 'v', string: 's\u0085' }],
    ['no-cache required fields', { variable: 'v' }],
    ['no-cache additional property', { variable: 'v', string: 's', extra: true }],
  ]) expectInvalid(validateCondition, value, label)
} finally {
  rmSync(temporaryDir, { recursive: true, force: true })
}

console.log('system default OpenAPI contract: passed')
