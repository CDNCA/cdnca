import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { lstat, mkdtemp, mkdir, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test, { after, afterEach } from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { promisify } from 'node:util'

import {
  AuditConfigurationError,
  auditRepository,
  writeReports,
} from '../../tools/i18n-audit/audit.mjs'

const execFileAsync = promisify(execFile)
const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const cli = path.join(workspace, 'tools/i18n-audit/cli.mjs')
const compilerDirectory = path.join(workspace, 'apps/web/node_modules/typescript')
const compilerModule = await import(pathToFileURL(path.join(compilerDirectory, 'lib/typescript.js')).href)
const typescript = compilerModule.default ?? compilerModule
const systemTemporaryDirectory = await realpath(tmpdir())
const fixtureParent = await mkdtemp(path.join(systemTemporaryDirectory, 'cdnca-i18n-test-run.'))
const unrelatedFixture = await mkdtemp(path.join(systemTemporaryDirectory, 'cdnca-i18n-fixture.unrelated.'))
const fixturePaths = new Set()

afterEach(async () => {
  for (const item of [...fixturePaths].sort((left, right) => right.length - left.length)) {
    const insideParent = item.startsWith(`${fixtureParent}${path.sep}`)
    const fallback = path.basename(item).startsWith('cdnca-i18n-audit-config-error.')
      && await realpath(path.dirname(item)) === systemTemporaryDirectory
    assert.ok(insideParent || fallback)
    await rm(item, { recursive: true, force: true })
  }
  fixturePaths.clear()
  assert.deepEqual(await readdir(fixtureParent), [])
  assert.ok((await lstat(unrelatedFixture)).isDirectory())
})

after(async () => {
  try {
    assert.deepEqual(await readdir(fixtureParent), [])
    assert.ok((await lstat(unrelatedFixture)).isDirectory())
  } finally {
    await rm(unrelatedFixture, { recursive: true, force: true })
    await rm(fixtureParent, { recursive: true, force: true })
  }
})

function baseConfig() {
  return {
    version: 1,
    maxFileBytes: 1024 * 1024,
    typescriptCompiler: 'node_modules/typescript/lib/typescript.js',
    apps: [{
      name: 'fixture',
      sourceRoots: ['src'],
      resourceFile: 'src/i18n.ts',
      defaultVariable: 'zhCN',
      secondaryVariable: 'enUS',
      defaultNamespace: 'common',
      namespaceFromTopLevel: true,
      pseudo: {
        sourceVariable: 'zhCN', transformFunction: 'inflate', transformKind: 'suffix-repeat-expansion',
        outputVariable: 'pseudoCN', minimumExpansionRatio: 1.2,
      },
      formatterEntrypoints: ['src/format.ts'],
    }],
    dynamicKeys: [],
    allowlist: [],
  }
}

function suffixResources(zhCN, enUS) {
  return `
export const zhCN = ${zhCN}
export const enUS = ${enUS}
function inflate(value: unknown): unknown {
  if (typeof value === 'string') return \`［\${value}\${'扩'.repeat(Math.max(2, Math.ceil(value.length / 3)))}］\`
  if (Array.isArray(value)) return value.map(inflate)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, inflate(item)]))
  return value
}
export const pseudoCN = inflate(zhCN)
`
}

const completeResources = suffixResources(
  "{ common: { hello: '你好' } }",
  "{ common: { hello: 'Hello' } }",
)

const characterResources = `
type TranslationTree = { [key: string]: string | TranslationTree }
export const zhCN = { common: { hello: '你好', traffic: '流量 {{count}} GB' } }
export const enUS = { common: { hello: 'Hello', traffic: 'Traffic {{count}} GB' } }
function pseudoText(value: string): string {
  const expanded = value
    .split(/({{[^}]+}})/g)
    .map((part) =>
      part.startsWith('{{') && part.endsWith('}}')
        ? part
        : [...part]
            .map((character) => (/\\s|\\d/.test(character) ? character : \`\${character}~\`))
            .join(''),
    )
    .join('')
  return \`［\${expanded}］\`
}
function pseudoTree(tree: TranslationTree): TranslationTree {
  return Object.fromEntries(
    Object.entries(tree).map(([key, value]) => [
      key,
      typeof value === 'string' ? pseudoText(value) : pseudoTree(value),
    ]),
  )
}
export const pseudoCN = pseudoTree(zhCN)
`

const completeSource = `
import { useTranslation } from 'react-i18next'
export function App() {
  const { t } = useTranslation('common')
  return <div>{t('hello')}</div>
}
`

async function fixture({ resources = completeResources, source = completeSource, configure, extraFiles = {} } = {}) {
  const root = await mkdtemp(path.join(fixtureParent, 'fixture.'))
  fixturePaths.add(root)
  await mkdir(path.join(root, 'src'), { recursive: true })
  await Promise.all([
    writeFile(path.join(root, 'src/i18n.ts'), resources),
    writeFile(path.join(root, 'src/App.tsx'), source),
  ])
  for (const [relative, contents] of Object.entries(extraFiles)) {
    await mkdir(path.dirname(path.join(root, relative)), { recursive: true })
    await writeFile(path.join(root, relative), contents)
  }
  const config = baseConfig()
  configure?.(config)
  const configPath = path.join(root, 'config.json')
  await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`)
  return { root, config, configPath }
}

async function audit(input, extra = {}) {
  return auditRepository({ ...input, today: '2030-01-01', typescript, ...extra })
}

function codes(report) {
  return new Set(report.findings.filter((item) => !item.suppressed).map((item) => item.code))
}

async function cliResult(argumentsList) {
  return execFileAsync(process.execPath, [cli, ...argumentsList])
    .then((result) => ({ code: 0, stdout: result.stdout }), (error) => ({ code: error.code, stdout: error.stdout ?? '' }))
}

test('accepts complete locale resources and a statically known key', async () => {
  const input = await fixture()
  const report = await audit(input)

  assert.equal(report.exitCode, 0, JSON.stringify(report.findings.filter((item) => item.severity === 'error')))
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.resources[0].zhCNKeys, 1)
  assert.equal(report.summary.resources[0].enUSKeys, 1)
  assert.equal(report.summary.resources[0].pseudoVerified, true)
  assert.equal(report.summary.resources[0].pseudoDerivedKeys, 1)
  assert.equal(report.summary.resources[0].staticallyUsedKeys, 1)
})

test('reports missing, extra, dynamic, visible, and raw-error findings', async () => {
  const input = await fixture({
    resources: suffixResources(
      "{ common: { hello: '你好', onlyZh: '仅中文', dynamic: { one: '一', two: '二' } } }",
      "{ common: { hello: 'Hello', extraEn: 'Extra' } }",
    ),
    source: `
import { message } from 'antd'
import { useTranslation } from 'react-i18next'
export function App({ error, item }: { error: Error, item: string }) {
  const { t } = useTranslation('common')
  message.error(error.message)
  return <><input placeholder="Search users" title="中文标题" />{t('hello')}{t(\`dynamic.\${item}\`)}</>
}
`,
  })
  const report = await audit(input)
  const found = codes(report)

  assert.equal(report.exitCode, 1)
  for (const code of ['KEY_MISSING_EN', 'KEY_EXTRA_EN', 'DYNAMIC_KEY_UNDECLARED', 'VISIBLE_LITERAL_EN', 'VISIBLE_LITERAL_ZH', 'RAW_ERROR_RENDER']) {
    assert.ok(found.has(code), `expected ${code}`)
  }
})

test('uses an exact reviewed enumeration for dynamic keys', async () => {
  const input = await fixture({
    resources: suffixResources(
      "{ common: { hello: '你好', dynamic: { one: '一', two: '二' } } }",
      "{ common: { hello: 'Hello', dynamic: { one: 'One', two: 'Two' } } }",
    ),
    source: `
import { useTranslation } from 'react-i18next'
export function App({ item }: { item: string }) {
  const { t } = useTranslation('common')
  return <>{t('hello')}{t(\`dynamic.\${item}\`)}</>
}
`,
    configure(config) {
      config.dynamicKeys.push({
        app: 'fixture', file: 'src/App.tsx', prefix: 'common.dynamic.',
        keys: ['common.dynamic.one', 'common.dynamic.two'],
        reason: 'Runtime state is a closed two-value protocol enum', owner: 'frontend-platform',
        contract: 'fixture DynamicState enum',
      })
    },
  })
  const report = await audit(input)

  assert.equal(report.exitCode, 0)
  assert.ok(!codes(report).has('DYNAMIC_KEY_UNDECLARED'))
  assert.equal(report.summary.resources[0].staticallyUsedKeys, 3)
})

test('verifies the application character transform, placeholders, and every leaf', async () => {
  const input = await fixture({
    resources: characterResources,
    source: completeSource.replace("{t('hello')}", "{t('hello')}{t('traffic', { count: 2 })}"),
    configure(config) {
      config.apps[0].pseudo = {
        sourceVariable: 'zhCN', transformFunction: 'pseudoTree', textTransformFunction: 'pseudoText',
        transformKind: 'placeholder-safe-character-expansion', outputVariable: 'pseudoCN', minimumExpansionRatio: 1.2,
      }
    },
  })
  const report = await audit(input)

  assert.equal(report.exitCode, 0, JSON.stringify(report.findings.filter((item) => item.severity === 'error')))
  assert.equal(report.summary.resources[0].pseudoVerified, true)
  assert.equal(report.summary.resources[0].pseudoDerivedKeys, 2)
  assert.ok(![...codes(report)].some((code) => code.startsWith('PSEUDO_')))
})

test('interprets expansion constants from the verified application transform', async () => {
  const input = await fixture({
    resources: completeResources.replace(
      'Math.max(2, Math.ceil(value.length / 3))',
      'Math.max(4, Math.ceil(value.length / 2))',
    ),
    configure(config) { config.apps[0].pseudo.minimumExpansionRatio = 3.5 },
  })
  const report = await audit(input)

  assert.equal(report.exitCode, 0, JSON.stringify(report.findings.filter((item) => item.severity === 'error')))
  assert.equal(report.summary.resources[0].pseudoVerified, true)
  assert.equal(report.summary.resources[0].pseudoDerivedKeys, 1)
})

test('rejects shadowed pseudo dependencies and ambiguous declarations', async () => {
  const variants = [
    `const Object = { entries: globalThis.Object.entries, fromEntries: globalThis.Object.fromEntries }\n${completeResources}`,
    `const Array = globalThis.Array\n${completeResources}`,
    `const Math = globalThis.Math\n${completeResources}`,
    `const { Object } = globalThis\n${completeResources}`,
    `namespace Math { export const max = globalThis.Math.max }\n${completeResources}`,
    `Object.fromEntries = (() => ({})) as typeof Object.fromEntries\n${completeResources}`,
    `Object['entries'] = (() => []) as typeof Object.entries\n${completeResources}`,
    `Array.isArray = (() => false) as typeof Array.isArray\n${completeResources}`,
    `Math.max = (() => 0) as typeof Math.max\n${completeResources}`,
    `Object.defineProperty(Object, 'fromEntries', { value: () => ({}) })\n${completeResources}`,
    `Reflect.set(Object, 'entries', () => [])\n${completeResources}`,
    `const BuiltinObject = Object\nBuiltinObject.fromEntries = () => ({})\n${completeResources}`,
    `globalThis['Object']['fromEntries'] = () => ({})\n${completeResources}`,
    `const root = globalThis\nroot['Object']['fromEntries'] = () => ({})\n${completeResources}`,
    `const root = globalThis\nReflect.set(root['Object'], 'fromEntries', () => ({}))\n${completeResources}`,
    `globalThis['Ob' + 'ject']['fromEntries'] = () => ({})\n${completeResources}`,
    `function poison() { const root = globalThis; root['Object']['fromEntries'] = () => ({}) }\npoison()\n${completeResources}`,
    `${completeResources}\nfunction inflate(value: unknown): unknown { return value }\n`,
    `${completeResources}\nconst { inflate } = { inflate: (value: unknown) => value }\n`,
    `${completeResources}\nexport const pseudoCN = zhCN\n`,
    completeResources.replace('export const pseudoCN = inflate(zhCN)', 'const apply = inflate\nexport const pseudoCN = apply(zhCN)'),
    completeResources.replaceAll('value', 'Object'),
    completeResources.replaceAll('value', 'Array'),
    completeResources.replaceAll('value', 'Math'),
    completeResources.replaceAll('value', 'inflate'),
  ]
  for (const resources of variants) {
    const input = await fixture({ resources })
    const report = await audit(input)
    assert.ok(codes(report).has('PSEUDO_TRANSFORM_UNVERIFIED'))
    assert.equal(report.summary.resources[0].pseudoVerified, false)
    assert.equal(report.summary.resources[0].pseudoDerivedKeys, 0)
  }
})

test('requires exactly one configured locale output call for the verified symbol', async () => {
  const output = "void i18n.init({ resources: { 'qps-ploc': { translation: inflate(zhCN) } } })"
  const resources = `import i18n from 'i18next'\n${completeResources.replace('export const pseudoCN = inflate(zhCN)', output)}`
  const configure = (config) => {
    delete config.apps[0].pseudo.outputVariable
    config.apps[0].pseudo.resourceLocale = 'qps-ploc'
    config.apps[0].pseudo.resourceNamespace = 'translation'
    config.apps[0].pseudo.initReceiver = 'i18n'
    config.apps[0].pseudo.initImportSource = 'i18next'
  }
  const valid = await fixture({ resources, configure })
  const validReport = await audit(valid)
  assert.equal(validReport.summary.resources[0].pseudoVerified, true)

  const trustedUse = await fixture({
    resources: `import i18n from 'i18next'\nimport { initReactI18next } from 'react-i18next'\n${completeResources.replace(
      'export const pseudoCN = inflate(zhCN)',
      "void i18n.use(initReactI18next).init({ resources: { 'qps-ploc': { translation: inflate(zhCN) } } })",
    )}`,
    configure,
  })
  const trustedUseReport = await audit(trustedUse)
  assert.equal(trustedUseReport.summary.resources[0].pseudoVerified, true)

  const duplicate = await fixture({ resources: `${resources}\n${output}\n`, configure })
  const duplicateReport = await audit(duplicate)
  assert.ok(codes(duplicateReport).has('PSEUDO_TRANSFORM_UNVERIFIED'))
  assert.equal(duplicateReport.summary.resources[0].pseudoDerivedKeys, 0)

  const competing = await fixture({
    resources: `${resources}\nfunction reinitialize() { ${output} }\nvoid reinitialize\n`,
    configure,
  })
  const competingReport = await audit(competing)
  assert.ok(codes(competingReport).has('PSEUDO_TRANSFORM_UNVERIFIED'))
  assert.equal(competingReport.summary.resources[0].pseudoDerivedKeys, 0)

  const decoy = await fixture({
    resources: `import i18n from 'i18next'\nconst decoy = { init(_options: unknown) {} }\n${completeResources.replace(
      'export const pseudoCN = inflate(zhCN)',
      "void i18n.init({ resources: { 'qps-ploc': { translation: zhCN } } })\nvoid decoy.init({ resources: { 'qps-ploc': { translation: inflate(zhCN) } } })",
    )}`,
    configure,
  })
  const decoyReport = await audit(decoy)
  assert.ok(codes(decoyReport).has('PSEUDO_TRANSFORM_UNVERIFIED'))
  assert.equal(decoyReport.summary.resources[0].pseudoDerivedKeys, 0)
})

test('rejects receiver aliases, mutation, spread overrides, and type-only receiver imports', async () => {
  const configure = (config) => {
    delete config.apps[0].pseudo.outputVariable
    Object.assign(config.apps[0].pseudo, {
      resourceLocale: 'qps-ploc', resourceNamespace: 'translation',
      initReceiver: 'i18n', initImportSource: 'i18next',
    })
  }
  const correct = "void i18n.init({ resources: { 'qps-ploc': { translation: inflate(zhCN) } } })"
  const base = completeResources.replace('export const pseudoCN = inflate(zhCN)', correct)
  const variants = [
    `import i18n from 'i18next'\nconst alias = i18n\n${base}\nvoid alias.init({ resources: { 'qps-ploc': { translation: zhCN } } })`,
    `import i18n from 'i18next'\ni18n.init = (() => undefined) as typeof i18n.init\n${base}`,
    `import i18n from 'i18next'\n${completeResources.replace(
      'export const pseudoCN = inflate(zhCN)',
      "void i18n.init({ resources: { 'qps-ploc': { translation: inflate(zhCN) } }, ...{ resources: { 'qps-ploc': { translation: zhCN } } } })",
    )}`,
    `import type i18n from 'i18next'\n${base}`,
    `import i18n from 'i18next'\n${completeResources.replace(
      'export const pseudoCN = inflate(zhCN)',
      "void i18n.cloneInstance().init({ resources: { 'qps-ploc': { translation: inflate(zhCN) } } })",
    )}`,
    `import i18n from 'i18next'\n${completeResources.replace(
      'export const pseudoCN = inflate(zhCN)',
      "void i18n.init({ resources: { 'qps-ploc': { translation: inflate(zhCN) } }, evil: (zhCN.common.hello = '原文') })",
    )}`,
    `import i18n from 'i18next'\n${completeResources.replace(
      'export const pseudoCN = inflate(zhCN)',
      "void i18n.init({ resources: { bad: { translation: (zhCN.common.hello = '原文') }, 'qps-ploc': { translation: inflate(zhCN) } } })",
    )}`,
    `import i18n, { default as alias } from 'i18next'\n${base}\nif (typeof document !== 'undefined') { void alias.init({ resources: { 'qps-ploc': { translation: zhCN } } }) }`,
    `import i18n from 'i18next'\n${base}\nif (typeof document !== 'undefined') { (eval)('void 0') }`,
    `import i18n from 'i18next'\n${base}\nif (typeof document !== 'undefined') { void import('./late-locale') }`,
    `import i18n from 'i18next'\n${base}\nif (typeof document !== 'undefined') { const holder: { value?: unknown } = {}; holder.value = i18n; (holder.value as any).options.resources['qps-ploc'].translation.common.hello = '原文' }`,
    `import i18n from 'i18next'\n${completeResources.replace(
      'export const pseudoCN = inflate(zhCN)',
      "void i18n.init({ resources: { 'qps-ploc': { translation: inflate(zhCN) } }, evil: (eval)('void 0') })",
    )}`,
  ]
  for (const resources of variants) {
    const input = await fixture({ resources, configure })
    const report = await audit(input)
    assert.ok(codes(report).has('PSEUDO_TRANSFORM_UNVERIFIED'))
    assert.equal(report.summary.resources[0].pseudoVerified, false)
    assert.equal(report.summary.resources[0].pseudoDerivedKeys, 0)
  }
})

test('rejects mutation or aliasing of pseudo source, transform, and output', async () => {
  const variants = [
    completeResources.replace('export const pseudoCN', 'inflate = ((value: unknown) => value) as typeof inflate\nexport const pseudoCN'),
    completeResources.replace('export const pseudoCN', "zhCN.common.hello = '原文'\nexport const pseudoCN"),
    completeResources.replace('export const pseudoCN', 'delete zhCN.common.hello\nexport const pseudoCN'),
    completeResources.replace("export const enUS = { common: { hello: 'Hello' } }", "export const enUS = (zhCN.common.hello = '原文', { common: { hello: 'Hello' } })"),
    `${completeResources}\npseudoCN.common.hello = '原文'\n`,
    `${completeResources}\nconst alias = pseudoCN\nalias.common.hello = '原文'\n`,
  ]
  for (const resources of variants) {
    const input = await fixture({ resources })
    const report = await audit(input)
    assert.ok(codes(report).has('PSEUDO_TRANSFORM_UNVERIFIED'))
    assert.equal(report.summary.resources[0].pseudoVerified, false)
    assert.equal(report.summary.resources[0].pseudoDerivedKeys, 0)
  }
})

test('rejects an identity application transform and reports zero proven leaves', async () => {
  const input = await fixture({
    resources: `
export const zhCN = { common: { hello: '你好' } }
export const enUS = { common: { hello: 'Hello' } }
function inflate(value: unknown) { return value }
export const pseudoCN = inflate(zhCN)
`,
  })
  const report = await audit(input)

  assert.ok(codes(report).has('PSEUDO_TRANSFORM_UNVERIFIED'))
  assert.equal(report.summary.resources[0].pseudoVerified, false)
  assert.equal(report.summary.resources[0].pseudoDerivedKeys, 0)
  assert.equal(report.exitCode, 1)
})

test('fails pseudo proof for non-literal resource leaves', async () => {
  const input = await fixture({
    resources: suffixResources(
      "{ common: { hello: getHello() } }",
      "{ common: { hello: 'Hello' } }",
    ),
  })
  const report = await audit(input)

  assert.ok(codes(report).has('RESOURCE_VALUE_NOT_LITERAL'))
  assert.ok(codes(report).has('PSEUDO_TRANSFORM_UNVERIFIED'))
  assert.equal(report.summary.resources[0].pseudoVerified, false)
  assert.equal(report.summary.resources[0].pseudoDerivedKeys, 0)
})

test('rejects prototype-sensitive resource paths and locale placeholder drift', async () => {
  const input = await fixture({
    resources: suffixResources(
      "{ common: { __proto__: '坏', constructor: '坏', nested: { prototype: '坏' }, hello: '你好 {{name}} {{name}}' } }",
      "{ common: { __proto__: 'Bad', constructor: 'Bad', nested: { prototype: 'Bad' }, hello: 'Hello {{name}} {{user}}' } }",
    ),
  })
  const report = await audit(input)

  assert.equal(report.findings.filter((item) => item.code === 'RESOURCE_KEY_FORBIDDEN').length, 6)
  assert.ok(codes(report).has('PLACEHOLDER_LOCALE_MISMATCH'))
  assert.equal(report.exitCode, 1)
})

test('requires locale-aware formatter entrypoints and rejects raw rendered errors', async () => {
  const input = await fixture({
    source: `
import { useTranslation } from 'react-i18next'
export function App({ locale, error }: { locale: string, error: Error }) {
  const { t } = useTranslation('common')
  new Intl.NumberFormat()
  new Intl.DateTimeFormat('en-US', { timeZone: 'UTC' })
  new Intl.NumberFormat(locale, { style: 'currency', currency: 'USD' })
  new Date().toLocaleString()
  const rounded = 1.5.toFixed(1)
  void rounded
  return <div title={error.message}>{t('hello')}</div>
}
`,
  })
  const report = await audit(input)
  const found = codes(report)

  for (const code of ['LOCALE_IMPLICIT_FORMATTER', 'LOCALE_FORMATTER_OUTSIDE_ENTRYPOINT', 'HARDCODED_LOCALE', 'HARDCODED_TIMEZONE', 'HARDCODED_CURRENCY', 'NUMBER_FORMATTER_BYPASS', 'RAW_ERROR_RENDER']) {
    assert.ok(found.has(code), `expected ${code}`)
  }
})

test('fails closed for aliased hooks, dynamic Trans, raw response messages, JSX strings, and Intl calls', async () => {
  const input = await fixture({
    resources: suffixResources(
      "{ common: { hello: '你好', other: '其他' } }",
      "{ common: { hello: 'Hello', other: 'Other' } }",
    ),
    source: `
import { message } from 'antd'
import { Trans as LocalTrans, useTranslation as useI18n } from 'react-i18next'
import * as ReactI18next from 'react-i18next'
export function App({ err, keyName, locale, otherKey, response }) {
  const { t: translate } = useI18n('common')
  const { t: translateOther } = ReactI18next.useTranslation('common')
  message.error(response.data.message)
  message.error(err.message)
  message.error(response.data['message'])
  return <div>
    {'Visible English'}
    {translate('hello')}
    {translateOther('other')}
    <LocalTrans i18nKey={keyName} />
    <ReactI18next.Trans i18nKey={otherKey} />
    {response?.data?.['message']}
    {Intl.NumberFormat(locale).format(1234)}
  </div>
}
`,
  })
  const report = await audit(input)

  assert.equal(report.summary.resources[0].staticallyUsedKeys, 2)
  assert.equal(report.findings.filter((item) => item.code === 'DYNAMIC_KEY_UNDECLARED').length, 2)
  assert.equal(report.findings.filter((item) => item.code === 'RAW_ERROR_RENDER').length, 4)
  assert.ok(codes(report).has('VISIBLE_LITERAL_EN'))
  assert.ok(codes(report).has('LOCALE_FORMATTER_OUTSIDE_ENTRYPOINT'))
})

test('allowlist entries are exact, reviewed, and expire closed', async () => {
  const active = await fixture({
    source: completeSource.replace('<div>', '<div title="UUID">'),
    configure(config) {
      config.allowlist.push({
        code: 'VISIBLE_LITERAL_EN', app: 'fixture', file: 'src/App.tsx', evidence: 'UUID',
        reason: 'Protocol field name is intentionally stable', owner: 'frontend-platform',
        contract: 'RFC 9562 UUID terminology',
      })
    },
  })
  const activeReport = await audit(active)
  assert.equal(activeReport.exitCode, 0)
  assert.equal(activeReport.summary.suppressedCount, 1)

  const expired = await fixture({
    source: completeSource.replace('<div>', '<div title="UUID">'),
    configure(config) {
      config.allowlist.push({
        code: 'VISIBLE_LITERAL_EN', app: 'fixture', file: 'src/App.tsx', evidence: 'UUID',
        reason: 'Temporary migration exception', owner: 'frontend-platform', expires: '2029-12-31',
      })
    },
  })
  const expiredReport = await audit(expired)
  assert.equal(expiredReport.exitCode, 1)
  assert.ok(codes(expiredReport).has('ALLOWLIST_EXPIRED'))
  assert.ok(expiredReport.findings.some((item) => item.code === 'VISIBLE_LITERAL_EN' && !item.suppressed))
})

test('allowlist entries fail configuration unless they match exactly one finding', async () => {
  const configure = (config) => config.allowlist.push({
    code: 'VISIBLE_LITERAL_EN', app: 'fixture', file: 'src/App.tsx', evidence: 'UUID',
    reason: 'Exact match fixture', owner: 'frontend-platform', contract: 'RFC 9562 UUID terminology',
  })
  const duplicate = await fixture({
    source: `
import { useTranslation } from 'react-i18next'
export function App() {
  const { t } = useTranslation('common')
  return <><span title="UUID">{t('hello')}</span><span title="UUID" /></>
}
`,
    configure,
  })
  await assert.rejects(
    () => audit(duplicate),
    (error) => error instanceof AuditConfigurationError && /matched 2/.test(error.message),
  )

  const missing = await fixture({ configure })
  await assert.rejects(
    () => audit(missing),
    (error) => error instanceof AuditConfigurationError && /matched 0/.test(error.message),
  )
})

test('validates allowlist dates with strict calendar and leap-year rules', async () => {
  const configureExpiry = (expires) => (config) => {
    config.allowlist.push({
      code: 'VISIBLE_LITERAL_EN', app: 'fixture', file: 'src/App.tsx', evidence: 'UUID',
      reason: 'Calendar validation fixture', owner: 'frontend-platform', expires,
    })
  }
  const source = completeSource.replace('<div>', '<div title="UUID">')

  for (const value of ['2032-02-29', '2000-02-29', '2030-04-30']) {
    const input = await fixture({ source, configure: configureExpiry(value) })
    await audit(input)
  }
  for (const value of ['2030-02-29', '2030-02-31', '2100-02-29', '2030-04-31', '0000-01-01']) {
    const input = await fixture({ source, configure: configureExpiry(value) })
    await assert.rejects(
      () => audit(input),
      (error) => error instanceof AuditConfigurationError && /expires must be YYYY-MM-DD/.test(error.message),
    )
  }

  const boundary = await fixture({ source, configure: configureExpiry('2030-01-01') })
  const boundaryReport = await audit(boundary)
  assert.equal(boundaryReport.summary.suppressedCount, 1)
  const expiredReport = await audit(boundary, { today: '2030-01-02' })
  assert.ok(codes(expiredReport).has('ALLOWLIST_EXPIRED'))
})

test('rejects invalid audit clock dates without prefix or suffix tolerance', async () => {
  const input = await fixture()
  for (const today of ['0000-00-00', '0000-00-00junk', '2030-02-31', '2030-01-01junk']) {
    await assert.rejects(
      () => audit(input, { today }),
      (error) => error instanceof AuditConfigurationError && /today must be a valid YYYY-MM-DD/.test(error.message),
    )
  }
})

test('does not allow lifecycle or configuration findings to be suppressed', async () => {
  for (const code of ['ALLOWLIST_EXPIRED', 'CONFIGURATION_ERROR', 'SOURCE_PARSE_ERROR']) {
    const input = await fixture({
      configure(config) {
        config.allowlist.push({
          code, app: 'fixture', file: 'src/App.tsx', evidence: 'exact lifecycle evidence',
          reason: 'Adversarial suppression attempt', owner: 'audit-reviewer', contract: 'test-only contract',
        })
      },
    })
    await assert.rejects(
      () => audit(input),
      (error) => error instanceof AuditConfigurationError && /cannot suppress lifecycle or configuration findings/.test(error.message),
    )
  }
})

test('baseline mode keeps known findings visible and fails on a new fingerprint', async () => {
  const input = await fixture({ source: completeSource.replace('<div>', '<div title="Search users">') })
  const first = await audit(input)
  const output = path.join(input.root, 'baseline-output')
  await writeReports(first, output)

  const known = await audit(input, { baselinePath: path.join(output, 'report.json') })
  assert.equal(known.exitCode, 0)
  assert.equal(known.summary.violationCount, 1)
  assert.equal(known.summary.newViolationCount, 0)

  await writeFile(path.join(input.root, 'src/New.tsx'), 'export const New = () => <div title="Another visible string" />\n')
  const changed = await audit(input, { baselinePath: path.join(output, 'report.json') })
  assert.equal(changed.exitCode, 1)
  assert.equal(changed.summary.newViolationCount, 1)
})

test('enforces an independent hard size limit for baseline JSON', async () => {
  const input = await fixture({ configure(config) { config.maxFileBytes = 8 * 1024 * 1024 } })
  const oversizedBaseline = path.join(input.root, 'oversized-baseline.json')
  await writeFile(oversizedBaseline, ' '.repeat(4 * 1024 * 1024 + 1))
  await assert.rejects(
    () => audit(input, { baselinePath: oversizedBaseline }),
    (error) => error instanceof AuditConfigurationError && /baseline exceeds hard size limit/.test(error.message),
  )
})

test('rejects path traversal and oversized inputs as configuration errors', async () => {
  const traversal = await fixture({ configure(config) { config.apps[0].sourceRoots = ['../outside'] } })
  await assert.rejects(() => audit(traversal), (error) => error instanceof AuditConfigurationError && /escapes the repository/.test(error.message))

  const oversized = await fixture({
    configure(config) { config.maxFileBytes = 1024 },
    extraFiles: { 'src/large.ts': `export const payload = '${'x'.repeat(2048)}'\n` },
  })
  await assert.rejects(() => audit(oversized), (error) => error instanceof AuditConfigurationError && /exceeds maxFileBytes/.test(error.message))
})

test('rejects repository and source-root symlink segments before realpath', async () => {
  const sourceRoot = await fixture({ configure(config) { config.apps[0].sourceRoots = ['linked-source'] } })
  await mkdir(path.join(sourceRoot.root, 'real-source'))
  await symlink(path.join(sourceRoot.root, 'real-source'), path.join(sourceRoot.root, 'linked-source'), 'dir')
  await assert.rejects(
    () => audit(sourceRoot),
    (error) => error instanceof AuditConfigurationError && /sourceRoot contains a symbolic-link segment/.test(error.message),
  )

  const parent = await fixture({ configure(config) { config.apps[0].sourceRoots = ['linked-parent/nested'] } })
  await mkdir(path.join(parent.root, 'real-parent/nested'), { recursive: true })
  await symlink(path.join(parent.root, 'real-parent'), path.join(parent.root, 'linked-parent'), 'dir')
  await assert.rejects(
    () => audit(parent),
    (error) => error instanceof AuditConfigurationError && /sourceRoot contains a symbolic-link segment/.test(error.message),
  )

  const resource = await fixture({ configure(config) { config.apps[0].resourceFile = 'linked-resource/i18n.ts' } })
  const externalResource = path.join(fixtureParent, `external-resource.${path.basename(resource.root)}`)
  fixturePaths.add(externalResource)
  await mkdir(externalResource, { recursive: true })
  await writeFile(path.join(externalResource, 'i18n.ts'), completeResources)
  await symlink(externalResource, path.join(resource.root, 'linked-resource'), 'dir')
  await assert.rejects(
    () => audit(resource),
    (error) => error instanceof AuditConfigurationError && /resourceFile contains a symbolic-link segment/.test(error.message),
  )

  const repository = await fixture()
  const linkedRoot = path.join(fixtureParent, `root-link-${path.basename(repository.root)}`)
  await symlink(repository.root, linkedRoot, 'dir')
  fixturePaths.add(linkedRoot)
  await assert.rejects(
    () => auditRepository({ root: linkedRoot, configPath: path.join(linkedRoot, 'config.json'), today: '2030-01-01', typescript }),
    (error) => error instanceof AuditConfigurationError && /repository root contains a symbolic-link segment/.test(error.message),
  )
})

test('CLI exit codes distinguish violations, pass, and configuration errors', async () => {
  const input = await fixture({ source: completeSource.replace('<div>', '<div title="Search users">') })
  await mkdir(path.join(input.root, 'node_modules'), { recursive: true })
  await symlink(compilerDirectory, path.join(input.root, 'node_modules/typescript'), 'dir')
  const violationOutput = path.join(input.root, 'violation-output')

  const violation = await execFileAsync(process.execPath, [cli, '--root', input.root, '--config', input.configPath, '--output-dir', violationOutput])
    .then(() => ({ code: 0 }), (error) => ({ code: error.code }))
  assert.equal(violation.code, 1)

  const passOutput = path.join(input.root, 'pass-output')
  const pass = await execFileAsync(process.execPath, [
    cli, '--root', input.root, '--config', input.configPath, '--output-dir', passOutput,
    '--baseline', path.join(violationOutput, 'report.json'),
  ]).then(() => ({ code: 0 }), (error) => ({ code: error.code }))
  assert.equal(pass.code, 0)

  const badConfig = JSON.parse(await readFile(input.configPath, 'utf8'))
  badConfig.apps[0].resourceFile = '../outside.ts'
  const badConfigPath = path.join(input.root, 'bad-config.json')
  await writeFile(badConfigPath, JSON.stringify(badConfig))
  const errorOutput = path.join(input.root, 'error-output')
  const invalid = await execFileAsync(process.execPath, [cli, '--root', input.root, '--config', badConfigPath, '--output-dir', errorOutput])
    .then(() => ({ code: 0 }), (error) => ({ code: error.code }))
  assert.equal(invalid.code, 2)
  const errorReport = JSON.parse(await readFile(path.join(errorOutput, 'report.json'), 'utf8'))
  assert.equal(errorReport.status, 'configuration_error')
})

test('CLI validates --today strictly and converts report path failures to exit 2', async () => {
  const input = await fixture()
  await mkdir(path.join(input.root, 'node_modules'), { recursive: true })
  await symlink(compilerDirectory, path.join(input.root, 'node_modules/typescript'), 'dir')

  for (const [index, today] of ['0000-00-00', '0000-00-00junk', '2030-02-31', '2030-01-01junk'].entries()) {
    const output = path.join(input.root, `invalid-today-${index}`)
    const result = await cliResult([
      '--root', input.root, '--config', input.configPath, '--output-dir', output, '--today', today,
    ])
    assert.equal(result.code, 2)
    const report = JSON.parse(await readFile(path.join(output, 'report.json'), 'utf8'))
    assert.equal(report.status, 'configuration_error')
  }

  const outputFile = path.join(input.root, 'output-is-file')
  await writeFile(outputFile, 'not a directory')
  const fileResult = await cliResult(['--root', input.root, '--config', input.configPath, '--output-dir', outputFile])
  assert.equal(fileResult.code, 2)
  const fileFallback = fileResult.stdout.trim()
  fixturePaths.add(fileFallback)
  assert.equal(JSON.parse(await readFile(path.join(fileFallback, 'report.json'), 'utf8')).status, 'configuration_error')

  const blockedOutput = path.join(input.root, 'blocked-output')
  await mkdir(path.join(blockedOutput, 'report.json'), { recursive: true })
  const blockedResult = await cliResult(['--root', input.root, '--config', input.configPath, '--output-dir', blockedOutput])
  assert.equal(blockedResult.code, 2)
  const blockedFallback = blockedResult.stdout.trim()
  fixturePaths.add(blockedFallback)
  assert.equal(JSON.parse(await readFile(path.join(blockedFallback, 'report.json'), 'utf8')).status, 'configuration_error')
})
