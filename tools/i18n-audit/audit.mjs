import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, readdir, realpath, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const SKIP_DIRECTORIES = new Set(['.git', 'build', 'coverage', 'dist', 'fixtures', 'node_modules', 'test', 'tests', '__tests__'])
const VISIBLE_PROPERTIES = new Set([
  'aria-label', 'cancelText', 'content', 'description', 'emptyText', 'label', 'message',
  'okText', 'placeholder', 'subTitle', 'title', 'tooltip',
])
const INTL_FORMATTERS = new Set(['Intl.DateTimeFormat', 'Intl.NumberFormat', 'Intl.RelativeTimeFormat'])
const LOCALE_METHODS = new Set(['toLocaleDateString', 'toLocaleString', 'toLocaleTimeString'])
const DATE_PATTERN = /(?:Y{2,4}|M{2,4}|D{2,4}|H{2,4}|m{2}|s{2})/
const USER_TEXT = /[A-Za-z\p{Script=Han}\p{Sc}]/u
const HAN_TEXT = /\p{Script=Han}/u
const ASCII_TEXT = /[A-Za-z]/
const PLACEHOLDER = /{{[^}]+}}/g
const FORBIDDEN_RESOURCE_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype'])
const NON_SUPPRESSIBLE_CODES = new Set(['ALLOWLIST_EXPIRED', 'CONFIGURATION_ERROR', 'SOURCE_PARSE_ERROR'])
const MAX_BASELINE_BYTES = 4 * 1024 * 1024
const PSEUDO_BUILTIN_MEMBERS = new Set([
  'Array.isArray', 'Math.ceil', 'Math.max', 'Object.entries', 'Object.fromEntries',
])
const SUGGESTIONS = {
  ALLOWLIST_EXPIRED: 'Remove the exception or renew it through review with a new expiry or stable contract.',
  DATE_PATTERN_OUTSIDE_ENTRYPOINT: 'Move display formatting into an approved locale-aware formatter.',
  DYNAMIC_KEY_UNDECLARED: 'Replace the dynamic key with static branches or add an exact reviewed key enumeration.',
  ERROR_CODE_UNMAPPED: 'Add a safe zh-CN mapping for the stable code and keep the English key set aligned.',
  HARDCODED_CURRENCY: 'Resolve currency through the centralized, documented business formatting contract.',
  HARDCODED_LOCALE: 'Pass the active application locale into the centralized formatter.',
  HARDCODED_TIMEZONE: 'Resolve the time zone through the centralized, documented business formatting contract.',
  KEY_EXTRA_EN: 'Add the corresponding zh-CN key or remove the unintended English-only key.',
  KEY_MISSING_EN: 'Add the matching en-US key without weakening zh-CN completeness.',
  KEY_MISSING_ZH: 'Add the required zh-CN translation before shipping the call site.',
  KEY_UNUSED_ZH: 'Review indirect runtime usage before retaining or removing the key; do not delete from this finding alone.',
  LOCALE_FORMATTER_OUTSIDE_ENTRYPOINT: 'Use the application formatter entrypoint instead of formatting in the component.',
  LOCALE_IMPLICIT_FORMATTER: 'Pass the active locale explicitly.',
  NUMBER_FORMATTER_BYPASS: 'Use a locale-aware number formatter for user-visible numeric text.',
  PSEUDO_PLACEHOLDER_MISMATCH: 'Fix the application transform so every interpolation placeholder is preserved byte-for-byte.',
  PSEUDO_TRANSFORM_UNVERIFIED: 'Use a supported pure transform shape and bind its output directly to the configured pseudo locale.',
  PLACEHOLDER_LOCALE_MISMATCH: 'Keep placeholder names and occurrence counts identical in zh-CN and en-US.',
  RAW_ERROR_RENDER: 'Map stable error codes to locale resources and use a safe unknown-error fallback with request ID.',
  RESOURCE_KEY_FORBIDDEN: 'Rename the resource key segment; prototype-sensitive names are not accepted.',
  SOURCE_PARSE_ERROR: 'Fix the syntax error so the audit can inspect the complete source file.',
  VISIBLE_LITERAL_EN: 'Move the user-visible text into the application locale resource.',
  VISIBLE_LITERAL_MIXED: 'Move the user-visible text into the application locale resource.',
  VISIBLE_LITERAL_SYMBOL: 'Move the user-visible symbol into a locale-aware message or formatter.',
  VISIBLE_LITERAL_ZH: 'Move the user-visible text into the application locale resource.',
  ZH_ASCII_VALUE_REVIEW: 'Document the stable protocol term in an exact allowlist entry or localize the value.',
  ZH_VALUE_ENGLISH: 'Replace the English default-locale text with complete Simplified Chinese.',
}

export class AuditConfigurationError extends Error {
  constructor(message) {
    super(message)
    this.name = 'AuditConfigurationError'
  }
}

function slash(value) {
  return value.split(path.sep).join('/')
}

function canonicalPath(root, relative, field) {
  if (typeof relative !== 'string' || relative === '' || path.isAbsolute(relative)) {
    throw new AuditConfigurationError(`${field} must be a non-empty repository-relative path`)
  }
  const normalized = slash(path.normalize(relative))
  if (normalized === '..' || normalized.startsWith('../')) {
    throw new AuditConfigurationError(`${field} escapes the repository: ${relative}`)
  }
  const absolute = path.resolve(root, normalized)
  const prefix = `${path.resolve(root)}${path.sep}`
  if (absolute !== path.resolve(root) && !absolute.startsWith(prefix)) {
    throw new AuditConfigurationError(`${field} escapes the repository: ${relative}`)
  }
  return { absolute, relative: normalized }
}

async function rejectSymlinkSegments(absolute, field) {
  const resolved = path.resolve(absolute)
  const parsed = path.parse(resolved)
  let current = parsed.root
  for (const segment of resolved.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment)
    const metadata = await lstat(current).catch(() => null)
    if (!metadata) throw new AuditConfigurationError(`${field} is missing: ${slash(current)}`)
    if (metadata.isSymbolicLink()) throw new AuditConfigurationError(`${field} contains a symbolic-link segment: ${slash(current)}`)
  }
}

async function readLimited(file, relative, maximum) {
  const metadata = await lstat(file).catch(() => null)
  if (!metadata || !metadata.isFile()) throw new AuditConfigurationError(`required file is missing: ${relative}`)
  if (metadata.isSymbolicLink()) throw new AuditConfigurationError(`symbolic-link input is not allowed: ${relative}`)
  if (metadata.size > maximum) {
    throw new AuditConfigurationError(`file exceeds maxFileBytes (${maximum}): ${relative}`)
  }
  return readFile(file, 'utf8')
}

function isTestFile(relative) {
  const parts = relative.split('/')
  const base = parts.at(-1) ?? ''
  return parts.some((part) => SKIP_DIRECTORIES.has(part)) || /\.(?:spec|test)\.[cm]?[jt]sx?$/.test(base) || base.endsWith('.d.ts')
}

async function sourceFiles(root, sourceRoot, maximum) {
  const files = []
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true })
    entries.sort((left, right) => left.name.localeCompare(right.name, 'en'))
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name)
      const relative = slash(path.relative(root, absolute))
      if (entry.isSymbolicLink()) throw new AuditConfigurationError(`symbolic-link input is not allowed: ${relative}`)
      if (entry.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(entry.name)) await visit(absolute)
        continue
      }
      if (!entry.isFile() || !/\.[cm]?[jt]sx?$/.test(entry.name) || isTestFile(relative)) continue
      const metadata = await stat(absolute)
      if (metadata.size > maximum) {
        throw new AuditConfigurationError(`file exceeds maxFileBytes (${maximum}): ${relative}`)
      }
      files.push({ absolute, relative })
    }
  }
  await visit(sourceRoot)
  return files
}

function validDate(value) {
  if (typeof value !== 'string') return false
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value)
  if (!match) return false
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  if (year < 1 || month < 1 || month > 12 || day < 1) return false
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return day <= days[month - 1]
}

function validateExemption(entry, label) {
  if (!entry || typeof entry !== 'object') throw new AuditConfigurationError(`${label} must be an object`)
  for (const field of ['reason', 'owner']) {
    if (typeof entry[field] !== 'string' || entry[field].trim() === '') {
      throw new AuditConfigurationError(`${label}.${field} is required`)
    }
  }
  if (!entry.contract && !entry.expires) throw new AuditConfigurationError(`${label} requires expires or contract`)
  if (entry.expires && !validDate(entry.expires)) throw new AuditConfigurationError(`${label}.expires must be YYYY-MM-DD`)
  if (entry.contract !== undefined && (typeof entry.contract !== 'string' || entry.contract.trim() === '')) {
    throw new AuditConfigurationError(`${label}.contract must be non-empty`)
  }
}

function validateConfiguration(config, root) {
  if (!config || config.version !== 1) throw new AuditConfigurationError('config.version must equal 1')
  if (!Number.isSafeInteger(config.maxFileBytes) || config.maxFileBytes < 1024) {
    throw new AuditConfigurationError('config.maxFileBytes must be an integer of at least 1024')
  }
  canonicalPath(root, config.typescriptCompiler, 'typescriptCompiler')
  if (!Array.isArray(config.apps) || config.apps.length === 0) throw new AuditConfigurationError('config.apps must not be empty')
  const appNames = new Set()
  for (const [index, app] of config.apps.entries()) {
    const label = `apps[${index}]`
    if (!app || typeof app.name !== 'string' || app.name === '' || appNames.has(app.name)) {
      throw new AuditConfigurationError(`${label}.name must be unique and non-empty`)
    }
    appNames.add(app.name)
    if (!Array.isArray(app.sourceRoots) || app.sourceRoots.length === 0) throw new AuditConfigurationError(`${label}.sourceRoots must not be empty`)
    app.sourceRoots.forEach((item, itemIndex) => canonicalPath(root, item, `${label}.sourceRoots[${itemIndex}]`))
    canonicalPath(root, app.resourceFile, `${label}.resourceFile`)
    for (const field of ['defaultVariable', 'secondaryVariable']) {
      if (typeof app[field] !== 'string' || app[field] === '') throw new AuditConfigurationError(`${label}.${field} is required`)
    }
    if (typeof app.namespaceFromTopLevel !== 'boolean') throw new AuditConfigurationError(`${label}.namespaceFromTopLevel must be boolean`)
    if (!app.pseudo || typeof app.pseudo.sourceVariable !== 'string' || typeof app.pseudo.transformFunction !== 'string') {
      throw new AuditConfigurationError(`${label}.pseudo must declare sourceVariable and transformFunction`)
    }
    if (app.pseudo.sourceVariable !== app.defaultVariable) throw new AuditConfigurationError(`${label}.pseudo.sourceVariable must equal defaultVariable`)
    const supportedPseudoKinds = new Set(['placeholder-safe-character-expansion', 'suffix-repeat-expansion'])
    if (!supportedPseudoKinds.has(app.pseudo.transformKind)) throw new AuditConfigurationError(`${label}.pseudo.transformKind is unsupported`)
    const variableOutput = typeof app.pseudo.outputVariable === 'string' && app.pseudo.outputVariable !== ''
    const localeOutput = typeof app.pseudo.resourceLocale === 'string' && app.pseudo.resourceLocale !== ''
      && typeof app.pseudo.resourceNamespace === 'string' && app.pseudo.resourceNamespace !== ''
    if (variableOutput === localeOutput) throw new AuditConfigurationError(`${label}.pseudo must declare exactly one outputVariable or resourceLocale/resourceNamespace output`)
    if (localeOutput && (typeof app.pseudo.initReceiver !== 'string' || !/^[A-Za-z_$][\w$]*$/.test(app.pseudo.initReceiver)
      || typeof app.pseudo.initImportSource !== 'string' || app.pseudo.initImportSource === '')) {
      throw new AuditConfigurationError(`${label}.pseudo locale output must declare initReceiver and initImportSource`)
    }
    if (app.pseudo.transformKind === 'placeholder-safe-character-expansion'
      && (typeof app.pseudo.textTransformFunction !== 'string' || app.pseudo.textTransformFunction === '')) {
      throw new AuditConfigurationError(`${label}.pseudo.textTransformFunction is required for character expansion`)
    }
    if (!(app.pseudo.minimumExpansionRatio > 1)) throw new AuditConfigurationError(`${label}.pseudo.minimumExpansionRatio must exceed 1`)
    if (!Array.isArray(app.formatterEntrypoints)) throw new AuditConfigurationError(`${label}.formatterEntrypoints must be an array`)
    app.formatterEntrypoints.forEach((item, itemIndex) => canonicalPath(root, item, `${label}.formatterEntrypoints[${itemIndex}]`))
  }
  if (!Array.isArray(config.dynamicKeys) || !Array.isArray(config.allowlist)) {
    throw new AuditConfigurationError('dynamicKeys and allowlist must be arrays')
  }
  for (const [index, declaration] of config.dynamicKeys.entries()) {
    const label = `dynamicKeys[${index}]`
    validateExemption(declaration, label)
    if (!appNames.has(declaration.app)) throw new AuditConfigurationError(`${label}.app is unknown`)
    canonicalPath(root, declaration.file, `${label}.file`)
    if (typeof declaration.prefix !== 'string' || declaration.prefix === '' || declaration.prefix.includes('*')) {
      throw new AuditConfigurationError(`${label}.prefix must be exact and non-empty`)
    }
    if (!Array.isArray(declaration.keys) || declaration.keys.length === 0 || declaration.keys.some((key) => typeof key !== 'string' || !key.startsWith(declaration.prefix) || key.includes('*'))) {
      throw new AuditConfigurationError(`${label}.keys must be a non-empty exact enumeration under prefix`)
    }
    if (new Set(declaration.keys).size !== declaration.keys.length) throw new AuditConfigurationError(`${label}.keys contains duplicates`)
  }
  for (const [index, entry] of config.allowlist.entries()) {
    const label = `allowlist[${index}]`
    validateExemption(entry, label)
    if (!appNames.has(entry.app)) throw new AuditConfigurationError(`${label}.app is unknown`)
    canonicalPath(root, entry.file, `${label}.file`)
    for (const field of ['code', 'evidence']) {
      if (typeof entry[field] !== 'string' || entry[field] === '' || entry[field].includes('*')) {
        throw new AuditConfigurationError(`${label}.${field} must be exact and non-empty`)
      }
    }
    if (NON_SUPPRESSIBLE_CODES.has(entry.code)) throw new AuditConfigurationError(`${label}.code cannot suppress lifecycle or configuration findings`)
  }
}

async function loadTypeScript(root, config, injected) {
  if (injected) return injected
  const compiler = canonicalPath(root, config.typescriptCompiler, 'typescriptCompiler')
  const metadata = await lstat(compiler.absolute).catch(() => null)
  if (!metadata?.isFile()) throw new AuditConfigurationError(`TypeScript compiler is missing: ${compiler.relative}`)
  const loaded = await import(pathToFileURL(compiler.absolute).href)
  const ts = loaded.default ?? loaded
  if (typeof ts.createSourceFile !== 'function') throw new AuditConfigurationError('configured TypeScript compiler has no createSourceFile API')
  return ts
}

function parseSource(ts, file, text) {
  const kind = file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  return ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, kind)
}

function unwrap(ts, node) {
  let current = node
  while (current && (ts.isAsExpression(current) || ts.isSatisfiesExpression?.(current) || ts.isParenthesizedExpression(current) || ts.isTypeAssertionExpression(current))) {
    current = current.expression
  }
  return current
}

function propertyName(ts, node) {
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node)) return node.text
  return null
}

function locationOf(source, node) {
  const point = source.getLineAndCharacterOfPosition(node.getStart(source))
  return { line: point.line + 1, column: point.character + 1 }
}

function findingFingerprint(finding) {
  return createHash('sha256').update([
    finding.code, finding.app, finding.file, finding.line, finding.column, finding.evidence,
  ].join('\0')).digest('hex').slice(0, 24)
}

function sortFindings(left, right) {
  return [left.app, left.code, left.file, left.line, left.column, left.evidence].join('\0')
    .localeCompare([right.app, right.code, right.file, right.line, right.column, right.evidence].join('\0'), 'en')
}

function makeCollector(config, today) {
  const findings = []
  const seen = new Set()
  const expired = new Set()
  for (const [index, item] of [...config.allowlist, ...config.dynamicKeys].entries()) {
    if (item.expires && item.expires < today) expired.add(item)
    if (item.expires && item.expires < today) {
      const type = index < config.allowlist.length ? 'allowlist' : 'dynamicKeys'
      findings.push({
        severity: 'error', suppressed: false, code: 'ALLOWLIST_EXPIRED', app: item.app,
        file: item.file, line: 1, column: 1,
        message: `${type} entry expired on ${item.expires}`,
        evidence: `${item.owner}:${item.expires}:${item.reason}`,
      })
    }
  }
  function add(input) {
    const base = {
      severity: input.severity ?? 'error', suppressed: false, app: input.app ?? 'repository',
      file: input.file ?? '.', line: input.line ?? 1, column: input.column ?? 1,
      code: input.code, message: input.message, evidence: String(input.evidence ?? '').slice(0, 300),
    }
    const key = [base.code, base.app, base.file, base.line, base.column, base.evidence].join('\0')
    if (seen.has(key)) return
    seen.add(key)
    findings.push(base)
  }
  function applyAllowlist() {
    const claimed = new Set()
    for (const [index, entry] of config.allowlist.entries()) {
      if (expired.has(entry)) continue
      if (NON_SUPPRESSIBLE_CODES.has(entry.code)) throw new AuditConfigurationError(`allowlist[${index}] cannot suppress lifecycle or configuration findings`)
      const matches = findings.filter((finding) => finding.code === entry.code && finding.app === entry.app
        && finding.file === entry.file && finding.evidence === entry.evidence)
      if (matches.length !== 1) {
        throw new AuditConfigurationError(`allowlist[${index}] must match exactly one finding; matched ${matches.length}`)
      }
      const finding = matches[0]
      if (claimed.has(finding)) throw new AuditConfigurationError(`allowlist[${index}] targets a finding already claimed by another entry`)
      claimed.add(finding)
      finding.severity = 'info'
      finding.suppressed = true
      finding.suppression = {
        owner: entry.owner, reason: entry.reason,
        ...(entry.expires ? { expires: entry.expires } : { contract: entry.contract }),
      }
    }
  }
  return { add, applyAllowlist, expired, findings }
}

function bindingNameContains(ts, binding, name) {
  if (ts.isIdentifier(binding)) return binding.text === name
  return (binding.elements ?? []).some((element) => ts.isBindingElement(element) && bindingNameContains(ts, element.name, name))
}

function topLevelBindings(ts, source, name) {
  const bindings = []
  for (const statement of source.statements) {
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (bindingNameContains(ts, declaration.name, name)) bindings.push(declaration)
      }
      continue
    }
    if ((ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement) || ts.isEnumDeclaration(statement) || ts.isModuleDeclaration(statement))
      && statement.name?.text === name) bindings.push(statement)
    if (ts.isImportEqualsDeclaration(statement) && statement.name.text === name) bindings.push(statement)
    if (!ts.isImportDeclaration(statement) || !statement.importClause) continue
    if (statement.importClause.name?.text === name) bindings.push(statement.importClause.name)
    const named = statement.importClause.namedBindings
    if (named && ts.isNamespaceImport(named) && named.name.text === name) bindings.push(named)
    if (named && ts.isNamedImports(named)) {
      for (const element of named.elements) if (element.name.text === name) bindings.push(element)
    }
  }
  return bindings
}

function findVariable(ts, source, name) {
  const bindings = topLevelBindings(ts, source, name)
  return bindings.length === 1 && ts.isVariableDeclaration(bindings[0]) ? bindings[0] : null
}

function findFunction(ts, source, name) {
  const bindings = topLevelBindings(ts, source, name)
  return bindings.length === 1 && ts.isFunctionDeclaration(bindings[0]) ? bindings[0] : null
}

function objectProperty(ts, object, name) {
  const value = unwrap(ts, object)
  if (!ts.isObjectLiteralExpression(value)) return null
  if (value.properties.some((property) => ts.isSpreadAssignment(property)
    || (property.name && ts.isComputedPropertyName(property.name)))) return null
  const matches = value.properties.filter((property) => property.name && propertyName(ts, property.name) === name)
  return matches.length === 1 && ts.isPropertyAssignment(matches[0]) ? matches[0] : null
}

function directCallOf(ts, node, callee, argument) {
  const value = unwrap(ts, node)
  return ts.isCallExpression(value) && ts.isIdentifier(value.expression) && value.expression.text === callee
    && value.arguments.length === 1 && ts.isIdentifier(unwrap(ts, value.arguments[0])) && unwrap(ts, value.arguments[0]).text === argument
}

function functionHasBinding(ts, declaration, names) {
  let found = false
  function bindingName(name) {
    for (const candidate of names) if (bindingNameContains(ts, name, candidate)) found = true
  }
  function visit(node) {
    if (found) return
    if (ts.isParameter(node) || ts.isVariableDeclaration(node) || ts.isBindingElement(node)) bindingName(node.name)
    if (node !== declaration && (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name) bindingName(node.name)
    if (!found) ts.forEachChild(node, visit)
  }
  visit(declaration)
  return found
}

function callOf(ts, node, source, callee, argumentsText) {
  const value = unwrap(ts, node)
  return ts.isCallExpression(value)
    && value.expression.getText(source) === callee
    && value.arguments.length === argumentsText.length
    && value.arguments.every((argument, index) => unwrap(ts, argument).getText(source) === argumentsText[index])
}

function returnExpression(ts, statement) {
  if (ts.isReturnStatement(statement)) return statement.expression ? unwrap(ts, statement.expression) : null
  if (!ts.isBlock(statement) || statement.statements.length !== 1 || !ts.isReturnStatement(statement.statements[0])) return null
  return statement.statements[0].expression ? unwrap(ts, statement.statements[0].expression) : null
}

function typeEquals(ts, node, identifier, expected) {
  const value = unwrap(ts, node)
  if (!ts.isBinaryExpression(value) || value.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsEqualsToken) return false
  return ts.isTypeOfExpression(value.left) && ts.isIdentifier(value.left.expression) && value.left.expression.text === identifier
    && ts.isStringLiteralLike(value.right) && value.right.text === expected
}

function importedReceiver(ts, source, receiver, moduleSource) {
  const matches = []
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause
      || statement.importClause.isTypeOnly
      || !ts.isStringLiteralLike(statement.moduleSpecifier) || statement.moduleSpecifier.text !== moduleSource) continue
    if (statement.importClause.name?.text === receiver) matches.push(statement.importClause.name)
    const bindings = statement.importClause.namedBindings
    if (bindings && ts.isNamespaceImport(bindings) && bindings.name.text === receiver) matches.push(bindings.name)
  }
  return matches.length === 1 && topLevelBindings(ts, source, receiver).length === 1 ? matches[0] : null
}

function receiverRoot(ts, node) {
  let current = unwrap(ts, node)
  while (current) {
    if (ts.isIdentifier(current)) return current.text
    if (ts.isCallExpression(current)) {
      current = unwrap(ts, current.expression)
      continue
    }
    if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
      current = unwrap(ts, current.expression)
      continue
    }
    return null
  }
  return null
}

function topLevelExpressionCall(ts, source, node) {
  let current = node.parent
  while (current && (ts.isParenthesizedExpression(current) || ts.isAsExpression(current)
    || ts.isSatisfiesExpression?.(current) || ts.isTypeAssertionExpression(current)
    || ts.isNonNullExpression(current) || ts.isVoidExpression(current) || ts.isAwaitExpression(current))) {
    current = current.parent
  }
  return Boolean(current && ts.isExpressionStatement(current) && current.parent === source)
}

function importReceivers(ts, source, moduleSource) {
  const receivers = new Set()
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause
      || statement.importClause.isTypeOnly
      || !ts.isStringLiteralLike(statement.moduleSpecifier) || statement.moduleSpecifier.text !== moduleSource) continue
    if (statement.importClause.name) receivers.add(statement.importClause.name.text)
    const bindings = statement.importClause.namedBindings
    if (bindings && ts.isNamespaceImport(bindings)) receivers.add(bindings.name.text)
    if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) {
        if (!element.isTypeOnly && element.propertyName?.text === 'default') receivers.add(element.name.text)
      }
    }
  }
  return receivers
}

function importedNamedReceiver(ts, source, localName, importedName, moduleSource) {
  const matches = []
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause || statement.importClause.isTypeOnly
      || !ts.isStringLiteralLike(statement.moduleSpecifier) || statement.moduleSpecifier.text !== moduleSource) continue
    const bindings = statement.importClause.namedBindings
    if (!bindings || !ts.isNamedImports(bindings)) continue
    for (const element of bindings.elements) {
      if (!element.isTypeOnly && element.name.text === localName
        && (element.propertyName?.text ?? element.name.text) === importedName) matches.push(element)
    }
  }
  return matches.length === 1 && topLevelBindings(ts, source, localName).length === 1
}

function trustedInitReceiver(ts, source, call, pseudo) {
  const receiver = unwrap(ts, call.expression.expression)
  if (ts.isIdentifier(receiver)) return receiver.text === pseudo.initReceiver
  if (!ts.isCallExpression(receiver) || !ts.isPropertyAccessExpression(receiver.expression)
    || receiver.expression.name.text !== 'use' || receiver.arguments.length !== 1
    || !ts.isIdentifier(unwrap(ts, receiver.expression.expression))
    || unwrap(ts, receiver.expression.expression).text !== pseudo.initReceiver
    || !ts.isIdentifier(unwrap(ts, receiver.arguments[0]))) return false
  return importedNamedReceiver(ts, source, unwrap(ts, receiver.arguments[0]).text, 'initReactI18next', 'react-i18next')
}

function pureInitResources(ts, resources, app) {
  const tree = unwrap(ts, resources.initializer)
  if (!ts.isObjectLiteralExpression(tree)) return false
  for (const locale of tree.properties) {
    if (!ts.isPropertyAssignment(locale) || ts.isComputedPropertyName(locale.name)) return false
    const namespaces = unwrap(ts, locale.initializer)
    if (!ts.isObjectLiteralExpression(namespaces)) return false
    for (const namespace of namespaces.properties) {
      if (!ts.isPropertyAssignment(namespace) || ts.isComputedPropertyName(namespace.name)) return false
      const value = unwrap(ts, namespace.initializer)
      const localeReference = ts.isIdentifier(value)
        && [app.defaultVariable, app.secondaryVariable].includes(value.text)
      if (!localeReference && !directCallOf(ts, value, app.pseudo.transformFunction, app.defaultVariable)) return false
    }
  }
  return true
}

function initOptionSafe(ts, node, criticalNames) {
  if (containsIdentifier(ts, node, criticalNames)) return false
  let safe = true
  function visit(child) {
    if (!safe) return
    if (ts.isNewExpression(child)) safe = false
    if (ts.isCallExpression(child) && child.expression.getText() !== 'window.localStorage.getItem') safe = false
    if (safe) ts.forEachChild(child, visit)
  }
  visit(node)
  return safe
}

function verifyPseudoOutput(ts, source, app) {
  const pseudo = app.pseudo
  if (pseudo.outputVariable) {
    const output = findVariable(ts, source, pseudo.outputVariable)
    return output?.initializer && directCallOf(ts, output.initializer, pseudo.transformFunction, pseudo.sourceVariable) ? output : null
  }
  if (!importedReceiver(ts, source, pseudo.initReceiver, pseudo.initImportSource)) return false
  const configuredReceivers = importReceivers(ts, source, pseudo.initImportSource)
  const initializers = []
  function visit(node) {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)
      || node.expression.name.text !== 'init') {
      ts.forEachChild(node, visit)
      return
    }
    const root = receiverRoot(ts, node.expression.expression)
    if (root && configuredReceivers.has(root)) initializers.push({ node, root, topLevel: topLevelExpressionCall(ts, source, node) })
    ts.forEachChild(node, visit)
  }
  visit(source)
  if (initializers.length !== 1 || initializers[0].root !== pseudo.initReceiver || !initializers[0].topLevel
    || !trustedInitReceiver(ts, source, initializers[0].node, pseudo)) return false
  const [initializer] = initializers
  if (initializer.node.arguments.length === 0) return false
  const options = unwrap(ts, initializer.node.arguments[0])
  if (!ts.isObjectLiteralExpression(options) || options.properties.some((property) => !ts.isPropertyAssignment(property))) return false
  const resources = objectProperty(ts, options, 'resources')
  if (!resources || options.properties[0] !== resources || !pureInitResources(ts, resources, app)) return false
  const critical = new Set([
    app.defaultVariable, app.secondaryVariable, pseudo.transformFunction, pseudo.textTransformFunction,
    ...configuredReceivers, 'Array', 'Math', 'Object', 'eval', 'Function',
  ].filter(Boolean))
  if (options.properties.slice(1).some((property) => !initOptionSafe(ts, property.initializer, critical))) return false
  const locale = resources && objectProperty(ts, resources.initializer, pseudo.resourceLocale)
  const namespace = locale && objectProperty(ts, locale.initializer, pseudo.resourceNamespace)
  return namespace && directCallOf(ts, namespace.initializer, pseudo.transformFunction, pseudo.sourceVariable) ? initializer.node : null
}

function builtinAccess(ts, node) {
  const value = unwrap(ts, node)
  if (ts.isPropertyAccessExpression(value) && ts.isIdentifier(unwrap(ts, value.expression))) {
    return `${unwrap(ts, value.expression).text}.${value.name.text}`
  }
  if (ts.isElementAccessExpression(value) && ts.isIdentifier(unwrap(ts, value.expression))) {
    const member = stringValue(ts, value.argumentExpression)
    return member === null ? null : `${unwrap(ts, value.expression).text}.${member}`
  }
  return null
}

function builtinRoot(ts, node) {
  const value = unwrap(ts, node)
  if (ts.isIdentifier(value) && ['Array', 'Math', 'Object'].includes(value.text)) return value.text
  const access = builtinAccess(ts, value)
  return access && PSEUDO_BUILTIN_MEMBERS.has(access) ? access : null
}

function mutatesPseudoBuiltins(ts, source) {
  let found = false
  function visit(node) {
    if (found) return
    if (ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment && PSEUDO_BUILTIN_MEMBERS.has(builtinAccess(ts, node.left))) found = true
    if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
      && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator)
      && PSEUDO_BUILTIN_MEMBERS.has(builtinAccess(ts, node.operand))) found = true
    if (ts.isDeleteExpression(node) && PSEUDO_BUILTIN_MEMBERS.has(builtinAccess(ts, node.expression))) found = true
    if (ts.isCallExpression(node)) {
      const callee = node.expression.getText(source)
      if (['Object.assign', 'Object.defineProperties', 'Object.setPrototypeOf', 'Reflect.setPrototypeOf'].includes(callee)
        && node.arguments[0] && builtinRoot(ts, node.arguments[0])) found = true
      if (['Object.defineProperty', 'Reflect.defineProperty', 'Reflect.set'].includes(callee)
        && node.arguments.length >= 2 && ts.isIdentifier(unwrap(ts, node.arguments[0]))) {
        const member = stringValue(ts, node.arguments[1])
        if (member !== null && PSEUDO_BUILTIN_MEMBERS.has(`${unwrap(ts, node.arguments[0]).text}.${member}`)) found = true
      }
    }
    if (!found) ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

function referencesPseudoBuiltinsOutside(ts, source, verifiedFunctions) {
  const skipped = new Set(verifiedFunctions)
  let found = false
  function visit(node) {
    if (found || skipped.has(node)) return
    if (ts.isIdentifier(node) && ['Array', 'Math', 'Object'].includes(node.text)) found = true
    if (ts.isElementAccessExpression(node) && ts.isIdentifier(unwrap(ts, node.expression))
      && unwrap(ts, node.expression).text === 'globalThis'
      && ['Array', 'Math', 'Object'].includes(stringValue(ts, node.argumentExpression))) found = true
    if (!found) ts.forEachChild(node, visit)
  }
  visit(source)
  return found
}

function topLevelStatement(source, node) {
  let current = node
  while (current?.parent && current.parent !== source) current = current.parent
  return current?.parent === source ? current : null
}

function containsIdentifier(ts, node, names) {
  let found = false
  function visit(child) {
    if (found) return
    if (ts.isIdentifier(child) && names.has(child.text)) found = true
    if (!found) ts.forEachChild(child, visit)
  }
  visit(node)
  return found
}

function allowedPostInitReceiverReference(ts, node) {
  const parent = node.parent
  if (!parent || !ts.isPropertyAccessExpression(parent) || parent.expression !== node) return false
  if (parent.name.text === 'language') return true
  return ['on', 't'].includes(parent.name.text)
    && ts.isCallExpression(parent.parent) && parent.parent.expression === parent
}

function postInitStatementSafe(ts, statement, pseudo, criticalNames) {
  let safe = true
  function visit(node) {
    if (!safe) return
    if (ts.isIdentifier(node) && criticalNames.has(node.text)) safe = false
    if (ts.isIdentifier(node) && node.text === pseudo.initReceiver
      && !allowedPostInitReceiverReference(ts, node)) safe = false
    if (ts.isVariableDeclaration(node) && node.initializer
      && containsIdentifier(ts, node.initializer, new Set([pseudo.initReceiver]))) safe = false
    if (ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
      && receiverRoot(ts, node.left) === pseudo.initReceiver) safe = false
    if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
      && receiverRoot(ts, node.operand) === pseudo.initReceiver) safe = false
    if (ts.isDeleteExpression(node) && receiverRoot(ts, node.expression) === pseudo.initReceiver) safe = false
    if (ts.isCallExpression(node)) {
      const root = receiverRoot(ts, node.expression)
      if (root === pseudo.initReceiver) {
        const expression = unwrap(ts, node.expression)
        const method = ts.isPropertyAccessExpression(expression) ? expression.name.text
          : ts.isElementAccessExpression(expression) ? stringValue(ts, expression.argumentExpression) : null
        if (!['on', 't'].includes(method)) safe = false
      } else safe = false
      if (node.arguments.some((argument) => ts.isIdentifier(unwrap(ts, argument))
        && unwrap(ts, argument).text === pseudo.initReceiver)) safe = false
    }
    if (!safe) return
    ts.forEachChild(node, visit)
  }
  visit(statement)
  return safe
}

function staticResourceInitializer(ts, node) {
  const value = unwrap(ts, node)
  if (ts.isStringLiteralLike(value)) return true
  if (!ts.isObjectLiteralExpression(value)) return false
  return value.properties.every((property) => ts.isPropertyAssignment(property)
    && !ts.isComputedPropertyName(property.name) && staticResourceInitializer(ts, property.initializer))
}

function verifyPseudoModuleEnvelope(ts, source, app, output, verifiedFunctions) {
  const pseudo = app.pseudo
  const outputStatement = topLevelStatement(source, output)
  const sourceDeclaration = findVariable(ts, source, app.defaultVariable)
  const secondaryDeclaration = findVariable(ts, source, app.secondaryVariable)
  if (!outputStatement || !sourceDeclaration || !secondaryDeclaration) return false
  if (!staticResourceInitializer(ts, sourceDeclaration.initializer)
    || !staticResourceInitializer(ts, secondaryDeclaration.initializer)) return false
  const declarationStatements = [sourceDeclaration, secondaryDeclaration]
  if (pseudo.outputVariable) declarationStatements.push(output)
  if (declarationStatements.some((declaration) => {
    const statement = topLevelStatement(source, declaration)
    return !statement || !ts.isVariableStatement(statement) || statement.declarationList.declarations.length !== 1
      || !(statement.declarationList.flags & ts.NodeFlags.Const)
  })) return false

  const allowed = new Set([
    ...declarationStatements.map((declaration) => topLevelStatement(source, declaration)),
    ...verifiedFunctions.map((declaration) => topLevelStatement(source, declaration)),
    outputStatement,
  ])
  const outputIndex = source.statements.indexOf(outputStatement)
  if (outputIndex < 0) return false
  const runtimeImports = new Set([pseudo.initImportSource, pseudo.resourceLocale ? 'react-i18next' : null].filter(Boolean))
  const typeOnly = (statement) => ts.isTypeAliasDeclaration(statement) || ts.isInterfaceDeclaration(statement)
  const safeImport = (statement) => ts.isImportDeclaration(statement) && statement.importClause
    && (statement.importClause.isTypeOnly
      || (ts.isStringLiteralLike(statement.moduleSpecifier) && runtimeImports.has(statement.moduleSpecifier.text)))

  for (let index = 0; index <= outputIndex; index += 1) {
    const statement = source.statements[index]
    if (!allowed.has(statement) && !typeOnly(statement) && !safeImport(statement)) return false
  }
  for (let index = outputIndex + 1; index < source.statements.length; index += 1) {
    const statement = source.statements[index]
    if (typeOnly(statement)) continue
    if (!pseudo.outputVariable && ts.isExportAssignment(statement) && !statement.isExportEquals
      && ts.isIdentifier(unwrap(ts, statement.expression)) && unwrap(ts, statement.expression).text === pseudo.initReceiver) continue
    if (!pseudo.outputVariable && ts.isIfStatement(statement)) {
      const criticalNames = new Set([
        app.defaultVariable, app.secondaryVariable, pseudo.transformFunction, pseudo.textTransformFunction,
        ...[...importReceivers(ts, source, pseudo.initImportSource)].filter((name) => name !== pseudo.initReceiver),
        'Array', 'Math', 'Object', 'eval', 'Function',
      ].filter(Boolean))
      if (postInitStatementSafe(ts, statement, pseudo, criticalNames)) continue
    }
    return false
  }
  return true
}

function verifyCharacterTree(ts, source, pseudo) {
  const tree = findFunction(ts, source, pseudo.transformFunction)
  const text = findFunction(ts, source, pseudo.textTransformFunction)
  if (!tree?.body || tree.parameters.length !== 1 || !ts.isIdentifier(tree.parameters[0].name)
    || !text?.body || text.parameters.length !== 1 || !ts.isIdentifier(text.parameters[0].name)) return false
  const treeParameter = tree.parameters[0].name.text
  const textParameter = text.parameters[0].name.text
  if (tree.body.statements.length !== 1 || text.body.statements.length !== 2) return false

  const treeReturn = returnExpression(ts, tree.body.statements[0])
  if (!treeReturn || !ts.isCallExpression(treeReturn) || treeReturn.expression.getText(source) !== 'Object.fromEntries'
    || treeReturn.arguments.length !== 1) return false
  const treeMap = unwrap(ts, treeReturn.arguments[0])
  if (!ts.isCallExpression(treeMap) || !ts.isPropertyAccessExpression(treeMap.expression) || treeMap.expression.name.text !== 'map'
    || treeMap.arguments.length !== 1) return false
  const entries = unwrap(ts, treeMap.expression.expression)
  if (!callOf(ts, entries, source, 'Object.entries', [treeParameter])) return false
  const treeMapper = unwrap(ts, treeMap.arguments[0])
  if (!ts.isArrowFunction(treeMapper) || treeMapper.parameters.length !== 1 || !ts.isArrayBindingPattern(treeMapper.parameters[0].name)
    || treeMapper.parameters[0].name.elements.length !== 2) return false
  const [keyBinding, valueBinding] = treeMapper.parameters[0].name.elements
  if (!ts.isBindingElement(keyBinding) || !ts.isIdentifier(keyBinding.name) || !ts.isBindingElement(valueBinding) || !ts.isIdentifier(valueBinding.name)) return false
  const pair = unwrap(ts, treeMapper.body)
  if (!ts.isArrayLiteralExpression(pair) || pair.elements.length !== 2 || pair.elements[0].getText(source) !== keyBinding.name.text) return false
  const branch = unwrap(ts, pair.elements[1])
  if (!ts.isConditionalExpression(branch) || !typeEquals(ts, branch.condition, valueBinding.name.text, 'string')
    || !directCallOf(ts, branch.whenTrue, pseudo.textTransformFunction, valueBinding.name.text)
    || !directCallOf(ts, branch.whenFalse, pseudo.transformFunction, valueBinding.name.text)) return null

  const declaration = text.body.statements[0]
  if (!ts.isVariableStatement(declaration) || declaration.declarationList.declarations.length !== 1) return false
  const expanded = declaration.declarationList.declarations[0]
  if (!ts.isIdentifier(expanded.name) || !expanded.initializer) return false
  const outerJoin = unwrap(ts, expanded.initializer)
  if (!ts.isCallExpression(outerJoin) || !ts.isPropertyAccessExpression(outerJoin.expression) || outerJoin.expression.name.text !== 'join'
    || outerJoin.arguments.length !== 1 || stringValue(ts, outerJoin.arguments[0]) !== '') return false
  const outerMap = unwrap(ts, outerJoin.expression.expression)
  if (!ts.isCallExpression(outerMap) || !ts.isPropertyAccessExpression(outerMap.expression) || outerMap.expression.name.text !== 'map'
    || outerMap.arguments.length !== 1) return false
  const split = unwrap(ts, outerMap.expression.expression)
  if (!ts.isCallExpression(split) || !ts.isPropertyAccessExpression(split.expression) || split.expression.name.text !== 'split'
    || split.expression.expression.getText(source) !== textParameter || split.arguments.length !== 1
    || split.arguments[0].getText(source) !== '/({{[^}]+}})/g') return null
  const outerMapper = unwrap(ts, outerMap.arguments[0])
  if (!ts.isArrowFunction(outerMapper) || outerMapper.parameters.length !== 1 || !ts.isIdentifier(outerMapper.parameters[0].name)) return false
  const part = outerMapper.parameters[0].name.text
  const placeholderBranch = unwrap(ts, outerMapper.body)
  if (!ts.isConditionalExpression(placeholderBranch) || placeholderBranch.whenTrue.getText(source) !== part) return false
  const condition = unwrap(ts, placeholderBranch.condition)
  if (!ts.isBinaryExpression(condition) || condition.operatorToken.kind !== ts.SyntaxKind.AmpersandAmpersandToken
    || !callOf(ts, condition.left, source, `${part}.startsWith`, ["'{{'"])
    || !callOf(ts, condition.right, source, `${part}.endsWith`, ["'}}'"])) return null
  const innerJoin = unwrap(ts, placeholderBranch.whenFalse)
  if (!ts.isCallExpression(innerJoin) || !ts.isPropertyAccessExpression(innerJoin.expression) || innerJoin.expression.name.text !== 'join'
    || innerJoin.arguments.length !== 1 || stringValue(ts, innerJoin.arguments[0]) !== '') return false
  const innerMap = unwrap(ts, innerJoin.expression.expression)
  if (!ts.isCallExpression(innerMap) || !ts.isPropertyAccessExpression(innerMap.expression) || innerMap.expression.name.text !== 'map'
    || innerMap.arguments.length !== 1) return false
  const characters = unwrap(ts, innerMap.expression.expression)
  if (!ts.isArrayLiteralExpression(characters) || characters.elements.length !== 1 || !ts.isSpreadElement(characters.elements[0])
    || characters.elements[0].expression.getText(source) !== part) return false
  const innerMapper = unwrap(ts, innerMap.arguments[0])
  if (!ts.isArrowFunction(innerMapper) || innerMapper.parameters.length !== 1 || !ts.isIdentifier(innerMapper.parameters[0].name)) return false
  const character = innerMapper.parameters[0].name.text
  const characterBranch = unwrap(ts, innerMapper.body)
  if (!ts.isConditionalExpression(characterBranch) || characterBranch.whenTrue.getText(source) !== character
    || !ts.isCallExpression(unwrap(ts, characterBranch.condition))
    || unwrap(ts, characterBranch.condition).expression.getText(source) !== '/\\s|\\d/.test'
    || unwrap(ts, characterBranch.condition).arguments.length !== 1
    || unwrap(ts, characterBranch.condition).arguments[0].getText(source) !== character) return false
  const expansion = unwrap(ts, characterBranch.whenFalse)
  if (!ts.isTemplateExpression(expansion) || expansion.head.text !== '' || expansion.templateSpans.length !== 1
    || expansion.templateSpans[0].expression.getText(source) !== character || expansion.templateSpans[0].literal.text !== '~') return null

  const textReturn = returnExpression(ts, text.body.statements[1])
  if (!textReturn || !ts.isTemplateExpression(textReturn) || textReturn.head.text !== '［' || textReturn.templateSpans.length !== 1
    || textReturn.templateSpans[0].expression.getText(source) !== expanded.name.text || textReturn.templateSpans[0].literal.text !== '］') return null
  const placeholderPattern = new RegExp(split.arguments[0].getText(source).slice(1, -2), 'g')
  const preservedText = unwrap(ts, characterBranch.condition).expression.expression.getText(source)
  const preservedBoundary = preservedText.lastIndexOf('/')
  const preservedPattern = new RegExp(preservedText.slice(1, preservedBoundary), preservedText.slice(preservedBoundary + 1))
  const placeholderStart = stringValue(ts, unwrap(ts, condition.left).arguments[0])
  const placeholderEnd = stringValue(ts, unwrap(ts, condition.right).arguments[0])
  const prefix = textReturn.head.text
  const suffix = textReturn.templateSpans[0].literal.text
  const marker = expansion.templateSpans[0].literal.text
  return {
    apply(value) {
      return `${prefix}${value.split(placeholderPattern).map((piece) => {
        if (piece.startsWith(placeholderStart) && piece.endsWith(placeholderEnd)) return piece
        return [...piece].map((item) => (preservedPattern.test(item) ? item : `${item}${marker}`)).join('')
      }).join('')}${suffix}`
    },
  }
}

function verifySuffixTree(ts, source, pseudo) {
  const transform = findFunction(ts, source, pseudo.transformFunction)
  if (!transform?.body || transform.parameters.length !== 1 || !ts.isIdentifier(transform.parameters[0].name)
    || transform.body.statements.length !== 4) return false
  const parameter = transform.parameters[0].name.text
  const [stringIf, arrayIf, objectIf, fallback] = transform.body.statements
  if (!ts.isIfStatement(stringIf) || !typeEquals(ts, stringIf.expression, parameter, 'string')) return false
  const stringResult = returnExpression(ts, stringIf.thenStatement)
  if (!stringResult || !ts.isTemplateExpression(stringResult) || stringResult.head.text !== '［' || stringResult.templateSpans.length !== 2
    || stringResult.templateSpans[0].expression.getText(source) !== parameter || stringResult.templateSpans[0].literal.text !== '') return false
  const repeat = unwrap(ts, stringResult.templateSpans[1].expression)
  if (!ts.isCallExpression(repeat) || !ts.isPropertyAccessExpression(repeat.expression) || repeat.expression.name.text !== 'repeat'
    || stringValue(ts, repeat.expression.expression) !== '扩' || repeat.arguments.length !== 1
    || stringResult.templateSpans[1].literal.text !== '］') return false
  const maximum = unwrap(ts, repeat.arguments[0])
  if (!ts.isCallExpression(maximum) || !ts.isPropertyAccessExpression(maximum.expression)
    || !ts.isIdentifier(maximum.expression.expression) || maximum.expression.expression.text !== 'Math' || maximum.expression.name.text !== 'max'
    || maximum.arguments.length !== 2 || !ts.isNumericLiteral(unwrap(ts, maximum.arguments[0]))) return null
  const ceiling = unwrap(ts, maximum.arguments[1])
  if (!ts.isCallExpression(ceiling) || !ts.isPropertyAccessExpression(ceiling.expression)
    || !ts.isIdentifier(ceiling.expression.expression) || ceiling.expression.expression.text !== 'Math' || ceiling.expression.name.text !== 'ceil'
    || ceiling.arguments.length !== 1) return null
  const division = unwrap(ts, ceiling.arguments[0])
  if (!ts.isBinaryExpression(division) || division.operatorToken.kind !== ts.SyntaxKind.SlashToken
    || !ts.isPropertyAccessExpression(unwrap(ts, division.left)) || unwrap(ts, division.left).name.text !== 'length'
    || !ts.isIdentifier(unwrap(ts, division.left).expression) || unwrap(ts, division.left).expression.text !== parameter
    || !ts.isNumericLiteral(unwrap(ts, division.right))) return null
  const minimum = Number(unwrap(ts, maximum.arguments[0]).text)
  const divisor = Number(unwrap(ts, division.right).text)
  if (!Number.isSafeInteger(minimum) || minimum < 1 || !Number.isSafeInteger(divisor) || divisor < 1) return null

  if (!ts.isIfStatement(arrayIf) || !callOf(ts, arrayIf.expression, source, 'Array.isArray', [parameter])) return false
  const arrayResult = returnExpression(ts, arrayIf.thenStatement)
  if (!callOf(ts, arrayResult, source, `${parameter}.map`, [pseudo.transformFunction])) return false

  if (!ts.isIfStatement(objectIf)) return false
  const objectCondition = unwrap(ts, objectIf.expression)
  if (!ts.isBinaryExpression(objectCondition) || objectCondition.operatorToken.kind !== ts.SyntaxKind.AmpersandAmpersandToken
    || objectCondition.left.getText(source) !== parameter || !typeEquals(ts, objectCondition.right, parameter, 'object')) return false
  const objectResult = returnExpression(ts, objectIf.thenStatement)
  if (!ts.isCallExpression(objectResult) || objectResult.expression.getText(source) !== 'Object.fromEntries' || objectResult.arguments.length !== 1) return false
  const map = unwrap(ts, objectResult.arguments[0])
  if (!ts.isCallExpression(map) || !ts.isPropertyAccessExpression(map.expression) || map.expression.name.text !== 'map'
    || map.arguments.length !== 1 || !callOf(ts, map.expression.expression, source, 'Object.entries', [parameter])) return false
  const mapper = unwrap(ts, map.arguments[0])
  if (!ts.isArrowFunction(mapper) || mapper.parameters.length !== 1 || !ts.isArrayBindingPattern(mapper.parameters[0].name)
    || mapper.parameters[0].name.elements.length !== 2) return false
  const [keyBinding, itemBinding] = mapper.parameters[0].name.elements
  if (!ts.isBindingElement(keyBinding) || !ts.isIdentifier(keyBinding.name) || !ts.isBindingElement(itemBinding) || !ts.isIdentifier(itemBinding.name)) return false
  const pair = unwrap(ts, mapper.body)
  if (!ts.isArrayLiteralExpression(pair) || pair.elements.length !== 2 || pair.elements[0].getText(source) !== keyBinding.name.text
    || !directCallOf(ts, pair.elements[1], pseudo.transformFunction, itemBinding.name.text)) return null
  const fallbackResult = returnExpression(ts, fallback)
  if (!fallbackResult || fallbackResult.getText(source) !== parameter) return null
  const prefix = stringResult.head.text
  const marker = stringValue(ts, repeat.expression.expression)
  const suffix = stringResult.templateSpans[1].literal.text
  return { apply: (value) => `${prefix}${value}${marker.repeat(Math.max(minimum, Math.ceil(value.length / divisor)))}${suffix}` }
}

function verifyPseudoTransform(ts, source, app) {
  const pseudo = app.pseudo
  if (source.parseDiagnostics.length > 0) return { verified: false, reason: 'resource source contains parse diagnostics' }
  if (!findVariable(ts, source, pseudo.sourceVariable)) return { verified: false, reason: 'configured default locale must have one unique variable declaration' }
  if (!findFunction(ts, source, pseudo.transformFunction)) return { verified: false, reason: 'configured pseudo transform must have one unique function declaration' }
  if (pseudo.outputVariable && !findVariable(ts, source, pseudo.outputVariable)) return { verified: false, reason: 'configured pseudo output must have one unique variable declaration' }
  if (pseudo.textTransformFunction && !findFunction(ts, source, pseudo.textTransformFunction)) return { verified: false, reason: 'configured pseudo text transform must have one unique function declaration' }
  const dependencies = new Set(['Object', 'Array', 'Math', pseudo.transformFunction, pseudo.textTransformFunction].filter(Boolean))
  const functions = [findFunction(ts, source, pseudo.transformFunction), pseudo.textTransformFunction && findFunction(ts, source, pseudo.textTransformFunction)].filter(Boolean)
  const shadowed = ['Object', 'Array', 'Math'].filter((name) => topLevelBindings(ts, source, name).length > 0)
  if (functions.some((declaration) => functionHasBinding(ts, declaration, dependencies))) shadowed.push('local binding')
  if (shadowed.length > 0) return { verified: false, reason: `pseudo transform dependency is shadowed: ${shadowed.join(', ')}` }
  if (mutatesPseudoBuiltins(ts, source)) return { verified: false, reason: 'pseudo transform builtin dependency is mutated' }
  if (referencesPseudoBuiltinsOutside(ts, source, functions)) return { verified: false, reason: 'pseudo transform builtin dependency is referenced outside verified transform declarations' }
  const output = verifyPseudoOutput(ts, source, app)
  if (!output) return { verified: false, reason: 'configured pseudo output is not bound to the default locale transform' }
  if (!verifyPseudoModuleEnvelope(ts, source, app, output, functions)) return { verified: false, reason: 'resource module contains executable statements outside the supported pseudo proof envelope' }
  if (pseudo.transformKind === 'placeholder-safe-character-expansion') {
    const proof = verifyCharacterTree(ts, source, pseudo)
    return proof
      ? { verified: true, apply: proof.apply }
      : { verified: false, reason: 'character-expansion transform is outside the supported pure-function AST shape' }
  }
  if (pseudo.transformKind === 'suffix-repeat-expansion') {
    const proof = verifySuffixTree(ts, source, pseudo)
    return proof
      ? { verified: true, apply: proof.apply }
      : { verified: false, reason: 'suffix-expansion transform is outside the supported pure-function AST shape' }
  }
  return { verified: false, reason: 'unsupported transform kind' }
}

function resourceTree(ts, source, declaration, app, file, add) {
  const leaves = new Map()
  function visit(node, prefix) {
    const value = unwrap(ts, node)
    if (ts.isObjectLiteralExpression(value)) {
      const segments = new Set()
      for (const property of value.properties) {
        if (!ts.isPropertyAssignment(property)) {
          throw new AuditConfigurationError(`resource ${declaration.name.getText(source)} contains an unsupported spread or shorthand in ${file}`)
        }
        const segment = propertyName(ts, property.name)
        if (segment === null) throw new AuditConfigurationError(`resource contains a computed key in ${file}`)
        const point = locationOf(source, property.name)
        if (segments.has(segment)) {
          add({ code: 'DUPLICATE_RESOURCE_KEY', app, file, ...point, message: 'Duplicate resource key segment is not allowed', evidence: prefix ? `${prefix}.${segment}` : segment })
          continue
        }
        segments.add(segment)
        if (FORBIDDEN_RESOURCE_SEGMENTS.has(segment)) {
          add({ code: 'RESOURCE_KEY_FORBIDDEN', app, file, ...point, message: 'Prototype-sensitive resource key segment is forbidden', evidence: prefix ? `${prefix}.${segment}` : segment })
        }
        if (segment.includes('.')) {
          add({ code: 'RESOURCE_KEY_CONTAINS_DOT', app, file, ...point, message: 'Resource key segments may not contain dots', evidence: segment })
        }
        const key = prefix ? `${prefix}.${segment}` : segment
        visit(property.initializer, key)
      }
      return
    }
    const point = locationOf(source, value)
    if (!ts.isStringLiteralLike(value)) {
      add({ code: 'RESOURCE_VALUE_NOT_LITERAL', app, file, ...point, message: 'Translation leaves must be static strings', evidence: prefix })
      leaves.set(prefix, { value: null, node: value })
      return
    }
    leaves.set(prefix, { value: value.text, node: value })
  }
  visit(declaration.initializer, '')
  return leaves
}

function placeholderSignature(value) {
  const counts = new Map()
  for (const placeholder of value.match(PLACEHOLDER) ?? []) counts.set(placeholder, (counts.get(placeholder) ?? 0) + 1)
  return JSON.stringify([...counts].sort(([left], [right]) => left.localeCompare(right, 'en')))
}

function namespaceBindings(ts, source, defaultNamespace) {
  const hookCallees = new Set()
  const transTags = new Set()
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteralLike(statement.moduleSpecifier)
      || statement.moduleSpecifier.text !== 'react-i18next' || !statement.importClause) continue
    const named = statement.importClause.namedBindings
    if (named && ts.isNamespaceImport(named)) {
      hookCallees.add(`${named.name.text}.useTranslation`)
      transTags.add(`${named.name.text}.Trans`)
    }
    if (named && ts.isNamedImports(named)) {
      for (const element of named.elements) {
        const imported = element.propertyName?.text ?? element.name.text
        if (imported === 'useTranslation') hookCallees.add(element.name.text)
        if (imported === 'Trans') transTags.add(element.name.text)
      }
    }
  }
  const bindings = new Map()
  function visit(node) {
    if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name) && node.initializer && ts.isCallExpression(node.initializer)
      && hookCallees.has(node.initializer.expression.getText(source))) {
      const namespace = node.initializer.arguments[0]
      const resolved = namespace && ts.isStringLiteralLike(namespace) ? namespace.text : defaultNamespace
      for (const element of node.name.elements) {
        const imported = element.propertyName?.getText(source) ?? element.name.getText(source)
        if (imported === 't' && ts.isIdentifier(element.name)) bindings.set(element.name.text, resolved)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return { bindings, transTags }
}

function finiteStrings(ts, node, source, maximum = 100) {
  const value = unwrap(ts, node)
  if (ts.isStringLiteralLike(value)) return [value.text]
  if (ts.isConditionalExpression(value)) {
    const combined = [...(finiteStrings(ts, value.whenTrue, source, maximum) ?? []), ...(finiteStrings(ts, value.whenFalse, source, maximum) ?? [])]
    return combined.length > 0 && combined.length <= maximum ? [...new Set(combined)] : null
  }
  if (ts.isTemplateExpression(value)) {
    let values = [value.head.text]
    for (const span of value.templateSpans) {
      const choices = finiteStrings(ts, span.expression, source, maximum)
      if (!choices) return null
      values = values.flatMap((prefix) => choices.map((choice) => `${prefix}${choice}${span.literal.text}`))
      if (values.length > maximum) return null
    }
    return [...new Set(values)]
  }
  if (ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = finiteStrings(ts, value.left, source, maximum)
    const right = finiteStrings(ts, value.right, source, maximum)
    if (!left || !right || left.length * right.length > maximum) return null
    return [...new Set(left.flatMap((prefix) => right.map((suffix) => `${prefix}${suffix}`)))]
  }
  return null
}

function dynamicPrefix(ts, node, source) {
  const value = unwrap(ts, node)
  if (ts.isTemplateExpression(value)) return value.head.text
  if (ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = finiteStrings(ts, value.left, source)
    return left?.length === 1 ? left[0] : ''
  }
  return ''
}

function normalizeKey(app, key, namespace) {
  const colon = key.indexOf(':')
  if (colon >= 0) return `${key.slice(0, colon)}.${key.slice(colon + 1)}`
  return app.namespaceFromTopLevel && namespace ? `${namespace}.${key}` : key
}

function stringValue(ts, node) {
  const value = node ? unwrap(ts, node) : null
  return value && ts.isStringLiteralLike(value) ? value.text : null
}

function jsxAttribute(ts, attributes, name) {
  return attributes.properties.find((property) => ts.isJsxAttribute(property) && property.name.getText() === name)
}

function attributeExpression(ts, attribute) {
  if (!attribute?.initializer) return null
  if (ts.isStringLiteral(attribute.initializer)) return attribute.initializer
  return ts.isJsxExpression(attribute.initializer) ? attribute.initializer.expression : null
}

function containsRawError(ts, node, source) {
  let found = false
  function visit(child) {
    if (ts.isPropertyAccessExpression(child) && child.name.text === 'message') found = true
    if (ts.isElementAccessExpression(child) && stringValue(ts, child.argumentExpression) === 'message') found = true
    if (ts.isCallExpression(child) && child.expression.getText(source) === 'String'
      && child.arguments.some((argument) => /(?:error|err|response)/i.test(argument.getText(source)))) found = true
    if (!found) ts.forEachChild(child, visit)
  }
  visit(node)
  return found
}

function literalKind(value) {
  if (HAN_TEXT.test(value) && ASCII_TEXT.test(value)) return 'mixed'
  if (HAN_TEXT.test(value)) return 'zh'
  return ASCII_TEXT.test(value) ? 'en' : 'symbol'
}

function scanSource(ts, source, app, relative, declarations, expired, used, apiCodes, add) {
  const { bindings, transTags } = namespaceBindings(ts, source, app.defaultNamespace)
  const formatterEntry = app.formatterEntrypoints.includes(relative)
  const tsx = relative.endsWith('.tsx')

  function addVisible(node, value, context) {
    const normalized = value.trim().replace(/\s+/g, ' ')
    if (!normalized || !USER_TEXT.test(normalized)) return
    const point = locationOf(source, node)
    add({
      code: `VISIBLE_LITERAL_${literalKind(normalized).toUpperCase()}`, app: app.name, file: relative, ...point,
      message: `User-visible ${literalKind(normalized)} literal must come from locale resources (${context})`, evidence: normalized,
    })
  }

  function recordKey(node, raw, namespace) {
    const key = normalizeKey(app, raw, namespace)
    const point = locationOf(source, node)
    used.set(key, [...(used.get(key) ?? []), { file: relative, ...point }])
  }

  function recordKeyExpression(expression, namespace) {
    const values = finiteStrings(ts, expression, source)
    if (values) {
      values.forEach((value) => recordKey(expression, value, namespace))
      return
    }
    const rawPrefix = dynamicPrefix(ts, expression, source)
    const prefix = normalizeKey(app, rawPrefix, namespace)
    const declaration = declarations.find((item) => !expired.has(item)
      && item.app === app.name && item.file === relative && item.prefix === prefix)
    if (declaration) declaration.keys.forEach((key) => recordKey(expression, key, null))
    else {
      const point = locationOf(source, expression)
      add({
        code: 'DYNAMIC_KEY_UNDECLARED', app: app.name, file: relative, ...point,
        message: 'Dynamic translation keys require an exact, reviewed enumeration',
        evidence: `${prefix || '<unknown>'}: ${expression.getText(source).slice(0, 200)}`,
      })
    }
  }

  function translationCall(node) {
    if (!ts.isCallExpression(node) || node.arguments.length === 0) return false
    let namespace = app.defaultNamespace
    if (ts.isIdentifier(node.expression) && bindings.has(node.expression.text)) {
      namespace = bindings.get(node.expression.text) ?? app.defaultNamespace
    } else if (ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 't') {
      namespace = app.defaultNamespace
    } else return false
    recordKeyExpression(node.arguments[0], namespace)
    return true
  }

  function inspectIntl(node, callee, argumentsList) {
    if (!INTL_FORMATTERS.has(callee) && !LOCALE_METHODS.has(callee)) return
    const point = locationOf(source, node)
    const first = argumentsList[0]
    if (!first || first.kind === ts.SyntaxKind.NullKeyword || (ts.isIdentifier(first) && first.text === 'undefined')) {
      add({ code: 'LOCALE_IMPLICIT_FORMATTER', app: app.name, file: relative, ...point, message: 'Locale-aware formatter must receive an explicit locale', evidence: node.getText(source).slice(0, 200) })
    } else if (ts.isStringLiteralLike(first)) {
      add({ code: 'HARDCODED_LOCALE', app: app.name, file: relative, ...point, message: 'Locale must come from the active locale', evidence: first.text })
    }
    if (!formatterEntry) {
      add({ code: 'LOCALE_FORMATTER_OUTSIDE_ENTRYPOINT', app: app.name, file: relative, ...point, message: 'User formatting must use an approved formatter entrypoint', evidence: node.getText(source).slice(0, 200) })
    }
    const options = INTL_FORMATTERS.has(callee) ? unwrap(ts, argumentsList[1]) : null
    if (options && ts.isObjectLiteralExpression(options)) {
      for (const property of options.properties) {
        if (!ts.isPropertyAssignment(property)) continue
        const name = propertyName(ts, property.name)
        const value = stringValue(ts, property.initializer)
        if (name === 'currency' && value) {
          const itemPoint = locationOf(source, property)
          add({ code: 'HARDCODED_CURRENCY', app: app.name, file: relative, ...itemPoint, message: 'Currency must come from a documented formatting contract', evidence: value })
        }
        if (name === 'timeZone' && value) {
          const itemPoint = locationOf(source, property)
          add({ code: 'HARDCODED_TIMEZONE', app: app.name, file: relative, ...itemPoint, message: 'Time zone must come from a documented formatting contract', evidence: value })
        }
      }
    }
  }

  function visit(node) {
    translationCall(node)

    if (ts.isCallExpression(node)) {
      const callee = node.expression.getText(source)
      if (ts.isPropertyAccessExpression(node.expression)) {
        inspectIntl(node, INTL_FORMATTERS.has(callee) ? callee : node.expression.name.text, node.arguments)
      }
      if (tsx && !formatterEntry && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'toFixed') {
        const point = locationOf(source, node)
        add({ code: 'NUMBER_FORMATTER_BYPASS', app: app.name, file: relative, ...point, message: 'toFixed is not locale-aware for user-visible formatting', evidence: node.getText(source).slice(0, 200) })
      }
      if (/^(?:message|notification)(?:Api)?\.(?:error|info|open|success|warning)$/.test(callee) && node.arguments[0]) {
        const value = stringValue(ts, node.arguments[0])
        if (value !== null) addVisible(node.arguments[0], value, callee)
        if (containsRawError(ts, node.arguments[0], source)) {
          const point = locationOf(source, node.arguments[0])
          add({ code: 'RAW_ERROR_RENDER', app: app.name, file: relative, ...point, message: 'Raw server or exception messages must not be rendered', evidence: node.arguments[0].getText(source).slice(0, 200) })
        }
      }
      if (!formatterEntry && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'format'
        && node.arguments[0] && ts.isStringLiteralLike(node.arguments[0]) && DATE_PATTERN.test(node.arguments[0].text)) {
        const point = locationOf(source, node)
        add({ code: 'DATE_PATTERN_OUTSIDE_ENTRYPOINT', app: app.name, file: relative, ...point, message: 'Hard-coded date patterns must be centralized in locale-aware formatters', evidence: node.arguments[0].text })
      }
    }

    if (ts.isNewExpression(node)) inspectIntl(node, node.expression.getText(source), node.arguments ?? [])

    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && ts.isStringLiteralLike(unwrap(ts, node.initializer))) {
      const value = stringValue(ts, node.initializer)
      const point = locationOf(source, node)
      if (/time_?zone/i.test(node.name.text) || /timeZone/.test(node.name.text)) {
        add({ code: 'HARDCODED_TIMEZONE', app: app.name, file: relative, ...point, message: 'Time-zone constants require a documented formatting contract', evidence: value })
      }
      if (/currency/i.test(node.name.text)) {
        add({ code: 'HARDCODED_CURRENCY', app: app.name, file: relative, ...point, message: 'Currency constants require a documented formatting contract', evidence: value })
      }
    }

    if (tsx && ts.isJsxText(node)) addVisible(node, node.text, 'JSX text')
    if (tsx && ts.isJsxAttribute(node) && VISIBLE_PROPERTIES.has(node.name.getText(source))) {
      const expression = attributeExpression(ts, node)
      const value = stringValue(ts, expression)
      if (value !== null) addVisible(expression, value, `JSX ${node.name.getText(source)}`)
      if (expression && containsRawError(ts, expression, source)) {
        const point = locationOf(source, expression)
        add({ code: 'RAW_ERROR_RENDER', app: app.name, file: relative, ...point, message: 'Raw server or exception messages must not be rendered', evidence: expression.getText(source).slice(0, 200) })
      }
    }
    if (tsx && ts.isJsxExpression(node) && node.expression && containsRawError(ts, node.expression, source)) {
      const point = locationOf(source, node.expression)
      add({ code: 'RAW_ERROR_RENDER', app: app.name, file: relative, ...point, message: 'Raw server or exception messages must not be rendered', evidence: node.expression.getText(source).slice(0, 200) })
    }
    if (tsx && ts.isJsxExpression(node) && !ts.isJsxAttribute(node.parent) && node.expression) {
      const values = finiteStrings(ts, node.expression, source)
      if (values) values.forEach((value) => addVisible(node.expression, value, 'JSX expression'))
    }
    if (tsx && ts.isPropertyAssignment(node) && VISIBLE_PROPERTIES.has(propertyName(ts, node.name))) {
      const value = stringValue(ts, node.initializer)
      if (value !== null) addVisible(node.initializer, value, `UI property ${propertyName(ts, node.name)}`)
      if (containsRawError(ts, node.initializer, source)) {
        const point = locationOf(source, node.initializer)
        add({ code: 'RAW_ERROR_RENDER', app: app.name, file: relative, ...point, message: 'Raw server or exception messages must not be rendered', evidence: node.initializer.getText(source).slice(0, 200) })
      }
    }

    if ((ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) && transTags.has(node.tagName.getText(source))) {
      const keyAttribute = jsxAttribute(ts, node.attributes, 'i18nKey')
      const keyExpression = attributeExpression(ts, keyAttribute)
      const namespaceValue = stringValue(ts, attributeExpression(ts, jsxAttribute(ts, node.attributes, 'ns'))) ?? app.defaultNamespace
      if (keyExpression) recordKeyExpression(keyExpression, namespaceValue)
    }

    if (ts.isBinaryExpression(node)) {
      const pairs = [[node.left, node.right], [node.right, node.left]]
      for (const [candidate, literal] of pairs) {
        if (ts.isPropertyAccessExpression(candidate) && candidate.name.text === 'code' && ts.isStringLiteralLike(literal)) apiCodes.add(literal.text)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
}

function englishClassification(value) {
  if (!ASCII_TEXT.test(value) || HAN_TEXT.test(value)) return null
  const withoutPlaceholders = value.replace(PLACEHOLDER, '').trim()
  if (!ASCII_TEXT.test(withoutPlaceholders)) return null
  if (/^[A-Za-z0-9._/+:#-]+$/.test(withoutPlaceholders)) return 'contract-candidate'
  return /[A-Za-z]+\s+[A-Za-z]+/.test(withoutPlaceholders) ? 'natural-language' : 'review'
}

function summarize(findings, resources, scannedFiles, baselineFingerprints, baselineProvided) {
  findings.sort(sortFindings)
  for (const finding of findings) {
    finding.suggestion ??= SUGGESTIONS[finding.code] ?? 'Review the finding and move user-visible behavior behind an explicit locale contract.'
    finding.fingerprint = findingFingerprint(finding)
  }
  const violations = findings.filter((item) => item.severity === 'error' && !item.suppressed)
  const current = new Set(violations.map((item) => item.fingerprint))
  const newViolations = baselineProvided ? violations.filter((item) => !baselineFingerprints.has(item.fingerprint)) : violations
  const byCodeMap = new Map()
  for (const finding of findings) byCodeMap.set(finding.code, (byCodeMap.get(finding.code) ?? 0) + 1)
  const byCode = [...byCodeMap].sort(([left], [right]) => left.localeCompare(right, 'en')).map(([code, count]) => ({ code, count }))
  return {
    scannedFiles,
    resources,
    findingCount: findings.length,
    violationCount: violations.length,
    warningCount: findings.filter((item) => item.severity === 'warning').length,
    suppressedCount: findings.filter((item) => item.suppressed).length,
    newViolationCount: newViolations.length,
    baselineKnownViolationCount: violations.length - newViolations.length,
    resolvedBaselineCount: baselineProvided ? [...baselineFingerprints].filter((fingerprint) => !current.has(fingerprint)).length : 0,
    byCode,
  }
}

async function baselineFingerprints(file) {
  if (!file) return { provided: false, fingerprints: new Set() }
  const metadata = await lstat(file).catch(() => null)
  if (!metadata || !metadata.isFile() || metadata.isSymbolicLink()) throw new AuditConfigurationError('baseline must be a regular file')
  if (metadata.size > MAX_BASELINE_BYTES) throw new AuditConfigurationError(`baseline exceeds hard size limit (${MAX_BASELINE_BYTES} bytes)`)
  let report
  try {
    report = JSON.parse(await readFile(file, 'utf8'))
  } catch (error) {
    throw new AuditConfigurationError(`baseline is not valid JSON: ${error instanceof Error ? error.message : 'unknown error'}`)
  }
  if (report?.schemaVersion !== 1 || !Array.isArray(report.findings)) throw new AuditConfigurationError('baseline must be an i18n audit schemaVersion 1 report')
  return {
    provided: true,
    fingerprints: new Set(report.findings
      .filter((item) => item?.severity === 'error' && !item?.suppressed && typeof item?.fingerprint === 'string')
      .map((item) => item.fingerprint)),
  }
}

export async function auditRepository({ root, configPath, baselinePath, today = new Date().toISOString().slice(0, 10), typescript }) {
  const absoluteRoot = path.resolve(root)
  await rejectSymlinkSegments(absoluteRoot, 'repository root')
  const resolvedRoot = await realpath(absoluteRoot)
  if (!validDate(today)) throw new AuditConfigurationError('today must be a valid YYYY-MM-DD calendar date')
  const configText = await readFile(configPath, 'utf8').catch(() => { throw new AuditConfigurationError('config file is missing') })
  let config
  try {
    config = JSON.parse(configText)
  } catch {
    throw new AuditConfigurationError('config file is not valid JSON')
  }
  validateConfiguration(config, resolvedRoot)
  const ts = await loadTypeScript(resolvedRoot, config, typescript)
  const baseline = await baselineFingerprints(baselinePath)
  const collector = makeCollector(config, today)
  const resourceSummary = []
  let scannedFiles = 0

  for (const app of config.apps) {
    const resource = canonicalPath(resolvedRoot, app.resourceFile, `${app.name}.resourceFile`)
    await rejectSymlinkSegments(resource.absolute, `${app.name}.resourceFile`)
    const realResource = await realpath(resource.absolute).catch(() => null)
    if (!realResource || (realResource !== resolvedRoot && !realResource.startsWith(`${resolvedRoot}${path.sep}`))) {
      throw new AuditConfigurationError(`resource file is missing or escapes the repository: ${resource.relative}`)
    }
    const resourceText = await readLimited(realResource, resource.relative, config.maxFileBytes)
    const resourceSource = parseSource(ts, resource.relative, resourceText)
    const defaultDeclaration = findVariable(ts, resourceSource, app.defaultVariable)
    const secondaryDeclaration = findVariable(ts, resourceSource, app.secondaryVariable)
    if (!defaultDeclaration?.initializer || !secondaryDeclaration?.initializer) {
      throw new AuditConfigurationError(`resource variables ${app.defaultVariable}/${app.secondaryVariable} are missing in ${resource.relative}`)
    }
    const zh = resourceTree(ts, resourceSource, defaultDeclaration, app.name, resource.relative, collector.add)
    const en = resourceTree(ts, resourceSource, secondaryDeclaration, app.name, resource.relative, collector.add)
    const pseudoProof = verifyPseudoTransform(ts, resourceSource, app)
    let pseudoVerified = pseudoProof.verified
    if (!pseudoProof.verified) {
      collector.add({ code: 'PSEUDO_TRANSFORM_UNVERIFIED', app: app.name, file: resource.relative, line: 1, column: 1, message: 'Application pseudo transform could not be conservatively verified', evidence: pseudoProof.reason })
    }
    for (const [key, item] of zh) {
      if (item.value === '') {
        const point = locationOf(resourceSource, item.node)
        collector.add({ code: 'ZH_VALUE_EMPTY', app: app.name, file: resource.relative, ...point, message: 'Default Chinese translation may not be empty', evidence: key })
      }
      if (typeof item.value === 'string') {
        const secondary = en.get(key)
        if (typeof secondary?.value === 'string' && placeholderSignature(item.value) !== placeholderSignature(secondary.value)) {
          const point = locationOf(resourceSource, item.node)
          collector.add({ code: 'PLACEHOLDER_LOCALE_MISMATCH', app: app.name, file: resource.relative, ...point, message: 'zh-CN and en-US placeholder names and occurrence counts differ', evidence: key })
        }
        const classification = englishClassification(item.value)
        if (classification) {
          const point = locationOf(resourceSource, item.node)
          collector.add({
            code: classification === 'natural-language' ? 'ZH_VALUE_ENGLISH' : 'ZH_ASCII_VALUE_REVIEW',
            severity: classification === 'natural-language' ? 'error' : 'warning',
            app: app.name, file: resource.relative, ...point,
            message: classification === 'natural-language' ? 'Default Chinese resource contains English natural language' : 'ASCII-only Chinese resource needs stable-contract review',
            evidence: `${key}=${item.value}`,
          })
        }
        if (pseudoProof.verified) {
          const pseudo = pseudoProof.apply(item.value)
          if (placeholderSignature(pseudo) !== placeholderSignature(item.value)) {
            pseudoVerified = false
            const point = locationOf(resourceSource, item.node)
            collector.add({ code: 'PSEUDO_PLACEHOLDER_MISMATCH', app: app.name, file: resource.relative, ...point, message: 'Application pseudo transform changed interpolation placeholders', evidence: key })
          }
          if (item.value.replace(PLACEHOLDER, '').trim() && pseudo.length / Math.max(item.value.length, 1) < app.pseudo.minimumExpansionRatio) {
            pseudoVerified = false
            const point = locationOf(resourceSource, item.node)
            collector.add({ code: 'PSEUDO_EXPANSION_TOO_SMALL', app: app.name, file: resource.relative, ...point, message: 'Application pseudo text does not meet the configured expansion ratio', evidence: key })
          }
        }
      }
      if (!en.has(key)) {
        const point = locationOf(resourceSource, item.node)
        collector.add({ code: 'KEY_MISSING_EN', app: app.name, file: resource.relative, ...point, message: 'English locale is missing a default-locale key', evidence: key })
      }
    }
    for (const [key, item] of en) {
      if (!zh.has(key)) {
        const point = locationOf(resourceSource, item.node)
        collector.add({ code: 'KEY_EXTRA_EN', app: app.name, file: resource.relative, ...point, message: 'English locale has a key absent from zh-CN', evidence: key })
      }
    }

    const files = []
    for (const sourceRootItem of app.sourceRoots) {
      const rootItem = canonicalPath(resolvedRoot, sourceRootItem, `${app.name}.sourceRoot`)
      await rejectSymlinkSegments(rootItem.absolute, `${app.name}.sourceRoot`)
      const realSourceRoot = await realpath(rootItem.absolute).catch(() => null)
      if (!realSourceRoot || (realSourceRoot !== resolvedRoot && !realSourceRoot.startsWith(`${resolvedRoot}${path.sep}`))) {
        throw new AuditConfigurationError(`source root is missing or escapes the repository: ${rootItem.relative}`)
      }
      files.push(...await sourceFiles(resolvedRoot, realSourceRoot, config.maxFileBytes))
    }
    files.sort((left, right) => left.relative.localeCompare(right.relative, 'en'))
    const uniqueFiles = files.filter((item, index) => index === 0 || item.relative !== files[index - 1].relative)
    const used = new Map()
    const apiCodes = new Set()
    for (const file of uniqueFiles) {
      const text = file.relative === resource.relative ? resourceText : await readLimited(file.absolute, file.relative, config.maxFileBytes)
      const source = file.relative === resource.relative ? resourceSource : parseSource(ts, file.relative, text)
      if (source.parseDiagnostics.length > 0) {
        const diagnostic = source.parseDiagnostics[0]
        const point = diagnostic.start === undefined ? { line: 1, column: 1 } : locationOf(source, { getStart: () => diagnostic.start })
        collector.add({ code: 'SOURCE_PARSE_ERROR', app: app.name, file: file.relative, ...point, message: 'TypeScript source could not be parsed completely', evidence: ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ') })
      }
      scanSource(ts, source, app, file.relative, config.dynamicKeys, collector.expired, used, apiCodes, collector.add)
    }
    scannedFiles += uniqueFiles.length

    for (const [key, usages] of used) {
      const first = usages[0]
      if (!zh.has(key)) collector.add({ code: 'KEY_MISSING_ZH', app: app.name, ...first, message: 'Used translation key is missing from zh-CN', evidence: key })
      if (!en.has(key)) collector.add({ code: 'KEY_MISSING_EN', app: app.name, ...first, message: 'Used translation key is missing from en-US', evidence: key })
    }
    for (const [key, item] of zh) {
      if (!used.has(key)) {
        const point = locationOf(resourceSource, item.node)
        collector.add({ code: 'KEY_UNUSED_ZH', severity: 'warning', app: app.name, file: resource.relative, ...point, message: 'Default-locale key has no statically proven caller', evidence: key })
      }
    }
    for (const code of [...apiCodes].sort((left, right) => left.localeCompare(right, 'en'))) {
      const suffix = `errors.${code}`
      const mapped = [...zh.keys()].some((key) => key === suffix || key.endsWith(`.${suffix}`))
      if (!mapped) collector.add({ code: 'ERROR_CODE_UNMAPPED', app: app.name, file: resource.relative, line: 1, column: 1, message: 'Stable API error code has no zh-CN resource mapping', evidence: code })
    }
    resourceSummary.push({
      app: app.name, zhCNKeys: zh.size, enUSKeys: en.size,
      pseudoVerified, pseudoDerivedKeys: pseudoVerified ? zh.size : 0,
      pseudoMinimumExpansionRatio: app.pseudo.minimumExpansionRatio,
      staticallyUsedKeys: used.size, stableErrorCodesObserved: apiCodes.size,
    })
  }

  collector.applyAllowlist()
  const summary = summarize(collector.findings, resourceSummary, scannedFiles, baseline.fingerprints, baseline.provided)
  return {
    schemaVersion: 1,
    status: summary.newViolationCount > 0 ? 'violations' : 'pass',
    baselineMode: baseline.provided,
    summary,
    findings: collector.findings,
    exitCode: summary.newViolationCount > 0 ? 1 : 0,
  }
}

export function configurationErrorReport(error) {
  const message = error instanceof Error ? error.message : 'unknown configuration error'
  const finding = {
    severity: 'error', suppressed: false, code: 'CONFIGURATION_ERROR', app: 'repository',
    file: '.', line: 1, column: 1, message, evidence: message,
  }
  finding.fingerprint = findingFingerprint(finding)
  finding.suggestion = 'Fix the configuration or input boundary and rerun the complete audit.'
  return {
    schemaVersion: 1,
    status: 'configuration_error',
    baselineMode: false,
    summary: {
      scannedFiles: 0, resources: [], findingCount: 1, violationCount: 1, warningCount: 0,
      suppressedCount: 0, newViolationCount: 0, baselineKnownViolationCount: 0, resolvedBaselineCount: 0,
      byCode: [{ code: 'CONFIGURATION_ERROR', count: 1 }],
    },
    findings: [finding],
    exitCode: 2,
  }
}

export function textReport(report, top = 20) {
  const lines = [
    'CDNCA i18n audit',
    `status: ${report.status}`,
    `scanned files: ${report.summary.scannedFiles}`,
    `findings: ${report.summary.findingCount}`,
    `violations: ${report.summary.violationCount}`,
    `new violations: ${report.summary.newViolationCount}`,
    `warnings: ${report.summary.warningCount}`,
    `suppressed: ${report.summary.suppressedCount}`,
    `baseline mode: ${report.baselineMode ? 'yes' : 'no'}`,
    '',
    `Top ${top} finding categories:`,
    ...report.summary.byCode.slice().sort((left, right) => right.count - left.count || left.code.localeCompare(right.code, 'en'))
      .slice(0, top).map((item) => `  ${item.code}: ${item.count}`),
    '',
    'First findings:',
    ...report.findings.filter((item) => !item.suppressed).slice(0, top)
      .map((item) => `  ${item.severity.toUpperCase()} ${item.code} ${item.file}:${item.line}:${item.column} ${item.evidence}`),
    '',
  ]
  return `${lines.join('\n')}\n`
}

export async function writeReports(report, outputDirectory) {
  await mkdir(outputDirectory, { recursive: true })
  await Promise.all([
    writeFile(path.join(outputDirectory, 'report.json'), `${JSON.stringify(report, null, 2)}\n`),
    writeFile(path.join(outputDirectory, 'report.txt'), textReport(report)),
  ])
}
