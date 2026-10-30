import fs from 'node:fs'
import { register } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url))
export const defaultSourceRoot = path.resolve(scriptDirectory, '../apps/web/src')
export const supportedLocales = ['zh-CN', 'en-US', 'qps-ploc']

const translationFiles = new Set([
  path.normalize('i18n/resources.ts'),
  path.normalize('pages/node-scheduling/messages.ts'),
])

const visibleAttributePattern =
  /(?:aria-label|label|placeholder|title|message|description|okText|cancelText|alt|tooltip|emptyText)\s*=\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["']/gu
const visibleTextPattern = /<[A-Za-z][^>]*>\s*([^<>{}\r\n]*[A-Za-z\p{Script=Han}][^<>{}\r\n]*)\s*<\/[A-Za-z][^>]*>/gu
const visibleObjectPropertyPattern =
  /(?:^|[,{]\s*)(?:ariaLabel|label|placeholder|title|message|description|okText|cancelText|alt|tooltip|emptyText)\s*:\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["']/gmu
const visibleExpressionPattern =
  /<[A-Za-z][^>]*>\s*\{\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["']\s*\}\s*<\/[A-Za-z][^>]*>/gu
const visibleConditionalExpressionPattern =
  /<[A-Za-z][^>]*>\s*\{\s*(?!t\s*\()[^{}]*\?\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["']\s*:\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["'][^{}]*\}\s*<\/[A-Za-z][^>]*>/gu
const cjkPattern = /[\p{Script=Han}]/u
const protectedTokenPattern = /({{[^}]+}}|<[^>]+>)/g
const translationKeyPattern = /^(?:[a-z][A-Za-z0-9_]*\.)+[A-Za-z0-9_]+$/

const allowedVisibleLiterals = new Set([
  'cdnca',
  'DNS API',
  'UUID',
  'JA4',
  'MD5',
  'HMAC-SHA256',
  'CNAME',
  'allow_origin',
  'allow_methods',
  'allow_headers',
  'expose_headers',
  'allow_credentials',
  'max_age',
  'Websocket',
  '2001:db8::10',
  // 以下与 apps/web/src/tests/i18nSafety.test.ts 白名单保持一致
  // 协议与算法标识
  'IP', 'Http', 'HTTP', 'HTTPS', 'Stream', 'Worker', 'TTL', 'zerossl', 'lets',
  'IPv6', 'TCP', 'PING', 'ID',
  // 带宽单位
  'Mbps', 'Gbps', 'GB',
  // 日志级别枚举
  'info', 'debug',
  // nginx 指令名与取值，属于配置语法本身，不翻译
  'server', 'server_tokens', 'worker_processes', 'worker_connections', 'worker_rlimit_nofile',
  'worker_shutdown_timeout', 'keepalive_requests', 'keepalive_timeout', 'log_not_found',
  'default_type', 'large_client_header_buffers', 'client_max_body_size', 'client_body_buffer_size',
  'server_names_hash_max_size', 'server_names_hash_bucket_size', 'gzip_min_length',
  'gzip_comp_level', 'gzip_http_version', 'gzip_vary', 'gzip types', 'proxy_http_version',
  'proxy_connect_timeout', 'proxy_send_timeout', 'proxy_read_timeout', 'proxy_buffering',
  'proxy_request_buffering', 'proxy_max_temp_file_size', 'proxy_next_upstream',
  'proxy_cache_dir', 'proxy_cache_max_size', 'proxy_cache_methods', 'proxy_timeout',
  'ocsp_stapling',
  // 证书颁发机构产品名（"Let's Encrypt" 被引号截成 "Let"）
  'Let', 'ZeroSSL', 'Google Trust Services',
  // 输入示例：主机名、接口地址、通配域名、扩展名、PEM 头、nginx 变量、cookie 名，按原样输入
  'edge-01.cdnca.com', 'https://api.dnspup.com/v1/tools/ip-intel-snapshot', '*.example.com', 'jpg',
  '-----BEGIN CERTIFICATE-----', '$cookie_uid$uri', 'cdnca_route',
])

function leafEntries(value, prefix = '') {
  if (typeof value === 'string') return [[prefix, value]]
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  return Object.entries(value).flatMap(([key, child]) =>
    leafEntries(child, prefix ? `${prefix}.${key}` : key),
  )
}

export function leafKeys(value) {
  return new Set(leafEntries(value).map(([key]) => key))
}

function placeholders(value) {
  return new Set(value.match(/{{[^}]+}}/g) ?? [])
}

function markupTokens(value) {
  return new Set(value.match(/<[^>]+>/g) ?? [])
}

function setDifference(left, right) {
  return [...left].filter((key) => !right.has(key)).sort()
}

function relativeSourcePath(filePath, sourceRoot) {
  return path.relative(sourceRoot, filePath).split(path.sep).join('/')
}

function sourceFiles(root) {
  const result = []
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const filePath = path.join(directory, entry.name)
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== 'dist') visit(filePath)
        continue
      }
      if (/\.(?:ts|tsx)$/.test(entry.name)) result.push(filePath)
    }
  }
  visit(root)
  return result.sort()
}

function isExcludedSource(relativePath) {
  return /(?:^|\/)tests?(?:\/|$)|\.(?:test|spec)\.[jt]sx?$/.test(relativePath) ||
    translationFiles.has(path.normalize(relativePath))
}

function addFinding(findings, category, detail) {
  findings.push({ category, detail })
}

export function visibleSourceLiterals(source) {
  const objectLiterals = [...source.matchAll(visibleObjectPropertyPattern)]
    .map((match) => match[1])
    .filter((literal) => !translationKeyPattern.test(literal))
  return [
    ...[...source.matchAll(visibleAttributePattern)].map((match) => match[1]),
    ...[...source.matchAll(visibleTextPattern)].map((match) => match[1]),
    ...objectLiterals,
    ...[...source.matchAll(visibleExpressionPattern)].map((match) => match[1]),
    // t(cond ? 'a.b' : 'a.c') 的两个分支是翻译 key，不是展示文本
    ...[...source.matchAll(visibleConditionalExpressionPattern)]
      .flatMap((match) => [match[1], match[2]])
      .filter((literal) => !translationKeyPattern.test(literal)),
  ].map((literal) => literal.trim()).filter(Boolean)
}

export function auditSourceLiterals(sourceRoot = defaultSourceRoot) {
  const findings = []
  for (const filePath of sourceFiles(sourceRoot)) {
    const relativePath = relativeSourcePath(filePath, sourceRoot)
    if (isExcludedSource(relativePath)) continue
    if (!relativePath.endsWith('.tsx')) continue
    const source = fs.readFileSync(filePath, 'utf8')
    for (const literal of visibleSourceLiterals(source)) {
      if (literal && !allowedVisibleLiterals.has(literal)) {
        addFinding(findings, 'hardcoded-visible-text', `${relativePath}: ${literal}`)
      }
    }
  }
  return findings
}

export function auditRawServerMessages(sourceRoot = defaultSourceRoot) {
  const findings = []
  const apiRoot = path.join(sourceRoot, 'api')
  if (!fs.existsSync(apiRoot)) return findings
  for (const filePath of sourceFiles(apiRoot)) {
    const relativePath = relativeSourcePath(filePath, sourceRoot)
    if (/\.(?:test|spec)\.[jt]sx?$/.test(relativePath)) continue
    const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/)
    lines.forEach((line, index) => {
      if (!/\b(?:body|value|payload|json)\??\.error\??\.message\b/u.test(line)) return
      if (/\b(?:typeof|exactKeys|length|text)\b/u.test(line)) return
      if (!/\b(?:return|throw|new\s+ApiError|message\s*:|description\s*:|set\w*Message|\.error\s*\()/u.test(line)) return
      addFinding(findings, 'raw-server-message', `${relativePath}:${index + 1}: ${line.trim()}`)
    })
  }
  return findings
}

function visibleLength(value) {
  return [...value.replace(protectedTokenPattern, '').replace(/\s/gu, '')].length
}

export function auditPseudoLocale(zhCN, pseudoCN) {
  const findings = []
  const sourceLeaves = new Map(leafEntries(zhCN))
  const pseudoLeaves = new Map(leafEntries(pseudoCN))
  for (const [key, source] of sourceLeaves) {
    const pseudo = pseudoLeaves.get(key)
    if (pseudo === undefined) continue
    if (!pseudo.startsWith('［') || !pseudo.endsWith('］')) {
      addFinding(findings, 'pseudo-locale-frame', `${key}: pseudo text must use full-width frames`)
      continue
    }
    if (JSON.stringify([...placeholders(source)].sort()) !== JSON.stringify([...placeholders(pseudo)].sort())) {
      addFinding(findings, 'pseudo-locale-token', `${key}: interpolation tokens changed`)
    }
    if (JSON.stringify([...markupTokens(source)].sort()) !== JSON.stringify([...markupTokens(pseudo)].sort())) {
      addFinding(findings, 'pseudo-locale-token', `${key}: markup tokens changed`)
    }
    const sourceVisible = visibleLength(source)
    const pseudoVisible = visibleLength(pseudo.slice(1, -1))
    if (sourceVisible > 0 && pseudoVisible <= sourceVisible) {
      addFinding(findings, 'pseudo-locale-growth', `${key}: pseudo text did not expand visible content`)
    }
    if (sourceVisible > 0 && pseudoVisible > sourceVisible * 3) {
      addFinding(findings, 'pseudo-locale-growth', `${key}: pseudo text expands beyond 3x visible content`)
    }
  }
  for (const key of setDifference(new Set(sourceLeaves.keys()), new Set(pseudoLeaves.keys()))) {
    addFinding(findings, 'pseudo-locale-key', `${key}: missing from pseudo locale`)
  }
  return findings
}

export function auditLocaleKeys(locales) {
  const findings = []
  const base = leafKeys(locales['zh-CN'])
  for (const locale of supportedLocales.slice(1)) {
    const keys = leafKeys(locales[locale])
    for (const key of setDifference(base, keys)) addFinding(findings, 'missing-locale-key', `${locale}: ${key}`)
    for (const key of setDifference(keys, base)) addFinding(findings, 'extra-locale-key', `${locale}: ${key}`)
  }
  for (const [key, value] of leafEntries(locales['en-US'])) {
    if (cjkPattern.test(value) && !allowedVisibleLiterals.has(value) && key !== 'common.simplifiedChinese') {
      addFinding(findings, 'english-locale-cjk', `${key}: ${value}`)
    }
  }
  return findings
}

export function auditWebI18n({ locales, sourceRoot = defaultSourceRoot }) {
  const findings = [
    ...auditLocaleKeys(locales),
    ...auditPseudoLocale(locales['zh-CN'], locales['qps-ploc']),
    ...auditSourceLiterals(sourceRoot),
    ...auditRawServerMessages(sourceRoot),
  ]
  return findings
}

async function runCli() {
  // resources.ts imports siblings without the .ts extension (bundler style);
  // register the resolver here so `node scripts/audit-web-i18n.mjs` works
  // without the CI flag --experimental-loader ./scripts/audit-web-i18n-loader.mjs.
  register(pathToFileURL(path.join(scriptDirectory, 'audit-web-i18n-loader.mjs')).href)
  const resourcesPath = path.join(sourceRootFromScript(), 'i18n/resources.ts')
  const resources = await import(pathToFileURL(resourcesPath).href)
  const findings = auditWebI18n({
    locales: {
      'zh-CN': resources.zhCN,
      'en-US': resources.enUS,
      'qps-ploc': resources.pseudoCN,
    },
  })
  if (findings.length > 0) {
    for (const finding of findings) console.error(`[${finding.category}] ${finding.detail}`)
    process.exitCode = 1
    return
  }
  console.log('web i18n audit passed: locale keys, visible literals, server errors, pseudo locale')
}

function sourceRootFromScript() {
  return defaultSourceRoot
}

const invokedPath = process.argv[1] && path.resolve(process.argv[1])
if (invokedPath === fileURLToPath(import.meta.url)) await runCli()
