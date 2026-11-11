#!/usr/bin/env node
// List control-api error codes that apps/web has no text for.
//
// Usage: node scripts/check-api-error-i18n.mjs [--publish-only] [--json]
//
// Backend codes: every `http.StatusXxx, "code"` pair (writeAPIError, the
// per-package writeError helpers, `return status, code` tuples) plus
// `Code: "code"` / `"code": "code"` literals in non-test Go files of
// services/control-api. Codes passed only through variables are not seen.
// Frontend text: any object key with a string value in apps/web/src (i18n
// resources and page message tables), or a quoted literal of the code (a page
// that compares error.code and builds its own text). A code counts as covered
// when either exists anywhere; it does not prove the calling page reads it.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const backendRoot = path.join(root, 'services/control-api')
const frontendRoot = path.join(root, 'apps/web/src')
const args = new Set(process.argv.slice(2))

// Publication pages the task names; first match on file path or code wins.
const publishCategories = [
  ['套餐', /(^|\/)package_|packagecatalog|package_catalog/],
  ['CC 规则', /(^|[/_])cc[a-z]*([/_]|$)|ccinherit|cccoord|ccautoswitch/],
  ['WAF', /waf/],
  ['挑战策略', /challenge/],
  ['规则包', /rule_?pack/],
  ['证书', /cert|acme/],
  ['站点发布', /site|publish|publication|release|edgeconfig/],
]

const statusNumbers = {
  StatusBadRequest: 400, StatusUnauthorized: 401, StatusPaymentRequired: 402, StatusForbidden: 403,
  StatusNotFound: 404, StatusMethodNotAllowed: 405, StatusNotAcceptable: 406, StatusRequestTimeout: 408,
  StatusConflict: 409, StatusGone: 410, StatusLengthRequired: 411, StatusPreconditionFailed: 412,
  StatusRequestEntityTooLarge: 413, StatusUnsupportedMediaType: 415, StatusRequestedRangeNotSatisfiable: 416,
  StatusUnprocessableEntity: 422, StatusLocked: 423, StatusFailedDependency: 424, StatusTooEarly: 425,
  StatusPreconditionRequired: 428, StatusTooManyRequests: 429, StatusRequestHeaderFieldsTooLarge: 431,
  StatusUnavailableForLegalReasons: 451, StatusInternalServerError: 500, StatusNotImplemented: 501,
  StatusBadGateway: 502, StatusServiceUnavailable: 503, StatusGatewayTimeout: 504, StatusInsufficientStorage: 507,
}

function walk(directory, accept, out = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue
    const full = path.join(directory, entry.name)
    if (entry.isDirectory()) walk(full, accept, out)
    else if (accept(entry.name)) out.push(full)
  }
  return out
}

const lineOf = (text, index) => text.slice(0, index).split('\n').length
const codePattern = '([a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]{3,})'
const statusCodePair = new RegExp(`http\\.(Status[A-Za-z]+)\\s*,\\s*"${codePattern}"`, 'g')
const codeLiteral = new RegExp(`(?:\\bCode:|"code":)\\s*"${codePattern}"`, 'g')

// code -> { statuses:Set, sites:[file:line] }
const backend = new Map()
function record(code, status, file, line) {
  const entry = backend.get(code) ?? { statuses: new Set(), sites: [] }
  if (status) entry.statuses.add(status)
  if (entry.sites.length < 5) entry.sites.push(`${path.relative(root, file)}:${line}`)
  backend.set(code, entry)
}
for (const file of walk(backendRoot, (name) => name.endsWith('.go') && !name.endsWith('_test.go'))) {
  const text = fs.readFileSync(file, 'utf8')
  for (const match of text.matchAll(statusCodePair)) {
    record(match[2], statusNumbers[match[1]] ?? match[1], file, lineOf(text, match.index))
  }
  for (const match of text.matchAll(codeLiteral)) record(match[1], undefined, file, lineOf(text, match.index))
}

const frontendKeys = new Set()
const keyPattern = /(?:^|[\s,{])['"]?([a-z][a-z0-9_]*)['"]?\s*:\s*['"`]/gm
for (const file of walk(frontendRoot, (name) => /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name))) {
  const text = fs.readFileSync(file, 'utf8')
  for (const match of text.matchAll(keyPattern)) frontendKeys.add(match[1])
  for (const match of text.matchAll(/['"`]([a-z][a-z0-9]*(?:_[a-z0-9]+)+)['"`]/g)) frontendKeys.add(match[1])
}

function categoryOf(code, sites) {
  for (const [name, pattern] of publishCategories) if (pattern.test(code)) return name
  for (const [name, pattern] of publishCategories) if (sites.some((site) => pattern.test(site.split(':')[0]))) return name
  return '其他'
}

const rows = [...backend.entries()].map(([code, entry]) => ({
  code,
  statuses: [...entry.statuses].sort(),
  clientError: [...entry.statuses].some((status) => typeof status === 'number' && status >= 400 && status < 500),
  covered: frontendKeys.has(code),
  category: categoryOf(code, entry.sites),
  sites: entry.sites,
})).sort((a, b) => a.category.localeCompare(b.category) || a.code.localeCompare(b.code))

const missing = rows.filter((row) => !row.covered && (!args.has('--publish-only') || row.category !== '其他'))
if (args.has('--json')) {
  process.stdout.write(`${JSON.stringify({ total: rows.length, missing }, null, 2)}\n`)
  process.exit(0)
}
const byCategory = new Map()
for (const row of missing) byCategory.set(row.category, [...(byCategory.get(row.category) ?? []), row])
console.log(`后端错误码 ${rows.length} 个，前端有文案 ${rows.filter((row) => row.covered).length} 个，缺文案 ${rows.length - rows.filter((row) => row.covered).length} 个（其中 4xx ${rows.filter((row) => !row.covered && row.clientError).length} 个）`)
for (const [category, list] of byCategory) {
  console.log(`\n## ${category}：缺 ${list.length} 个（4xx ${list.filter((row) => row.clientError).length} 个）`)
  for (const row of list) console.log(`- ${row.code} [${row.statuses.join(',') || '?'}] ${row.sites[0]}`)
}
