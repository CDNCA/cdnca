// installer-i18n B：四个安装器共用 scripts/lib/install-i18n.sh（逐字嵌入）。--lang zh|en 优先，其次
// CDNCA_INSTALL_LANG，再按 LC_ALL/LC_MESSAGES/LANG（zh* 中文，其余英文）；--lang 从参数里剥离，其余参数不变。
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { embedded, embeds } from '../scripts/sync-install-preflight.mjs'

const read = (relative) => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8')
const library = read('scripts/lib/install-i18n.sh')
const control = read('scripts/install-control.sh')
const node = read('scripts/install-node.sh')

function block(source, name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  if (lines[start].endsWith('}')) return lines[start]
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

function lang(args, env = {}) {
  const script = ['set -Eeuo pipefail', library, 'install_lang_init "$@"',
    'printf "%s|%s|" "$INSTALL_LANG" "$INSTALL_LANG_AUTO"; for a in ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}; do printf "<%s>" "$a"; done'].join('\n')
  return spawnSync('bash', ['-c', script, 'x', ...args], { encoding: 'utf8', env: { PATH: process.env.PATH, ...env } })
}

test('language selection order: --lang, CDNCA_INSTALL_LANG, then the locale', () => {
  assert.equal(lang(['--lang', 'en', '--master-host', 'cdnca.com']).stdout, 'en|false|<--master-host><cdnca.com>')
  assert.equal(lang(['--lang=zh', '-y'], { CDNCA_INSTALL_LANG: 'en' }).stdout, 'zh|false|<-y>')
  assert.equal(lang(['-y'], { CDNCA_INSTALL_LANG: 'en', LANG: 'zh_CN.UTF-8' }).stdout, 'en|false|<-y>')
  assert.equal(lang([], { LANG: 'zh_CN.UTF-8' }).stdout, 'zh|true|')
  assert.equal(lang([], { LC_ALL: 'en_US.UTF-8', LANG: 'zh_CN.UTF-8' }).stdout, 'en|true|')
  assert.equal(lang([], { LANG: 'C.UTF-8' }).stdout, 'en|true|')
  assert.equal(lang([]).stdout, 'en|true|')
  assert.equal(lang(['a b', '', '--x']).stdout, 'en|true|<a b><><--x>')
})

test('invalid or missing --lang values are refused', () => {
  const bad = lang(['--lang', 'fr'])
  assert.equal(bad.status, 2)
  assert.match(bad.stderr, /must be zh or en/)
  assert.equal(lang(['--lang']).status, 2)
  assert.equal(lang([], { CDNCA_INSTALL_LANG: 'jp' }).status, 2)
})

test('msg prints the selected language and defaults to Chinese before init', () => {
  const run = (pre) => spawnSync('bash', ['-c', [library, pre, "msg '中文' 'English'"].join('\n')], { encoding: 'utf8', env: { PATH: process.env.PATH } }).stdout
  assert.equal(run(''), '中文')
  assert.equal(run('install_lang_init --lang en'), 'English')
  assert.equal(run('install_lang_init --lang zh'), '中文')
})

test('the first interactive screen offers the language only when it was not chosen explicitly', () => {
  const tty = '[() { if [[ "$1" == -t ]]; then return 0; fi; builtin [ "$@"; }'
  const run = (args, input) => spawnSync('bash', ['-c', [library, tty, 'install_lang_init "$@"', 'install_lang_prompt', 'printf "%s" "$INSTALL_LANG"'].join('\n'), 'x', ...args],
    { encoding: 'utf8', input, env: { PATH: process.env.PATH, LANG: 'en_US.UTF-8' } })
  const chosen = run([], '1\n')
  assert.equal(chosen.stdout, 'zh')
  assert.match(chosen.stderr, /Language \/ 语言:  1\) 中文   2\) English  \[2\]/)
  assert.equal(run([], '\n').stdout, 'en')
  const explicit = run(['--lang', 'en'], '1\n')
  assert.equal(explicit.stdout, 'en')
  assert.equal(explicit.stderr, '')
})

test('every installer embeds the library verbatim and initialises the language before parsing', () => {
  for (const [relative, names] of Object.entries(embeds)) {
    if (!names.includes('install-i18n')) continue
    assert.equal(embedded(read(relative), 'install-i18n').body, library, `${relative} is stale; run node scripts/sync-install-preflight.mjs`)
  }
  for (const source of [control, node]) {
    const main = block(source, 'main')
    assert.ok(main.indexOf('install_lang_init "$@"') < main.indexOf('parse_args "$@"'))
    assert.ok(main.indexOf('parse_args "$@"') < main.indexOf('install_lang_prompt'))
  }
})

test('control usage, prompts and Gateway port notes are English with --lang en and Chinese by default', () => {
  const usage = (args) => spawnSync('bash', ['-c', [library, block(control, 'usage'), 'install_lang_init "$@"', 'usage'].join('\n'), 'x', ...args],
    { encoding: 'utf8', env: { PATH: process.env.PATH } }).stdout
  const en = usage(['--lang', 'en'])
  assert.match(en, /^CDNCA control-plane bundle installer/)
  assert.match(en, /--lang zh\|en/)
  assert.match(en, /--signer-revocation-offline-root-key-id/)
  assert.doesNotMatch(en, /\p{Script=Han}/u)
  assert.match(usage(['--lang', 'zh']), /^CDNCA 管理端整包安装器/)
  const ports = (args) => spawnSync('bash', ['-c', [library, block(control, 'print_gateway_ports'), 'install_lang_init "$@"',
    'GATEWAY_ENROLLMENT_PORT=21443 GATEWAY_AGENT_PORT=21444', 'print_gateway_ports'].join('\n'), 'x', ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } }).stderr
  assert.match(ports(['--lang', 'en']), /Node channel \(Gateway\) ports: enrollment 21443, agent channel 21444/)
  assert.doesNotMatch(ports(['--lang', 'en']), /\p{Script=Han}/u)
  assert.match(ports(['--lang', 'zh']), /节点通道（网关）端口：注册 21443，通道 21444/)
  const prompt = spawnSync('bash', ['-c', [library, ...['fail', 'warn', 'valid_host', 'valid_port', 'control_domain_is_ip', 'prompt_public_endpoints'].map((name) => block(control, name)),
    '[() { if [[ "$1" == "-t" ]]; then return 0; fi; builtin [ "$@"; }', 'install_lang_init --lang en', 'MASTER_HOST= MASTER_PORT= GATEWAY_HOST= CONTROL_DOMAIN= PUBLIC_CERT_FILE=', 'prompt_public_endpoints'].join('\n')],
  { encoding: 'utf8', input: 'cdnca.com\n\n', env: { PATH: process.env.PATH } })
  assert.equal(prompt.status, 0, prompt.stderr)
  assert.match(prompt.stderr, /Public domain or IP of the management console: Management HTTPS port \[443\]: /)
})

test('node failure messages follow the language', () => {
  const run = (args) => spawnSync('bash', ['-c', [library, block(node, 'fail'), 'install_lang_init "$@"',
    "fail \"$(msg '注册请求过于频繁，请 1 分钟后重试' 'too many registration requests; retry in a minute')\""].join('\n'), 'x', ...args], { encoding: 'utf8', env: { PATH: process.env.PATH } })
  assert.match(run(['--lang', 'en']).stderr, /error: too many registration requests; retry in a minute/)
  assert.match(run([]).stderr, /error: too many registration requests/)
  assert.match(node, /fail "\$\(msg '注册请求过于频繁，请 1 分钟后重试' 'too many registration requests; retry in a minute'\)"/)
})
