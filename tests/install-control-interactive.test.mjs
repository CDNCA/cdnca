import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runInNewContext } from 'node:vm'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  if (lines[start].endsWith('}')) return lines[start]
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}
function prompt(input, values = {}, interactive = true) {
  return spawnSync('bash', ['-c', [
    'set -Eeuo pipefail',
    // prompt_public_endpoints 在 IP 控制域名且未提供证书时会 warn（10/12 起），需要这两个依赖与 PUBLIC_CERT_FILE。
    ...['fail', 'warn', 'valid_host', 'valid_port', 'control_domain_is_ip', 'prompt_public_endpoints'].map(block),
    interactive ? '[() { if [[ "$1" == "-t" ]]; then return 0; fi; builtin [ "$@"; }' : '',
    'prompt_public_endpoints',
    'printf "%s|%s|%s|%s\\n" "$MASTER_HOST" "$MASTER_PORT" "$GATEWAY_HOST" "$CONTROL_DOMAIN"',
  ].join('\n')], {
    encoding: 'utf8', input, env: { ...process.env, MASTER_HOST: '', MASTER_PORT: '', GATEWAY_HOST: '', CONTROL_DOMAIN: '', PUBLIC_CERT_FILE: '', ...values },
  })
}

// 2026-10-14 起交互只问管理端地址与端口；节点 Gateway 默认与管理端同地址（端口安装时随机 20000–29999，ADR 0013 §3.5），
// 仅分离部署时用 --gateway-host 显式传入，不再交互询问。
test('interactive prompt collects addresses and port without falling back to machine hostname', () => {
  const result = prompt('CONTROL.example.com\n8443\n')
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim(), 'control.example.com|8443|control.example.com|control.example.com')
  assert.match(result.stderr, /管理端公网/)
  assert.doesNotMatch(result.stderr, /Gateway/)
  assert.doesNotMatch(block('normalise_defaults'), /hostname/)
})

test('interactive defaults are visible and only chosen at the terminal', () => {
  const result = prompt('control.example.com\n\n')
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim(), 'control.example.com|443|control.example.com|control.example.com')
  assert.match(result.stderr, /\[443\]/)
})

test('a split deployment passes the Gateway host explicitly', () => {
  const result = prompt('control.example.com\n\n', { GATEWAY_HOST: 'Gateway.example.com' })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim(), 'control.example.com|443|gateway.example.com|control.example.com')
})

test('automation with explicit values does not need a TTY', () => {
  const result = prompt('', { MASTER_HOST: 'control.example.com', MASTER_PORT: '8443', GATEWAY_HOST: 'gateway.example.com', CONTROL_DOMAIN: 'CONTROL.example.com' }, false)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim(), 'control.example.com|8443|gateway.example.com|control.example.com')
  assert.equal(result.stderr, '')
})

test('missing noninteractive host and invalid interactive input fail before installation', () => {
  assert.notEqual(prompt('', {}, false).status, 0)
  for (const input of ['https://control.example.com\n', 'control.example.com\n65536\n']) {
    assert.notEqual(prompt(input).status, 0)
  }
  // Gateway 不再交互输入；显式传入的非法 --gateway-host 同样在安装前失败。
  assert.notEqual(prompt('control.example.com\n443\n', { GATEWAY_HOST: 'user@gateway.example.com' }).status, 0)
  const main = block('main')
  assert.ok(main.indexOf('prompt_public_endpoints') < main.indexOf('install_dependencies'))
})

test('public port rejects fixed native services and occupied listeners before identity or activation', () => {
  for (const [port, occupied, accepted] of [
    ...['4222', '5432', '6379', '8080', '8082', '8123', '8222', '9000', '9004', '9005', '9009', '9091', '9445', '19000']
      .map((port) => [port, false, false]),
    ['019000', false, false], ['09445', false, false], ['443', true, false], ['8443', false, true], ['443', false, true],
    ['21443', false, false], ['19443', false, true],
  ]) {
    const result = spawnSync('bash', ['-c', source.replace(/\nmain "\$@"\s*$/, '') + `
MASTER_HOST=control.example.test
MASTER_PORT=${port}
GATEWAY_PORTS=21443,21444
LICENSING_SERVER=https://auth.example.test
DATABASE_URL=postgresql://localhost/fixture
host_architecture() { printf amd64; }
ss() { ${occupied ? 'printf occupied' : ':'}; }
normalise_defaults
printf accepted
`], { encoding: 'utf8', timeout: 5000 })
    assert.equal(result.status === 0, accepted, `${port}/${occupied}: ${result.stderr}`)
    assert.equal(result.stdout.includes('accepted'), accepted)
    if (!accepted) assert.match(result.stderr, /reserved|occupied/)
  }
})

test('runtime configuration JSON-escapes the public download fallback without changing Gateway identity', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-control-runtime-test-'))
  try {
    const web = join(directory, 'web')
    mkdirSync(web)
    const entry = '<script src="/runtime-config.js"></script>'
    writeFileSync(join(web, 'index.html'), entry)
    writeFileSync(join(web, 'runtime-config.js'), '// immutable release default\n')
    const licensing = 'https://auth.example.test?quoted="value"'
    const upgradeTrust = 'ab'.repeat(32)
    const unpublished = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), block('write_web_runtime_config'), 'write_node_install_defaults() { :; }', 'write_web_runtime_config'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, WEB_ROOT: web, DATA_DIR: directory, GATEWAY_HOST: 'gateway.example.test', GATEWAY_ENROLLMENT_PORT: '23001', GATEWAY_AGENT_PORT: '23002', LICENSING_SERVER: licensing, LICENSING_SERVER_FALLBACK: 'https://fallback.example.test', UPGRADE_TRUST_SHA256: '' },
    })
    assert.notEqual(unpublished.status, 0)
    assert.match(unpublished.stderr, /node upgrade trust was not published/)
    const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), block('write_web_runtime_config'), 'write_node_install_defaults() { :; }', 'write_web_runtime_config'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, WEB_ROOT: web, DATA_DIR: directory, GATEWAY_HOST: 'gateway.example.test', GATEWAY_ENROLLMENT_PORT: '23001', GATEWAY_AGENT_PORT: '23002', LICENSING_SERVER: licensing, LICENSING_SERVER_FALLBACK: 'https://fallback.example.test', UPGRADE_TRUST_SHA256: upgradeTrust },
    })
    assert.equal(result.status, 0, result.stderr)
    const window = {}
    runInNewContext(readFileSync(join(directory, 'runtime-config.js'), 'utf8'), { window })
    assert.equal(window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__, upgradeTrust)
    assert.equal(window.__CDNCA_DOWNLOAD_FALLBACK_ORIGIN__, licensing)
    assert.equal(window.__CDNCA_GATEWAY_ADDRESS__, 'gateway.example.test:23002')
    assert.equal(window.__CDNCA_GATEWAY_ENROLLMENT_ADDRESS__, 'gateway.example.test:23001')
    assert.equal(window.__CDNCA_GATEWAY_SERVER_NAME__, 'gateway.example.test')
    assert.equal(readFileSync(join(web, 'index.html'), 'utf8'), entry)
    assert.equal(readFileSync(join(web, 'runtime-config.js'), 'utf8'), '// immutable release default\n')
    assert.equal(statSync(join(directory, 'runtime-config.js')).mode & 0o777, 0o644)
    writeFileSync(join(web, 'index.html'), '<script type="module" src="/assets/main.js"></script>')
    const missingHook = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), block('write_web_runtime_config'), 'write_node_install_defaults() { :; }', 'write_web_runtime_config'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, WEB_ROOT: web, DATA_DIR: directory, GATEWAY_HOST: 'gateway.example.test', GATEWAY_ENROLLMENT_PORT: '23001', GATEWAY_AGENT_PORT: '23002', LICENSING_SERVER: licensing, LICENSING_SERVER_FALLBACK: 'https://fallback.example.test', UPGRADE_TRUST_SHA256: upgradeTrust },
    })
    assert.notEqual(missingHook.status, 0)
    assert.equal(readFileSync(join(web, 'index.html'), 'utf8'), '<script type="module" src="/assets/main.js"></script>')
  } finally {
    rmSync(directory, { recursive: true })
  }
})

test('public nginx serves instance configuration outside the release and denies internal API paths', () => {
  const config = block('write_nginx_config')
  assert.match(config, /location = \/runtime-config\.js\s*\{\s*alias \$\{DATA_DIR\}\/runtime-config\.js;/)
  assert.match(config, /location = \/dashboard\/runtime-config\.js\s*\{\s*alias \$\{DATA_DIR\}\/runtime-config\.js;/)
  assert.match(config, /location \^~ \/v1\/internal\/\s*\{ return 404; \}/)
  assert.match(config, /location = \/v1\/internal\s*\{ return 404; \}/)
})

test('mutable installer downloads inherit the complete server no-store and security headers', () => {
  const config = block('write_nginx_config')
  const server = config.slice(config.indexOf('    server {'), config.indexOf('        location = /healthz'))
  for (const header of ['Cache-Control \\$cdnca_cache_control', 'X-Content-Type-Options "nosniff"', 'X-Frame-Options "DENY"', 'Referrer-Policy "strict-origin-when-cross-origin"']) {
    assert.ok(server.includes(`add_header ${header} always;`), header)
  }
  const downloads = config.match(/location \^~ \/downloads\/ \{([\s\S]*?)\n        \}/)?.[1]
  assert.ok(downloads, 'the actual installer download location must exist')
  assert.doesNotMatch(downloads, /\badd_header\b/, 'a location header suppresses every inherited server header')
})

test('management nginx compresses, speaks HTTP/2 and caches only content-hashed assets', () => {
  const config = block('write_nginx_config')
  assert.ok(config.includes('listen ${WEB_LISTEN} ssl http2;'), 'nginx 1.24 needs the listen-level http2 flag')
  assert.doesNotMatch(config, /\bhttp2 on;/, 'Ubuntu 24.04 nginx 1.24 does not support "http2 on"')
  for (const directive of ['gzip on;', 'gzip_static on;', 'gzip_vary on;', 'gzip_proxied any;']) {
    assert.ok(config.includes(`    ${directive}\n`), directive)
  }
  const types = config.match(/^ {4}gzip_types ([^;]+);$/m)?.[1].split(/\s+/) ?? []
  for (const type of ['application/javascript', 'text/css', 'image/svg+xml']) assert.ok(types.includes(type), type)
  // nginx weakens a compressed response's ETag to W/"n"; the console compares API ETags exactly.
  assert.ok(!types.includes('application/json'), 'API JSON must keep its strong ETag')
  const map = config.match(/map "\\\$status:\\\$uri" \\\$cdnca_cache_control \{\n([\s\S]*?)\n {4}\}/)?.[1]
  assert.ok(map, 'one server-wide Cache-Control map keyed by status and URI')
  const rows = map.split('\n').map((line) => line.trim())
  assert.equal(rows[0], 'default "no-store";')
  const immutable = rows.filter((row) => row.endsWith('"public, max-age=31536000, immutable";'))
  assert.deepEqual(immutable, ['"~^(?:200|304):/(?:dashboard/)?assets/[^/]+-[-_A-Za-z0-9]{8,}\\.[^/]+\\$" "public, max-age=31536000, immutable";',
    '"~^(?:200|304):/site/assets/[^/]+-[-_A-Za-z0-9]{8,}\\.[^/]+\\$" "public, max-age=31536000, immutable";'])
  assert.deepEqual(rows.filter((row) => row.endsWith(' "";')), ['"~^(?:200|304):/v1/brand-assets/(?:favicon|logo|login_ad)\\$" "";'])
  assert.equal(rows.length, 4)
  // Only the page bundle location sets headers (it repeats the server's, checked below).
  const locations = config.slice(config.indexOf('        location = /healthz')).replace(/ {8}location \^~ \/site\/t\/ \{[\s\S]*?\n {8}\}\n/, '')
  assert.doesNotMatch(locations, /\badd_header\b/, 'a location add_header drops every inherited server security header')
  const auth = config.match(/location \^~ \/v1\/auth\/ \{([\s\S]*?)\n {8}\}/)?.[1]
  assert.ok(auth, 'credential responses get their own location')
  assert.match(auth, /^\s+gzip off;$/m, 'token-bearing auth responses must not be compressed (BREACH)')
  assert.match(auth, /proxy_pass http:\/\/127\.0\.0\.1:8080;/)
  assert.ok(config.indexOf('location ^~ /v1/internal/') < config.indexOf('location ^~ /v1/auth/'))
})

test('management nginx sandboxes only /site/t/ page bundles and keeps the built-in website as it was', () => {
  const config = block('write_nginx_config')
  // No server-level CSP or $uri map: the built-in website (/site/index.html,
  // /site/assets/) and the console are not sandboxed; no /auth/ pages.
  assert.equal(config.match(/Content-Security-Policy/g).length, 1)
  assert.doesNotMatch(config, /cdnca_site_csp|cdnca_auth_csp|location \^~ \/auth\/|location \^~ \/site\/ /)
  assert.ok(config.includes('location = /favicon.ico { access_log off; log_not_found off; try_files /site/favicon.ico =404; }'))
  assert.ok(config.includes('location = /robots.txt { try_files /site/robots.txt =404; }'))
  const bundles = config.match(/ {8}location \^~ \/site\/t\/ \{([\s\S]*?)\n {8}\}\n/)?.[1]
  assert.ok(bundles, 'the page bundle location exists')
  assert.match(bundles, /^ {12}alias \$\{DATA_DIR\}\/site-themes\/;$/m)
  assert.match(bundles, /^ {12}limit_except GET \{ deny all; \}$/m)
  const csp = bundles.match(/^ {12}add_header Content-Security-Policy "([^"]*)" always;$/m)?.[1]
  assert.equal(csp, "sandbox allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation; default-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'")
  assert.ok(!csp.includes('allow-same-origin'))
  assert.match(bundles, /^ {12}add_header Access-Control-Allow-Origin "\*" always;$/m)
  assert.doesNotMatch(config, /Allow-Credentials/)
  assert.match(bundles, /^ {12}error_page 403 404 405 500 502 503 504 \/site\/t\/\.error;$/m)
  assert.match(bundles, /location = \/site\/t\/\.error \{\s*internal;/)
  // Raw dot segments (../, %2e%2e, also behind %2f) are refused before nginx normalizes them.
  assert.ok(config.includes('        if (\\$request_uri ~ "^/site/t/(?:[^?]*(?:/|%2[fF]))?(?:\\\\.|%2[eE])") { return 404; }\n        location ^~ /site/t/ {\n'))
  // A location add_header drops the server's: every one is repeated here.
  const server = config.slice(config.indexOf('    server {'), config.indexOf('        location = /healthz'))
  const inherited = server.split('\n').filter((line) => line.startsWith('        add_header '))
  assert.equal(inherited.length, 4)
  for (const line of inherited) assert.ok(bundles.includes('    ' + line + '\n'), line)
  // / falls back to the active bundle entry (an internal redirect into /site/t/), else as before.
  assert.ok(config.includes('        location / {\n            try_files \\$uri @website;\n        }\n'))
  const website = config.match(/location @website \{([\s\S]*?)\n {8}\}/)?.[1]
  assert.ok(website.includes('if (-f ${DATA_DIR}/site-themes/current.html) { rewrite ^ /site/t/current.html last; }'))
  assert.ok(website.includes('try_files /site/index.html /index.html;'))
  // Only these two lines reach the bundle directory.
  assert.equal(config.split('\n').filter((line) => !line.trim().startsWith('#') && line.includes('site-themes')).length, 2)
  assert.deepEqual(config.match(/location [^{]*\/site\/[^{]*\{/g), ['location ^~ /site/t/ {', 'location ~ ^/site/t/(?:.*/)?\\. {', 'location = /site/t/.error {'])
})

test('download and dependency failures happen before the community installation record is written', () => {
  const main = block('main').replace('[ "$EUID" -eq 0 ]', 'true')
  const steps = main.split('\n').map((line) => line.trim()).filter((line) => /^[a-z_]+$/.test(line))
  for (const failed of ['download_native_support', 'configure_runtime_dependencies', 'prepare_native_baseline', 'download_nats_binaries', 'download_node_assets', 'prepare_database', 'migrate_database', 'setup_redis', 'setup_nats', 'preprovision_nats', 'configure_control_runtime', 'publish_upgrade_trust', '']) {
    if (failed) assert.ok(steps.includes(failed), `missing failure gate ${failed}`)
    // gateway_mode_requested must report "not gateway" (non-zero) to reach the fresh-install path.
    const stubs = ['parse_args', 'valid_url', 'require_commands', ...steps].map((name) => `${name}() { printf '%s\\n' '${name}'; [[ '$FAILED_STEP' != '${name}' ]]; }`.replace('$FAILED_STEP', failed))
    const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), 'log() { :; }', ...stubs, 'gateway_mode_requested() { return 1; }', main, 'main'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, SKIP_DEPENDENCIES: 'true', INSTALL_MODE: 'all', CONTROL_BINARY: '/opt/cdnca/current/bin/control-api' },
    })
    const calls = result.stdout.trim().split('\n')
    if (failed) {
      assert.notEqual(result.status, 0, failed)
      assert.ok(!calls.includes('install_community'), `${failed} wrote the installation record`)
    } else {
      assert.equal(result.status, 0, result.stderr)
      assert.equal(calls.filter((name) => name === 'install_community').length, 1)
      assert.ok(calls.indexOf('install_community') > calls.indexOf('publish_upgrade_trust'))
      assert.ok(calls.indexOf('install_community') < calls.indexOf('setup_native_upgrade'))
    }
  }
})

test('fresh installation guard refuses existing state before writes', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-fresh-install-'))
  try {
    // CONTROL_INSTALL_STATE_DIR：半途失败的安装记录（AUDIT-1029 ①-12），存在即拒绝并提示 --cleanup-failed。
    const paths = { CONFIG_DIR: join(directory, 'config'), DATA_DIR: join(directory, 'data'), INSTALL_ROOT: join(directory, 'bin'), NATIVE_ROOT: join(directory, 'native'),
      CONTROL_INSTALL_STATE_DIR: join(directory, 'install-state') }
    const fixedPaths = ['/etc/cdnca-upgrade', '/var/lib/cdnca-upgrade', '/run/cdnca-upgrade', '/var/lib/cdnca-native-upgrade-maintenance']
    let guard = block('assert_fresh_installation')
    for (const [index, path] of fixedPaths.entries()) guard = guard.replace(path, join(directory, `fixed-${index}`))
    const run = () => spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), 'control_install_failed_hint() { :; }', guard, 'assert_fresh_installation'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, ...paths },
    })
    assert.equal(run().status, 0)
    for (const target of [...Object.values(paths), ...fixedPaths.map((_, index) => join(directory, `fixed-${index}`))]) {
      for (const kind of ['file', 'directory', 'dangling symlink']) {
        if (kind === 'file') writeFileSync(target, 'existing state')
        else if (kind === 'directory') mkdirSync(target)
        else symlinkSync(join(directory, 'absent'), target)
        assert.notEqual(run().status, 0, `${target} ${kind}`)
        if (kind === 'file') assert.equal(readFileSync(target, 'utf8'), 'existing state')
        rmSync(target, { recursive: true })
      }
    }
    assert.ok(block('main').indexOf('assert_fresh_installation') < block('main').indexOf('install_dependencies'))
  } finally {
    rmSync(directory, { recursive: true })
  }
})

test('database setup uses only the fixed read-only URI connection check', () => {
  const dsn = 'postgres://test:private-password@127.0.0.1/cdnca'
  const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), 'log() { :; }',
    'control_database_psql() { [[ "$#" == 1 && "$1" == empty ]] || return 1; printf t; }',
    block('prepare_database'), 'prepare_database'].join('\n')], {
    encoding: 'utf8', env: { ...process.env, DATABASE_PASSWORD: '', DATABASE_URL: dsn },
  })
  assert.equal(result.status, 0, result.stderr)
  assert.doesNotMatch(block('prepare_database'), /--dbname "\$DATABASE_URL"/)
  assert.doesNotMatch(block('prepare_database'), /PGDATABASE=/)
  assert.doesNotMatch(block('install_community'), /migrate up/)
  assert.match(block('migrate_database'), /migrate up/)
})

test('fresh PostgreSQL preflight refuses existing business state before any password or schema change', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-fresh-postgres-'))
  try {
    for (const external of [false, true]) {
      const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), block('prepare_database'),
        'log() { :; }; pg_isready() { return 0; }; psql() { return 99; }',
        'control_database_psql() { printf "external-read\\n" >>"$TEMP_DIR/calls"; printf f; }',
        'runuser() { printf "local-read\\n" >>"$TEMP_DIR/calls"; printf occupied; }',
        'prepare_database', 'printf unexpected-success',
      ].join('\n')], { encoding: 'utf8', env: { ...process.env, TEMP_DIR: directory,
        DATABASE_PASSWORD: external ? '' : 'fixture-generated-hex', DATABASE_URL: 'postgresql://localhost/fixture', PG_PORT: '5432',
      } })
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /existing|empty/)
      assert.doesNotMatch(result.stdout, /unexpected-success/)
      assert.equal(statSync(directory).isDirectory(), true)
      assert.throws(() => statSync(join(directory, 'postgres-init.sql')), /ENOENT/)
    }
    assert.doesNotMatch(block('prepare_database'), /ALTER ROLE/)
    assert.match(block('control_database_psql'), /pg_catalog\.pg_depend/)
    assert.match(block('control_database_psql'), /refclassid='pg_catalog\.pg_namespace'::pg_catalog\.regclass/)
    assert.match(block('control_database_psql'), /nspname <> 'public'/)
  } finally { rmSync(directory, { recursive: true }) }
})

test('complete baseline preflight precedes binary execution and compiled version must match the signed release', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-control-version-test-'))
  try {
    const installRoot = join(directory, 'installed')
    mkdirSync(installRoot)
    const installed = join(installRoot, 'control-api')
    mkdirSync(join(directory, 'native-stage/bin'), { recursive: true })
    writeFileSync(join(directory, 'native-stage/bin/control-api'), '#!/usr/bin/env bash\nprintf "%s\\n" "$BUILD_VERSION"\n', { mode: 0o755 })
    const commit = 'a'.repeat(40)
    writeFileSync(join(directory, 'install.manifest.json'), JSON.stringify({ schema: 'cdnca.native-management.install/v1', version: '1.0.1', source: { commit }, files: [] }))
    for (const [compiled, requested, preflight, accepted] of [
      ['1.0.1', '', 'true', true],
      ['1.0.1', '1.0.1', 'true', true],
      ['1.0.1', '1.0.0', 'true', false],
      ['development', '', 'true', false],
      ['1.0.1\n1.0.0', '', 'true', false],
      ['1.01.1', '', 'true', false],
      ['1.0.1', '', 'false', false],
    ]) {
      writeFileSync(installed, 'previous verified binary')
      const result = spawnSync('bash', ['-c', [
        'set -Eeuo pipefail', block('fail'), block('prepare_native_baseline'),
        // prepare_native_baseline 末尾用 progress_line 报安装版本（06d4d74e1）；进度输出本身由 install-progress 测试覆盖。
        'progress_line() { printf "%s\\n" "$1" >&2; }',
        `git() { if [[ "$*" == *"bundle list-heads"* ]]; then printf '%s HEAD\\n' '${commit}'; fi; }`,
        'python3() { [[ "$BASELINE_PREFLIGHT" == true ]]; }',
        'prepare_native_baseline', 'printf "%s" "$CONTROL_VERSION"',
      ].join('\n')], { encoding: 'utf8', env: { ...process.env,
        TEMP_DIR: directory, INSTALL_ROOT: installRoot, BUILD_VERSION: compiled, CONTROL_VERSION: requested,
        NATIVE_SUPPORT: directory, BASELINE_PREFLIGHT: preflight,
      } })
      if (accepted) {
        assert.equal(result.status, 0, result.stderr)
        assert.equal(result.stdout, compiled)
        assert.match(result.stderr, new RegExp(`安装版本 ${compiled.replaceAll('.', '\\.')}`))
      } else {
        assert.notEqual(result.status, 0, `${compiled}/${requested}/${preflight} was accepted`)
      }
      assert.equal(readFileSync(installed, 'utf8'), 'previous verified binary')
    }
    assert.match(source, /^CONTROL_VERSION=""$/m)
    assert.match(block('normalise_defaults'), /\[ -z "\$CONTROL_VERSION" \]/)
  } finally {
    rmSync(directory, { recursive: true })
  }
})

test('source-free baseline uses independent artifact trust and never invokes Git', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-control-sourcefree-test-'))
  try {
    mkdirSync(join(directory, 'native-stage/bin'), { recursive: true })
    writeFileSync(join(directory, 'native-stage/bin/control-api'), '#!/bin/sh\nprintf "1.0.10\\n"\n', { mode: 0o755 })
    writeFileSync(join(directory, 'install.manifest.json'), JSON.stringify({
      schema: 'cdnca.native-management.install/v2', version: '1.0.10',
      source: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), previous_commit: 'c'.repeat(40) },
      files: ['native-management.tar', 'release.manifest.json', 'control-upgrade-runner'].map((path) => ({ path, sha256: 'a'.repeat(64), bytes: 1024 })),
    }))
    const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), block('prepare_native_baseline'),
      'progress_line() { printf "%s\\n" "$1" >&2; }',
      'git() { printf "unexpected Git" >&2; exit 99; }', 'python3() { :; }', 'prepare_native_baseline'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, TEMP_DIR: directory, NATIVE_SUPPORT: directory,
        NATIVE_ARTIFACT_TRUST_FILE: join(directory, 'independent-trust.json'), CONTROL_VERSION: '' },
    })
    assert.equal(result.status, 0, result.stderr)
    const inputs = JSON.parse(readFileSync(join(directory, 'native-baseline-input.json'), 'utf8'))
    assert.equal(inputs.schema, 'cdnca.native-management.baseline-input/v2')
    assert.equal(inputs.artifact_trust_file, join(directory, 'independent-trust.json'))
    assert.equal(Object.hasOwn(inputs, 'source_git'), false)
  } finally { rmSync(directory, { recursive: true }) }
})

test('new installation enables database-backed APIs with distinct private persistent cursor keys', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-control-profile-test-'))
  try {
    const result = spawnSync('bash', ['-c', [
      'set -Eeuo pipefail', block('fail'), block('generate_runtime_secrets'), block('signer_revocation_environment'), block('remote_gateway_access'), block('local_gateway_environment'), block('upgrade_download_origin'), 'GATEWAY_HOST=gateway.example.test GATEWAY_AGENT_PORT=9444 GATEWAY_ENROLLMENT_PORT=9443', block('write_environment'),
      'generate_runtime_secrets', 'write_environment',
      'source "$CONFIG_DIR/control.env"',
      'printf "%s" "$ANNOUNCEMENT_CURSOR_KEYS_JSON" | jq -e \'keys == ["announcement-v1"]\' >/dev/null',
      'printf "%s" "$JOB_QUERY_CURSOR_KEYS_JSON" | jq -e \'keys == ["jobs-v1"]\' >/dev/null',
    ].join('\n')], { encoding: 'utf8', env: { ...process.env, CONFIG_DIR: directory, KEY_DIR: directory,
      PKI_DIR: directory, DATABASE_URL: 'postgresql://localhost/test', REDIS_URL: 'redis://localhost/0',
      NATS_URL: 'nats://localhost:4222', LICENSING_SERVER: 'https://auth.example.test',
      INSTALLATION_ID: 'test-installation', INSTALLATION_NAME: 'test', CONTROL_VERSION: '1.0.1',
      DOWNLOAD_DIR: join(directory, 'downloads'), CONTROL_ORIGIN: 'https://control.example.test', DATA_DIR: directory,
      UPGRADE_KEY_DIR: join(directory, 'upgrade'), UPGRADE_CONTROL_KEY_ID: 'control-execution-v1', UPGRADE_EDGE_KEY_ID: 'edge-execution-v1',
    } })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, '')
    const path = join(directory, 'control.env')
    // Theme plugin page bundles: the directory nginx serves /site/ from.
    assert.match(readFileSync(path, 'utf8'), new RegExp(`^CONTROL_SITE_THEMES_DIR=${join(directory, 'site-themes')}$`, 'm'))
    assert.equal(statSync(path).mode & 0o777, 0o600)
    const environment = readFileSync(path, 'utf8')
    const entries = Object.fromEntries(environment.trim().split('\n').map((line) => {
      const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)]
    }))
    for (const key of ['ANNOUNCEMENT_ENABLED', 'NODE_SCHEDULING_RUNTIME_ENABLED', 'JOB_QUERY_ENABLED']) assert.equal(entries[key], 'true', key)
    // cdncaCE: promotion and traffic-package billing are not part of the community edition.
    for (const key of ['PROMOTION_HTTP_ENABLED', 'TRAFFIC_PACKAGE_RUNTIME_ENABLED']) assert.equal(entries[key], undefined, key)
    assert.equal(entries.ANNOUNCEMENT_EXTERNAL_CHANNEL, 'disabled')
    assert.equal(entries.NOTIFICATION_RUNTIME_ENABLED, 'false')
    assert.equal(entries.TRAFFIC_PACKAGE_WORKLOAD_RUNTIME_ENABLED, undefined)
    assert.equal(entries.EDGE_PUBLISH_RUNTIME_ENABLED, undefined)
    // ui-fix4 F8: MFA (required by custom roles) and custom roles are on with their own keys.
    assert.equal(entries.MFA_ENABLED, 'true')
    assert.equal(entries.CUSTOM_RBAC_RUNTIME_ENABLED, 'true')
    const mfaKeys = JSON.parse(entries.MFA_ENCRYPTION_KEYS_JSON.replace(/^'|'$/g, ''))
    assert.deepEqual(Object.keys(mfaKeys), [entries.MFA_ENCRYPTION_ACTIVE_KEY_ID])
    assert.equal(entries.CDNCA_SECURITY_ACTIVATION_ENABLED, undefined)
    assert.equal(entries.JOB_QUERY_CURSOR_ACTIVE_KEY_ID, 'jobs-v1')
    assert.equal(entries.SITE_STATUS_RECOVERY_RUNTIME_ENABLED, undefined)
    const announcement = JSON.parse(entries.ANNOUNCEMENT_CURSOR_KEYS_JSON.replace(/^'|'$/g, ''))
    const jobs = JSON.parse(entries.JOB_QUERY_CURSOR_KEYS_JSON.replace(/^'|'$/g, ''))
    const cursorKeys = [announcement[entries.ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID], jobs[entries.JOB_QUERY_CURSOR_ACTIVE_KEY_ID],
      mfaKeys[entries.MFA_ENCRYPTION_ACTIVE_KEY_ID], entries.CUSTOM_RBAC_CURSOR_KEY_BASE64]
    assert.equal(new Set([...cursorKeys, entries.API_KEY_PEPPER_BASE64, entries.DNS_CREDENTIAL_KEY_BASE64,
      entries.ACCESS_TOKEN_SECRET, entries.IMPERSONATION_HMAC_KEY_BASE64,
      entries.OPENRESTY_SECURITY_SECRET_KEY_BASE64, entries.OBSERVABILITY_LOG_CURSOR_KEY_BASE64]).size, 10)
    for (const value of cursorKeys) {
      assert.equal(Buffer.from(value, 'base64').length, 32)
      assert.equal(Buffer.from(value, 'base64').toString('base64'), value)
    }
    // cdncaCE: no activation, so no license service or license-granted online upgrades; the pinned public
    // signing keys (write_upgrade_trust) still back the entitlement trust store.
    assert.equal(entries.LICENSE_SERVICE_URL, '')
    assert.equal(entries.ENTITLEMENT_TRUSTED_KEYS_FILE, join(directory, 'entitlement-trusted-keys.json'))
    assert.equal(entries.CONTROL_UPGRADE_RUNTIME_ENABLED, 'false')
    assert.equal(entries.CONTROL_UPGRADE_ARTIFACT_CACHE_DIR, join(directory, 'downloads', 'edge-agent', 'upgrades', 'sha256'))
    assert.equal(entries.CONTROL_UPGRADE_ARTIFACT_BASE_URL, 'https://control.example.test/downloads/edge-agent/upgrades/sha256')
    assert.equal(entries.CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE, join(directory, 'entitlement-trusted-keys.json'))
    assert.notEqual(entries.CONTROL_UPGRADE_CONTROL_SIGNING_KEY_ID, entries.CONTROL_UPGRADE_EDGE_SIGNING_KEY_ID)
    assert.notEqual(entries.CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE, entries.CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE)
    const rejected = spawnSync('bash', ['-c', [
      'set -Eeuo pipefail', block('fail'), block('generate_runtime_secrets'), block('signer_revocation_environment'), block('remote_gateway_access'), block('local_gateway_environment'), block('upgrade_download_origin'), 'GATEWAY_HOST=gateway.example.test GATEWAY_AGENT_PORT=9444 GATEWAY_ENROLLMENT_PORT=9443', block('write_environment'),
      'generate_runtime_secrets', 'JOB_QUERY_CURSOR_KEY_BASE64=', 'write_environment',
    ].join('\n')], { encoding: 'utf8', env: { ...process.env, CONFIG_DIR: directory } })
    assert.notEqual(rejected.status, 0)
    assert.match(rejected.stderr, /runtime secrets were not generated/)
    assert.equal(rejected.stdout, '')
    assert.equal(readFileSync(path, 'utf8'), environment)
  } finally {
    rmSync(directory, { recursive: true })
  }
})

test('new PKI publishes only its Gateway CA through a worker-readable download root', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-control-public-ca-test-'))
  try {
    const config = join(directory, 'config')
    const data = join(directory, 'data')
    const keys = join(config, 'keys')
    const pki = join(keys, 'pki')
    const downloads = join(data, 'downloads')
    mkdirSync(keys, { recursive: true, mode: 0o700 })
    mkdirSync(data, { mode: 0o755 })
    for (const name of ['control.env', 'activation-code', 'administrator-password']) {
      writeFileSync(join(config, name), `private fixture ${name}`, { mode: 0o600 })
    }
    const result = spawnSync('bash', ['-c', [
      'set -Eeuo pipefail', 'umask 077', block('fail'), block('host_san'), block('generate_pki'),
      'log() { :; }',
      'generate_ca() { printf "fixture private key\\n" >"$2"; printf "fixture public CA\\n" >"$3"; chmod 0600 "$2"; chmod 0444 "$3"; }',
      'issue_certificate() { printf "fixture private key\\n" >"$PKI_DIR/$1-key.pem"; printf "fixture certificate\\n" >"$PKI_DIR/$1.pem"; chmod 0600 "$PKI_DIR/$1-key.pem"; chmod 0444 "$PKI_DIR/$1.pem"; }',
      'generate_pki',
    ].join('\n')], { encoding: 'utf8', env: { ...process.env, PKI_DIR: pki, DOWNLOAD_DIR: downloads,
      GATEWAY_HOST: 'gateway.example.test', CONTROL_DOMAIN: 'control.example.test', PUBLIC_CERT_FILE: '', PUBLIC_KEY_FILE: '',
    } })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(statSync(downloads).mode & 0o777, 0o755)
    assert.equal(statSync(join(downloads, 'gateway-ca.pem')).mode & 0o777, 0o644)
    assert.equal(readFileSync(join(downloads, 'gateway-ca.pem'), 'utf8'), 'fixture public CA\n')
    for (const privateDirectory of [config, keys, pki]) assert.equal(statSync(privateDirectory).mode & 0o777, 0o700)
    for (const name of ['root-ca', 'gateway-client-ca', 'node-ca', 'control-internal-server', 'gateway-server', 'public-server', 'gateway-control-client']) {
      assert.equal(statSync(join(pki, `${name}-key.pem`)).mode & 0o777, 0o600, name)
    }
    for (const name of ['control.env', 'activation-code', 'administrator-password']) {
      assert.equal(statSync(join(config, name)).mode & 0o777, 0o600, name)
      assert.equal(readFileSync(join(config, name), 'utf8'), `private fixture ${name}`)
    }
  } finally {
    rmSync(directory, { recursive: true })
  }
})

test('published node downloads are readable without opening private installation state', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-control-public-node-test-'))
  try {
    const downloads = join(directory, 'downloads')
    const activation = join(directory, 'activation')
    mkdirSync(activation, { mode: 0o700 })
    writeFileSync(join(activation, 'bundle.json'), 'private activation fixture', { mode: 0o400 })
    mkdirSync(join(directory, 'scripts'))
    const facts = { version: '1.0.1', source: { commit: 'a'.repeat(40), tree: 'b'.repeat(40) } }
    writeFileSync(join(directory, 'install.manifest.json'), JSON.stringify(facts))
    writeFileSync(join(directory, 'cdnca-ed25519'), 'pinned tool fixture\n', { mode: 0o555 })
    writeFileSync(join(directory, 'scripts/install-node.sh'), `#!/usr/bin/env bash\n[[ "$1" = --verify-native-package && "$#" = 4 ]] || exit 1\nprintf '%s\\n' '${JSON.stringify(facts)}'\n`, { mode: 0o755 })
    const result = spawnSync('bash', ['-c', [
      'set -Eeuo pipefail', 'umask 077', block('fail'), block('download_node_assets'),
      'log() { :; }; assert_not_html() { :; }; tar() { :; }',
      'download_verified() { printf "fixture archive\\n" >"$5"; printf "fixture checksum\\n" >"$8"; }',
      'download_json_verified() { printf "fixture public trust\\n" >"$3"; }',
      'download_node_assets',
    ].join('\n')], { encoding: 'utf8', env: { ...process.env, DOWNLOAD_DIR: downloads,
      NATIVE_SUPPORT: directory, TEMP_DIR: directory, CONTROL_VERSION: facts.version, EDGE_AGENT_URL: '', EDGE_AGENT_FALLBACK_URL: '',
      ED25519_TOOL: join(directory, 'cdnca-ed25519'),
      EDGE_AGENT_SHA256_URL: '', EDGE_AGENT_SHA256_FALLBACK_URL: '', EDGE_ARTIFACT_TRUST_URL: '', EDGE_ARTIFACT_TRUST_FALLBACK_URL: '',
    } })
    assert.equal(result.status, 0, result.stderr)
    for (const name of ['', 'edge-agent', 'edge-agent/latest']) {
      assert.equal(statSync(join(downloads, name)).mode & 0o777, 0o755, name || 'downloads')
    }
    // install-node.sh downloads the pinned Ed25519 tool from beside the node artifacts.
    for (const name of ['install-node.sh', 'edge-agent/artifacts.json', 'edge-agent/cdnca-ed25519', 'edge-agent/latest/cdnca-edge-agent.tar.gz', 'edge-agent/latest/SHA256SUMS']) {
      assert.equal(statSync(join(downloads, name)).mode & 0o777, 0o644, name)
    }
    assert.equal(readFileSync(join(downloads, 'install-node.sh'), 'utf8'), readFileSync(join(directory, 'scripts/install-node.sh'), 'utf8'))
    assert.equal(statSync(activation).mode & 0o777, 0o700)
    assert.equal(statSync(join(activation, 'bundle.json')).mode & 0o777, 0o400)
    assert.equal(readFileSync(join(activation, 'bundle.json'), 'utf8'), 'private activation fixture')
  } finally {
    rmSync(directory, { recursive: true })
  }
})

test('new installation verifies the fixed monitoring stream and durable profile without updating live definitions', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-control-nats-test-'))
  try {
    const provision = block('preprovision_nats')
    for (const failed of [false, true]) {
      const result = spawnSync('bash', ['-c', [
        'set -Eeuo pipefail', block('fail'), provision, 'log() { :; }',
        'python3() { printf "%s\\n" "$@" >"$TEMP_DIR/calls"; [[ "$PROFILE_FAIL" == false ]]; }',
        'preprovision_nats', 'printf verified',
      ].join('\n')], { encoding: 'utf8', env: { ...process.env, TEMP_DIR: directory,
        NATIVE_SUPPORT: directory, CONFIG_DIR: directory, NATS_URL: 'nats://127.0.0.1:4222', PROFILE_FAIL: String(failed),
      } })
      assert.equal(result.status === 0, !failed, result.stderr)
      assert.equal(result.stdout, failed ? '' : 'verified')
      assert.deepEqual(readFileSync(join(directory, 'calls'), 'utf8').trim().split('\n'), [
        '-I', '-B', join(directory, 'scripts/native-runtime/configure-nats.py'), 'install',
        '--server', 'nats://127.0.0.1:4222', '--receipt', join(directory, 'native-nats-receipt.json'),
      ])
    }
    assert.doesNotMatch(provision, /stream update|consumer update/)
    const profile = JSON.parse(readFileSync(new URL('../scripts/native-runtime/native-nats-profile.json', import.meta.url)))
    assert.equal(profile.streams.length, 17)
    assert.equal(profile.consumers.length, 10)
    const command = profile.streams.find((stream) => stream.name === 'NODE_MONITORING_COMMANDS')
    const status = profile.streams.find((stream) => stream.name === 'NODE_MONITORING_STATUS')
    assert.deepEqual(command, { ...status, name: 'NODE_MONITORING_COMMANDS', subjects: ['cdnca.agent.node-monitoring.commands.*'] })
    assert.equal(command.retention, 'workqueue')
    assert.equal(profile.stream_defaults.storage, 'file')
    assert.equal(command.max_age, 0)
    assert.equal(command.discard, 'new')
  } finally { rmSync(directory, { recursive: true }) }
})
