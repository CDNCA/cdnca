import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { test } from 'node:test'

const file = new URL('../scripts/native-node-runtime-smoke.sh', import.meta.url)
const source = existsSync(file) ? readFileSync(file, 'utf8') : ''
const definitions = source.replace(/^main "\$@"\s*$/m, '')

test('harness is present, bounded, and uses only a private mount/network/PID namespace', () => {
  assert.ok(source.length > 0, 'native runtime smoke harness is missing')
  assert.match(source, /unshare --mount --net --pid --fork --mount-proc --kill-child/)
  assert.match(source, /timeout --signal=TERM --kill-after=5s 90s/)
  assert.match(source, /mount --make-rprivate \/ /)
  assert.match(source, /mount -t tmpfs[^\n]+ \/opt/)
  assert.match(source, /mount -t tmpfs[^\n]+ \/usr\/local/)
  assert.match(source, /mount -o remount,bind,ro/)
  assert.doesNotMatch(source, /(?:useradd|groupadd|systemctl|enroll|pkill|killall)\b/)
  assert.doesNotMatch(source, /(?:site-runtime|cdnca-edge)\/current/)
})

test('namespace entry refuses host execution before any mount or network change', () => {
  const result = spawnSync('bash', ['-c', `${definitions}\nmount() { printf 'UNSAFE-MOUNT'; }; ip() { printf 'UNSAFE-NET'; }; smoke_namespace`], { encoding: 'utf8' })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /fresh mount, network and PID namespaces required/)
  assert.doesNotMatch(result.stdout, /UNSAFE/)
})

test('ordinary invocation rejects non-Linux and non-root before creating evidence', () => {
  for (const [os, uid] of [['Darwin', '0'], ['Linux', '501']]) {
    const result = spawnSync('bash', ['-c', `${definitions}\nuname() { printf '${os}'; }; id() { printf '${uid}'; }; main`], { encoding: 'utf8' })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Linux root is required/)
  }
})

test('missing or malformed source identities fail before namespace execution', () => {
  for (const commit of ['', 'a'.repeat(39), 'not-a-commit', 'A'.repeat(40)]) {
    const result = spawnSync('bash', ['-c', `${definitions}\nuname() { printf Linux; }; id() { printf 0; }; unshare() { printf UNSAFE; }; main`], {
      encoding: 'utf8', env: { ...process.env, SOURCE_COMMIT: commit, SOURCE_TREE: 'b'.repeat(40) },
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /40 lowercase hex source commit and tree are required/)
    assert.doesNotMatch(result.stdout, /UNSAFE/)
  }
})

test('input paths reject relative, shell/config metacharacters and namespace-hidden locations', () => {
  for (const path of ['relative', '/tmp/unsafe path', '/tmp/a;return', '/opt/payload', '/usr/local/payload']) {
    const result = spawnSync('bash', ['-c', `${definitions}\nuname() { printf Linux; }; id() { printf 0; }; main`], {
      encoding: 'utf8', env: { ...process.env, SOURCE_COMMIT: 'a'.repeat(40), SOURCE_TREE: 'b'.repeat(40), PAYLOAD_DIR: path, EVIDENCE_DIR: '/tmp/evidence' },
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /absolute safe paths outside \/opt and \/usr\/local are required/)
  }
})

test('existing evidence and linked input are rejected without overwriting either', () => {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-native-smoke-contract.'))
  try {
    mkdirSync(join(root, 'payload'))
    mkdirSync(join(root, 'evidence'))
    writeFileSync(join(root, 'evidence', 'keep'), 'preserve')
    for (const linked of [false, true]) {
      if (linked) symlinkSync(join(root, 'payload'), join(root, 'linked'))
      const result = spawnSync('bash', ['-c', `${definitions}\nuname() { printf Linux; }; id() { printf 0; }; main`], {
        encoding: 'utf8', env: { ...process.env, SOURCE_COMMIT: 'a'.repeat(40), SOURCE_TREE: 'b'.repeat(40), PAYLOAD_DIR: join(root, linked ? 'linked' : 'payload'), EVIDENCE_DIR: join(root, 'evidence') },
      })
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /real inputs and a new evidence directory are required/)
      assert.equal(readFileSync(join(root, 'evidence', 'keep'), 'utf8'), 'preserve')
    }
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('inventory includes every runtime and Lua file in deterministic path order', () => {
  const python = source.match(/<<'INVENTORY'\n([\s\S]*?)\nINVENTORY/)?.[1]
  assert.ok(python, 'inventory implementation is missing')
  const root = mkdtempSync(join(tmpdir(), 'cdnca-native-smoke-contract.'))
  try {
    mkdirSync(join(root, 'runtime', 'lib'), { recursive: true })
    mkdirSync(join(root, 'lua', 'nested'), { recursive: true })
    writeFileSync(join(root, 'runtime', 'lib', 'z.so'), 'runtime')
    writeFileSync(join(root, 'lua', 'nested', 'a.lua'), 'return {}')
    const result = spawnSync('python3', ['-c', python, root], { encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    assert.deepEqual(JSON.parse(result.stdout), [
      { path: 'lua/nested/a.lua', sha256: createHash('sha256').update('return {}').digest('hex') },
      { path: 'runtime/lib/z.so', sha256: createHash('sha256').update('runtime').digest('hex') },
    ])
    symlinkSync('/etc/passwd', join(root, 'lua', 'escape.lua'))
    const rejected = spawnSync('python3', ['-c', python, root], { encoding: 'utf8' })
    assert.notEqual(rejected.status, 0)
    assert.match(rejected.stderr, /ordinary payload files and directories required/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('fixture binds only loopback, verifies all Lua and dynamic modules, and keeps worker non-root', () => {
  assert.match(source, /user nobody nogroup;/)
  assert.match(source, /nginx\/modules/)
  assert.match(source, /ngx_\*_module\.so/)
  assert.match(source, /require\('resty\.core'\)/)
  assert.match(source, /require\('cjson'\)/)
  assert.match(source, /assert\(loadfile\(/)
  assert.match(source, /subjectAltName=IP:127\.0\.0\.1/)
  for (const port of ['18080', '18443', '18444']) assert.match(source, new RegExp(`127\\.0\\.0\\.1:${port}`))
  assert.doesNotMatch(source, /0\.0\.0\.0|\[::\]|--insecure|curl[^\n]+ -k\b/)
})

test('requests assert negotiated protocols and fresh HTTP3 after a same-master new-worker reload', () => {
  assert.match(source, /--http1\.1/)
  assert.match(source, /--http2 --cacert/)
  assert.match(source, /--bind 127\.0\.0\.1:0/)
  assert.match(source, /\.protocol == "HTTP\/3\.0"/)
  assert.match(source, /\.tls_version == "TLSv1\.3"/)
  assert.match(source, /kill -HUP "\$SMOKE_MASTER"/)
  assert.match(source, /smoke_requests v2/)
  assert.match(source, /master_start/)
  assert.match(source, /worker_before/)
  assert.match(source, /worker_after/)
})

test('report never claims source signatures or security patches have passed', () => {
  assert.match(source, /cdnca\.native-node\.runtime-smoke\/v1/)
  assert.match(source, /status=FAIL/)
  assert.match(source, /files\.after\.json/)
  assert.match(source, /cmp[^\n]+files\.json[^\n]+files\.after\.json/)
  assert.doesNotMatch(source, /(?:source_signatures|patches|release_eligible)[^\n]*(?:true|PASS)/)
  assert.doesNotMatch(source, /cp[^\n]+server\.key/)
})

test('namespace denial, unproven zero exit, and changed payload all emit FAIL and clean only owned temp files', () => {
  const python = spawnSync('which', ['python3'], { encoding: 'utf8' }).stdout.trim()
  const jq = spawnSync('which', ['jq'], { encoding: 'utf8' }).stdout.trim()
  assert.ok(python && jq, 'contract tests require python3 and jq')
  for (const outcome of ['denied', 'empty-success', 'changed']) {
    const root = mkdtempSync(join(tmpdir(), 'cdnca-native-smoke-contract.'))
    const before = readdirSync('/tmp').filter((name) => name.startsWith('cdnca-native-runtime-smoke.'))
    try {
      mkdirSync(join(root, 'payload', 'runtime'), { recursive: true })
      mkdirSync(join(root, 'payload', 'lua'))
      writeFileSync(join(root, 'payload', 'runtime', 'fixture'), 'not an executable')
      writeFileSync(join(root, 'payload', 'lua', 'fixture.lua'), 'return {}')
      mkdirSync(join(root, 'payload', 'runtime', 'bin'))
      writeFileSync(join(root, 'payload', 'runtime', 'bin', 'h3probe'), 'not an executable', { mode: 0o555 })
      writeFileSync(join(root, 'definitions.sh'), `${definitions}
uname() { printf Linux; }
id() { if [[ $# == 2 && $2 == nobody ]]; then printf 65534; else printf 0; fi; }
getent() { printf 'nogroup:x:65534:\\n'; }
curl() { printf 'Features: HTTP2\\n'; }
readelf() { printf 'Machine: Advanced Micro Devices X86-64\\n'; }
realpath() { if [[ $1 == -e ]]; then shift; fi; printf '%s\\n' "$1"; }
readlink() { printf 'ns[original]'; }
python3() { "$SMOKE_TEST_PYTHON" "$@"; }
jq() { "$SMOKE_TEST_JQ" "$@"; }
unshare() { :; }
mount() { printf 'UNSAFE-MOUNT' >&2; return 99; }
ip() { printf 'UNSAFE-NET' >&2; return 99; }
timeout() {
  case $SMOKE_TEST_OUTCOME in
    denied) printf 'namespace creation denied\\n' >&2; return 73;;
    changed) printf 'changed' >> "$PAYLOAD_DIR/lua/fixture.lua";;
  esac
}
main
`)
      const result = spawnSync('bash', [join(root, 'definitions.sh')], {
        encoding: 'utf8', timeout: 5000,
        env: { ...process.env, SOURCE_COMMIT: 'a'.repeat(40), SOURCE_TREE: 'b'.repeat(40), PAYLOAD_DIR: join(root, 'payload'), EVIDENCE_DIR: join(root, 'evidence'), SMOKE_TEST_PYTHON: python, SMOKE_TEST_JQ: jq, SMOKE_TEST_OUTCOME: outcome },
      })
      assert.notEqual(result.status, 0, `${outcome} cannot pass`)
      const report = JSON.parse(readFileSync(join(root, 'evidence', 'result.json'), 'utf8'))
      assert.equal(report.status, 'FAIL', outcome)
      assert.deepEqual(report.source, { commit: 'a'.repeat(40), tree: 'b'.repeat(40) })
      assert.equal(report.files.length, 3)
      assert.deepEqual(report.checks, {})
      assert.doesNotMatch(readFileSync(join(root, 'evidence', 'namespace.log'), 'utf8'), /UNSAFE/)
      assert.equal(readFileSync(join(root, 'payload', 'runtime', 'bin', 'h3probe'), 'utf8'), 'not an executable')
      assert.deepEqual(readdirSync('/tmp').filter((name) => name.startsWith('cdnca-native-runtime-smoke.')), before)
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
})

test('request assertions reject HTTP2 fallback, bad Lua evidence and incorrect HTTP3 generation or TLS', () => {
  const validH3 = { protocol: 'HTTP/3.0', status: 200, tls_version: 'TLSv1.3', version_header: 'v1', body: '{"lua":"ok","files":12}' }
  for (const value of [
    { name: 'valid fixture', status: 0 },
    { name: 'HTTP2 fallback', protocol: '1.1', status: 1 },
    { name: 'missing Lua asset', lua: '{"lua":"ok","files":11}', status: 1 },
    { name: 'wrong stream response', stream: 'old', status: 1 },
    { name: 'wrong HTTP3 protocol', h3: { protocol: 'HTTP/2' }, status: 1 },
    { name: 'wrong HTTP3 generation', h3: { version_header: 'old' }, status: 1 },
    { name: 'wrong TLS', h3: { tls_version: 'TLSv1.2' }, status: 1 },
    { name: 'bad Lua result', h3: { body: '{"lua":"bad","files":12}' }, status: 1 },
    { name: 'HTTP3 missing Lua asset', h3: { body: '{"lua":"ok","files":11}' }, status: 1 },
  ]) {
    const root = mkdtempSync(join(tmpdir(), 'cdnca-native-smoke-contract.'))
    try {
      writeFileSync(join(root, 'client'), '#!/usr/bin/env bash\nprintf \'%s\\n\' "$SMOKE_H3_RESPONSE"\n', { mode: 0o700 })
      const result = spawnSync('bash', ['-c', `${definitions}
curl() {
  case "$*" in
    *--http1.1*) printf v1 > "$EVIDENCE_DIR/http1-v1.txt"; printf 1.1;;
    *--http2*) printf '%s' "$SMOKE_LUA" > "$EVIDENCE_DIR/http2-v1.json"; printf '%s' "$SMOKE_PROTOCOL";;
    *) printf '%s' "$SMOKE_STREAM";;
  esac
}
smoke_requests v1
`], {
        encoding: 'utf8', timeout: 5000,
        env: { ...process.env, EVIDENCE_DIR: root, SMOKE_WORK: root, SMOKE_H3PROBE: join(root, 'client'), SMOKE_PROTOCOL: value.protocol ?? '2', SMOKE_LUA: value.lua ?? '{"lua":"ok","files":12}', SMOKE_STREAM: value.stream ?? 'v1', SMOKE_H3_RESPONSE: JSON.stringify({ ...validH3, ...value.h3 }) },
      })
      assert.equal(result.status, value.status, `${value.name}: ${result.stderr}`)
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
})

test('inner failure leaves the shared temp directory for the outer evidence collector', () => {
  const root = spawnSync('mktemp', ['-d', '/tmp/cdnca-native-runtime-smoke.XXXXXXXX'], { encoding: 'utf8' }).stdout.trim()
  assert.match(root, /^\/tmp\/cdnca-native-runtime-smoke\.[A-Za-z0-9]{8}$/)
  try {
    writeFileSync(join(root, 'keep'), 'outer collector still needs this')
    const result = spawnSync('bash', ['-c', `${definitions}\nSMOKE_INSIDE=1; SMOKE_MASTER=; SMOKE_RUNNER=; cleanup_smoke`], {
      encoding: 'utf8', env: { ...process.env, SMOKE_WORK: root },
    })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(readFileSync(join(root, 'keep'), 'utf8'), 'outer collector still needs this')
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('all three required dynamic modules must be present, not merely one module', () => {
  const check = source.match(/  for file in ngx_http_geoip_module\.so[^\n]+done/)?.[0]
  assert.ok(check, 'exact three-module preflight is missing')
  const root = mkdtempSync(join(tmpdir(), 'cdnca-native-smoke-contract.'))
  const names = ['ngx_http_geoip_module.so', 'ngx_http_image_filter_module.so', 'ngx_http_xslt_filter_module.so']
  try {
    const directory = join(root, 'openresty', 'nginx', 'modules')
    mkdirSync(directory, { recursive: true })
    for (const missing of [...names, 'none']) {
      for (const name of names) {
        if (name === missing) rmSync(join(directory, name), { force: true })
        else writeFileSync(join(directory, name), 'not an executable')
      }
      const result = spawnSync('bash', ['-c', `check_modules() { local runtime=$1 file; ${check}; }; check_modules "$1"`, 'fixture', root], { encoding: 'utf8' })
      assert.equal(result.status, missing === 'none' ? 0 : 1, `${missing}: ${result.stderr}`)
    }
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('smoke loader prefers its exact OpenResty libraries before colliding generic libraries', () => {
  const declaration = source.match(/  local -a nginx=\([^\n]+\)/)?.[0]
  assert.ok(declaration, 'native loader command is missing')
  const result = spawnSync('bash', ['-c', `runtime=/candidate/runtime\n${declaration.replace('local ', 'declare ')}\nprintf '%s\\n' "\${nginx[@]}"`], { encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(result.stdout.trim().split('\n'), [
    '/candidate/runtime/lib/ld-musl-x86_64.so.1', '--library-path',
    ['openresty/luajit/lib', 'openresty/openssl3/lib', 'openresty/pcre2/lib', 'lib', 'usr/lib'].map((path) => `/candidate/runtime/${path}`).join(':'),
    '/candidate/runtime/openresty/nginx/sbin/nginx',
  ])
})

test('Lua smoke resolves the production module names and asserts their public exports', () => {
  assert.match(source, /lua_package_path '\/usr\/local\/share\/cdnca\/\?\.lua;\/usr\/local\/share\/cdnca\/security\/\?\.lua;\/usr\/local\/openresty\/lualib\/\?\.lua;/)
  assert.match(source, /local cc=require\('cc'\)/)
  for (const method of ['init', 'access', 'metrics', 'log']) assert.match(source, new RegExp(`type\\(cc\\.${method}\\)=='function'`))
  assert.match(source, /local http=require\('httppolicy\.engine'\)/)
  for (const method of ['access', 'header_filter']) assert.match(source, new RegExp(`type\\(http\\.${method}\\)=='function'`))
  assert.match(source, /local firewall=require\('firewallaction\.engine'\)/)
  assert.match(source, /type\(firewall\.handle\)=='function'/)
  assert.match(source, /assert\(count>=12\)/)
})

// HTTP/3 is exercised with the h3probe the package ships (runtime/bin/h3probe,
// what the Agent runs), never a client handed in from outside.
test('HTTP3 requests use the packaged h3probe, and a payload without one is refused', () => {
  assert.doesNotMatch(source, /HTTP3_CLIENT/)
  assert.match(source, /SMOKE_H3PROBE:-\/opt\/cdnca-node\/current\/runtime\/bin\/h3probe/)
  assert.match(source, /readelf -h "\$file"/)
  const root = mkdtempSync(join(tmpdir(), 'cdnca-native-smoke-contract.'))
  try {
    mkdirSync(join(root, 'payload', 'runtime'), { recursive: true })
    const result = spawnSync('bash', ['-c', `${definitions}\nuname() { printf Linux; }; id() { printf 0; }; unshare() { printf UNSAFE; }; main`], {
      encoding: 'utf8', env: { ...process.env, SOURCE_COMMIT: 'a'.repeat(40), SOURCE_TREE: 'b'.repeat(40), PAYLOAD_DIR: join(root, 'payload'), EVIDENCE_DIR: join(root, 'evidence') },
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /packaged runtime\/bin\/h3probe is required/)
    assert.doesNotMatch(result.stdout, /UNSAFE/)
    assert.equal(existsSync(join(root, 'evidence')), false)
  } finally { rmSync(root, { recursive: true, force: true }) }
})
