import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { test } from 'node:test'

// The reusable install command carries a scope-level registration key; the
// host registers itself and only then receives a one-time enrollment token.
const script = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
  .replace(/^main "\$@"\s*$/m, '')
const key = `nrk1.${'0123456789abcdef'.repeat(2)}.${'A'.repeat(43)}`

// A fake curl answers the registration call: it records its arguments, the
// request body (read from the @file argument) and returns RESPONSE/STATUS.
const run = (command, { response = '', status = '201' } = {}) => spawnSync('bash', ['-c', `
fake=$(mktemp -d); trap 'rm -rf "$fake"' EXIT
cat >"$fake/curl" <<'CURL'
#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$CURL_LOG"
out='' body=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    --data-binary) body=\${2#@}; shift 2 ;;
    *) shift ;;
  esac
done
[ -z "$body" ] || cp "$body" "$CURL_BODY"
printf '%s' "$RESPONSE" >"$out"
printf '%s' "$STATUS"
CURL
chmod +x "$fake/curl"; export PATH="$fake:$PATH" CURL_LOG="$fake/log" CURL_BODY="$fake/body"
machine="$fake/machine-id"; product="$fake/product_uuid"
printf 'machine-fixture\\n' >"$machine"; printf 'PRODUCT-FIXTURE\\n' >"$product"
${script}
MACHINE_ID_FILE=$machine
PRODUCT_UUID_FILE=$product
TEMP_DIR=$(mktemp -d "$fake/tmp.XXXX")
${command}`], { encoding: 'utf8', env: { ...process.env, RESPONSE: response, STATUS: status, CDNCA_PUBLIC_IP_SOURCES: '' } })

test('registration key is accepted instead of a one-time token and never mixed with one', () => {
  const ok = run(`parse_args --control-plane https://control.example --registration-key-stdin
read_enrollment_token <<<'${key}'
printf '%s|%s' "$REGISTRATION_KEY" "$ENROLLMENT_TOKEN"`)
  assert.equal(ok.status, 0, ok.stderr)
  assert.equal(ok.stdout, `${key}|`)
  for (const [flags, input] of [['--registration-key-stdin --token fixture-once', `'${key}'`],
    ['--registration-key-stdin', "'nrk1.bad'"], ['--registration-key-stdin', `$'${key}\\nextra'`],
    ['--registration-key-stdin', "''"], [`--registration-key '${key}'`, "''"]]) {
    const rejected = run(`parse_args --control-plane https://control.example ${flags}\nread_enrollment_token <<<${input}`)
    assert.notEqual(rejected.status, 0, `${flags} ${input}`)
    assert.equal(rejected.stderr.includes(key), false)
  }
})

test('register_node posts the machine fingerprint and uses the returned enrollment token', () => {
  const response = JSON.stringify({ node: { id: 'node-id', display_id: '7', name: 'edge-a' }, enrollment_token: { token: 'issued-once-token' }, reused: false })
  const result = run(`parse_args --control-plane https://control.example --registration-key-stdin --node-name edge-a
read_enrollment_token <<<'${key}'
register_node
printf 'TOKEN=%s\\n' "$ENROLLMENT_TOKEN"
cat "$CURL_LOG"
jq -c . "$CURL_BODY"`, { response })
  assert.equal(result.status, 0, result.stderr)
  const [token, curl, body] = result.stdout.trim().split('\n').filter((line) => !line.startsWith('[cdnca-edge]'))
  assert.equal(token, 'TOKEN=issued-once-token')
  assert.match(curl, /--proto =https --proto-redir =https/)
  assert.match(curl, /https:\/\/control\.example\/v1\/node-registrations$/)
  assert.equal(curl.includes(key), false, 'registration key must not appear in curl argv')
  const request = JSON.parse(body)
  const expected = spawnSync('bash', ['-c', "printf 'cdnca-node-registration-v1\\0machine-fixture\\0product-fixture' | sha256sum | cut -d' ' -f1"], { encoding: 'utf8' }).stdout.trim()
  assert.equal(request.machine_fingerprint, expected)
  assert.equal(request.credential, key)
  assert.equal(request.hostname, 'edge-a')
  assert.match(result.stdout, /待初始化/)
})

test('register_node prints readable Chinese errors and fails closed', () => {
  for (const [status, code, pattern] of [
    ['401', 'invalid_registration_credential', /注册凭据无效或已被重置/],
    ['409', 'node_already_registered', /已注册/],
    ['429', 'node_registration_rate_limited', /过于频繁/],
    ['503', 'node_registration_unavailable', /未启用节点注册/],
  ]) {
    const result = run(`parse_args --control-plane https://control.example --registration-key-stdin
read_enrollment_token <<<'${key}'
register_node`, { status, response: JSON.stringify({ error: { code, message: 'x' } }) })
    assert.notEqual(result.status, 0, code)
    assert.match(result.stderr, pattern, code)
    assert.equal(result.stderr.includes(key), false)
  }
})
