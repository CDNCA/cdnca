import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { test } from 'node:test'

const script = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
  .replace(/^main "\$@"\s*$/m, '')

test('node installer accepts a single token on stdin without an argv credential', () => {
  const result = spawnSync('bash', ['-c', `${script}\nparse_args --control-plane https://control.example --enrollment-token-stdin\nread_enrollment_token\n[[ "$ENROLLMENT_TOKEN" == 'fixture-once' ]]`], {
    input: 'fixture-once\n', encoding: 'utf8',
  })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.includes('fixture-once'), false)
  assert.equal(result.stderr.includes('fixture-once'), false)
})

test('node installer rejects empty, multiline and mixed credential inputs', () => {
  for (const [input, flags] of [['', ''], ['one\ntwo\n', ''], ['fixture-once\n', '--enrollment-token old-fixture']]) {
    const result = spawnSync('bash', ['-c', `${script}\nparse_args --control-plane https://control.example --enrollment-token-stdin ${flags}\nread_enrollment_token`], { input, encoding: 'utf8' })
    assert.notEqual(result.status, 0)
    assert.equal(result.stderr.includes('fixture-once'), false)
  }
})

test('node installer carries the copied upgrade trust pin and URLs without a credential in argv', () => {
  const result = spawnSync('bash', ['-c', `${script}\nparse_args --control-plane https://control.example --enrollment-token-stdin --upgrade-trust-sha256 ${'a'.repeat(64)} --upgrade-trust-url https://control.example/downloads/edge-agent/upgrade-trust.json --upgrade-trust-fallback-url https://auth.example/downloads/edge-agent/upgrade-trust.json\nread_enrollment_token\nprintf '%s|%s|%s' "$UPGRADE_TRUST_SHA256" "$UPGRADE_TRUST_URL" "$UPGRADE_TRUST_FALLBACK_URL"`], {
    input: 'fixture-once\n', encoding: 'utf8',
  })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, `${'a'.repeat(64)}|https://control.example/downloads/edge-agent/upgrade-trust.json|https://auth.example/downloads/edge-agent/upgrade-trust.json`)
  assert.equal(result.stdout.includes('fixture-once'), false)
})

// A fake curl serves the console defaults so the short command can be checked
// without network access; it records the URL and flags it was called with.
const withFakeCurl = (body, command) => spawnSync('bash', ['-c', `
fake=$(mktemp -d); trap 'rm -rf "$fake"' EXIT
cat >"$fake/curl" <<'CURL'
#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$CURL_LOG"
[ -n "$DEFAULTS_BODY" ] || exit 22
printf '%s' "$DEFAULTS_BODY"
CURL
chmod +x "$fake/curl"; export PATH="$fake:$PATH" CURL_LOG="$fake/log"
${script}
${command}`], { encoding: 'utf8', env: { ...process.env, DEFAULTS_BODY: body } })

const defaults = [
  `upgrade_trust_sha256=${'b'.repeat(64)}`, 'gateway_enrollment_address=gw.example:19443',
  'gateway_address=gw.example:19444', 'gateway_server_name=gw.example', 'download_fallback_origin=https://auth.example', '',
].join('\n')

test('short command reads the token from --token and fills defaults from the console over HTTPS', () => {
  const result = withFakeCurl(defaults, `parse_args --control-plane https://control.example --token fixture-once
read_enrollment_token
load_console_defaults
printf '%s|%s|%s|%s|%s|%s\\n' "$ENROLLMENT_TOKEN" "$UPGRADE_TRUST_SHA256" "$GATEWAY_ENROLLMENT_ADDRESS" "$GATEWAY_ADDRESS" "$GATEWAY_SERVER_NAME" "$AGENT_FALLBACK_URL"
cat "$CURL_LOG"`)
  assert.equal(result.status, 0, result.stderr)
  const [values, curl] = result.stdout.trim().split('\n')
  assert.equal(values, `fixture-once|${'b'.repeat(64)}|gw.example:19443|gw.example:19444|gw.example|https://auth.example/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz`)
  assert.match(curl, /--proto =https --proto-redir =https/)
  assert.match(curl, /https:\/\/control\.example\/downloads\/node-install-defaults$/)
})

test('explicit flags win over console defaults and a copied trust pin skips the fetch', () => {
  const explicit = withFakeCurl(defaults, `parse_args --control-plane https://control.example --token fixture-once --gateway-address explicit.example:1
load_console_defaults
printf '%s' "$GATEWAY_ADDRESS"`)
  assert.equal(explicit.status, 0, explicit.stderr)
  assert.equal(explicit.stdout, 'explicit.example:1')
  const pinned = withFakeCurl('', `parse_args --control-plane https://control.example --token fixture-once --upgrade-trust-sha256 ${'a'.repeat(64)}
load_console_defaults
[ ! -e "$CURL_LOG" ] && printf '%s' "$UPGRADE_TRUST_SHA256"`)
  assert.equal(pinned.status, 0, pinned.stderr)
  assert.equal(pinned.stdout, 'a'.repeat(64))
})

test('console defaults fail closed when unreadable, unknown or malformed', () => {
  for (const body of ['', 'unexpected=1\n', `upgrade_trust_sha256=${'z'.repeat(64)}\n`,
    `upgrade_trust_sha256=${'b'.repeat(64)}\ndownload_fallback_origin=http://auth.example\n`,
    'gateway_address=gw.example:19444\n']) {
    const result = withFakeCurl(body, 'parse_args --control-plane https://control.example --token fixture-once\nload_console_defaults')
    assert.notEqual(result.status, 0, `accepted defaults: ${JSON.stringify(body)}`)
    assert.match(result.stderr, /node install defaults|upgrade trust pin/)
  }
})

// 10-22: a console on a temporary self-signed certificate (Let's Encrypt rate
// limited) failed at "cannot read node install defaults": the defaults fetch
// ignored --control-plane-ca-file. It now goes through curl_download.
test('console defaults are fetched with the pinned control-plane CA', () => {
  const result = withFakeCurl(defaults, `parse_args --control-plane https://control.example --token fixture-once --control-plane-ca-file /tmp/console-ca.pem
read_enrollment_token
load_console_defaults
cat "$CURL_LOG"`)
  assert.equal(result.status, 0, result.stderr)
  const first = result.stdout.trim().split('\n')[0]
  assert.match(first, /--cacert \/tmp\/console-ca\.pem/)
  assert.match(first, /https:\/\/control\.example\/downloads\/node-install-defaults$/)
})
