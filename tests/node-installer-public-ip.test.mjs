import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { test } from 'node:test'

// The node's public IP goes with the self-registration
// (decisions/market-node-admission-and-compat-2026-10-16.md): --public-ip,
// else a public address on an interface, else agreeing external echo
// services, else the terminal; a control plane older than the field gets the
// registration again without it.
const script = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
  .replace(/^main "\$@"\s*$/m, '')
const key = `nrk1.${'0123456789abcdef'.repeat(2)}.${'A'.repeat(43)}`
const ok = JSON.stringify({ node: { id: 'n', display_id: '7', name: 'edge-a' }, enrollment_token: { token: 'issued-once-token' } })

// Fake ip prints IP_ADDRS (one CIDR per line) for "-4"/"-6"; fake curl answers
// echo services from ECHO_<n> by position in CDNCA_PUBLIC_IP_SOURCES and the
// registration from REG_STATUS_<call>/REG_RESPONSE_<call>, saving each body.
const run = (command, env = {}) => spawnSync('bash', ['-c', `
fake=$(mktemp -d); trap 'rm -rf "$fake"' EXIT
cat >"$fake/ip" <<'IP'
#!/usr/bin/env bash
family=$1
printf '%s\\n' "\${IP_ADDRS:-}" | while read -r a; do
  [ -n "$a" ] || continue
  case "$family:$a" in -4:*:*|-6:*.*) continue ;; esac
  printf '2: eth0    inet %s scope global eth0\\n' "$a"
done
IP
cat >"$fake/curl" <<'CURL'
#!/usr/bin/env bash
out='' body='' url=''
for arg in "$@"; do url=$arg; done
while [ "$#" -gt 0 ]; do
  case "$1" in -o) out=$2; shift 2 ;; --data-binary) body=\${2#@}; shift 2 ;; *) shift ;; esac
done
case "$url" in
  https://echo*)
    n=\${url#https://echo}; n=\${n%%.*}; var="ECHO_$n"; [ -n "\${!var:-}" ] || exit 7; printf '%s\\n' "\${!var}"; exit 0 ;;
esac
calls=$(($(cat "$CURL_CALLS" 2>/dev/null || echo 0) + 1)); printf '%s' "$calls" >"$CURL_CALLS"
cp "$body" "$CURL_BODY.$calls"
s="REG_STATUS_$calls"; r="REG_RESPONSE_$calls"
printf '%s' "\${!r:-$REG_RESPONSE}" >"$out"; printf '%s' "\${!s:-201}"
CURL
chmod +x "$fake/ip" "$fake/curl"; export PATH="$fake:$PATH" CURL_CALLS="$fake/calls" CURL_BODY="$fake/body"
machine="$fake/machine-id"; product="$fake/product_uuid"
printf 'machine-fixture\\n' >"$machine"; printf 'PRODUCT-FIXTURE\\n' >"$product"
${script}
MACHINE_ID_FILE=$machine
PRODUCT_UUID_FILE=$product
TEMP_DIR=$(mktemp -d "$fake/tmp.XXXX")
${command}`], { encoding: 'utf8', input: '', env: { ...process.env, REG_RESPONSE: ok,
  CDNCA_PUBLIC_IP_SOURCES: 'https://echo1.test https://echo2.test https://echo3.test', ...env } })

const register = `parse_args --control-plane https://control.example --registration-key-stdin --yes \${EXTRA:-}
read_enrollment_token <<<'${key}'
register_node
for f in "$CURL_BODY".*; do jq -c . "$f"; done`

const bodies = (result) => result.stdout.trim().split('\n').filter((line) => line.startsWith('{')).map((line) => JSON.parse(line))

test('public_ip_or_empty accepts only public unicast addresses', () => {
  const result = run(`for a in 8.8.8.8 ' 1.1.1.1 ' 2606:4700::1111 ::ffff:8.8.4.4 10.0.0.1 100.64.1.1 127.0.0.1 169.254.1.1 192.0.2.1 \\
  198.51.100.7 203.0.113.9 224.0.0.1 0.0.0.0 fe80::1 fc00::1 2001:db8::1 nope 300.1.1.1; do printf '%s=%s\\n' "$a" "$(public_ip_or_empty "$a")"; done`)
  assert.equal(result.status, 0, result.stderr)
  const got = Object.fromEntries(result.stdout.trim().split('\n').map((l) => l.split('=')))
  assert.equal(got['8.8.8.8'], '8.8.8.8')
  assert.equal(got[' 1.1.1.1 '], '1.1.1.1')
  assert.equal(got['2606:4700::1111'], '2606:4700::1111')
  assert.equal(got['::ffff:8.8.4.4'], '8.8.4.4')
  for (const bad of ['10.0.0.1', '100.64.1.1', '127.0.0.1', '169.254.1.1', '192.0.2.1', '198.51.100.7', '203.0.113.9', '224.0.0.1',
    '0.0.0.0', 'fe80::1', 'fc00::1', '2001:db8::1', 'nope', '300.1.1.1']) {
    assert.equal(got[bad], '', bad)
  }
})

test('--public-ip wins and an invalid one fails before anything is sent', () => {
  const given = run(register, { EXTRA: '--public-ip 8.8.4.4', IP_ADDRS: '1.1.1.1/24', ECHO_1: '9.9.9.9', ECHO_2: '9.9.9.9' })
  assert.equal(given.status, 0, given.stderr)
  assert.equal(bodies(given)[0].public_ip, '8.8.4.4')
  const bad = run(register, { EXTRA: '--public-ip 10.1.2.3' })
  assert.notEqual(bad.status, 0)
  assert.match(bad.stderr, /--public-ip 10\.1\.2\.3 is not a public/)
  assert.equal(bodies(bad).length, 0, 'nothing may be sent')
})

test('an interface address comes first, then agreeing echo services', () => {
  const nic = run(register, { IP_ADDRS: '10.0.0.5/24\n1.1.1.1/24', ECHO_1: '9.9.9.9', ECHO_2: '9.9.9.9' })
  assert.equal(nic.status, 0, nic.stderr)
  assert.equal(bodies(nic)[0].public_ip, '1.1.1.1')
  const echo = run(register, { IP_ADDRS: '10.0.0.5/24', ECHO_1: '9.9.9.9', ECHO_2: 'garbage', ECHO_3: '9.9.9.9' })
  assert.equal(echo.status, 0, echo.stderr)
  assert.equal(bodies(echo)[0].public_ip, '9.9.9.9')
  const single = run(register, { IP_ADDRS: '', ECHO_2: '8.8.8.8' })
  assert.equal(bodies(single)[0].public_ip, '8.8.8.8')
  assert.match(single.stderr, /only one external IP service answered/)
})

test('disagreeing or missing answers register without public_ip (the control plane records the source)', () => {
  const split = run(register, { IP_ADDRS: '10.0.0.5/24', ECHO_1: '9.9.9.9', ECHO_2: '8.8.8.8' })
  assert.equal(split.status, 0, split.stderr)
  assert.match(split.stderr, /disagree/)
  assert.equal('public_ip' in bodies(split)[0], false)
  const none = run(register, { IP_ADDRS: '', CDNCA_PUBLIC_IP_SOURCES: '' })
  assert.equal(none.status, 0, none.stderr)
  assert.equal('public_ip' in bodies(none)[0], false)
  assert.match(none.stderr, /未检测到本机公网 IP/)
})

test('an older control plane rejecting public_ip gets the registration again without it', () => {
  const old = run(register, { EXTRA: '--public-ip 8.8.4.4', REG_STATUS_1: '400',
    REG_RESPONSE_1: JSON.stringify({ error: { code: 'invalid_request' } }) })
  assert.equal(old.status, 0, old.stderr)
  const [first, second] = bodies(old)
  assert.equal(first.public_ip, '8.8.4.4')
  assert.equal(second && 'public_ip' in second, false)
  assert.match(old.stdout, /待初始化/)
  // Other errors are not retried.
  const denied = run(register, { EXTRA: '--public-ip 8.8.4.4', REG_STATUS_1: '401',
    REG_RESPONSE_1: JSON.stringify({ error: { code: 'invalid_registration_credential' } }) })
  assert.notEqual(denied.status, 0)
  assert.match(denied.stderr, /注册凭据无效/)
  assert.doesNotMatch(denied.stderr, /管理端版本较旧/)
})
