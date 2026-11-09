// install-control.sh 的 fetch_with_retry（第三方下载有限重试）。
// PATH 里放一个假 curl：按调用次序读计划文件的一行“退出码 HTTP状态码”，照 curl 的 --write-out 输出状态码，
// 成功时写 --output 文件；每次调用的参数记下来核对 TLS 选项没有被降级。
import assert from 'node:assert/strict'
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import test from 'node:test'

const read = (relative) => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8')
const control = read('scripts/install-control.sh')
const fetchBlock = control.match(/^FETCH_RETRY_DELAYS=\(.*\)\nfetch_with_retry\(\) \{[\s\S]*?^\}/m)?.[0]
const progress = read('scripts/lib/install-progress.sh')

const fakeCurl = `#!/usr/bin/env bash
n=$(( $(cat "$FAKE_DIR/count" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$FAKE_DIR/count"
printf '%s\\n' "$*" >>"$FAKE_DIR/calls"
out='' write=''
while [ $# -gt 0 ]; do case "$1" in -o|--output) out=$2; shift ;; --write-out) write=$2; shift ;; esac; shift; done
read -r rc http < <(sed -n "\${n}p" "$FAKE_DIR/plan")
rc=\${rc:-0} http=\${http:-200}
[ "$rc" -ne 0 ] || printf 'body' >"$out"
[ "$rc" -eq 0 ] || echo "curl: ($rc) fake failure" >&2
[ -z "$write" ] || printf '%s' "$http"
exit "$rc"
`

function run(t, plan, { command = 'curl', lang = 'zh', prefix = '' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-fetch-retry-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  writeFileSync(join(dir, 'curl'), fakeCurl); chmodSync(join(dir, 'curl'), 0o755)
  writeFileSync(join(dir, 'plan'), plan.join('\n') + '\n')
  assert.ok(fetchBlock, 'fetch_with_retry not found in install-control.sh')
  const script = ['set -Eeuo pipefail', progress,
    'log() { printf "[cdnca-control] %s\\n" "$*"; }', 'warn() { printf "[cdnca-control] warning: %s\\n" "$*" >&2; }',
    'sleep() { printf "%s\\n" "$1" >>"$FAKE_DIR/sleeps"; }', fetchBlock,
    // A non-empty PROGRESS_PREFIX takes the progress_download pipeline (curl stdout via fd 3, stderr through awk).
    prefix ? `PROGRESS_PREFIX='${prefix}'` : ':',
    `status=0; fetch_with_retry RustFS ${command} --proto '=https' --proto-redir '=https' --tlsv1.2 -fL --output "$FAKE_DIR/out" https://example.invalid/a.zip || status=$?`,
    'echo "status=$status"'].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', timeout: 20000,
    env: { PATH: `${dir}:${process.env.PATH}`, FAKE_DIR: dir, INSTALL_LANG: lang } })
  const file = (name) => existsSync(join(dir, name)) ? readFileSync(join(dir, name), 'utf8') : ''
  return { ...result, calls: file('calls').trim().split('\n').filter(Boolean), sleeps: file('sleeps').trim().split('\n').filter(Boolean),
    output: file('out'), status: Number(/status=(\d+)/.exec(result.stdout)?.[1]) }
}

test('network errors are retried with 2/5/10 s back-off and the download then succeeds', (t) => {
  const result = run(t, ['28 000', '35 000', '0 200'])
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.calls.length, 3)
  assert.deepEqual(result.sleeps, ['2', '5'])
  assert.equal(result.output, 'body')
  assert.match(result.stderr, /RustFS 第 1 次下载失败（curl 退出码 28，HTTP 000），2 秒后重试/)
  assert.match(result.stderr, /RustFS 第 2 次下载失败（curl 退出码 35，HTTP 000），5 秒后重试/)
  assert.match(result.stdout, /RustFS 第 3 次下载成功/)
  for (const call of result.calls) {
    assert.match(call, /--proto =https --proto-redir =https --tlsv1\.2 -fL/)
    assert.doesNotMatch(call, /(^| )(-k|--insecure)( |$)/)
  }
})

test('every network error code in the list is retried; HTTP 5xx is retried', (t) => {
  for (const code of ['6', '7', '16', '18', '28', '35', '52', '55', '56', '92']) {
    const result = run(t, [`${code} 000`, '0 200'])
    assert.equal(result.status, 0, `${code}: ${result.stderr}`)
    assert.equal(result.calls.length, 2, code)
  }
  const result = run(t, ['22 503', '56 502', '0 200'])
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.calls.length, 3)
})

test('HTTP 4xx fails at once without a retry, even when curl reports it as exit 56 (HTTP/2)', (t) => {
  for (const [rc, http] of [['22', '404'], ['56', '404'], ['22', '403']]) {
    const result = run(t, [`${rc} ${http}`, '0 200'])
    assert.equal(result.status, Number(rc), result.stderr)
    assert.equal(result.calls.length, 1)
    assert.deepEqual(result.sleeps, [])
    assert.match(result.stderr, new RegExp(`RustFS 下载失败（HTTP ${http}），不重试`))
  }
})

test('non-network curl errors (file too large, write error) are not retried', (t) => {
  for (const rc of ['63', '23', '60']) {
    const result = run(t, [`${rc} 200`, '0 200'])
    assert.equal(result.status, Number(rc))
    assert.equal(result.calls.length, 1)
    assert.match(result.stderr, new RegExp(`curl 退出码 ${rc}），不是网络错误，不重试`))
  }
})

test('four failed attempts give up with the last curl exit code', (t) => {
  const result = run(t, ['28 000', '7 000', '6 000', '35 000', '0 200'])
  assert.equal(result.status, 35)
  assert.equal(result.calls.length, 4)
  assert.deepEqual(result.sleeps, ['2', '5', '10'])
  assert.match(result.stderr, /RustFS 连续 4 次下载失败（最后一次 curl 退出码 35，HTTP 000），放弃/)
})

test('English messages with --lang en', (t) => {
  const result = run(t, ['28 000', '22 404'], { lang: 'en' })
  assert.equal(result.status, 22)
  assert.match(result.stderr, /RustFS download attempt 1 failed \(curl exit 28, HTTP 000\); retrying in 2s/)
  assert.match(result.stderr, /RustFS download failed \(HTTP 404\); not retried/)
  assert.doesNotMatch(result.stderr + result.stdout, /\p{Script=Han}/u)
})

test('works behind progress_download (the status code still reaches the retry decision)', (t) => {
  let result = run(t, ['28 000', '0 200'], { command: 'progress_download RustFS curl', prefix: '[2/12] ' })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.calls.length, 2)
  result = run(t, ['56 404'], { command: 'progress_download RustFS curl', prefix: '[2/12] ' })
  assert.equal(result.status, 56)
  assert.equal(result.calls.length, 1)
})

test('RustFS and the NATS CLI download through fetch_with_retry; no stacked curl --retry there', () => {
  const rustfs = control.match(/^configure_runtime_dependencies\(\) \{[\s\S]*?^\}/m)[0]
  assert.match(rustfs, /fetch_with_retry RustFS progress_download RustFS curl --proto '=https' --proto-redir '=https' --tlsv1\.2 -fL/)
  const nats = control.match(/^download_nats_binaries\(\) \{[\s\S]*?^\}/m)[0]
  assert.match(nats, /fetch_with_retry 'NATS CLI' progress_download 'NATS CLI' curl --proto '=https' --proto-redir '=https' --tlsv1\.2 -fL/)
  assert.match(nats, /fetch_with_retry 'NATS CLI SHA256SUMS' curl --proto '=https' --proto-redir '=https' --tlsv1\.2 -fL/)
  assert.match(nats, /fail "\$\(msg 'NATS CLI 校验和不符' 'NATS CLI checksum mismatch'\)"/)
  for (const block of [rustfs, nats]) assert.doesNotMatch(block, /--retry |--insecure|(^|\s)-k(\s|$)/)
})
