// final-fix-a：传入 --public-cert-file/--public-key-file 时的续期处理。
// 文件来自 /etc/letsencrypt/live/<名>/ 时与自签一样装 deploy hook；
// 不是 certbot lineage 时不装 hook，安装结束打印到期日和替换方法。
import assert from 'node:assert/strict'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const extract = (name) => source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}\\n`, 'm'))?.[0]
const lineage = extract('public_certificate_lineage')
const hookWriter = extract('install_public_certificate_renewal_hook')
const issuer = extract('issue_public_certificate')
const reporter = extract('report_public_certificate_renewal')
const realHook = '/etc/letsencrypt/renewal-hooks/deploy/cdnca-control-web.sh'

// Runs the real functions with the hook path redirected into a temporary
// directory; certbot is never reached because PUBLIC_CERT_FILE is set.
function run({ certFile, keyFile, certPath = '', step = 'issue_public_certificate' }) {
  assert.ok(lineage && hookWriter && issuer && reporter, 'extract the real certificate functions')
  const root = mkdtempSync(join(tmpdir(), 'cdnca-public-cert-renewal-'))
  const hook = join(root, 'hooks/cdnca-control-web.sh')
  const script = [
    'set -Eeuo pipefail',
    'log() { printf "LOG %s\\n" "$*"; }', 'warn() { printf "WARN %s\\n" "$*"; }', 'fail() { printf "FAIL %s\\n" "$*"; exit 1; }',
    'control_domain_is_ip() { return 1; }',
    lineage, hookWriter.replace(realHook, hook), issuer, reporter, step,
  ].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: {
    PATH: '/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin', CONTROL_DOMAIN: 'console.example.com', PUBLIC_CERT_FILE: certFile,
    PUBLIC_KEY_FILE: keyFile, PUBLIC_CERT_PATH: certPath, PKI_DIR: '/var/lib/cdnca/pki', WEB_SERVICE_NAME: 'cdnca-control-web',
  } })
  const hookText = existsSync(hook) ? readFileSync(hook, 'utf8') : ''
  rmSync(root, { recursive: true, force: true })
  return { ...result, hookText }
}

test('operator files from a certbot lineage get the renewal deploy hook for that lineage', () => {
  const result = run({ certFile: '/etc/letsencrypt/live/console.example.com/fullchain.pem',
    keyFile: '/etc/letsencrypt/live/console.example.com/privkey.pem' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.stdout, /LOG public certificate comes from \/etc\/letsencrypt\/live\/console\.example\.com/)
  assert.match(result.hookText, /RENEWED_LINEAGE:-\}" = "\/etc\/letsencrypt\/live\/console\.example\.com"/)
  assert.match(result.hookText, /install -m 0444 "\/etc\/letsencrypt\/live\/console\.example\.com\/fullchain\.pem" "\/var\/lib\/cdnca\/pki\/public-cert\.pem"/)
  assert.match(result.hookText, /install -m 0600 "\/etc\/letsencrypt\/live\/console\.example\.com\/privkey\.pem" "\/var\/lib\/cdnca\/pki\/public-key\.pem"/)
  assert.match(result.hookText, /systemctl reload "cdnca-control-web"/)
})

test('the hook copies the file names the operator passed (cert.pem instead of fullchain.pem)', () => {
  const result = run({ certFile: '/etc/letsencrypt/live/a.example/cert.pem', keyFile: '/etc/letsencrypt/live/a.example/privkey.pem' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.hookText, /install -m 0444 "\/etc\/letsencrypt\/live\/a\.example\/cert\.pem"/)
})

test('files outside a certbot lineage, or split across lineages, get no hook', () => {
  for (const [certFile, keyFile] of [
    ['/root/tls/fullchain.pem', '/root/tls/privkey.pem'],
    ['/etc/letsencrypt/live/a.example/fullchain.pem', '/etc/letsencrypt/live/b.example/privkey.pem'],
    ['/etc/letsencrypt/archive/a.example/fullchain1.pem', '/etc/letsencrypt/archive/a.example/privkey1.pem'],
    ['/etc/letsencrypt/live/a.example/sub/fullchain.pem', '/etc/letsencrypt/live/a.example/sub/privkey.pem'],
  ]) {
    const result = run({ certFile, keyFile })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    assert.equal(result.hookText, '', certFile)
    assert.doesNotMatch(result.stdout, /renewal deploy hook/)
  }
})

test('an operator certificate outside a lineage reports its expiry and how to replace it at the end', () => {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-public-cert-expiry-'))
  try {
    const cert = join(root, 'served.pem')
    const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-days', '30', '-subj', '/CN=console.example.com', '-keyout', join(root, 'served.key'), '-out', cert], { encoding: 'utf8' })
    assert.equal(made.status, 0, made.stderr)
    const enddate = spawnSync('openssl', ['x509', '-in', cert, '-noout', '-enddate'], { encoding: 'utf8' }).stdout.trim().replace(/^notAfter=/, '')
    const result = run({ certFile: '/root/tls/fullchain.pem', keyFile: '/root/tls/privkey.pem', certPath: cert,
      step: 'report_public_certificate_renewal' })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    assert.ok(result.stdout.includes(`到期时间：${enddate}`), result.stdout)
    assert.match(result.stdout, /不会自动续期/)
    assert.match(result.stdout, /install -m 0444 <新证书链> \/var\/lib\/cdnca\/pki\/public-cert\.pem && install -m 0600 <新私钥> \/var\/lib\/cdnca\/pki\/public-key\.pem && systemctl reload cdnca-control-web/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('no end-of-install renewal notice for our own or a lineage certificate', () => {
  for (const [certFile, keyFile] of [['', ''],
    ['/etc/letsencrypt/live/console.example.com/fullchain.pem', '/etc/letsencrypt/live/console.example.com/privkey.pem']]) {
    const result = run({ certFile, keyFile, certPath: '/nonexistent', step: 'report_public_certificate_renewal' })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    assert.equal(result.stdout, '')
  }
})

test('the installer reports the renewal notice after the endpoints, at the end of main', () => {
  assert.match(source, /\n  print_gateway_ports\n  bt_report\n  report_public_certificate_renewal\n  log 'control-api installed, activated and ready'\n/)
})
