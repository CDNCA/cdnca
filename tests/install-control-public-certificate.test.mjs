import assert from 'node:assert/strict'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
// 被抽取的函数会调用进度展示（未 progress_init 时原样直通），与函数一起加载。
const progress = readFileSync(new URL('../scripts/lib/install-progress.sh', import.meta.url), 'utf8')
const issuer = source.match(/^issue_public_certificate\(\) \{[\s\S]*?^\}\n/m)?.[0]
const resolver = source.match(/^resolved_addresses\(\) \{.*\}$/m)?.[0]
// final-fix-a 起续期 hook 与 lineage 判断拆成独立函数，与 issue_public_certificate 一起加载。
const lineage = source.match(/^public_certificate_lineage\(\) \{[\s\S]*?^\}\n/m)?.[0]
const hookWriter = source.match(/^install_public_certificate_renewal_hook\(\) \{[\s\S]*?^\}\n/m)?.[0]
// 10/14 起 IP 判断抽成 control_domain_is_ip（与交互提示共用）；缺它时 if 会把“命令不存在”当假继续申请证书。
const ipCheck = source.match(/^control_domain_is_ip\(\) \{.*\}$/m)?.[0]
// 签发前先经 acme_issue_mode 判断 new/skip/renew。
const issueMode = source.match(/^acme_issue_mode\(\) \{[\s\S]*?^\}\n/m)?.[0]

// Runs only the real issue_public_certificate body with certbot/ss/apt stubbed,
// so the test proves the decision logic without contacting Let's Encrypt.
// existing: 预置 lineage（{ issuer, days, server, names }），此时 /etc/letsencrypt 改指临时目录。
function run({ domain, certFile = '', certbotExit = 0, portBusy = false, hosts = {}, existing = null }) {
  assert.ok(issuer, 'extract the real issue_public_certificate function')
  assert.ok(issueMode, 'extract the real acme_issue_mode function')
  assert.ok(ipCheck, 'extract the real control_domain_is_ip function')
  assert.ok(lineage && hookWriter, 'extract the real renewal hook helpers')
  const root = mkdtempSync(join(tmpdir(), 'cdnca-public-cert-'))
  const bin = join(root, 'bin')
  mkdirSync(bin)
  writeFileSync(join(bin, 'certbot'), `#!/bin/sh\necho "$@" >> "${root}/certbot.args"\nexit ${certbotExit}\n`)
  writeFileSync(join(bin, 'ss'), `#!/bin/sh\n${portBusy ? 'echo "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*"' : 'true'}\n`)
  writeFileSync(join(bin, 'apt-get'), '#!/bin/sh\nexit 0\n')
  // getent ahosts stub: one "<address> STREAM <name>" line per resolved address.
  const table = Object.entries(hosts).map(([name, addresses]) => `${name}) ${addresses.map((a) => `echo "${a} STREAM $2"`).join('; ') || 'exit 2'} ;;`).join('\n')
  writeFileSync(join(bin, 'getent'), `#!/bin/bash\ncase "$2" in\n${table}\n*) exit 2 ;;\nesac\n`)
  for (const name of ['certbot', 'ss', 'apt-get', 'getent']) chmodSync(join(bin, name), 0o755)
  const hook = join(root, 'hooks/cdnca-control-web.sh')
  const le = existing ? join(root, 'le') : '/etc/letsencrypt'
  if (existing) {
    mkdirSync(join(le, 'live', domain), { recursive: true })
    mkdirSync(join(le, 'renewal'))
    const san = existing.names.map((n) => `DNS:${n}`).join(',')
    const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
      '-days', String(existing.days), '-subj', `/CN=${existing.issuer}`, '-addext', `subjectAltName=${san}`,
      '-keyout', join(le, 'live', domain, 'privkey.pem'), '-out', join(le, 'live', domain, 'cert.pem')], { encoding: 'utf8' })
    assert.equal(made.status, 0, made.stderr)
    writeFileSync(join(le, 'renewal', `${domain}.conf`), `server = ${existing.server}\n`)
  }
  const relocate = (text) => text.replaceAll('/etc/letsencrypt/live', `${le}/live`).replaceAll('/etc/letsencrypt/renewal/', `${le}/renewal/`)
  const script = [
    'set -Eeuo pipefail',
    'log() { printf "LOG %s\\n" "$*"; }', 'warn() { printf "WARN %s\\n" "$*"; }',
    'fail() { printf "FAIL %s\\n" "$*"; exit 1; }', progress, resolver, ipCheck,
    lineage, hookWriter.replace('/etc/letsencrypt/renewal-hooks/deploy/cdnca-control-web.sh', hook), issueMode, relocate(issuer),
    'issue_public_certificate', 'printf "CERT=%s\\nKEY=%s\\n" "$PUBLIC_CERT_FILE" "$PUBLIC_KEY_FILE"',
  ].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: {
    PATH: `${bin}:/usr/bin:/bin`, INSTALL_ENV: 'plain', CONTROL_DOMAIN: domain, PUBLIC_CERT_FILE: certFile, PUBLIC_KEY_FILE: certFile ? `${certFile}.key` : '',
    CERTIFICATE_EMAIL: 'ops@example.com', TEMP_DIR: root, PKI_DIR: '/var/lib/cdnca/pki', WEB_SERVICE_NAME: 'cdnca-control-web',
  } })
  const args = existsSync(join(root, 'certbot.args')) ? readFileSync(join(root, 'certbot.args'), 'utf8') : ''
  const hookText = existsSync(hook) ? readFileSync(hook, 'utf8') : ''
  rmSync(root, { recursive: true, force: true })
  return { ...result, args, hookText }
}

test('www alias is added to the certificate only when it resolves to the same host', () => {
  const same = run({ domain: 'cdnca.com', hosts: { 'cdnca.com': ['203.0.113.73'], 'www.cdnca.com': ['203.0.113.73'] } })
  assert.equal(same.status, 0, same.stdout + same.stderr)
  assert.match(same.args, /--cert-name cdnca\.com -d cdnca\.com -d www\.cdnca\.com\n/)
  for (const www of [['198.51.100.7'], []]) {
    const other = run({ domain: 'cdnca.com', hosts: { 'cdnca.com': ['203.0.113.73'], 'www.cdnca.com': www } })
    assert.equal(other.status, 0, other.stdout + other.stderr)
    assert.doesNotMatch(other.args, /www\.cdnca\.com/)
  }
  const sub = run({ domain: 'www.cdnca.com', hosts: { 'www.cdnca.com': ['203.0.113.73'], 'www.www.cdnca.com': ['203.0.113.73'] } })
  assert.doesNotMatch(sub.args, /www\.www\./)
})

test('DNS control domain gets a Let\'s Encrypt certificate and a renewal deploy hook', () => {
  const result = run({ domain: 'cdnca.com' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.args, /certonly --standalone --non-interactive --agree-tos --email ops@example\.com --cert-name cdnca\.com -d cdnca\.com/)
  assert.match(result.stdout, /CERT=\/etc\/letsencrypt\/live\/cdnca\.com\/fullchain\.pem/)
  assert.match(result.stdout, /KEY=\/etc\/letsencrypt\/live\/cdnca\.com\/privkey\.pem/)
  assert.match(result.hookText, /RENEWED_LINEAGE:-\}" = "\/etc\/letsencrypt\/live\/cdnca\.com"/)
  assert.match(result.hookText, /install -m 0600 "\/etc\/letsencrypt\/live\/cdnca\.com\/privkey\.pem" "\/var\/lib\/cdnca\/pki\/public-key\.pem"/)
  assert.match(result.hookText, /systemctl reload "cdnca-control-web"/)
})

test('default installation name is unique per installation so a host reinstall does not collide', () => {
  const line = source.match(/^\s*INSTALLATION_NAME=\$\{INSTALLATION_NAME:-.*\}$/m)?.[0]
  assert.ok(line, 'extract the real default installation name assignment')
  const render = (installationId, explicit = '') => spawnSync('bash', ['-c', `set -u\n${line}\nprintf %s "$INSTALLATION_NAME"`], {
    encoding: 'utf8', env: { PATH: '/usr/bin:/bin', MASTER_HOST: 'cdnca.com', INSTALLATION_ID: installationId, INSTALLATION_NAME: explicit },
  }).stdout
  const first = render('6f93d6bb-e479-492f-88c2-b643f6a5ea01')
  assert.equal(first, 'control-cdnca.com-6f93d6bb')
  assert.notEqual(first, render('0a1b2c3d-0000-4000-8000-000000000000'))
  assert.equal(render('6f93d6bb-e479-492f-88c2-b643f6a5ea01', 'operator-chosen'), 'operator-chosen')
})

test('upgrade configurator reads the downloaded artifact trust from a root-private directory', () => {
  const setup = source.match(/^setup_native_upgrade\(\) \{[\s\S]*?^\}\n/m)?.[0]
  assert.ok(setup, 'extract the real setup_native_upgrade function')
  const root = mkdtempSync(join(tmpdir(), 'cdnca-native-upgrade-'))
  const temp = join(root, 'tmp'), responses = join(root, 'activation'), bin = join(root, 'bin')
  for (const directory of [temp, responses, bin]) mkdirSync(directory)
  writeFileSync(join(temp, 'native-baseline-input.json'), JSON.stringify({ schema: 'cdnca.native-management.baseline-input/v2', runner_sha256: 'a', archive_sha256: 'b' }))
  writeFileSync(join(temp, 'native-install-trust.json'), '{"version":1,"keys":[]}')
  // Record the configurator's trust argument and its mode; run nothing else.
  writeFileSync(join(bin, 'python3'), `#!/bin/bash\nfor ((i=1;i<=$#;i++)); do [ "\${!i}" = --artifact-trust-file ] && { j=$((i+1)); f=\${!j}; echo "$f $(stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f")" >>"${root}/trust.args"; }; done\nexit 0\n`)
  writeFileSync(join(bin, 'bash'), '#!/bin/sh\nexit 0\n')
  for (const name of ['python3', 'bash']) chmodSync(join(bin, name), 0o755)
  const result = spawnSync('/bin/bash', ['-c', `set -Eeuo pipefail\n${setup}\nsetup_native_upgrade`], { encoding: 'utf8', env: {
    PATH: `${bin}:/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin`, TEMP_DIR: temp, RESPONSE_DIR: responses, NATIVE_SUPPORT: root,
    NATIVE_ARTIFACT_TRUST_FILE: join(temp, 'native-install-trust.json'), INSTALLATION_ID: 'id', CONTROL_ORIGIN: 'https://cdnca.com', NATIVE_ROOT: root,
    PUBLIC_CERT_FILE: '',
  } })
  const recorded = existsSync(join(root, 'trust.args')) ? readFileSync(join(root, 'trust.args'), 'utf8').trim() : ''
  rmSync(root, { recursive: true, force: true })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(recorded, `${join(responses, 'native-artifact-trust.json')} 600`)
})

test('operator-supplied certificate files are used as-is', () => {
  const result = run({ domain: 'cdnca.com', certFile: '/root/tls/fullchain.pem' })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.args, '')
  assert.match(result.stdout, /CERT=\/root\/tls\/fullchain\.pem/)
})

test('IP literal control address keeps the private CA without contacting ACME', () => {
  for (const domain of ['203.0.113.73', '2001:db8::1']) {
    const result = run({ domain })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.args, '')
    assert.match(result.stdout, /WARN control-plane address is an IP literal/)
    assert.match(result.stdout, /CERT=\n/)
  }
})

// certbot 调用不再带 --keep-until-expiring。已有同 CA 正式证书、域名一致且
// 30 天内不到期时不请求 CA（重装不打满频率）；测试证书换正式、域名变化、临近到期一律 --force-renewal。
const PROD = 'https://acme-v02.api.letsencrypt.org/directory'
const STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
test('certbot is never asked to keep an unexpired certificate', () => {
  assert.doesNotMatch(source, /keep-until-expiring/)
  const fresh = run({ domain: 'cdnca.com' })
  assert.equal(fresh.status, 0, fresh.stdout + fresh.stderr)
  assert.doesNotMatch(fresh.args, /--keep-until-expiring|--force-renewal/)
})

test('an unexpired production certificate for the same names is reused without contacting ACME', () => {
  const result = run({ domain: 'cdnca.com', existing: { issuer: 'R11', days: 80, server: PROD, names: ['cdnca.com'] } })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.equal(result.args, '')
  assert.match(result.stdout, /not requesting a new one/)
  assert.match(result.stdout, /CERT=.*\/live\/cdnca\.com\/fullchain\.pem/)
  assert.match(result.hookText, /RENEWED_LINEAGE/)
})

test('a staging, expiring or differently named certificate is force-renewed', () => {
  for (const existing of [
    { issuer: '(STAGING) Pseudo Plum E5', days: 80, server: PROD, names: ['cdnca.com'] },
    { issuer: 'R11', days: 80, server: STAGING, names: ['cdnca.com'] },
    { issuer: 'R11', days: 10, server: PROD, names: ['cdnca.com'] },
    { issuer: 'R11', days: 80, server: PROD, names: ['cdnca.com', 'old.cdnca.com'] },
  ]) {
    const result = run({ domain: 'cdnca.com', existing })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    assert.match(result.args, /--cert-name cdnca\.com -d cdnca\.com --force-renewal\n/, JSON.stringify(existing))
  }
  // www 同机解析时证书须带 www；已有证书缺 www 也要重签。
  const www = run({ domain: 'cdnca.com', hosts: { 'cdnca.com': ['203.0.113.73'], 'www.cdnca.com': ['203.0.113.73'] },
    existing: { issuer: 'R11', days: 80, server: PROD, names: ['cdnca.com'] } })
  assert.match(www.args, /-d cdnca\.com -d www\.cdnca\.com --force-renewal/)
})

test('busy port 80 or a failed ACME request stops the installation', () => {
  const busy = run({ domain: 'cdnca.com', portBusy: true })
  assert.notEqual(busy.status, 0)
  assert.match(busy.stdout, /FAIL port 80 is in use/)
  assert.equal(busy.args, '')
  const failed = run({ domain: 'cdnca.com', certbotExit: 1 })
  assert.notEqual(failed.status, 0)
  assert.match(failed.stdout, /FAIL public certificate request failed/)
  assert.equal(failed.hookText, '')
})

// 10-22: a temporary self-signed operator certificate (Let's Encrypt rate
// limited) failed the setup_web self-check, which trusted only the system
// store for operator certificates. The self-check trusts the private CA for
// the built-in certificate, the operator certificate itself when it does not
// chain to the system store, and the system store otherwise.
const trustHelper = source.match(/^public_https_trust_args\(\) \{[\s\S]*?^\}\n/m)?.[0]
function trustArgs({ certFile, certPath }) {
  assert.ok(trustHelper, 'extract the real public_https_trust_args function')
  const script = ['set -Eeuo pipefail', trustHelper, 'public_https_trust_args | tr "\\n" "|"'].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: {
    PATH: '/usr/bin:/bin', PKI_DIR: '/pki', PUBLIC_CERT_FILE: certFile, PUBLIC_CERT_PATH: certPath,
  } })
  assert.equal(result.status, 0, result.stderr)
  return result.stdout
}

test('local HTTPS self-checks trust the certificate actually served', () => {
  assert.equal(trustArgs({ certFile: '', certPath: '/pki/public-server.pem' }), '--cacert|/pki/root-ca-cert.pem|')
  const root = mkdtempSync(join(tmpdir(), 'cdnca-trust-'))
  try {
    const cert = join(root, 'self.pem')
    const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-days', '1', '-subj', '/CN=console.example.test', '-keyout', join(root, 'self.key'), '-out', cert], { encoding: 'utf8' })
    assert.equal(made.status, 0, made.stderr)
    assert.equal(trustArgs({ certFile: '/operator/self.pem', certPath: cert }), `--cacert|${cert}|`)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

// 10-22: with a temporary self-signed operator certificate the node upgrade
// trust document said root_ca "system", so install-node.sh could not verify
// the download endpoint. publish_upgrade_trust now embeds the operator
// certificate under the same rule as the local self-checks.
test('node upgrade trust embeds an operator certificate the system store cannot verify', () => {
  const publish = source.match(/^publish_upgrade_trust\(\) \{[\s\S]*?^\}\n/m)?.[0]
  assert.ok(publish, 'extract the real publish_upgrade_trust function')
  // btenv3 moved the rule into upgrade_download_root_ca_file (written to control.env as
  // CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE); the installer builds the document from that line.
  const rootRule = source.match(/^upgrade_download_root_ca_file\(\) \{[\s\S]*?^\}\n/m)?.[0]
  assert.match(rootRule, /elif \[ "\$\(public_https_trust_args \| head -n 1\)" = --cacert \]; then\n\s+printf '%s' "\$PUBLIC_CERT_PATH"/)
  assert.match(rootRule, /\[ -z "\$PUBLIC_CERT_FILE" \]; then\n\s+printf '%s' "\$\{PKI_DIR\}\/root-ca-cert\.pem"/)
  assert.match(publish, /native-backup publish-node-install-trust/)
})

// 10-22 73: the upgrade runner's console index check used only the system
// roots, so a temporary self-signed operator certificate kept it unconfirmed.
// setup_native_upgrade passes that certificate as the runner's web CA only
// when public_https_trust_args (the self-check rule) says the store cannot verify it.
function webCAArgs({ certFile, certPath }) {
  const setup = source.match(/^setup_native_upgrade\(\) \{[\s\S]*?^\}\n/m)?.[0]
  assert.ok(setup && trustHelper, 'extract the real setup_native_upgrade and public_https_trust_args functions')
  const root = mkdtempSync(join(tmpdir(), 'cdnca-native-webca-'))
  try {
    const temp = join(root, 'tmp'), bin = join(root, 'bin')
    for (const directory of [temp, bin]) mkdirSync(directory)
    writeFileSync(join(temp, 'native-baseline-input.json'), JSON.stringify({ schema: 'cdnca.native-management.baseline-input/v2', runner_sha256: 'a', archive_sha256: 'b' }))
    writeFileSync(join(temp, 'native-install-trust.json'), '{"version":1,"keys":[]}')
    writeFileSync(join(bin, 'python3'), `#!/bin/bash\ncase "$*" in *configure-native-upgrade.py*) printf '%s\\n' "$@" >"${root}/configure.args" ;; esac\nexit 0\n`)
    writeFileSync(join(bin, 'bash'), '#!/bin/sh\nexit 0\n')
    for (const name of ['python3', 'bash']) chmodSync(join(bin, name), 0o755)
    const result = spawnSync('/bin/bash', ['-c', `set -Eeuo pipefail\n${trustHelper}\n${setup}\nsetup_native_upgrade`], { encoding: 'utf8', env: {
      PATH: `${bin}:/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin`, TEMP_DIR: temp, RESPONSE_DIR: root, NATIVE_SUPPORT: root, PKI_DIR: '/pki',
      PUBLIC_CERT_FILE: certFile, PUBLIC_CERT_PATH: certPath, NATIVE_ARTIFACT_TRUST_FILE: join(temp, 'native-install-trust.json'), INSTALLATION_ID: 'id', CONTROL_ORIGIN: 'https://cdnca.com', NATIVE_ROOT: root,
    } })
    assert.equal(result.status, 0, result.stderr)
    const args = readFileSync(join(root, 'configure.args'), 'utf8').trim().split('\n')
    const index = args.indexOf('--web-ca-file')
    return index < 0 ? null : args[index + 1]
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

test('upgrade runner gets the operator certificate as console CA only when the system store cannot verify it', () => {
  assert.equal(webCAArgs({ certFile: '', certPath: '/pki/public-server.pem' }), null)
  const root = mkdtempSync(join(tmpdir(), 'cdnca-webca-cert-'))
  try {
    const cert = join(root, 'self.pem')
    const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-days', '1', '-subj', '/CN=console.example.test', '-keyout', join(root, 'self.key'), '-out', cert], { encoding: 'utf8' })
    assert.equal(made.status, 0, made.stderr)
    assert.equal(webCAArgs({ certFile: '/root/selfcert/console.crt', certPath: cert }), cert)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
  // A store-verifiable certificate keeps the system roots: no web CA argument.
  const setup = source.match(/^setup_native_upgrade\(\) \{[\s\S]*?^\}\n/m)?.[0]
  assert.match(setup, /if \[ -n "\$PUBLIC_CERT_FILE" \] && \[ -n "\$\(public_https_trust_args\)" \]; then\n\s+artifact_options\+=\(--web-ca-file "\$PUBLIC_CERT_PATH"\)/)
})
