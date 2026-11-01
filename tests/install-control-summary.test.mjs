// installer-i18n A：主控安装完成摘要（屏幕 + /root/cdnca-install-summary.txt 0600），中英双语，
// 摘要与文件都不含口令、激活凭据与令牌。
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const i18n = readFileSync(new URL('../scripts/lib/install-i18n.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  if (lines[start].endsWith('}')) return lines[start]
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

const SECRET_PASSWORD = 'Sup3r-Secret-Pass!'
const SECRET_ACTIVATION = 'ACT-0123456789abcdef'
const SECRET_TOKEN = 'tok_9f8e7d6c5b4a'

function summary({ lang = 'zh', env = 'plain', cert = 'self', mode = 'all', interactive = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-summary-'))
  const certFile = join(dir, 'cert.pem')
  writeFileSync(certFile, 'x')
  const publicCert = { self: '', own: join(dir, 'own.pem'), le: '/etc/letsencrypt/live/cdnca.com/fullchain.pem' }[cert]
  const publicKey = { self: '', own: join(dir, 'own-key.pem'), le: '/etc/letsencrypt/live/cdnca.com/privkey.pem' }[cert]
  const script = ['set -Eeuo pipefail', i18n,
    ...['log', 'warn', 'fail', 'remote_gateway_access', 'public_certificate_lineage', 'summary_host_addresses', 'summary_certificate', 'gateway_direct_ports_hint'].map(block),
    source.match(/^CONTROL_SUMMARY_FILE=.*$/m)[0], block('control_install_summary'),
    `ip() { printf '%s\\n' '2: eth0    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth0' '3: eth1    inet 10.0.0.5/8 scope global eth1'; }`,
    `openssl() { printf 'notAfter=Jan 29 00:00:00 2027 GMT\\n'; }`,
    `install_lang_init --lang ${lang}`,
    `NATIVE_ROOT=/data/cdnca-native-root/cdnca CONFIG_DIR=/etc/cdnca-control DATA_DIR=/var/lib/cdnca-control`,
    `SERVICE_NAME=cdnca-control-api GATEWAY_SERVICE_NAME=cdnca-agent-gateway WEB_SERVICE_NAME=cdnca-control-web`,
    `TEMP_DIR=${JSON.stringify(dir)} CONTROL_SUMMARY_FILE=${JSON.stringify(join(dir, 'summary.txt'))}`,
    `CONTROL_VERSION=1.0.35 INSTALLATION_ID=11111111-2222-3333-4444-555555555555 INSTALLATION_NAME=control-cdnca.com-11111111`,
    `CONTROL_ORIGIN=https://cdnca.com CONTROL_DOMAIN=cdnca.com GATEWAY_HOST=gateway.cdnca.com MASTER_PORT=443`,
    `ADMIN_USERNAME=admin ADMIN_PASSWORD=${JSON.stringify(SECRET_PASSWORD)} ACTIVATION_CODE=${JSON.stringify(SECRET_ACTIVATION)} ENROLLMENT_TOKEN=${JSON.stringify(SECRET_TOKEN)}`,
    `GATEWAY_ENROLLMENT_PORT=21443 GATEWAY_AGENT_PORT=21444 INSTALL_ENV=${env} WEB_PORT=18443 NODE_DOWNLOAD_PORT=19445 INSTALL_MODE=${mode}`,
    `CONTROL_INTERNAL_REMOTE_PORT=9446 NATS_GATEWAY_WS_PORT=4223 REDIS_GATEWAY_TLS_PORT=6380`,
    `PUBLIC_CERT_FILE=${JSON.stringify(publicCert)} PUBLIC_KEY_FILE=${JSON.stringify(publicKey)} PUBLIC_CERT_PATH=${JSON.stringify(certFile)}`,
    `PROGRESS_LOG=/var/log/cdnca-install-control-20261031-010203.log`,
    'control_install_summary'].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { PATH: process.env.PATH } })
  let file = '', mode0 = 0
  try { file = readFileSync(join(dir, 'summary.txt'), 'utf8'); mode0 = statSync(join(dir, 'summary.txt')).mode & 0o777 } catch {}
  rmSync(dir, { recursive: true, force: true })
  return { ...result, file, fileMode: mode0 }
}

function assertNoSecrets(text) {
  for (const secret of [SECRET_PASSWORD, SECRET_ACTIVATION, SECRET_TOKEN]) assert.ok(!text.includes(secret), `secret leaked: ${secret}`)
}

test('Chinese summary lists every recorded field and the file matches the screen without secrets', () => {
  const result = summary()
  assert.equal(result.status, 0, result.stderr)
  for (const expected of ['CDNCA 主控安装完成', '版本： 1.0.35', '实例 ID： 11111111-2222-3333-4444-555555555555',
    '/data/cdnca-native-root/cdnca/current', '管理端地址： https://cdnca.com/dashboard/', '用户端地址：',
    '节点网关地址： gateway.cdnca.com', '本机公网 IP： 203.0.113.10', '本机内网 IP： 10.0.0.5', '管理员账号： admin',
    '使用你在安装时设置的口令', 'TCP 443  管理端网页 HTTPS', 'TCP 21443 节点网关注册', 'TCP 21444 节点网关通道',
    '请在防火墙/云安全组放行网关两个端口 21443、21444（TCP），节点直连 gateway.cdnca.com',
    '主控私有 CA 自签', '到期 Jan 29 00:00:00 2027 GMT', '节点管理 → 节点列表 → 安装节点', 'native-backup create',
    'migrate-from', '/var/log/cdnca-install-control-20261031-010203.log', 'journalctl -u cdnca-control-api']) {
    assert.ok(result.stderr.includes(expected), `missing ${expected}\n${result.stderr}`)
  }
  assert.ok(result.stderr.includes(result.file), 'summary file must hold the same text as the screen')
  assert.equal(result.fileMode, 0o600)
  assertNoSecrets(result.stderr)
  assertNoSecrets(result.file)
  assert.doesNotMatch(result.file, /password=|token=|activation[_-]?code/i)
})

test('English summary is in English', () => {
  const result = summary({ lang: 'en' })
  assert.equal(result.status, 0, result.stderr)
  for (const expected of ['CDNCA control plane installed', 'Management URL: https://cdnca.com/dashboard/', 'Administrator: admin',
    'the password you set during installation', 'TCP 21443 node Gateway enrollment', 'Open both Gateway ports 21443 and 21444 (TCP)', 'Self-signed by the private control CA',
    'Nodes → Node list → Install node', 'Next steps:']) {
    assert.ok(result.stderr.includes(expected), `missing ${expected}\n${result.stderr}`)
  }
  assert.doesNotMatch(result.stderr, /\p{Script=Han}/u)
  assertNoSecrets(result.file)
})

test('BaoTa, standalone Gateway access and certificate kinds change the port and certificate lines', () => {
  const bt = summary({ env: 'bt', mode: 'control' })
  assert.equal(bt.status, 0, bt.stderr)
  assert.match(bt.stderr, /TCP 19445 节点升级下载/)
  assert.match(bt.stderr, /127\.0\.0\.1:18443/)
  assert.match(bt.stderr, /TCP 9446,4223,6380  独立网关接入/)
  assert.match(bt.stderr, /宝塔站点证书/)
  const le = summary({ cert: 'le' })
  assert.match(le.stderr, /Let's Encrypt（自动续期）; 到期/)
  assert.match(le.stderr, /TCP 80 /)
  const own = summary({ cert: 'own', lang: 'en' })
  assert.match(own.stderr, /Your own certificate \(not renewed automatically\)/)
  assert.doesNotMatch(summary().stderr, /9446|19445|TCP 80 /)
})

test('main prints the summary as the last step and never with the password', () => {
  const main = block('main')
  assert.match(main, /control_install_summary\n  progress_done\n}$/)
  assert.doesNotMatch(block('control_install_summary'), /ADMIN_PASSWORD|ACTIVATION_CODE|TOKEN|SECRET/)
})
