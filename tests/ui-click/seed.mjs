// 本机 UI 巡检种子：五类身份 + 少量测试数据，全部走产品公开接口（与浏览器同源、同 Origin）。
// 只在 up.sh 起的一次性本地库上运行；口令只用于本机测试库，写在 state/identities.json（不入库）。
//
//   platform-admin  主控平台管理员（control-api bootstrap-user，up.sh 建）
//   tenant-admin    主控租户主账号 tenant_owner（POST /v1/admin/users）
//   tenant-user     主控只读租户账号 tenant_viewer（POST /v1/admin/users；租户成员增删接口 1.0.35 已删）
//   seller          客户门户客户（POST /portal/v1/accounts 注册）→ 门户/卖家站
//   operator        运营后台受限运营员（owner 邀请 + 自定义角色，只给读权限）
//   owner           运营后台 owner（license-bootstrap，up.sh 建），只用于建种子与运营后台全权限巡检
//
// 门户注册与邮件验证码要图形验证码：本地库的 HMAC 密钥由 up.sh 生成，种子按服务端同一算法
// （services/license-service/internal/identity/token.go deriveTokenDigest）写一条已知答案的验证码，
// 不改任何产品代码；邮件验证码从本机 mailpit 读。
import crypto from 'node:crypto'
import fs from 'node:fs'
import { execFileSync } from 'node:child_process'

const STATE = process.env.UICLICK_STATE ?? '/tmp/uiclick-state'
const WEB = process.env.UICLICK_WEB ?? 'http://localhost:55101'
const AUTH = process.env.UICLICK_AUTH ?? 'http://localhost:55102'
const PSQL = '/opt/homebrew/opt/postgresql@17/bin/psql'
const LICENSE_DB = process.env.UICLICK_LICENSE_ADMIN_DB ?? 'postgres://cdnca@127.0.0.1:55990/cdnca_license'
const PW = fs.readFileSync(`${STATE}/secrets/owner-pw`, 'utf8')
const envFile = (f) => Object.fromEntries(fs.readFileSync(f, 'utf8').split('\n').filter((l) => /^[A-Z]/.test(l)).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]))
const licenseEnv = envFile(`${STATE}/license.env`)

// 极简 cookie 罐：每个身份一个。
class Jar {
  constructor() { this.c = new Map() }
  set(res) { for (const h of res.headers.getSetCookie?.() ?? []) { const [kv] = h.split(';'); const i = kv.indexOf('='); if (kv.slice(i + 1)) this.c.set(kv.slice(0, i), kv.slice(i + 1)); else this.c.delete(kv.slice(0, i)) } }
  header() { return [...this.c].map(([k, v]) => `${k}=${v}`).join('; ') }
}
async function call(jar, origin, method, path, body, extra = {}) {
  const headers = { Accept: 'application/json', Origin: origin, Cookie: jar.header(), ...(jar.bearer ? { Authorization: `Bearer ${jar.bearer}` } : {}), ...extra }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && !headers['Idempotency-Key']) headers['Idempotency-Key'] = crypto.randomUUID()
  const res = await fetch(origin + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' })
  jar.set(res)
  const text = await res.text()
  let json = null; try { json = JSON.parse(text) } catch {}
  if (json?.access_token) jar.bearer = json.access_token
  return { status: res.status, json, text }
}
const must = (r, what, ok = [200, 201, 204]) => { if (!ok.includes(r.status)) throw new Error(`${what}: ${r.status} ${r.text.slice(0, 300)}`); return r.json }

const keys = JSON.parse(licenseEnv.LICENSE_IDENTITY_TOKEN_KEYS_JSON)
const keyID = licenseEnv.LICENSE_IDENTITY_TOKEN_KEY_ID
const digestHex = (purpose, value) => crypto.createHmac('sha256', Buffer.from(keys[keyID], 'base64'))
  .update('cdnca.identity.' + purpose + '\x00' + value).digest('hex')
const sql = (q) => execFileSync(PSQL, ['-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1', LICENSE_DB, '-c', q]).toString().trim()

// 邮件验证码：本机 Go（macOS 系统钥匙串）不信任本地自签 SMTP 证书，发不出信；
// 按 portal/codes.go 的同一摘要（portal-email-code/v1，值 = id\0code）写一条已知验证码。
function knownEmailCode(purpose, email) {
  const id = crypto.randomUUID(); const code = '135790'
  sql(`UPDATE license.portal_email_codes SET superseded_at=now() WHERE purpose='${purpose}' AND email='${email}' AND consumed_at IS NULL AND superseded_at IS NULL`)
  sql(`INSERT INTO license.portal_email_codes(id,purpose,email,code_digest,code_key_id,expires_at,created_at) VALUES ('${id}','${purpose}','${email}','\\x${digestHex('portal-email-code/v1', id + '\x00' + code)}','${keyID}',now()+interval '10 minutes',now())`)
  return code
}
// 运营者邀请令牌：同理把邀请行的令牌摘要换成已知令牌（identity/recovery.go invitation-token/v1）。
function knownInvitationToken(username) {
  const token = crypto.randomBytes(32).toString('base64url')
  sql(`UPDATE license.operator_invitations SET token_digest='\\x${digestHex('invitation-token/v1', token)}', token_key_id='${keyID}' WHERE username='${username}' AND consumed_at IS NULL AND revoked_at IS NULL`)
  return token
}

function knownCaptcha() {
  const id = crypto.randomUUID(); const answer = '24680'
  sql(`INSERT INTO license.portal_captcha_challenges(id,answer_digest,answer_key_id,expires_at,created_at) VALUES ('${id}','\\x${digestHex('portal-captcha/v1', id + '\x00' + answer)}','${keyID}',now()+interval '5 minutes',now())`)
  return { captcha_id: id, captcha_answer: answer }
}

// RFC 6238 TOTP（与 services/license-service/internal/identity/totp.go 同：SHA1、30 秒、6 位）。
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const b32 = (buf) => { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)]; return out }
const unb32 = (s) => { let bits = ''; for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, '0'); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out) }
export const totp = (secret, at = Date.now()) => {
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(at / 30000)))
  const d = crypto.createHmac('sha1', unb32(secret)).update(counter).digest(); const o = d[d.length - 1] & 15
  return String((d.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0')
}

// 重跑种子时保留上次生成的字段（如受限运营员 TOTP 种子，账号已存在时无法再取得）。
const previous = fs.existsSync(`${STATE}/identities.json`) ? JSON.parse(fs.readFileSync(`${STATE}/identities.json`, 'utf8')) : {}
const ids = { ...previous, password: PW, identities: {} }
const log = (...a) => console.log('[seed]', ...a)

// ---- 主控：平台管理员登录 → 建租户主账号 → 建只读租户账号 ----
const admin = new Jar()
must(await call(admin, WEB, 'POST', '/v1/auth/login', { username: 'admin', password: PW }), 'admin login')
const tenantOwner = await call(admin, WEB, 'POST', '/v1/admin/users', { username: 'tenant1', password: PW, display_name: '测试租户', email: 'tenant1@example.test', role: 'tenant_owner' })
must(tenantOwner, 'create tenant owner', [201, 409])
log('tenant-admin', tenantOwner.status)
const tenant = new Jar()
must(await call(tenant, WEB, 'POST', '/v1/auth/login', { username: 'tenant1', password: PW }), 'tenant login')
const member = await call(admin, WEB, 'POST', '/v1/admin/users', { username: 'member1', password: PW, display_name: '测试成员', email: 'member1@example.test', role: 'tenant_viewer' })
log('tenant-user', member.status, member.status >= 300 ? member.text.slice(0, 200) : '')
// 种子替该账号改一次口令（若要求下次登录改密，components/PasswordChangeGate.tsx 也就此解除），
// 改成同一测试口令的变体，之后巡检直接用新口令。
const memberPW = PW + 'M'
const mem = new Jar()
const ml = await call(mem, WEB, 'POST', '/v1/auth/login', { username: 'member1', password: PW })
if (ml.status === 200) {
  const ch = await call(mem, WEB, 'POST', '/v1/account/password', { current_password: PW, new_password: memberPW })
  log('member password change', ch.status, ch.status >= 300 ? ch.text.slice(0, 200) : '')
}
ids.memberPassword = memberPW
ids.identities['platform-admin'] = { app: 'web', username: 'admin' }
ids.identities['tenant-admin'] = { app: 'web', username: 'tenant1' }
ids.identities['tenant-user'] = { app: 'web', username: 'member1' }

// ---- 授权端：门户客户注册（卖家/开发者身份同一门户账号）----
const seller = new Jar()
const sellerEmail = 'seller1@example.test'
let r = await call(seller, AUTH, 'POST', '/portal/v1/email-codes', { purpose: 'register', email: sellerEmail, ...knownCaptcha() })
log('email-code', r.status, r.status >= 300 ? r.text.slice(0, 200) : '')
if (r.status < 300) {
  const code = knownEmailCode('register', sellerEmail)
  r = await call(seller, AUTH, 'POST', '/portal/v1/accounts', { username: 'seller1', email: sellerEmail, password: PW, email_code: code, accept_terms: true })
  log('portal register', r.status, r.status >= 300 ? r.text.slice(0, 200) : '')
}
ids.identities.seller = { app: 'license-portal', username: 'seller1' }

// ---- 运营后台：owner 建只读角色并邀请受限运营员 ----
// 用户名可由 UICLICK_OPERATOR 覆盖（TOTP 种子只在接受邀请时可得，丢了就换个名字重邀）。
const OP_USER = process.env.UICLICK_OPERATOR ?? 'operator1'
const owner = new Jar()
must(await call(owner, AUTH, 'POST', '/auth/v1/sessions', { identifier: 'owner', password: PW }), 'owner login')
must(await call(owner, AUTH, 'POST', '/operator/v1/session/reauthenticate', { current_password: PW }), 'owner reauth', [200, 204])
const perms = must(await call(owner, AUTH, 'GET', '/operator/v1/rbac/permissions'), 'perms')
const permList = (Array.isArray(perms) ? perms : perms.items ?? perms.permissions ?? []).map((p) => (typeof p === 'string' ? p : p.code ?? p.name))
log('perm sample', JSON.stringify(perms).slice(0, 200))
// 受限运营员：只给只读类权限（.read / .view / .list），用于核对菜单隐藏与 403。
const readOnly = permList.filter((p) => /\.(read|view|list)$/.test(p))
log('perms', permList.length, 'read-only', readOnly.length)
const role = await call(owner, AUTH, 'POST', '/operator/v1/rbac/roles', { name: 'uiclick-readonly', description: '本机巡检受限运营员（只读）', permissions: readOnly })
log('role', role.status, role.status >= 300 ? role.text.slice(0, 200) : '')
const inv = await call(owner, AUTH, 'POST', '/operator/v1/operator-invitations', { username: OP_USER, display_name: '测试运营员', email: `${OP_USER}@example.test` })
log('invite', inv.status, inv.status >= 300 ? inv.text.slice(0, 200) : '')
if (inv.status < 300) {
  const token = knownInvitationToken(OP_USER)
  const op = new Jar()
  const secret = b32(crypto.randomBytes(20))
  const recovery = Array.from({ length: 10 }, () => b32(crypto.randomBytes(10)))
  const acc = await call(op, AUTH, 'POST', '/operator/v1/invitations/accept', { token, password: PW, totp_secret: secret, totp_code: totp(secret), recovery_codes: recovery })
  if (acc.status === 204) { ids.operatorTOTP = secret; ids.operatorUser = OP_USER }
  log('accept', acc.status, acc.status >= 300 ? acc.text.slice(0, 300) : '')
}
// 受限运营员默认得到 platform_operator；改配为只读角色（PUT rbac/operators/{id}/roles）。
const ops = must(await call(owner, AUTH, 'GET', '/operator/v1/rbac/operators'), 'rbac operators')
const op1 = (ops.items ?? ops).find((o) => o.username === OP_USER)
const roles = must(await call(owner, AUTH, 'GET', '/operator/v1/rbac/roles'), 'rbac roles')
const ro = (roles.items ?? roles).find((x) => x.name === 'uiclick-readonly')
if (op1 && ro) {
  const assign = await call(owner, AUTH, 'PUT', `/operator/v1/rbac/operators/${op1.id}/roles`, { role_ids: [ro.id], expected_revision: op1.revision })
  log('assign readonly', assign.status, assign.status >= 300 ? assign.text.slice(0, 200) : '')
}
ids.identities.operator = { app: 'operator-console', username: OP_USER }
ids.identities.owner = { app: 'operator-console', username: 'owner' }

fs.writeFileSync(`${STATE}/identities.json`, JSON.stringify(ids, null, 2), { mode: 0o600 })
log('done →', `${STATE}/identities.json`)
