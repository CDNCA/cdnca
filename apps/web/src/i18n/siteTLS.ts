import i18n from './index'

type Messages = { [key: string]: string | Messages }

const zhCN = {
  field: {
    label: 'TLS 协议',
    help: '“仅 TLS 1.3”拒绝旧客户端；“兼容旧客户端”允许 TLS 1.0/1.1，只适合必须支持老设备的网站。不支持 SSLv2/SSLv3。',
  },
  versions: {
    tls13: '仅 TLS 1.3',
    recommended: 'TLS 1.2 + 1.3（推荐）',
    compatible: '兼容旧客户端（TLS 1.0 – 1.3）',
    legacyWarning: 'TLS 1.0/1.1 已被主流浏览器淘汰，开启后需使用“旧版兼容”加密套件，安全性降低。',
  },
  ciphers: {
    label: '加密套件',
    help: 'TLS 1.3 套件固定为安全默认值；此处决定 TLS 1.2 及更早版本可用的套件。',
    modern: '现代（仅 ECDHE + AEAD）',
    compatible: '兼容（另含 CBC 与 RSA 密钥交换）',
    legacy: '旧版兼容（OpenSSL 全部默认套件，SECLEVEL=0）',
    custom: '自定义',
    customLabel: '自定义套件',
    customHelp: '按所选顺序生效（服务端套件优先默认开启），只影响 TLS 1.2；需要 TLS 版本含 TLS 1.2，节点需支持 SITE_TLS_CUSTOM_CIPHERS。',
    customSafeOnly: '仅可选安全套件：列表只包含 ECDHE/RSA 密钥交换的 AES-GCM、ChaCha20-Poly1305 与 AES-CBC 套件，至少要选一个 ECDHE-ECDSA 和一个 ECDHE-RSA 的 GCM/CHACHA20 套件。',
  },
  ocsp: {
    label: 'OCSP Stapling',
    help: '节点向证书签发机构的 OCSP 服务查询吊销状态，校验后随握手发给访客，访客不必自己查询。证书不含 OCSP 地址时不生效（Let’s Encrypt 新证书已不含）。',
  },
  http2: {
    label: 'HTTP/2',
    help: '关闭后本站 HTTPS 只协商 HTTP/1.1，同端口其它网站不受影响。需要节点支持 SITE_TLS_OPTIONS，未升级的节点会拒绝发布并给出原因。',
  },
  http3: {
    label: 'HTTP/3',
    help: '通过 QUIC 提供 HTTP/3 并下发 Alt-Svc；仅在 TLS 版本含 TLSv1.3 时生效。关闭后本站拒绝 QUIC 握手。',
  },
  preferServerCiphers: {
    label: '优先使用服务端套件',
    help: '对应 ssl_prefer_server_ciphers，影响 TLS 1.2 及更早版本。“按套件预设”时现代关闭、兼容与旧版开启；单独开或关需要节点支持 SITE_TLS_OPTIONS。',
    preset: '按套件预设（当前{{state}}）',
    on: '开启',
    off: '关闭',
  },
  clientAuth: {
    label: '客户端证书校验（mTLS）',
    help: '“必须”：没有本站 CA 签发的客户端证书无法建立连接；“可选”：都放行，校验结果通过 X-Client-Verify / X-Client-Cert-Subject / X-Client-Cert-Fingerprint 请求头告诉源站。',
    off: '关闭',
    optional: '可选',
    required: '必须',
    ca: '客户端 CA 证书（PEM）',
  },
  legacy: {
    title: '检测到不受支持的 SSL 协议',
    description: '当前保存值包含 {{protocols}}。请重新选择 TLS 协议后再保存，系统不会自动改写旧值。',
  },
  unknown: {
    title: '检测到未知 TLS 协议',
    description: '当前保存值包含 {{protocols}}。这些值仅供查看；请重新选择 TLS 协议后再保存。',
  },
  validation: {
    safeOnly: '请选择一组连续的 TLS 版本；含 TLS 1.0/1.1 时必须使用“旧版兼容”加密套件。',
    clientCA: '开启客户端证书校验时请粘贴 PEM 格式的 CA 证书。',
    customCiphers: '自定义套件至少要包含一个 ECDHE-ECDSA 和一个 ECDHE-RSA 的 GCM 或 CHACHA20 套件，且不能重复。',
  },
} satisfies Messages

const enUS = {
  field: {
    label: 'TLS protocols',
    help: '"TLS 1.3 only" refuses older clients; "Legacy clients" allows TLS 1.0/1.1 and is only for sites that must serve old devices. SSLv2/SSLv3 are not supported.',
  },
  versions: {
    tls13: 'TLS 1.3 only',
    recommended: 'TLS 1.2 + 1.3 (recommended)',
    compatible: 'Legacy clients (TLS 1.0 – 1.3)',
    legacyWarning: 'TLS 1.0/1.1 are retired by major browsers and need the legacy cipher suites, which lowers security.',
  },
  ciphers: {
    label: 'Cipher suites',
    help: 'TLS 1.3 suites are always the secure defaults; this sets the suites TLS 1.2 and older may use.',
    modern: 'Modern (ECDHE + AEAD only)',
    compatible: 'Compatible (adds CBC and RSA key exchange)',
    legacy: 'Legacy (all OpenSSL default suites, SECLEVEL=0)',
    custom: 'Custom',
    customLabel: 'Custom cipher suites',
    customHelp: 'Applied in the chosen order (server cipher preference on by default), TLS 1.2 only; needs TLS 1.2 among the versions and nodes with SITE_TLS_CUSTOM_CIPHERS.',
    customSafeOnly: 'Only secure suites can be chosen: AES-GCM, ChaCha20-Poly1305 and AES-CBC suites with ECDHE or RSA key exchange; choose at least one ECDHE-ECDSA and one ECDHE-RSA GCM/CHACHA20 suite.',
  },
  ocsp: {
    label: 'OCSP stapling',
    help: "The node fetches the issuer's OCSP response, verifies it and sends it with the handshake so visitors need not ask the CA. It has no effect when the certificate names no OCSP responder (new Let's Encrypt certificates do not).",
  },
  http2: {
    label: 'HTTP/2',
    help: 'Off: this site negotiates HTTP/1.1 only over HTTPS; other sites on the same port are unaffected. Needs nodes with SITE_TLS_OPTIONS; nodes without it refuse the publication with the reason.',
  },
  http3: {
    label: 'HTTP/3',
    help: 'Serves HTTP/3 over QUIC and sends Alt-Svc; only with TLSv1.3 in the TLS versions. Off: QUIC handshakes for this site are refused.',
  },
  preferServerCiphers: {
    label: 'Prefer server ciphers',
    help: 'ssl_prefer_server_ciphers, for TLS 1.2 and older. "By cipher preset": off for modern, on for compatible and legacy; turning it on or off yourself needs nodes with SITE_TLS_OPTIONS.',
    preset: 'By cipher preset (now {{state}})',
    on: 'On',
    off: 'Off',
  },
  clientAuth: {
    label: 'Client certificate verification (mTLS)',
    help: '"Required": clients without a certificate from this CA cannot connect. "Optional": every client is served and the origin gets the result in X-Client-Verify / X-Client-Cert-Subject / X-Client-Cert-Fingerprint.',
    off: 'Off',
    optional: 'Optional',
    required: 'Required',
    ca: 'Client CA certificates (PEM)',
  },
  legacy: {
    title: 'Unsupported SSL protocols detected',
    description: 'The saved value contains {{protocols}}. Choose TLS protocols again before saving; legacy values are never rewritten automatically.',
  },
  unknown: {
    title: 'Unknown TLS protocols detected',
    description: 'The saved value contains {{protocols}}. These values are read-only; choose TLS protocols again before saving.',
  },
  validation: {
    safeOnly: 'Choose a contiguous range of TLS versions; TLS 1.0/1.1 need the legacy cipher suites.',
    clientCA: 'Paste the PEM CA certificates when client certificate verification is on.',
    customCiphers: 'Custom suites need at least one ECDHE-ECDSA and one ECDHE-RSA GCM or CHACHA20 suite, without repeats.',
  },
} satisfies Messages

function pseudoText(value: string): string {
  const expanded = value
    .split(/({{[^}]+}})/g)
    .map((part) => part.startsWith('{{') && part.endsWith('}}')
      ? part
      : [...part].map((character) => (/\s|\d/.test(character) ? character : `${character}~`)).join(''))
    .join('')
  return `［${expanded}］`
}

function pseudo(tree: Messages): Messages {
  return Object.fromEntries(Object.entries(tree).map(([key, value]) => [
    key,
    typeof value === 'string' ? pseudoText(value) : pseudo(value),
  ]))
}

const pseudoCN = pseudo(zhCN)

export const siteTLSMessages: Record<'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc', Messages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(siteTLSMessages)) {
  i18n.addResourceBundle(locale, 'siteTLS', messages, true, true)
}
