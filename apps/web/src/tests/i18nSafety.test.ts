import { authApi, ApiError } from '../api/auth'
import i18n from '../i18n'
import { localizedApiError } from '../i18n/apiError'
import '../i18n/maintenanceUpgrade'

const componentSources = import.meta.glob(
  ['../components/**/*.tsx', '../pages/**/*.tsx'],
  { eager: true, import: 'default', query: '?raw' },
) as Record<string, string>

const apiSources = import.meta.glob('../api/*.ts', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>

const visibleAttributePattern =
  /(?:aria-label|label|placeholder|title|message|description|okText|cancelText)\s*=\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["']/gu
const visibleTextPattern =
  /<[A-Za-z][^>]*>\s*([^<>{}\r\n]*[A-Za-z\p{Script=Han}][^<>{}\r\n]*)\s*<\/[A-Za-z][^>]*>/gu
const visibleObjectPropertyPattern =
  /(?:^|[,{]\s*)(?:label|placeholder|title|message|description|okText|cancelText|emptyText)\s*:\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["']/gmu
const visibleExpressionPattern =
  /<[A-Za-z][^>]*>\s*\{\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["']\s*\}\s*<\/[A-Za-z][^>]*>/gu
const visibleConditionalExpressionPattern =
  /<[A-Za-z][^>]*>\s*\{\s*(?!t\s*\()[^{}]*\?\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["']\s*:\s*["']([^"']*[A-Za-z\p{Script=Han}][^"']*)["'][^{}]*\}\s*<\/[A-Za-z][^>]*>/gu
const translationKeyPattern = /^(?:[a-z][A-Za-z0-9_]*\.)+[A-Za-z0-9_]+$/

const allowedVisibleLiterals = new Set([
  // Shell log prefix of the node install command, not UI copy.
  '[cdnca-edge]',
  'DNS API',
  'UUID',
  'JA4',
  'MD5',
  'HMAC-SHA256',
  'CNAME',
  'allow_origin',
  'allow_methods',
  'allow_headers',
  'expose_headers',
  'allow_credentials',
  'max_age',
  'Websocket',
  // Website brand placeholder (control-api controlsite.BrandPlaceholder).
  '{{brand}}',
  '2001:db8::10',
  // 协议与算法标识
  'IP', 'Http', 'HTTP', 'HTTPS', 'HTTP/2', 'HTTP/3', 'Stream', 'Worker', 'TTL', 'zerossl', 'lets',
  'IPv6', 'TCP', 'PING', 'ID',
  // 带宽单位
  'Mbps', 'Gbps', 'GB',
  // 日志级别枚举
  'info', 'debug',
  // nginx 指令名与取值，属于配置语法本身，不翻译
  'server', 'server_tokens', 'worker_processes', 'worker_connections', 'worker_rlimit_nofile',
  'worker_shutdown_timeout', 'keepalive_requests', 'keepalive_timeout', 'log_not_found',
  'default_type', 'large_client_header_buffers', 'client_max_body_size', 'client_body_buffer_size',
  'server_names_hash_max_size', 'server_names_hash_bucket_size', 'gzip_min_length',
  'gzip_comp_level', 'gzip_http_version', 'gzip_vary', 'gzip types', 'proxy_http_version',
  'proxy_connect_timeout', 'proxy_send_timeout', 'proxy_read_timeout', 'proxy_buffering',
  'proxy_request_buffering', 'proxy_max_temp_file_size', 'proxy_next_upstream',
  'proxy_cache_dir', 'proxy_cache_max_size', 'proxy_cache_methods', 'proxy_timeout',
  'ocsp_stapling',
  // 三元分支已是 t() 的翻译 key，正则误判为字面量
  'bill08.values.supported', 'bill08.values.disabled',
  'assetValues.autoRenewEnabled', 'assetValues.autoRenewDisabled',
  // tp-b6 账户日志：嵌套三元的 verbCreate/verbUpdate/verbDelete 是 text() 的 key
  'verbUpdate', 'verbDelete',
  // 证书颁发机构产品名（"Let's Encrypt" 被引号截成 "Let"）
  'Let', 'ZeroSSL', 'Google Trust Services',
  // 输入示例：主机名、接口地址、通配域名、扩展名、PEM 头、nginx 变量、cookie 名，按原样输入
  'edge-01.cdnca.com', 'https://api.dnspup.com/v1/tools/ip-intel-snapshot', '*.example.com', 'jpg',
  '-----BEGIN CERTIFICATE-----', '$cookie_uid$uri', 'cdnca_route',
  'https://api.dnspup.com', 'control.example.com', 'X-Powered-By', 'ops@example.com',
  // tp-b3c Header 设置：请求头/响应头规则的配置语法示例（动作:头名:值），按原样输入
  'set:X-Request-ID:$request_id', 'set:Cache-Control:no-store',
  // stream-parity 批量修改：四层协议名（与 resources 里 proxyV1 等一致，不翻译）
  'Proxy Protocol',
  // tp-b3c-be 错误页「按文本创建」的预置模板正文：写进错误页资源的用户内容，不是界面文案
  '请求无法完成，请稍后重试。', 'Error', '出错了', '我们正在处理，请稍后再试。',
])

function visibleLiterals(source: string): string[] {
  const objectLiterals = [...source.matchAll(visibleObjectPropertyPattern)]
    .map((match) => match[1])
    .filter((literal) => !translationKeyPattern.test(literal))
  return [
    ...[...source.matchAll(visibleAttributePattern)].map((match) => match[1]),
    ...[...source.matchAll(visibleTextPattern)].map((match) => match[1]),
    ...objectLiterals,
    ...[...source.matchAll(visibleExpressionPattern)].map((match) => match[1]),
    ...[...source.matchAll(visibleConditionalExpressionPattern)].flatMap((match) => [match[1], match[2]]),
  ].map((literal) => literal.trim()).filter(Boolean)
}

// 维护升级页通过 maintenanceUpgradeMessage(locale, key) 取文案，title/description 与三元分支里是
// 该命名空间的 key 而不是展示文本；只认真实存在的 key，未知字符串仍会被报出来。
function isMaintenanceUpgradeKey(literal: string): boolean {
  return /^[a-z][A-Za-z0-9]*$/.test(literal) && i18n.exists(literal, { ns: 'maintenanceUpgrade', lng: 'zh-CN' })
}

describe('internationalization safety gates', () => {
  it('keeps component-visible literals in locale resources except the protocol whitelist', () => {
    const findings = Object.entries(componentSources).flatMap(([file, source]) =>
      /\.(?:test|spec)\.tsx$/.test(file) ? [] : visibleLiterals(source)
        .filter((literal) => literal && !allowedVisibleLiterals.has(literal))
        .filter((literal) => !(/ControlUpgradesPage/.test(file) && isMaintenanceUpgradeKey(literal)))
        .map((literal) => `${file}: ${literal}`),
    )

    expect(findings).toEqual([])
  })

  it('finds visible literals in JSX text, expressions, and option objects without matching comparisons', () => {
    const sourceLiteralFixture = `
      const options = [{ value: 'ip_hash', label: 'IP Hash' }]
      const withinRange = value > 1 && value < 10
      const view = <section title="Hardcoded title"><span>硬编码文本</span><b>{'Expression text'}</b><i>{enabled ? 'On text' : 'Off text'}</i></section>
    `

    expect(visibleLiterals(sourceLiteralFixture)).toEqual([
      'Hardcoded title',
      '硬编码文本',
      'IP Hash',
      'Expression text',
      'On text',
      'Off text',
    ])
  })

  it('does not consume raw server messages in API clients', () => {
    const findings = Object.entries(apiSources)
      .filter(([, source]) => /body\.error\?\.message|error\?\.message/.test(source))
      .map(([file]) => file)

    expect(findings).toEqual([])
  })

  it('keeps raw server text out of errors and localized UI fallbacks', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: {
        code: 'future_error',
        message: 'raw English https://internal.example/?token=secret stack trace',
        request_id: 'req-safe-42',
      },
    }), { status: 500, headers: { 'Content-Type': 'application/json' } }))

    const error = await authApi.login({ username: 'jason', password: 'secret' })
      .then(() => null, (reason: unknown) => reason)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).message).not.toContain('raw English')
    expect(localizedApiError(error)).toBe('请求失败，请稍后重试（请求 ID：req-safe-42）')
  })

  it('drops unsafe request IDs instead of rendering attacker-controlled text', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: {
        code: 'future_error',
        message: 'do not render me',
        request_id: 'https://internal.example/?secret=1',
      },
    }), { status: 500, headers: { 'Content-Type': 'application/json' } }))

    const error = await authApi.login({ username: 'jason', password: 'secret' })
      .then(() => null, (reason: unknown) => reason)

    expect(localizedApiError(error)).toBe('请求失败，请稍后重试')
  })
})
