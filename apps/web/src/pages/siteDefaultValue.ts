import type { SiteDefaultSettingName } from '../api/siteDefaults'
import { validSiteTLSCipherSuites } from '../api/sites'

// 与后端 normalizeSiteDefaultValue 同一规则（SITE-CURRENT-08）：端口 1–65535
// 不重复，空格或逗号分隔；空闲超时 1–300 整数秒；回源 HTTP/HTTPS 端口单个端口；
// 回源连接超时 1–30 秒、读取超时 1–300 秒；TLS 协议为 TLSv1..TLSv1.3 中的连续区间；
// 黑名单时间 1–86400 秒、白名单时间 60–604800 秒（与 CC 策略同一范围）；DNS API 与规则库为 ID；
// 上传限制 1–1024 MB；源站请求头每行「名称: 值」，名称不重复（其余由后端按站点 HTTP 策略校验）；
// 网站缓存为缓存策略 JSON、条件源站为 {"routes":[...]} 且每条 pool_id 为占位 @default，都至少一条规则（细则由后端校验）。
const tlsVersions = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']

export function siteDefaultValueError(name: SiteDefaultSettingName | undefined, raw: string): 'ports' | 'port' | 'timeout' | 'connectTimeout' | 'protocols' | 'banSeconds' | 'passSeconds' | 'dnsProvider' | 'policy' | 'postSize' | 'reqHeader' | 'document' | 'cipherSuites' | null {
  const value = raw.trim()
  const port = (text: string) => /^\d{1,5}$/u.test(text) && Number(text) >= 1 && Number(text) <= 65_535
  if (name === 'http_listen_port' || name === 'https_listen_port') {
    const ports = value.split(/[\s,]+/u).filter(Boolean)
    return ports.length > 0 && ports.length <= 32 && ports.every(port) && new Set(ports.map(Number)).size === ports.length ? null : 'ports'
  }
  if (name === 'backend_https_port' || name === 'backend_http_port') return port(value) ? null : 'port'
  if (name === 'origin_connect_timeout') return /^\d{1,2}$/u.test(value) && Number(value) >= 1 && Number(value) <= 30 ? null : 'connectTimeout'
  if (name === 'origin_read_timeout') return /^\d{1,3}$/u.test(value) && Number(value) >= 1 && Number(value) <= 300 ? null : 'timeout'
  if (name === 'ssl_protocols') {
    // 后端 normalizeTLSProtocols：TLSv1..TLSv1.3 中的连续区间
    const indexes = value.split(/\s+/u).filter(Boolean).map((item) => tlsVersions.indexOf(item))
    const sorted = [...new Set(indexes)].sort()
    return sorted.length > 0 && sorted.length === indexes.length && sorted[0]! >= 0 &&
      sorted.every((item, index) => index === 0 || item === sorted[index - 1]! + 1) ? null : 'protocols'
  }
  const seconds = (min: number, max: number) => /^\d{1,6}$/u.test(value) && Number(value) >= min && Number(value) <= max
  if (name === 'cc_ban_seconds') return seconds(1, 86_400) ? null : 'banSeconds'
  if (name === 'cc_pass_seconds') return seconds(60, 604_800) ? null : 'passSeconds'
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu
  if (name === 'cc_policy' || name === 'waf_policy' || name === 'acl_policy') return uuid.test(value) ? null : 'policy'
  if (name === 'post_size_limit') return /^\d{1,4}$/u.test(value) && Number(value) >= 1 && Number(value) <= 1024 ? null : 'postSize'
  if (name === 'req_header') {
    const lines = value.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean)
    const names = lines.map((line) => line.split(':', 1)[0]!.trim().toLowerCase())
    return lines.length > 0 && lines.length <= 64 && value.length <= 8192 && lines.every((line) => line.includes(':')) &&
      names.every((item) => /^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/u.test(item)) && new Set(names).size === names.length ? null : 'reqHeader'
  }
  if (name === 'proxy_cache' || name === 'cond_origin') {
    let parsed: unknown
    try { parsed = JSON.parse(value) } catch { return 'document' }
    if (value.length > 65_536 || typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return 'document'
    if (name === 'proxy_cache') {
      const rules = (parsed as { rules?: unknown }).rules
      return Array.isArray(rules) && rules.length > 0 ? null : 'document'
    }
    const routes = (parsed as { routes?: unknown }).routes
    return Object.keys(parsed).length === 1 && Array.isArray(routes) && routes.length > 0 &&
      routes.every((route: unknown) => typeof route === 'object' && route !== null &&
        (route as { pool_id?: unknown }).pool_id === '@default' && !('fallback_pool_id' in route)) ? null : 'document'
  }
  // #11 自定义套件：与站点 tls_cipher_suites 同一白名单与规则（后端 edgeconfig.ValidateTLSCipherSuites）
  if (name === 'ssl_cipher_suites') return validSiteTLSCipherSuites(value.split(/[\s,:]+/u).filter(Boolean)) ? null : 'cipherSuites'
  if (name === 'dns_provider') return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value) ? null : 'dnsProvider'
  if (name === 'ups_keepalive_timeout') return /^\d{1,3}$/u.test(value) && Number(value) >= 1 && Number(value) <= 300 ? null : 'timeout'
  return null
}
