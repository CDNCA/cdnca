// 筛选条件里的地址与端口规则（B 批共用）：与各接口的服务端解析一致（Go netip.ParseAddr / ParsePrefix、端口 1–65535），
// 页面在发请求前用它就地拦下非法值；服务端仍做最终校验（保留地址段、最小前缀等由服务端拒绝并映射到字段）。

/** 单个 IPv4（点分十进制、无前导零）或 IPv6（不带 zone）地址。 */
export function isIPAddress(value: string): boolean {
  if (value.length === 0 || value.length > 64) return false
  if (!value.includes(':')) {
    const parts = value.split('.')
    return parts.length === 4 && parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
  }
  if (value.includes('%') || !/^[0-9A-Fa-f:.]+$/.test(value)) return false
  try {
    return new URL(`http://[${value}]/`).hostname.startsWith('[')
  } catch {
    return false
  }
}

export interface CIDRBits { v4: number; v6: number }

/**
 * 地址或网段（address/bits，bits 不超过 32 / 128）。minBits：服务端允许的最宽网段（例如封禁名单 /8、/32），
 * 更宽的网段同样算不合法。
 */
export function isIPOrCIDR(value: string, minBits: CIDRBits = { v4: 0, v6: 0 }): boolean {
  const [address, bits, extra] = value.split('/')
  if (extra !== undefined || !isIPAddress(address)) return false
  if (bits === undefined) return true
  if (!/^\d{1,3}$/.test(bits)) return false
  const ipv6 = address.includes(':')
  const length = Number(bits)
  return length >= (ipv6 ? minBits.v6 : minBits.v4) && length <= (ipv6 ? 128 : 32)
}

/** 单个端口 1–65535（十进制整数）。 */
export function isPort(value: string): boolean {
  return /^\d{1,5}$/.test(value) && Number(value) >= 1 && Number(value) <= 65535
}
