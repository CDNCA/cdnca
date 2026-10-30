// 登录页没有会话，匿名读 GET /v1/system-settings/public 的品牌白名单
// （系统名称与两个控制台标题）。任何失败都返回 null，调用方回落主题或内置名称。
const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const keys = ['system_name', 'user_title', 'admin_title'] as const

export interface PublicBranding {
  systemName: string
  userTitle: string
  adminTitle: string
}

export async function publicBranding(signal?: AbortSignal): Promise<PublicBranding | null> {
  try {
    const response = await fetch(`${apiRoot}/v1/system-settings/public`, { method: 'GET', credentials: 'omit', cache: 'no-store', signal })
    if (!response.ok) return null
    const body: unknown = await response.json().catch(() => null)
    if (!body || typeof body !== 'object' || Array.isArray(body)) return null
    const value = body as Record<string, unknown>
    if (Object.keys(value).length !== keys.length || !keys.every((key) => typeof value[key] === 'string')) return null
    return { systemName: value.system_name as string, userTitle: value.user_title as string, adminTitle: value.admin_title as string }
  } catch {
    return null
  }
}
