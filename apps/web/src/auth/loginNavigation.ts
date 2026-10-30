interface LoginNavigationState {
  returnTo?: unknown
}

const loginPath = '/login'
const internalOrigin = 'https://cdnca.invalid'

export function safeLoginReturnTo(state: unknown): string | null {
  if (!state || typeof state !== 'object') return null
  const candidate = (state as LoginNavigationState).returnTo
  if (
    typeof candidate !== 'string' ||
    candidate.length === 0 ||
    !candidate.startsWith('/') ||
    candidate.startsWith('//') ||
    candidate.includes('\\') ||
    [...candidate].some((character) => {
      const code = character.charCodeAt(0)
      return code <= 0x1f || code === 0x7f
    })
  ) return null

  try {
    const parsed = new URL(candidate, internalOrigin)
    const decodedPath = decodeURIComponent(parsed.pathname).toLowerCase().replace(/\/+$/, '') || '/'
    return parsed.origin === internalOrigin && decodedPath !== loginPath ? candidate : null
  } catch {
    return null
  }
}

const roleHomes = ['/home', '/admin-home'] as const

// fp-role ID-01：返回地址先过 safeLoginReturnTo（只管站内、不外跳），再按登录后的角色定落点。
// 另一角色的首页（旧书签）静默换成自己的首页，其余路径（含 query/hash）原样保留，由路由守卫按角色和权限处理。
export function loginDestination(returnTo: string | null, home: '/home' | '/admin-home'): string {
  if (!returnTo) return home
  const path = new URL(returnTo, internalOrigin).pathname.replace(/\/+$/, '') || '/'
  return roleHomes.some((roleHome) => roleHome === path) ? home : returnTo
}
