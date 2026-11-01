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

type RouteRole = 'admin' | 'user'
let routeRoleForPath: (pathname: string) => RouteRole | null = () => null

/** App.tsx 在加载时注册：按其路由树里的 RoleRoute 判定路径所属角色（登录页按需加载，不反向引用 App）。 */
export function setLoginRouteRoleResolver(resolver: (pathname: string) => RouteRole | null): void {
  routeRoleForPath = resolver
}

// fp-role ID-01 / om返回地址先过 safeLoginReturnTo（只管站内、不外跳），再按登录后的角色定落点。
// 属于另一角色的路由（含对方首页这类旧书签）静默换成自己的首页，不再弹「此页面属于管理员端」；
// 其余路径（含 query/hash）原样保留，由路由守卫按权限处理。
export function loginDestination(returnTo: string | null, home: '/home' | '/admin-home'): string {
  if (!returnTo) return home
  const path = new URL(returnTo, internalOrigin).pathname.replace(/\/+$/, '') || '/'
  const ownRole: RouteRole = home === '/admin-home' ? 'admin' : 'user'
  const pathRole = path === '/home' ? 'user' : path === '/admin-home' ? 'admin' : routeRoleForPath(path)
  return pathRole && pathRole !== ownRole ? home : returnTo
}
