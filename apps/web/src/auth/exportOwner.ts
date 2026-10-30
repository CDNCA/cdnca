import type { Principal } from '../api/auth'
import { useSessionStore } from './session'

// TEL-UX-EXPORT-OWNER：导出是慢请求，响应回来时账号可能已切换、退出或被撤权。
// 发起时记下当前身份，响应后用 stillCurrent() 复核：同一 scope/租户/用户/会话代数且仍有权限才下载、才提示。
export function exportOwnerGuard(allowed: (principal: Principal) => boolean): () => boolean {
  const signature = (): string | null => {
    const { status, principal, sessionEpoch } = useSessionStore.getState()
    if (status !== 'authenticated' || !principal || !allowed(principal)) return null
    return JSON.stringify([principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch])
  }
  const started = signature()
  return () => started !== null && signature() === started
}
