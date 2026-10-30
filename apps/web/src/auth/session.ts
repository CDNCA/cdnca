import { create } from 'zustand'

import { ApiError, authApi, type AuthResponse, type LoginRequest, type Principal } from '../api/auth'
import { forgetAnnouncementPopupLater } from './announcementPopupLater'

export type SessionStatus = 'bootstrapping' | 'authenticated' | 'anonymous'
export type SessionUpdate = 'new' | 'refresh'

interface SessionState {
  accessToken: string | null
  expiresAt: number | null
  principal: Principal | null
  sessionEpoch: number
  status: SessionStatus
  setSession: (response: AuthResponse, principal: Principal, update?: SessionUpdate) => void
  updatePrincipal: (changes: Pick<Principal, 'display_name'>) => void
  // A14: entering, leaving or timing out of impersonation swaps the principal
  // on the same access token. It is a new identity, so it starts a new epoch
  // (SessionQueryBoundary clears the previous identity's cache); applied only
  // while the epoch is still `expectedEpoch`, false otherwise.
  transitionPrincipal: (expectedEpoch: number, principal: Principal) => boolean
  clearSession: () => void
}

const initialSession = {
  accessToken: null,
  expiresAt: null,
  principal: null,
  status: 'bootstrapping' as const,
}

let lastSessionEpoch = 0
let lastPrincipalTransitionAt = 0

/** True right after an impersonation enter/exit swapped the principal (the role redirect then stays silent). */
export function principalJustTransitioned(windowMs = 3000): boolean {
  return Date.now() - lastPrincipalTransitionAt < windowMs
}

function nextSessionEpoch(current: number): number {
  lastSessionEpoch = Math.max(lastSessionEpoch, current) + 1
  return lastSessionEpoch
}

export const useSessionStore = create<SessionState>((set, get) => ({
  ...initialSession,
  sessionEpoch: 0,
  setSession: (response, principal, update = 'new') => {
    // A new sign-in shows "稍后再看" announcements again.
    if (update === 'new') forgetAnnouncementPopupLater()
    set((state) => ({
      accessToken: response.access_token,
      expiresAt: Date.now() + response.expires_in * 1000,
      principal,
      sessionEpoch: update === 'refresh' && state.status === 'authenticated'
        ? state.sessionEpoch
        : nextSessionEpoch(state.sessionEpoch),
      status: 'authenticated',
    }))
  },
  updatePrincipal: (changes) =>
    set((state) => ({ principal: state.principal ? { ...state.principal, ...changes } : null })),
  transitionPrincipal: (expectedEpoch, principal) => {
    const state = get()
    if (state.status !== 'authenticated' || state.sessionEpoch !== expectedEpoch) return false
    // 代登录进入/退出会把当前页换成另一角色的页面，这时直接回首页，不弹"此页面属于…"提示。
    lastPrincipalTransitionAt = Date.now()
    set({ principal, sessionEpoch: nextSessionEpoch(state.sessionEpoch) })
    return true
  },
  clearSession: () =>
    set((state) => ({
      accessToken: null,
      expiresAt: null,
      principal: null,
      sessionEpoch: nextSessionEpoch(state.sessionEpoch),
      status: 'anonymous',
    })),
}))

interface RefreshLineage {
  sessionEpoch: number
  status: SessionStatus
  scopeKind: Principal['scope_kind'] | null
  scopeId: string | null
  tenantId: string | null
  userId: string | null
}

interface RefreshAttempt {
  lineage: RefreshLineage
  promise: Promise<Principal>
}

let refreshAttempt: RefreshAttempt | null = null

function currentRefreshLineage(): RefreshLineage {
  const { principal, sessionEpoch, status } = useSessionStore.getState()
  return {
    sessionEpoch,
    status,
    scopeKind: principal?.scope_kind ?? null,
    scopeId: principal?.scope_id ?? null,
    tenantId: principal?.tenant_id ?? null,
    userId: principal?.user_id ?? null,
  }
}

function sameRefreshLineage(left: RefreshLineage, right: RefreshLineage): boolean {
  return left.sessionEpoch === right.sessionEpoch
    && left.status === right.status
    && left.scopeKind === right.scopeKind
    && left.scopeId === right.scopeId
    && left.tenantId === right.tenantId
    && left.userId === right.userId
}

function principalMatchesRefreshLineage(principal: Principal, lineage: RefreshLineage): boolean {
  return principal.scope_kind === lineage.scopeKind
    && principal.scope_id === lineage.scopeId
    && principal.tenant_id === lineage.tenantId
    && principal.user_id === lineage.userId
}

function samePrincipalIdentity(left: Principal, right: Principal): boolean {
  return left.scope_kind === right.scope_kind
    && left.scope_id === right.scope_id
    && left.tenant_id === right.tenant_id
    && left.user_id === right.user_id
}

async function applyAuthResponse(
  response: AuthResponse,
  update: SessionUpdate,
  canApply: () => boolean = () => true,
  validPrincipal: (principal: Principal) => boolean = () => true,
  signal?: AbortSignal,
): Promise<Principal> {
  if (!canApply()) throw new Error('Session changed during refresh')
  const principal = await authApi.me(response.access_token, signal)
  if (!canApply()) throw new Error('Session changed during refresh')
  if (!validPrincipal(principal)) throw new Error('Refresh principal identity changed')
  useSessionStore.getState().setSession(response, principal, update)
  return principal
}

export function hydrateLoginSession(response: AuthResponse, canApply: () => boolean = () => true, signal?: AbortSignal): Promise<Principal> {
  return applyAuthResponse(response, 'new', canApply, () => true, signal)
}

export async function loginSession(
  input: LoginRequest,
  idempotencyKey?: string,
  canApply: () => boolean = () => true,
  onResponse?: (response: AuthResponse) => void,
  signal?: AbortSignal,
): Promise<Principal> {
  await settledLogout()
  const response = await authApi.login(input, idempotencyKey, signal)
  onResponse?.(response)
  return applyAuthResponse(response, 'new', canApply, () => true, signal)
}

export function isTransientRefreshError(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 0 || error.status === 429 || error.status >= 500)
}

export function refreshSession(): Promise<Principal> {
  const lineage = currentRefreshLineage()
  if (refreshAttempt && sameRefreshLineage(refreshAttempt.lineage, lineage)) {
    return refreshAttempt.promise
  }

  const canApply = () => sameRefreshLineage(currentRefreshLineage(), lineage)
  const promise = authApi
    .refresh()
    .then((response) => {
      const validPrincipal = lineage.userId === null
        ? (principal: Principal) => samePrincipalIdentity(principal, response.principal)
        : (principal: Principal) => principalMatchesRefreshLineage(principal, lineage) &&
          principalMatchesRefreshLineage(response.principal, lineage)
      return applyAuthResponse(response, 'refresh', canApply, validPrincipal)
    })
    .catch((error: unknown) => {
      // A network error or a 5xx/429 is not a refusal: keep the session so the
      // renewal can be retried instead of sending the user to the login page.
      // (On page load SessionBootstrap retries and gives up after a few tries.)
      if (canApply() && !isTransientRefreshError(error)) useSessionStore.getState().clearSession()
      throw error
    })
    .finally(() => {
      if (refreshAttempt?.promise === promise) refreshAttempt = null
    })

  refreshAttempt = { lineage, promise }
  return promise
}

// The server-side sign-out still running in the background (logoutSession).
let pendingLogout: Promise<void> | null = null
const pendingLogoutWaitMilliseconds = 3_000

// Signing out clears this tab's session at once; the server revokes the
// refresh family in the background and a failure is not shown.
// The login page never resumes a session from the cookie (SessionBootstrap
// skips /login), so a failed revoke cannot send the user back in.
export async function logoutSession(): Promise<void> {
  useSessionStore.getState().clearSession()
  const request = authApi.logout().catch(() => undefined)
  pendingLogout = request
  void request.finally(() => {
    if (pendingLogout === request) pendingLogout = null
  })
}

// A sign-in right after signing out waits (briefly) for that sign-out, so its
// cookie-clearing response cannot land on top of the new session.
async function settledLogout(): Promise<void> {
  const pending = pendingLogout
  if (!pending) return
  await Promise.race([pending, new Promise<void>((resolve) => window.setTimeout(resolve, pendingLogoutWaitMilliseconds))])
}

export function resetSessionStore(): void {
  refreshAttempt = null
  useSessionStore.setState((state) => ({
    ...initialSession,
    sessionEpoch: nextSessionEpoch(state.sessionEpoch),
  }))
}

export type AppRole = 'admin' | 'user'

export function roleForPrincipal(principal: Principal): AppRole {
  return principal.scope_kind === 'platform' ? 'admin' : 'user'
}

export function homeForPrincipal(principal: Principal): '/admin-home' | '/home' {
  return roleForPrincipal(principal) === 'admin' ? '/admin-home' : '/home'
}
