import { act, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { resetAccountLocaleSync } from '../api/accountLocale'
import { AccountLocaleSync } from '../auth/AccountLocaleSync'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'

const principal = { user_id: 'u-1', scope_id: 's-1', scope_kind: 'tenant', tenant_id: 't-1', username: 'alice', display_name: 'Alice' }

describe('AccountLocaleSync', () => {
  const fetchMock = vi.fn(async () => new Response(null, { status: 204 }))
  beforeEach(async () => {
    resetAccountLocaleSync()
    fetchMock.mockClear()
    vi.stubGlobal('fetch', fetchMock)
    await i18n.changeLanguage('zh-CN')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    useSessionStore.setState({ accessToken: null, principal: null })
  })

  it('saves the language once after sign-in and again after a switch', async () => {
    useSessionStore.setState({ accessToken: 'token-1', principal: principal as never })
    render(<AccountLocaleSync />)
    await act(async () => { await i18n.changeLanguage('en-US') })
    expect(fetchMock.mock.calls.map((call) => JSON.parse(String((call as unknown as [string, RequestInit])[1].body)).locale)).toEqual(['zh-CN', 'en-US'])
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toMatch(/\/v1\/account\/locale$/)
    expect(init.method).toBe('PUT')
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer token-1')
  })

  it('does nothing without a session or while impersonating', () => {
    render(<AccountLocaleSync />)
    expect(fetchMock).not.toHaveBeenCalled()
    act(() => { useSessionStore.setState({ accessToken: 'token-1', principal: { ...principal, impersonation: {} } as never }) })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
