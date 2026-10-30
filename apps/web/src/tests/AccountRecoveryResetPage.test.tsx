import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'

import { AppRoutes } from '../App'
import { useSessionStore } from '../auth/session'
import { SessionBootstrap, SessionRefreshTimer } from '../auth/SessionBootstrap'
import { AccountRecoveryResetPage } from '../pages/account-recovery/ResetPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const token = 't'.repeat(43)
const recoveryContext = 'c'.repeat(162)
const resetRoute = `/reset-password#token=${token}&recovery_context=${recoveryContext}`

function errorResponse(status: number, code: string, retryAfter?: string) {
  return new Response(JSON.stringify({
    error: {
      code,
      message: 'raw recovery authority detail',
      request_id: `request-recovery-${status}`,
    },
  }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...(retryAfter ? { 'Retry-After': retryAfter } : {}),
    },
  })
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="recovery-location">{location.pathname + location.search + location.hash}</output>
}

describe('AccountRecoveryResetPage', () => {
  it('is reachable without session bootstrap or refresh requests', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(
      <SessionBootstrap><AccountRecoveryResetPage /></SessionBootstrap>,
      [resetRoute],
    )

    expect(screen.getByLabelText('新密码')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('rejects missing, malformed, or query-string recovery material', async () => {
    window.history.replaceState({}, '', `/dashboard/reset-password?token=${token}&recovery_context=${recoveryContext}`)
    const replaceStateSpy = vi.spyOn(window.history, 'replaceState')
    const view = renderWithProviders(
      <><AccountRecoveryResetPage /><LocationProbe /></>,
      [`/reset-password?token=${token}&recovery_context=${recoveryContext}`],
    )

    expect(screen.getByText('重置链接无效或不完整，请重新申请')).toBeInTheDocument()
    expect(screen.queryByLabelText('新密码')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: '重新申请重置链接' })).toHaveAttribute(
      'href',
      '/forgot-password',
    )
    expect(replaceStateSpy.mock.calls[0]?.[2]).toBe('/dashboard/reset-password')
    await waitFor(() => expect(screen.getByTestId('recovery-location')).toHaveTextContent(
      /^\/reset-password$/,
    ))
    expect(window.location.search).toBe('')

    view.unmount()
    renderWithProviders(
      <AccountRecoveryResetPage />,
      ['/reset-password#token=too-short&recovery_context=also-too-short'],
    )
    expect(screen.getByText('重置链接无效或不完整，请重新申请')).toBeInTheDocument()
    expect(screen.queryByLabelText('新密码')).not.toBeInTheDocument()
    window.history.replaceState({}, '', '/')
  })

  it('reads valid material from the fragment and clears it before interaction', async () => {
    localStorage.clear()
    sessionStorage.clear()
    window.history.replaceState({}, '', `/dashboard${resetRoute}`)
    const replaceStateSpy = vi.spyOn(window.history, 'replaceState')
    const consoleErrorSpy = vi.spyOn(console, 'error')
    renderWithProviders(
      <><AccountRecoveryResetPage /><LocationProbe /></>,
      [resetRoute],
    )

    expect(screen.getByLabelText('新密码')).toBeInTheDocument()
    expect(replaceStateSpy).toHaveBeenCalled()
    expect(replaceStateSpy.mock.calls[0]?.[2]).toBe('/dashboard/reset-password')
    await waitFor(() => expect(screen.getByTestId('recovery-location')).toHaveTextContent(
      /^\/reset-password$/,
    ))
    const storedValues = [localStorage, sessionStorage].flatMap((storage) =>
      Array.from({ length: storage.length }, (_, index) => storage.getItem(storage.key(index) ?? '') ?? ''))
    expect(storedValues.join('\n')).not.toContain(token)
    expect(JSON.stringify(consoleErrorSpy.mock.calls)).not.toContain(token)
    window.history.replaceState({}, '', '/')
  })

  it('redirects a legacy signed link to the canonical reset route', async () => {
    renderWithProviders(
      <><AppRoutes /><LocationProbe /></>,
      [`/forget-password#token=${token}&recovery_context=${recoveryContext}`],
    )

    expect(await screen.findByLabelText('新密码')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByTestId('recovery-location')).toHaveTextContent(
      /^\/reset-password$/,
    ))
  })

  it('validates the new password with the shared policy and both fields for equality', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryResetPage />, [resetRoute])

    await user.type(screen.getByLabelText('新密码'), 'Ab1-')
    await user.type(screen.getByLabelText('确认新密码'), 'different-value')
    await user.click(screen.getByRole('button', { name: '重置密码' }))

    expect(await screen.findByText('密码长度须为 8–1024 位')).toBeInTheDocument()
    expect(await screen.findByText('两次输入的密码不一致')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['12345678', '密码须至少包含大写字母、小写字母、数字、符号中的两种'],
    ['abcd 1234', '密码不能含空格、中文、全角或其他非英文符号'],
  ])('rejects %s before calling the API and shows the rule hint', async (password, message) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryResetPage />, [resetRoute])

    expect(screen.getByText(/8–1024 位，至少包含大写字母、小写字母、数字、符号中的两种/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: password } })
    fireEvent.change(screen.getByLabelText('确认新密码'), { target: { value: password } })
    await user.click(screen.getByRole('button', { name: '重置密码' }))

    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    [400, 'account_recovery_invalid_token', '重置链接无效或已过期，请重新申请'],
    [409, 'account_recovery_principal_changed', '账号状态已变化，请重新申请重置链接'],
  ])('treats terminal link error %s as consumed and cannot submit it again', async (
    status,
    code,
    localizedMessage,
  ) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: {
        code,
        message: 'raw recovery authority detail',
        request_id: 'request-recovery-terminal',
      },
    }), { status, headers: { 'Content-Type': 'application/json' } }))
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryResetPage />, [resetRoute])

    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'correct-horse-battery' } })
    fireEvent.change(screen.getByLabelText('确认新密码'), { target: { value: 'correct-horse-battery' } })
    await user.click(screen.getByRole('button', { name: '重置密码' }))

    expect(await screen.findByText(localizedMessage)).toBeInTheDocument()
    expect(screen.queryByText('重置链接无效或不完整，请重新申请')).not.toBeInTheDocument()
    expect(screen.queryByText(/raw recovery authority detail|request-recovery-terminal/)).not.toBeInTheDocument()
    expect(screen.queryByLabelText('新密码')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('确认新密码')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重置密码' })).not.toBeInTheDocument()
    const requestNewLink = screen.getByRole('link', { name: '重新申请重置链接' })
    expect(requestNewLink).toHaveAttribute('href', '/forgot-password')

    await user.click(requestNewLink)
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(document.body.innerHTML).not.toContain(token)
    expect(document.body.innerHTML).not.toContain(recoveryContext)
  })

  it('reuses the exact confirmation after an unknown service result', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response('<html>unavailable</html>', {
        status: 503, headers: { 'Content-Type': 'text/html' },
      }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const user = userEvent.setup()
    renderWithProviders(
      <><AppRoutes /><LocationProbe /></>,
      [resetRoute],
    )

    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'correct-horse-battery' } })
    fireEvent.change(screen.getByLabelText('确认新密码'), { target: { value: 'correct-horse-battery' } })
    await user.click(screen.getByRole('button', { name: '重置密码' }))
    // 失败提示改为 FeedbackWhen 弹窗（role=dialog，.cdnca-feedback-error）。
    expect(await screen.findByRole('dialog')).toHaveClass('cdnca-feedback-error')
    expect(screen.getByLabelText('新密码')).toBeDisabled()
    expect(screen.getByLabelText('确认新密码')).toBeDisabled()
    const firstHeaders = fetchSpy.mock.calls[0]?.[1]?.headers as Record<string, string>

    await user.click(screen.getByRole('button', { name: '重置密码' }))
    expect(await screen.findByText('密码修改成功，请重新登录')).toBeInTheDocument()
    const secondHeaders = fetchSpy.mock.calls[1]?.[1]?.headers as Record<string, string>
    expect(secondHeaders['Idempotency-Key']).toBe(firstHeaders['Idempotency-Key'])
    expect(fetchSpy.mock.calls[1]?.[1]?.body).toBe(fetchSpy.mock.calls[0]?.[1]?.body)
  })

  it('abandons an unknown confirmation, clears secrets, and requests a new link without another POST', async () => {
    localStorage.clear()
    sessionStorage.clear()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(
      new TypeError('connection reset'),
    )
    const user = userEvent.setup()
    renderWithProviders(
      <><AppRoutes /><LocationProbe /></>,
      [resetRoute],
    )

    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'correct-horse-battery' } })
    fireEvent.change(screen.getByLabelText('确认新密码'), { target: { value: 'correct-horse-battery' } })
    await user.click(screen.getByRole('button', { name: '重置密码' }))
    expect(await screen.findByText('无法连接服务，请稍后重试')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '重新申请重置链接' }))
    await waitFor(() => expect(screen.getByTestId('recovery-location')).toHaveTextContent(
      /^\/forgot-password$/,
    ))
    expect(fetchSpy).toHaveBeenCalledTimes(1)
    expect(screen.queryByLabelText('新密码')).not.toBeInTheDocument()
    expect(document.body.innerHTML).not.toContain('correct-horse-battery')
    expect(document.body.innerHTML).not.toContain(token)
    expect(document.body.innerHTML).not.toContain(recoveryContext)
    const storedValues = [localStorage, sessionStorage].flatMap((storage) =>
      Array.from({ length: storage.length }, (_, index) => storage.getItem(storage.key(index) ?? '') ?? ''))
    expect(storedValues.join('\n')).not.toContain('correct-horse-battery')
    expect(storedValues.join('\n')).not.toContain(token)
    expect(storedValues.join('\n')).not.toContain(recoveryContext)
  })

  it('treats HTTP 429 as terminal and starts a fresh confirmation after Retry-After', async () => {
    let releaseRetry!: () => void
    const originalSetTimeout = window.setTimeout.bind(window)
    vi.spyOn(window, 'setTimeout').mockImplementation((handler, timeout, ...args) => {
      // Retry-After 1: the page waits retryAt - Date.now(), a few ms under 1 s
      if (typeof timeout === 'number' && timeout > 500 && timeout <= 1_000) {
        releaseRetry = () => {
          if (typeof handler === 'function') handler(...args)
        }
        return 1 as unknown as NodeJS.Timeout
      }
      return originalSetTimeout(handler, timeout, ...args) as unknown as NodeJS.Timeout
    })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(errorResponse(429, 'account_recovery_rate_limited', '1'))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const user = userEvent.setup()
    renderWithProviders(
      <><AppRoutes /><LocationProbe /></>,
      [resetRoute],
    )

    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'correct-horse-battery' } })
    fireEvent.change(screen.getByLabelText('确认新密码'), { target: { value: 'correct-horse-battery' } })
    await user.click(screen.getByRole('button', { name: '重置密码' }))
    expect(await screen.findByText('请求过于频繁，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重新申请重置链接' })).not.toBeInTheDocument()
    const firstHeaders = fetchSpy.mock.calls[0]?.[1]?.headers as Record<string, string>

    act(() => releaseRetry())
    await waitFor(() => expect(screen.getByRole('button', { name: '重置密码' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '重置密码' }))

    expect(await screen.findByText('密码修改成功，请重新登录')).toBeInTheDocument()
    const secondHeaders = fetchSpy.mock.calls[1]?.[1]?.headers as Record<string, string>
    expect(secondHeaders['Idempotency-Key']).not.toBe(firstHeaders['Idempotency-Key'])
  })

  it('localizes confirmation errors without exposing raw service text', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: {
        code: 'account_recovery_password_reused',
        message: 'argon2 digest matched historical secret',
        request_id: 'request-recovery-confirm-2',
      },
    }), { status: 422, headers: { 'Content-Type': 'application/json' } }))
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryResetPage />, [resetRoute])

    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'correct-horse-battery' } })
    fireEvent.change(screen.getByLabelText('确认新密码'), { target: { value: 'correct-horse-battery' } })
    await user.click(screen.getByRole('button', { name: '重置密码' }))

    expect(await screen.findByText('新密码不能与当前密码相同')).toBeInTheDocument()
    expect(screen.queryByText(/argon2 digest|historical secret/i)).not.toBeInTheDocument()
    expect(screen.getByLabelText('新密码')).toBeEnabled()
    expect(screen.getByLabelText('确认新密码')).toBeEnabled()
    expect(screen.getByRole('button', { name: '重置密码' })).toBeEnabled()
    expect(screen.queryByRole('link', { name: '重新申请重置链接' })).not.toBeInTheDocument()
  })

  it('submits once, revokes the local session, and returns to login without auto-login', async () => {
    let resolveConfirmation!: (response: Response) => void
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockReturnValue(
      new Promise((resolve) => { resolveConfirmation = resolve }),
    )
    const actor = principal()
    useSessionStore.getState().setSession(authResponse(actor), actor)
    const user = userEvent.setup()
    renderWithProviders(
      <><AppRoutes /><LocationProbe /></>,
      [resetRoute],
    )

    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'correct-horse-battery' } })
    fireEvent.change(screen.getByLabelText('确认新密码'), { target: { value: 'correct-horse-battery' } })
    const submit = screen.getByRole('button', { name: '重置密码' })
    await user.click(submit)
    await waitFor(() => expect(submit).toBeDisabled())
    await user.click(submit)
    expect(fetchSpy).toHaveBeenCalledTimes(1)

    resolveConfirmation(new Response(null, { status: 204 }))
    expect(await screen.findByText('密码修改成功，请重新登录')).toBeInTheDocument()
    expect(useSessionStore.getState().principal).toBeNull()
    expect(screen.getByTestId('recovery-location')).toHaveTextContent(/^\/login$/)
  })

  it('suppresses session refresh and keeps controls reachable at a 390px viewport', () => {
    vi.useFakeTimers()
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const actor = principal()
    useSessionStore.getState().setSession({ ...authResponse(actor), expires_in: 1 }, actor)

    const view = renderWithProviders(
      <><SessionRefreshTimer /><AccountRecoveryResetPage /></>,
      [resetRoute],
    )
    act(() => vi.advanceTimersByTime(5_000))

    expect(fetchSpy).not.toHaveBeenCalled()
    expect(view.container.querySelector('.recovery-container')).toBeInTheDocument()
    expect(screen.getByLabelText('新密码')).toBeEnabled()
    expect(screen.getByRole('button', { name: '重置密码' })).toBeEnabled()
    vi.useRealTimers()
  })
})
