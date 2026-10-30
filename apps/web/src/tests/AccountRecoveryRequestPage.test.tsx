import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useLocation } from 'react-router-dom'

import { AppRoutes } from '../App'
import { SessionBootstrap } from '../auth/SessionBootstrap'
import i18n from '../i18n'
import { AccountRecoveryRequestPage } from '../pages/account-recovery/RequestPage'
import { renderWithProviders } from '../test/render'

function acceptedResponse() {
  return new Response(JSON.stringify({
    data: {
      code: 'account_recovery_request_accepted',
      accepted_at: '2026-07-23T10:00:00.123456789Z',
    },
  }), { status: 202, headers: { 'Content-Type': 'application/json' } })
}

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

describe('AccountRecoveryRequestPage', () => {
  it('is reachable through the public forgot-password route', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    renderWithProviders(<SessionBootstrap><AppRoutes /></SessionBootstrap>, ['/forgot-password'])

    // 找回密码页懒加载。
    expect(await screen.findByRole('heading', { name: 'cdnca' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '发送重置指引' })).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('redirects the legacy request entry to the canonical public route', async () => {
    renderWithProviders(<><AppRoutes /><LocationProbe /></>, ['/forget-password'])

    expect(await screen.findByRole('button', { name: '发送重置指引' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByTestId('recovery-location')).toHaveTextContent(
      /^\/forgot-password$/,
    ))
  })

  it('validates the trimmed UTF-8 username without calling the API', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])

    await user.click(screen.getByRole('button', { name: '发送重置指引' }))
    expect(await screen.findByText('请输入用户名')).toBeInTheDocument()

    await user.type(screen.getByLabelText('用户名'), `  ${'界'.repeat(342)}  `)
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))
    expect(await screen.findByText('用户名不能超过 1024 字节')).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('sends only the normalized username and shows the uniform acceptance message', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(acceptedResponse())
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])

    await user.type(screen.getByLabelText('用户名'), '  missing-or-disabled-user  ')
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))

    expect(await screen.findByText('如账号可用，重置指引将发送至已绑定联系方式')).toBeInTheDocument()
    const body = JSON.parse(String(fetchSpy.mock.calls[0]?.[1]?.body))
    expect(body).toEqual({ username: 'missing-or-disabled-user' })
    expect(body).not.toHaveProperty('tenant_id')
    expect(body).not.toHaveProperty('scope_id')
    expect(body).not.toHaveProperty('email')
    expect(body).not.toHaveProperty('phone')
    expect(screen.queryByText(/不存在|禁用|missing|disabled/i)).not.toBeInTheDocument()
  })

  it('reuses the exact idempotency key and body after an unknown result', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('connection reset'))
      .mockResolvedValueOnce(acceptedResponse())
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])

    await user.type(screen.getByLabelText('用户名'), 'jason')
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))
    expect(await screen.findByText('无法连接服务，请稍后重试')).toBeInTheDocument()
    expect(screen.getByLabelText('用户名')).toBeDisabled()

    const firstHeaders = fetchSpy.mock.calls[0]?.[1]?.headers as Record<string, string>
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))
    expect(await screen.findByText('如账号可用，重置指引将发送至已绑定联系方式')).toBeInTheDocument()
    const secondHeaders = fetchSpy.mock.calls[1]?.[1]?.headers as Record<string, string>
    expect(secondHeaders['Idempotency-Key']).toBe(firstHeaders['Idempotency-Key'])
    expect(fetchSpy.mock.calls[1]?.[1]?.body).toBe(fetchSpy.mock.calls[0]?.[1]?.body)
  })

  it.each([
    ['HTTP 408', 408, 'account_recovery_timeout'],
    ['a contract-declared unknown result', 409, 'account_recovery_request_cancelled'],
    ['HTTP 5xx', 503, 'account_recovery_unavailable'],
  ])('keeps the exact request after %s', async (_label, status, code) => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(errorResponse(status, code))
      .mockResolvedValueOnce(acceptedResponse())
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])

    await user.type(screen.getByLabelText('用户名'), 'jason')
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))
    // The failure opens the shared feedback dialog (FeedbackWhen) instead of an in-page Alert.
    expect(await screen.findByRole('dialog')).toBeInTheDocument()
    const firstHeaders = fetchSpy.mock.calls[0]?.[1]?.headers as Record<string, string>

    await user.click(screen.getByRole('button', { name: '发送重置指引' }))
    expect(await screen.findByText('如账号可用，重置指引将发送至已绑定联系方式')).toBeInTheDocument()
    const secondHeaders = fetchSpy.mock.calls[1]?.[1]?.headers as Record<string, string>
    expect(secondHeaders['Idempotency-Key']).toBe(firstHeaders['Idempotency-Key'])
    expect(fetchSpy.mock.calls[1]?.[1]?.body).toBe(fetchSpy.mock.calls[0]?.[1]?.body)
  })

  it('abandons an unknown request and starts again with a new idempotency key', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(new TypeError('connection reset'))
      .mockResolvedValueOnce(acceptedResponse())
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])

    await user.type(screen.getByLabelText('用户名'), 'jason')
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))
    expect(await screen.findByText('无法连接服务，请稍后重试')).toBeInTheDocument()
    const firstHeaders = fetchSpy.mock.calls[0]?.[1]?.headers as Record<string, string>

    await user.click(screen.getByRole('button', { name: '重新申请' }))
    expect(screen.queryByText('无法连接服务，请稍后重试')).not.toBeInTheDocument()
    expect(screen.getByLabelText('用户名')).toBeEnabled()
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))

    expect(await screen.findByText('如账号可用，重置指引将发送至已绑定联系方式')).toBeInTheDocument()
    const secondHeaders = fetchSpy.mock.calls[1]?.[1]?.headers as Record<string, string>
    expect(secondHeaders['Idempotency-Key']).not.toBe(firstHeaders['Idempotency-Key'])
  })

  it('treats HTTP 429 as terminal and starts a fresh attempt after Retry-After', async () => {
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
      .mockResolvedValueOnce(acceptedResponse())
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])

    await user.type(screen.getByLabelText('用户名'), 'jason')
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))
    expect(await screen.findByText('请求过于频繁，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重新申请' })).not.toBeInTheDocument()
    const firstHeaders = fetchSpy.mock.calls[0]?.[1]?.headers as Record<string, string>

    act(() => releaseRetry())
    await waitFor(() => expect(screen.getByRole('button', { name: '发送重置指引' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))

    expect(await screen.findByText('如账号可用，重置指引将发送至已绑定联系方式')).toBeInTheDocument()
    const secondHeaders = fetchSpy.mock.calls[1]?.[1]?.headers as Record<string, string>
    expect(secondHeaders['Idempotency-Key']).not.toBe(firstHeaders['Idempotency-Key'])
  })

  it('prevents duplicate submission while the request result is pending', async () => {
    let resolveRequest!: (response: Response) => void
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockReturnValue(
      new Promise((resolve) => { resolveRequest = resolve }),
    )
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])

    await user.type(screen.getByLabelText('用户名'), 'jason')
    const submit = screen.getByRole('button', { name: '发送重置指引' })
    await user.click(submit)
    await waitFor(() => expect(submit).toBeDisabled())
    await user.click(submit)
    expect(fetchSpy).toHaveBeenCalledTimes(1)

    resolveRequest(acceptedResponse())
    expect(await screen.findByText('如账号可用，重置指引将发送至已绑定联系方式')).toBeInTheDocument()
  })

  it('localizes stable errors and never renders a raw service message', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      error: {
        code: 'account_recovery_rate_limited',
        message: 'subject digest exceeded secret threshold',
        request_id: 'request-recovery-1',
      },
    }), { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '900' } }))
    const user = userEvent.setup()
    renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])

    await user.type(screen.getByLabelText('用户名'), 'jason')
    await user.click(screen.getByRole('button', { name: '发送重置指引' }))

    expect(await screen.findByText('请求过于频繁，请稍后重试')).toBeInTheDocument()
    expect(screen.queryByText(/subject digest|secret threshold/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '发送重置指引' })).toBeDisabled()
  })

  it('renders complete English and pseudo-locale controls', async () => {
    await i18n.changeLanguage('en-US')
    const view = renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])
    expect(screen.getByRole('button', { name: 'Send reset instructions' })).toBeInTheDocument()

    view.unmount()
    await i18n.changeLanguage('qps-ploc')
    renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])
    expect(screen.getByRole('button', {
      name: i18n.t('auth:recovery.sendInstructions'),
    })).toBeInTheDocument()
  })

  it('keeps the request control reachable at a 390px viewport', () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    window.dispatchEvent(new Event('resize'))

    const view = renderWithProviders(<AccountRecoveryRequestPage />, ['/forgot-password'])
    expect(view.container.querySelector('.recovery-container')).toBeInTheDocument()
    expect(screen.getByLabelText('用户名')).toBeEnabled()
    expect(screen.getByRole('button', { name: '发送重置指引' })).toBeEnabled()
  })
})
