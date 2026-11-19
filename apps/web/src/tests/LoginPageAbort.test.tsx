import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App, ConfigProvider } from 'antd'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { LoginPage } from '../pages/LoginPage'
import { authResponse, principal } from '../test/fixtures'

// The console showed "Uncaught (in promise) AbortError:
// signal is aborted without reason" with the stack at the unmount cleanup's
// loginAttempt abort. Leaving the page with a sign-in in flight must leave no
// unhandled rejection, abort with a reason of its own, and that reason must
// not be reported when a fetch wrapper outside the app (an extension chaining
// .then() on window.fetch) leaves its copy of the rejection unhandled.
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })

// As a browser fetch: pending until answered or aborted (rejects with the signal's reason).
function pendingFetch(signals: AbortSignal[]) {
  return (_input: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
    const signal = init?.signal as AbortSignal
    signals.push(signal)
    signal.addEventListener('abort', () => reject(signal.reason), { once: true })
  })
}

function setup() {
  const view = render(<ConfigProvider button={{ autoInsertSpace: false }}><App><MemoryRouter initialEntries={['/login']}><Routes>
    <Route path="/login" element={<LoginPage />} /><Route path="/home" element={<div>signed in</div>} />
  </Routes></MemoryRouter></App></ConfigProvider>)
  return { ...view, user: userEvent.setup() }
}

it.each(['login', 'me'])('leaving the page while %s is in flight aborts with its own reason and leaves no unhandled rejection', async (stage) => {
  const unhandled: unknown[] = []
  const record = (reason: unknown) => { unhandled.push(reason) }
  process.on('unhandledRejection', record)
  try {
    const signals: AbortSignal[] = []
    const spy = vi.spyOn(globalThis, 'fetch')
    if (stage === 'me') spy.mockResolvedValueOnce(json(authResponse(principal())))
    spy.mockImplementationOnce(pendingFetch(signals))
    const { user, unmount } = setup()
    await user.type(screen.getByLabelText('用户名、手机或邮箱'), 'jason')
    await user.type(screen.getByLabelText('密码'), 'secret-password')
    await user.click(screen.getByRole('button', { name: '登录' }))
    await waitFor(() => expect(signals).toHaveLength(1))
    act(() => unmount())
    await new Promise(resolve => setTimeout(resolve, 20))
    const reason = signals[0].reason as DOMException
    expect(signals[0].aborted).toBe(true)
    expect(reason).toBeInstanceOf(DOMException)
    expect(reason.name).toBe('AbortError')
    expect(reason.message).toBe('Login page request abandoned')
    expect(unhandled).toEqual([])
    // what a browser reports for an outside wrapper's unhandled copy: prevented
    const event = Object.assign(new Event('unhandledrejection', { cancelable: true }), { reason })
    window.dispatchEvent(event)
    expect(event.defaultPrevented).toBe(true)
    const other = Object.assign(new Event('unhandledrejection', { cancelable: true }), { reason: new DOMException('x', 'AbortError') })
    window.dispatchEvent(other)
    expect(other.defaultPrevented).toBe(false)
  } finally {
    process.off('unhandledRejection', record)
  }
})
