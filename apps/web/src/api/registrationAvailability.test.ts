import { vi } from 'vitest'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

describe('registrationAvailable', () => {
  it('follows registration_enabled and treats failures as closed', async () => {
    const { registrationAvailable } = await vi.importActual<typeof import('./registrationAvailability')>('./registrationAvailability')
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    fetchSpy.mockResolvedValueOnce(json({ data: { registration_enabled: true } }))
    await expect(registrationAvailable()).resolves.toBe(true)
    expect(String(fetchSpy.mock.calls[0][0])).toMatch(/\/v1\/auth\/login-methods$/)
    fetchSpy.mockResolvedValueOnce(json({ data: { registration_enabled: false } }))
    await expect(registrationAvailable()).resolves.toBe(false)
    fetchSpy.mockResolvedValueOnce(json({ data: {} }))
    await expect(registrationAvailable()).resolves.toBe(false)
    fetchSpy.mockResolvedValueOnce(json({ error: { code: 'account_login_unavailable' } }, 503))
    await expect(registrationAvailable()).resolves.toBe(false)
    fetchSpy.mockRejectedValueOnce(new TypeError('offline'))
    await expect(registrationAvailable()).resolves.toBe(false)
  })
})
