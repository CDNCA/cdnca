import { act, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { PluginUIPage } from '../api/pluginUI'
import { useSessionStore } from '../auth/session'
import { PluginFrame } from '../pluginui/PluginFrame'
import { protocolVersion } from '../pluginui/bridge'
import { principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const page: PluginUIPage = {
  plugin_id: 'acme.reports', plugin_version: '1.0.0', page_id: 'report', origin: 'https://ui.acme.example',
  url: 'https://ui.acme.example/report', mount: 'menu', menu_parent: 'monitor', role: 'admin',
  title: { 'zh-CN': '报表' }, has_api: true,
}

function mount() {
  useSessionStore.setState({ status: 'authenticated', accessToken: 'session-token-secret',
    principal: principal({ scope_kind: 'platform' }) })
  const view = renderWithProviders(<PluginFrame page={page} title="报表" />)
  const frame = view.container.querySelector('iframe') as HTMLIFrameElement
  const nonce = decodeURIComponent(frame.getAttribute('src')?.split('#cdnca-nonce=')[1] ?? '')
  return { view, frame, nonce }
}

// Dispatch a message as if it came from a given window.
function post(source: Window | null, data: unknown, origin = 'null') {
  window.dispatchEvent(new MessageEvent('message', { data, source, origin }))
}

describe('PluginFrame (PA-19)', () => {
  afterEach(() => {
    useSessionStore.setState({ status: 'anonymous', accessToken: null, principal: null })
    vi.restoreAllMocks()
  })

  it('mounts the page sandboxed without allow-same-origin', () => {
    const { frame, nonce } = mount()
    expect(frame.getAttribute('sandbox')).toBe('allow-scripts allow-forms')
    expect(frame.getAttribute('sandbox')).not.toContain('allow-same-origin')
    expect(frame.getAttribute('referrerpolicy')).toBe('no-referrer')
    expect(frame.getAttribute('src')).toBe(`https://ui.acme.example/report#cdnca-nonce=${encodeURIComponent(nonce)}`)
    // The session token never appears in what the frame is given.
    expect(frame.outerHTML).not.toContain('session-token-secret')
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{22}$/)
  })

  it('hands a private port only to its own frame window with the right nonce', async () => {
    const { frame, nonce } = mount()
    const frameWindow = frame.contentWindow as Window
    const delivered = vi.spyOn(frameWindow, 'postMessage')
    // Wrong window (a different frame or the host itself), wrong nonce: ignored.
    act(() => {
      post(window, { protocol: protocolVersion, type: 'cdnca.hello', nonce })
      post(frameWindow, { protocol: protocolVersion, type: 'cdnca.hello', nonce: 'guessed' })
      post(frameWindow, { protocol: protocolVersion, type: 'context.get', nonce })
    })
    expect(delivered).not.toHaveBeenCalled()
    act(() => post(frameWindow, { protocol: protocolVersion, type: 'cdnca.hello', nonce }))
    expect(delivered).toHaveBeenCalledTimes(1)
    const [message, target, transfer] = delivered.mock.calls[0] as unknown as [unknown, string, MessagePort[]]
    expect(message).toEqual({ protocol: protocolVersion, type: 'cdnca.ready', nonce })
    expect(target).toBe('*')
    expect(transfer).toHaveLength(1)

    // Over the port: a whitelisted request is answered, others refused.
    const port = transfer[0]
    const answers: unknown[] = []
    port.onmessage = (event) => answers.push(event.data)
    port.start()
    port.postMessage({ protocol: protocolVersion, nonce, id: 'a', method: 'context.get' })
    port.postMessage({ protocol: protocolVersion, nonce, id: 'b', method: 'session.token' })
    await waitFor(() => expect(answers).toHaveLength(2))
    const byID = Object.fromEntries((answers as { id: string }[]).map((answer) => [answer.id, answer]))
    expect(byID.a).toMatchObject({ ok: true, result: { plugin_id: 'acme.reports', user: { role: 'admin' } } })
    expect(JSON.stringify(byID.a)).not.toContain('session-token-secret')
    expect(byID.b).toMatchObject({ ok: false, error: 'message_not_allowed' })

    // A second hello (e.g. a script replaying it) does not open another port.
    act(() => post(frameWindow, { protocol: protocolVersion, type: 'cdnca.hello', nonce }))
    expect(delivered).toHaveBeenCalledTimes(1)
    port.close()
  })
})
