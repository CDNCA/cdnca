import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from 'antd'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import { renderWithProviders } from '../test/render'
import CnameLabelEditor, { cnameLabelPreview } from './CnameLabelEditor'

type Call = { method: string; url: string; body: unknown; key: string | null }

function mockApi(handler: (call: Call) => Response) {
  const calls: Call[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const headers = new Headers(init?.headers)
    const call = { method: init?.method ?? 'GET', url: String(input), body: init?.body ? JSON.parse(String(init.body)) : undefined, key: headers.get('Idempotency-Key') }
    calls.push(call)
    return handler(call)
  })
  return calls
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const refusal = (status: number, code: string) => json({ error: { code, message: 'raw server text', request_id: 'req-1' } }, status)

function renderEditor(props: Partial<React.ComponentProps<typeof CnameLabelEditor>> = {}) {
  return renderWithProviders(<App><CnameLabelEditor kind="site" subjectID="site-1" mode="full" domain="cdn86.com" {...props} /></App>)
}

beforeEach(async () => {
  await i18n.changeLanguage('zh-CN')
  useSessionStore.setState({ accessToken: 'access-token', sessionEpoch: 1, status: 'authenticated' } as never)
})
afterEach(() => { vi.restoreAllMocks() })

describe('cnameLabelPreview', () => {
  it('shows host.domain for a full name and prefix-xxxxxxxx.domain for a prefix', () => {
    expect(cnameLabelPreview('full', ' Shop ', 'cdn86.com')).toBe('shop.cdn86.com')
    expect(cnameLabelPreview('prefix', 'gd', 'cdn86.com')).toBe('gd-xxxxxxxx.cdn86.com')
    expect(cnameLabelPreview('full', '', 'cdn86.com')).toBe('')
    expect(cnameLabelPreview('full', 'shop', '')).toBe('shop')
  })
})

describe('CnameLabelEditor', () => {
  it('previews the full hostname live and saves it with an idempotency key', async () => {
    const calls = mockApi((call) => call.method === 'GET' ? json({ label: '' }) : json({ label: 'shop' }))
    const onSaved = vi.fn()
    const user = userEvent.setup({ delay: null })
    renderEditor({ onSaved })

    const input = await screen.findByRole('textbox', { name: '主机名' })
    await waitFor(() => expect(input).toBeEnabled())
    await user.type(input, 'Shop')
    expect(screen.getByTestId('cname-label-preview')).toHaveTextContent('shop.cdn86.com')
    await user.click(screen.getByRole('button', { name: '保存主机名' }))

    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    const put = calls.find((call) => call.method === 'PUT')!
    expect(put.url).toContain('/v1/admin/cname-labels/site/site-1')
    expect(put.body).toEqual({ label: 'shop' })
    expect(put.key).toMatch(/^cname-label-/)
  })

  it('blocks an invalid name before any request and explains how to fix it', async () => {
    const calls = mockApi(() => json({ label: '' }))
    const user = userEvent.setup({ delay: null })
    renderEditor()

    const input = await screen.findByRole('textbox', { name: '主机名' })
    await waitFor(() => expect(input).toBeEnabled())
    await user.type(input, 'a_b')
    expect(screen.getByRole('alert')).toHaveTextContent('只能用小写字母、数字和连字符')
    expect(screen.getByRole('button', { name: '保存主机名' })).toBeDisabled()
    expect(screen.queryByTestId('cname-label-preview')).toBeNull()
    expect(calls.filter((call) => call.method === 'PUT')).toHaveLength(0)
  })

  it.each([
    ['cname_label_taken', 409, '已被其他网站使用'],
    ['cname_label_reserved', 400, '系统保留名'],
  ])('shows a readable reason for %s and never the server text', async (code, status, text) => {
    mockApi((call) => call.method === 'GET' ? json({ label: '' }) : refusal(status, code))
    const user = userEvent.setup({ delay: null })
    renderEditor()

    const input = await screen.findByRole('textbox', { name: '主机名' })
    await waitFor(() => expect(input).toBeEnabled())
    await user.type(input, 'brand')
    await user.click(screen.getByRole('button', { name: '保存主机名' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(text)
    expect(alert).not.toHaveTextContent('raw server text')
  })

  it('shows the English reasons', async () => {
    await i18n.changeLanguage('en-US')
    mockApi((call) => call.method === 'GET' ? json({ label: '' }) : refusal(409, 'cname_label_taken'))
    const user = userEvent.setup({ delay: null })
    renderEditor()

    const input = await screen.findByRole('textbox', { name: 'Hostname' })
    await waitFor(() => expect(input).toBeEnabled())
    await user.type(input, 'brand')
    await user.click(screen.getByRole('button', { name: 'Save hostname' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('already used by another site')
  })

  it('previews a prefix and asks how many sites are affected before regenerating', async () => {
    const calls = mockApi((call) => {
      if (call.method === 'GET' && call.url.endsWith('/affected')) return json({ sites: 3 })
      if (call.method === 'POST') return json({ sites: 3 })
      return json({ label: 'gd' })
    })
    const user = userEvent.setup({ delay: null })
    renderEditor({ kind: 'line-group', mode: 'prefix' })

    await waitFor(() => expect(screen.getByTestId('cname-label-preview')).toHaveTextContent('gd-xxxxxxxx.cdn86.com'))
    await user.click(screen.getByRole('button', { name: '按新前缀重新生成' }))
    expect(await screen.findByText(/将重新生成 3 个网站的 CNAME/)).toBeInTheDocument()
    expect(calls.some((call) => call.method === 'POST')).toBe(false)

    await user.click(screen.getByRole('button', { name: '确认重新生成' }))
    await waitFor(() => expect(calls.some((call) => call.method === 'POST' && call.url.endsWith('/regenerate') && call.key?.startsWith('cname-label-'))).toBe(true))
  })

  it('does not offer to regenerate when no site is affected', async () => {
    mockApi((call) => call.url.endsWith('/affected') ? json({ sites: 0 }) : json({ label: 'gd' }))
    const user = userEvent.setup({ delay: null })
    renderEditor({ kind: 'line-group', mode: 'prefix' })

    await waitFor(() => expect(screen.getByRole('button', { name: '按新前缀重新生成' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '按新前缀重新生成' }))
    expect(await screen.findByText('没有需要按新前缀重新生成的网站。')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '确认重新生成' })).toBeDisabled()
  })
})
