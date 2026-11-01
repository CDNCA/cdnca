import { act, render, screen, waitFor } from '@testing-library/react'
import { App } from 'antd'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { useEffect } from 'react'
import { describe, expect, it } from 'vitest'

import { CdncaProvider, useApp } from './index'

type Api = ReturnType<typeof App.useApp>

// antd confirm renders the title twice (aria title + visible); match the visible one.
const title = { selector: '.ant-modal-confirm-title' }

function Grab({ onApi }: { onApi: (api: Api) => void }) {
  const api = App.useApp()
  useEffect(() => onApi(api), [api, onApi])
  return null
}

function mount(look?: 'console') {
  let api!: Api
  const view = render(<CdncaProvider look={look}><Grab onApi={(a) => { api = a }} /><span>page</span></CdncaProvider>)
  return { view, api: () => api }
}

describe('CdncaApp (antd App without modal code in the first load)', () => {
  it('keeps the antd App root: classes and App.useApp() of antd and @cdnca/ui are the same value', () => {
    let ours: Api | undefined
    function Ours() { ours = useApp(); return null }
    let api!: Api
    const { container } = render(<CdncaProvider look="console"><Grab onApi={(a) => { api = a }} /><Ours /></CdncaProvider>)
    const root = container.firstElementChild as HTMLElement
    expect(root.classList.contains('ant-app')).toBe(true)
    expect(root.classList.contains('cdnca-app')).toBe(true)
    expect(root.classList.contains('cdnca-console')).toBe(true)
    expect(ours).toBe(api)
    expect(typeof api.message.success).toBe('function')
    expect(typeof api.notification.open).toBe('function')
  })

  it('modal.confirm before the modal code is loaded opens the dialog and resolves then() with the choice', async () => {
    const { api } = mount()
    let handle!: ReturnType<Api['modal']['confirm']>
    act(() => { handle = api().modal.confirm({ title: 'Delete it?', okText: 'Yes' }) })
    const result = handle.then((ok) => ok, () => undefined)
    expect(await screen.findByText('Delete it?', title)).toBeInTheDocument()
    act(() => { screen.getByRole('button', { name: 'Yes' }).click() })
    await expect(result).resolves.toBe(true)
  })

  it('update() and destroy() called right after open wait for the real dialog', async () => {
    const { api } = mount()
    let handle!: ReturnType<Api['modal']['confirm']>
    act(() => {
      handle = api().modal.confirm({ title: 'First' })
      handle.update({ title: 'Second' })
    })
    expect(await screen.findByText('Second', title)).toBeInTheDocument()
    act(() => handle.destroy())
    await waitFor(() => expect(screen.queryByText('Second', title)).not.toBeInTheDocument())
  })

  it('calls after the first one open at once (no extra load)', async () => {
    const { api } = mount()
    act(() => { api().modal.info({ title: 'One' }) })
    expect(await screen.findByText('One', title)).toBeInTheDocument()
    act(() => { api().modal.warning({ title: 'Two' }) })
    expect(screen.getByText('Two', title)).toBeInTheDocument()
  })

  it('index.tsx no longer renders antd App (its useModal pulled Modal/rc-field-form into every entry)', () => {
    const source = readFileSync(join(__dirname, 'index.tsx'), 'utf8')
    expect(source).not.toMatch(/import \{[^}]*\bApp\b[^}]*\} from 'antd'/)
    expect(readFileSync(join(__dirname, 'app.tsx'), 'utf8')).not.toMatch(/from 'antd\/es\/modal'|import Modal/)
  })
})
