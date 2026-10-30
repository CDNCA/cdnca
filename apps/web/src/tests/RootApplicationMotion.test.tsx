import { StrictMode, useState } from 'react'
import { act, fireEvent, render, screen, within } from '@testing-library/react'
import { Input, Modal, Select, theme } from 'antd'
import { vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { RootApplication } from '../main'

vi.mock('react-dom/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('react-dom/client')>()
  return {
    ...original,
    createRoot: (container: Element | DocumentFragment) => container
      ? original.createRoot(container)
      : { render: vi.fn() },
  }
})

vi.mock('../App', () => ({
  AppRoutes: function MotionControls() {
    const { token } = theme.useToken()
    const [group, setGroup] = useState<string>()
    const [editing, setEditing] = useState(false)
    const [draft, setDraft] = useState('')
    const [editorGroup, setEditorGroup] = useState<string>()
    return <>
      <output aria-label="组件动效">{String(token.motion)}</output>
      <Select aria-label="筛选用户组" value={group} onChange={setGroup} options={[{ value: 'group-a', label: '验收用户组' }]} />
      <output aria-label="已选用户组">{group ?? ''}</output>
      <button onClick={() => setEditing(true)}>打开编辑</button>
      <Modal title="动效验收编辑" open={editing} onCancel={() => setEditing(false)} footer={null}>
        <Input aria-label="未保存备注" value={draft} onChange={(event) => setDraft(event.target.value)} />
        <Select aria-label="编辑用户组" value={editorGroup} onChange={setEditorGroup} options={[
          { value: 'group-a', label: '编辑组甲' }, { value: 'group-b', label: '编辑组乙' },
        ]} />
        <output aria-label="编辑已选用户组">{editorGroup ?? ''}</output>
      </Modal>
    </>
  },
}))

function mockMotionPreference(reduced: boolean) {
  const media = Object.assign(new EventTarget(), {
    matches: reduced,
    media: '(prefers-reduced-motion: reduce)',
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
  }) satisfies MediaQueryList
  const originalMatchMedia = window.matchMedia.bind(window)
  vi.spyOn(window, 'matchMedia').mockImplementation((query) => query === media.media ? media : originalMatchMedia(query))
  const add = vi.spyOn(media, 'addEventListener')
  const remove = vi.spyOn(media, 'removeEventListener')
  return {
    add,
    remove,
    change(reducedMotion: boolean) {
      media.matches = reducedMotion
      media.dispatchEvent(new Event('change'))
    },
  }
}

async function selectGroup() {
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '筛选用户组' }))
  fireEvent.click(await screen.findByText('验收用户组', { selector: '.ant-select-item-option-content' }))
  expect(screen.getByLabelText('已选用户组')).toHaveTextContent('group-a')
}

describe('RootApplication motion preference', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/dashboard/')
    useSessionStore.getState().clearSession()
  })

  it.each([false, true])('uses native Ant Design motion for reduced=%s and permits selecting a group', async (reduced) => {
    mockMotionPreference(reduced)
    render(<RootApplication />)

    expect(screen.getByLabelText('组件动效')).toHaveTextContent(String(!reduced))
    await selectGroup()
  })

  it('follows system preference changes and removes each subscription in StrictMode', async () => {
    const preference = mockMotionPreference(false)
    const { unmount } = render(<StrictMode><RootApplication /></StrictMode>)
    expect(screen.getByLabelText('组件动效')).toHaveTextContent('true')
    await selectGroup()
    fireEvent.click(screen.getByRole('button', { name: '打开编辑' }))
    const modal = await screen.findByRole('dialog')
    const draft = within(modal).getByRole('textbox', { name: '未保存备注' })
    fireEvent.change(draft, { target: { value: '未保存的草稿' } })

    act(() => preference.change(true))
    expect(screen.getByLabelText('组件动效')).toHaveTextContent('false')
    expect(screen.getByLabelText('已选用户组')).toHaveTextContent('group-a')
    expect(screen.getByRole('dialog')).toBe(modal)
    expect(within(modal).getByRole('textbox', { name: '未保存备注' })).toBe(draft)
    expect(draft).toHaveValue('未保存的草稿')
    fireEvent.mouseDown(within(modal).getByRole('combobox', { name: '编辑用户组' }))
    fireEvent.click(await screen.findByText('编辑组乙', { selector: '.ant-select-item-option-content' }))
    expect(within(modal).getByLabelText('编辑已选用户组')).toHaveTextContent('group-b')

    act(() => preference.change(false))
    expect(screen.getByLabelText('组件动效')).toHaveTextContent('true')
    expect(screen.getByLabelText('已选用户组')).toHaveTextContent('group-a')
    expect(screen.getByRole('dialog')).toBe(modal)
    expect(draft).toHaveValue('未保存的草稿')
    fireEvent.mouseDown(within(modal).getByRole('combobox', { name: '编辑用户组' }))
    fireEvent.click(await screen.findByText('编辑组甲', { selector: '.ant-select-item-option-content' }))
    expect(within(modal).getByLabelText('编辑已选用户组')).toHaveTextContent('group-a')
    expect(draft).toHaveValue('未保存的草稿')

    unmount()
    expect(preference.add).toHaveBeenCalled()
    expect(preference.remove.mock.calls).toEqual(preference.add.mock.calls)
  })
})
