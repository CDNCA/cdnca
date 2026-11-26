import { fireEvent, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'

import { renderWithProviders } from '../test/render'
import SearchSelect from './SearchSelect'

// 键入一串字符只在停顿后查一次，结果按最终词显示。
function Picker({ search }: { search: (text: string, signal: AbortSignal) => Promise<{ id: string; name: string }[]> }) {
  const [value, setValue] = useState<string[] | string>([])
  return <SearchSelect mode="multiple" ariaLabel="节点" queryKey={['picker-test']} search={search} value={value} onChange={setValue} />
}

describe('SearchSelect', () => {
  it('queries once for a quickly typed term and shows that result', async () => {
    const search = vi.fn(async (text: string) => [{ id: `node-${text}`, name: `节点 ${text}` }])
    renderWithProviders(<Picker search={search} />)
    const input = screen.getByRole('combobox', { name: '节点' })
    fireEvent.mouseDown(input)
    let typed = ''
    for (const char of '203.0.113.30') {
      typed += char
      fireEvent.change(input, { target: { value: typed } })
    }
    await waitFor(() => expect(search).toHaveBeenCalledTimes(1))
    expect(search.mock.calls[0]?.[0]).toBe('203.0.113.30')
    expect(await screen.findByText(/^节点 203.0.113.30（/)).toBeInTheDocument()
    await new Promise((resolve) => setTimeout(resolve, 400))
    expect(search).toHaveBeenCalledTimes(1)
  })

  it('still finds a short numeric ID after a pause', async () => {
    const search = vi.fn(async (text: string) => [{ id: `node-${text}`, name: `节点 ${text}` }])
    renderWithProviders(<Picker search={search} />)
    const input = screen.getByRole('combobox', { name: '节点' })
    fireEvent.mouseDown(input)
    fireEvent.change(input, { target: { value: '1' } })
    await waitFor(() => expect(search).toHaveBeenCalledWith('1', expect.anything()))
    expect(await screen.findByText(/^节点 1（/)).toBeInTheDocument()
  })

  // 硬刷新后已保存的 ID 按 ID 读回名称；读取期间不把 UUID 当标签，查不到的标“已删除”。
  it('names saved IDs through resolve and marks the ones not found', async () => {
    let finish: (options: { id: string; name: string; code: string }[]) => void = () => undefined
    const resolve = vi.fn<(ids: string[]) => Promise<{ id: string; name: string; code: string }[]>>(() => new Promise((done) => { finish = done }))
    const search = vi.fn(async () => [])
    renderWithProviders(<SearchSelect mode="multiple" ariaLabel="节点" queryKey={['picker-resolve']} search={search}
      value={['node-a', 'node-gone']} onChange={() => undefined} resolve={resolve}
      resolvingLabel="读取中…" missingLabel={(id) => `已删除：${id}`} />)
    expect(await screen.findAllByText('读取中…')).toHaveLength(2)
    expect(screen.queryByText('node-a')).not.toBeInTheDocument()
    expect(resolve).toHaveBeenCalledWith(['node-a', 'node-gone'], expect.anything())
    finish([{ id: 'node-a', name: '香港 1', code: '7' }])
    expect(await screen.findByText('香港 1（7）')).toBeInTheDocument()
    expect(screen.getByText('已删除：node-gone')).toBeInTheDocument()
    expect(resolve).toHaveBeenCalledTimes(1)
    expect(search).not.toHaveBeenCalled()
  })

  it('keeps showing a saved ID as is without resolve', async () => {
    renderWithProviders(<SearchSelect mode="multiple" ariaLabel="节点" queryKey={['picker-plain']} search={async () => []}
      value={['node-a']} onChange={() => undefined} />)
    expect(await screen.findByText('node-a')).toBeInTheDocument()
  })
})
