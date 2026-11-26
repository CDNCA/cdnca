import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import BalanceMethodChoices from './BalanceMethodChoices'

const t = i18n.getFixedT('zh-CN', 'sites')
const methods = ['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random', 'hash', 'sticky'] as const
const option = (title: string) => screen.getAllByTitle(title).find((node) => node.classList.contains('ant-select-item-option'))!

// 负载方式是一个紧凑下拉，不再平铺七张卡片和长说明。
describe('BalanceMethodChoices', () => {
  it('is one select named 源站负载方式 showing the chosen method, without the seven cards', () => {
    render(<BalanceMethodChoices value="round_robin" onChange={() => undefined} />)
    const select = screen.getByRole('combobox', { name: '源站负载方式' })
    expect(select).toBeInTheDocument()
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument()
    expect(screen.queryAllByRole('radio')).toHaveLength(0)
    expect(screen.getByTitle('轮询')).toBeInTheDocument()
    for (const method of methods) expect(screen.queryByText(t(`edit.basic.balanceChoice.${method}.detail`))).not.toBeInTheDocument()
  })

  it('lists every method with its one-line use case and picks one by mouse', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<BalanceMethodChoices value="round_robin" onChange={onChange} />)
    await user.click(screen.getByRole('combobox', { name: '源站负载方式' }))
    for (const method of methods) {
      const item = option(t(`edit.basic.balanceChoice.${method}.name`))
      expect(item).toHaveTextContent(t(`edit.basic.balanceChoice.${method}.short`))
    }
    await user.click(option('IP 哈希'))
    expect(onChange).toHaveBeenLastCalledWith('ip_hash', expect.anything())
  })

  it('is reachable and changed by keyboard', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<BalanceMethodChoices value="round_robin" onChange={onChange} />)
    await user.tab()
    expect(screen.getByRole('combobox', { name: '源站负载方式' })).toHaveFocus()
    // rc-select 打开靠 key，选中靠 which；user-event 不带 which（同 PackageSoldTenantTools 的写法）。
    await user.keyboard('{Enter}')
    const combobox = screen.getByRole('combobox', { name: '源站负载方式' })
    fireEvent.keyDown(combobox, { key: 'ArrowDown', keyCode: 40, which: 40 })
    fireEvent.keyDown(combobox, { key: 'Enter', keyCode: 13, which: 13 })
    await waitFor(() => expect(onChange).toHaveBeenCalledTimes(1))
    expect(onChange.mock.calls[0]?.[0]).toBe('ip_hash')
  })

  it('is disabled when read only', () => {
    render(<BalanceMethodChoices value="sticky" disabled onChange={() => undefined} />)
    expect(screen.getByRole('combobox', { name: '源站负载方式' })).toBeDisabled()
  })
})
