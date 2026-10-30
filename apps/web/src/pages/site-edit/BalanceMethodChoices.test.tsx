import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import i18n from '../../i18n'
import BalanceMethodChoices from './BalanceMethodChoices'

const t = i18n.getFixedT('zh-CN', 'sites')
const methods = ['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random', 'hash', 'sticky'] as const

describe('BalanceMethodChoices (fix-lbtags)', () => {
  it('shows every method as a card with its use case and full explanation', () => {
    render(<BalanceMethodChoices value="round_robin" onChange={() => undefined} />)
    const group = screen.getByRole('radiogroup', { name: '源站负载方式' })
    expect(within(group).queryByRole('combobox')).not.toBeInTheDocument()
    for (const method of methods) {
      const radio = within(group).getByRole('radio', { name: t(`edit.basic.balanceChoice.${method}.name`) })
      expect(radio).toHaveAccessibleDescription(
        `${t(`edit.basic.balanceChoice.${method}.short`)} ${t(`edit.basic.balanceChoice.${method}.detail`)}`,
      )
    }
    expect(screen.getByRole('radio', { name: '轮询' })).toBeChecked()
  })

  it('selects by click and opens the explanation on hover', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<BalanceMethodChoices value="round_robin" onChange={onChange} />)
    await user.click(screen.getByRole('radio', { name: 'IP 哈希' }))
    expect(onChange).toHaveBeenCalledWith('ip_hash')
    await user.hover(screen.getByText(t('edit.basic.balanceChoice.url_hash.short')))
    const detail = t('edit.basic.balanceChoice.url_hash.detail')
    await waitFor(() => expect(screen.getAllByRole('tooltip').some((tip) => tip.textContent?.includes(detail))).toBe(true))
  })

  it('disables every card when read only', () => {
    render(<BalanceMethodChoices value="sticky" disabled onChange={() => undefined} />)
    for (const radio of screen.getAllByRole('radio')) expect(radio).toBeDisabled()
  })
})
