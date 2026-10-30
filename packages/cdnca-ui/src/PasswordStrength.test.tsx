import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { Input } from 'antd'

import { PasswordStrengthPanel, PasswordStrengthPopover } from './PasswordStrength'
import { passwordStrength } from './passwordPolicy'

describe('passwordStrength', () => {
  it.each([
    ['', 'weak'], ['abcdefgh', 'weak'], ['abcd 1234', 'weak'],
    ['abcd1234', 'medium'], ['Abcd1234', 'medium'], ['abcdefgh12345', 'medium'],
    ['Abcdefgh1234', 'strong'], ['abcdefgh12!@', 'strong'],
  ])('%s → %s', (password, level) => {
    expect(passwordStrength(password)).toBe(level)
  })
})

describe('PasswordStrengthPanel', () => {
  it('shows level, bar and rule states', () => {
    render(<PasswordStrengthPanel value="abc" />)
    expect(screen.getByText('弱')).toBeInTheDocument()
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '1')
    expect(screen.getByText('请至少输入 8 个字符。').closest('li')).toHaveClass('is-unmet')
    expect(screen.getByText('请不要使用容易被猜到的密码。')).toBeInTheDocument()
  })

  it('English', () => {
    render(<PasswordStrengthPanel value="Abcdefgh1234" locale="en-US" />)
    expect(screen.getByText('Strong')).toBeInTheDocument()
    expect(screen.getByText('Enter at least 8 characters.').closest('li')).toHaveClass('is-met')
  })
})

describe('PasswordStrengthPopover', () => {
  function Field() {
    const [value, setValue] = useState('')
    return <PasswordStrengthPopover value={value}>
      <Input.Password aria-label="密码" onChange={(event) => setValue(event.target.value)} />
    </PasswordStrengthPopover>
  }

  it('opens under the field on focus, follows typing and closes on blur', async () => {
    render(<Field />)
    const input = screen.getByLabelText('密码')
    expect(screen.queryByText('强度：')).not.toBeInTheDocument()
    await act(async () => { fireEvent.focus(input) })
    expect(await screen.findByText('弱')).toBeInTheDocument()
    expect(input.getAttribute('aria-describedby')).toBeTruthy()
    await act(async () => { fireEvent.change(input, { target: { value: 'Abcdefgh1234' } }) })
    expect(await screen.findByText('强')).toBeInTheDocument()
    await act(async () => { fireEvent.blur(input) })
    await waitFor(() => expect(document.querySelector('.cdnca-password-strength-popover:not(.ant-popover-hidden)')).toBeNull())
  })
})
