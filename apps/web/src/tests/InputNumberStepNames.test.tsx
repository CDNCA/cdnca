import { act, screen, waitFor } from '@testing-library/react'
import { Form, InputNumber, Modal } from 'antd'
import { useState } from 'react'
import { afterEach, describe, expect, it } from 'vitest'

import { InputNumberStepNames } from '../components/InputNumberStepNames'
import i18n from '../i18n'
import { renderWithProviders } from '../test/render'

// （开通套餐弹窗）：四组增减按钮都叫 Increase Value / Decrease Value。
function Fields({ later }: { later?: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Form>
        <Form.Item label="网站上限" name="sites"><InputNumber /></Form.Item>
        <Form.Item label="节点上限" name="nodes"><InputNumber /></Form.Item>
      </Form>
      <InputNumber aria-label="TCP 流量系数分子" />
      <InputNumber />
      {later ? <button type="button" onClick={() => setOpen(true)}>打开</button> : null}
      <Modal open={open} title="开通"><Form><Form.Item label="TCP 流量系数分母" name="denominator"><InputNumber /></Form.Item></Form></Modal>
    </>
  )
}

// AdvancedSiteTab 状态码 ↔ 状态码范围：同一个字段原位换标签（aria-label 或 Form.Item label）。
function Renamed() {
  const [range, setRange] = useState(false)
  return (
    <>
      <InputNumber aria-label={range ? '起始状态码' : '状态码'} />
      <Form><Form.Item label={range ? '结束状态码' : '目标状态码'} name="end"><InputNumber /></Form.Item></Form>
      <button type="button" onClick={() => setRange((value) => !value)}>切换</button>
    </>
  )
}

afterEach(async () => { await i18n.changeLanguage('zh-CN') })

describe('number field step buttons', () => {
  it('name each field in Chinese, including fields mounted later and in a modal', async () => {
    renderWithProviders(<><InputNumberStepNames /><Fields later /></>)
    for (const name of ['网站上限', '节点上限', 'TCP 流量系数分子']) {
      expect(await screen.findByRole('button', { name: `增加 ${name}`, hidden: true })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: `减少 ${name}`, hidden: true })).toBeInTheDocument()
    }
    expect(screen.getByRole('button', { name: '增加数值', hidden: true })).toBeInTheDocument()
    act(() => screen.getByRole('button', { name: '打开' }).click())
    expect(await screen.findByRole('button', { name: '增加 TCP 流量系数分母', hidden: true })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Increase Value|Decrease Value/, hidden: true })).toBeNull()
  })

  it('renames the buttons when the same field is relabelled in place, both ways', async () => {
    renderWithProviders(<><InputNumberStepNames /><Renamed /></>)
    expect(await screen.findByRole('button', { name: '增加 状态码', hidden: true })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '增加 目标状态码', hidden: true })).toBeInTheDocument()
    act(() => screen.getByRole('button', { name: '切换' }).click())
    await waitFor(() => expect(screen.getByRole('button', { name: '增加 起始状态码', hidden: true })).toBeInTheDocument())
    expect(screen.getByRole('button', { name: '减少 起始状态码', hidden: true })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: '增加 结束状态码', hidden: true })).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /^(增加|减少) (状态码|目标状态码)$/, hidden: true })).toBeNull()
    act(() => screen.getByRole('button', { name: '切换' }).click())
    await waitFor(() => expect(screen.getByRole('button', { name: '增加 状态码', hidden: true })).toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole('button', { name: '减少 目标状态码', hidden: true })).toBeInTheDocument())
  })

  it('follows the language', async () => {
    renderWithProviders(<><InputNumberStepNames /><Fields /></>)
    await screen.findByRole('button', { name: '增加 网站上限', hidden: true })
    await act(async () => { await i18n.changeLanguage('en-US') })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Increase 网站上限', hidden: true })).toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Decrease value', hidden: true })).toBeInTheDocument()
  })
})
