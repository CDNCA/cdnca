import { act, fireEvent, render, screen } from '@testing-library/react'
import { Button, DatePicker, Form, Input, Table } from 'antd'
import { vi } from 'vitest'

import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
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
  AppRoutes: () => <>
    <DatePicker />
    <Table dataSource={[]} pagination={false} />
    <Form>
      <Form.Item name="email" label="被邀请人邮箱" rules={[{ type: 'email' }]}><Input /></Form.Item>
      <Button htmlType="submit">提交</Button>
    </Form>
  </>,
}))

describe('RootApplication locale', () => {
  it('updates built-in date and empty-table text when switching among the supported languages', async () => {
    window.history.replaceState(null, '', '/dashboard/')
    useSessionStore.getState().clearSession()
    await changeLocale('zh-CN')
    render(<RootApplication />)

    expect(screen.getByPlaceholderText('请选择日期')).toBeInTheDocument()
    expect(screen.getByText('暂无数据', { selector: '.ant-empty-description' })).toBeInTheDocument()

    await act(() => changeLocale('zh-TW'))
    expect(screen.getByPlaceholderText('請選擇日期')).toBeInTheDocument()
    expect(screen.getByText('無此資料', { selector: '.ant-empty-description' })).toBeInTheDocument()

    await act(() => changeLocale('en-US'))
    expect(screen.getByPlaceholderText('Select date')).toBeInTheDocument()
    expect(screen.getByText('No data', { selector: '.ant-empty-description' })).toBeInTheDocument()

    await act(() => changeLocale('zh-CN'))
    expect(screen.getByPlaceholderText('请选择日期')).toBeInTheDocument()
    expect(screen.getByText('暂无数据', { selector: '.ant-empty-description' })).toBeInTheDocument()
  })

  it('gives antd type-rule messages a localized type name instead of the raw rule type (W5)', async () => {
    window.history.replaceState(null, '', '/dashboard/')
    useSessionStore.getState().clearSession()
    await changeLocale('zh-CN')
    render(<RootApplication />)

    fireEvent.change(screen.getByLabelText('被邀请人邮箱'), { target: { value: 'not-an-email' } })
    fireEvent.click(screen.getByRole('button', { name: '提交' }))
    expect(await screen.findByText('被邀请人邮箱不是一个有效的邮箱地址')).toBeInTheDocument()
    expect(screen.queryByText(/email/)).not.toBeInTheDocument()

    await act(() => changeLocale('zh-TW'))
    fireEvent.click(screen.getByRole('button', { name: '提交' }))
    expect(await screen.findByText('被邀请人邮箱不是一個有效的電子郵件地址')).toBeInTheDocument()

    await act(() => changeLocale('en-US'))
    fireEvent.click(screen.getByRole('button', { name: '提交' }))
    expect(await screen.findByText('被邀请人邮箱 is not a valid email')).toBeInTheDocument()
    await act(() => changeLocale('zh-CN'))
  })
})
