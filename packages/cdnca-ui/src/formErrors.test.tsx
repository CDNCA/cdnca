import { act, fireEvent, render, screen } from '@testing-library/react'
import { Button, Form, Input, type FormInstance } from 'antd'
import enUS from 'antd/locale/en_US'
import { describe, expect, it, vi } from 'vitest'

import { applyFormSubmitError, CdncaProvider, InlineNotice, submitErrorFields, useFormSubmitError } from './index'

// An ApiError look-alike: every end keeps the refused field on the error object.
const refused = (field: string, reason = '', code = 'validation_error') => Object.assign(new Error(code), { code, field, reason })

function Harness({ onReady, onFail, mapping }: {
  onReady: (form: FormInstance, submit: (error: unknown, fallback?: () => void) => boolean) => void
  onFail?: () => void
  mapping?: Parameters<typeof useFormSubmitError>[1]
}) {
  const [form] = Form.useForm()
  const submit = useFormSubmitError(form, mapping)
  onReady(form, submit)
  return (
    <Form form={form}>
      <Form.Item name="name" label="名称"><Input /></Form.Item>
      <Form.Item name={['origins', 0, 'host']} label="源站"><Input /></Form.Item>
      <Form.Item name="displayName" label="显示名"><Input /></Form.Item>
      <Button onClick={onFail}>提交</Button>
    </Form>
  )
}

function setup(mapping?: Parameters<typeof useFormSubmitError>[1], locale?: typeof enUS) {
  const ref: { form?: FormInstance; submit?: (error: unknown, fallback?: () => void) => boolean } = {}
  render(<CdncaProvider locale={locale}><Harness mapping={mapping} onReady={(form, submit) => { ref.form = form; ref.submit = submit }} /></CdncaProvider>)
  return ref as Required<typeof ref>
}

describe('submitErrorFields', () => {
  it('reads field / reason and field lists of validation errors only', () => {
    expect(submitErrorFields(refused('name', 'too_long'))).toEqual([{ field: 'name', reason: 'too_long' }])
    expect(submitErrorFields(Object.assign(new Error('x'), { code: 'invalid_request', field: 'a.b' }))).toEqual([{ field: 'a.b', reason: '' }])
    expect(submitErrorFields({ code: 'validation_error', fields: [{ field: 'name', reason: 'required' }, 'remark', { field: 'name' }] }))
      .toEqual([{ field: 'name', reason: 'required' }, { field: 'remark', reason: '' }])
    expect(submitErrorFields({ code: 'validation_error', details: { field: 'origins[0].host', reason: 'invalid' } }))
      .toEqual([{ field: 'origins[0].host', reason: 'invalid' }])
    // market-service: {"error":"invalid","field","reason"}.
    expect(submitErrorFields({ code: 'invalid', field: 'name', reason: 'invalid_format' })).toEqual([{ field: 'name', reason: 'invalid_format' }])
    // A resource's own *_invalid_request (node_scheduling_invalid_request) counts too (fix-fielderr-be).
    expect(submitErrorFields({ code: 'node_scheduling_invalid_request', field: 'endpoints[1].port', reason: 'out_of_range' }))
      .toEqual([{ field: 'endpoints[1].port', reason: 'out_of_range' }])
    // Other errors that happen to carry a field are not form errors.
    expect(submitErrorFields({ code: 'version_conflict', field: 'name' })).toEqual([])
    expect(submitErrorFields({ code: 'validation_error', field: 'Bad Field!' })).toEqual([])
    expect(submitErrorFields(null)).toEqual([])
  })
})

describe('useFormSubmitError', () => {
  it('marks the same-named Form.Item with the reason text and scrolls to it', async () => {
    const ref = setup()
    const scroll = vi.spyOn(ref.form, 'scrollToField')
    let marked = false
    await act(async () => { marked = ref.submit(refused('name', 'too_long')) })
    expect(marked).toBe(true)
    expect(await screen.findByText('长度超过上限')).toBeInTheDocument()
    expect(scroll).toHaveBeenCalledWith('name', { block: 'center' })
  })

  it('resolves nested paths (dots and [index]) and a mapping table with page texts', async () => {
    const ref = setup({ display_name: { name: 'displayName', messages: { required: '请填写显示名' } } })
    await act(async () => { ref.submit({ code: 'validation_error', fields: [{ field: 'origins[0].host', reason: 'invalid' }, { field: 'display_name', reason: 'required' }] }) })
    expect(ref.form.getFieldError(['origins', 0, 'host'])).toEqual(['填写的内容不符合要求'])
    expect(await screen.findByText('请填写显示名')).toBeInTheDocument()
    await act(async () => { ref.submit(refused('origins.0.host', 'required')) })
    expect(ref.form.getFieldError(['origins', 0, 'host'])).toEqual(['此项为必填'])
  })

  it('falls back to the dialog for unknown or field-less errors', async () => {
    const ref = setup()
    const fallback = vi.fn()
    expect(ref.submit(refused('not_on_this_form', 'invalid'), fallback)).toBe(false)
    expect(ref.submit(new Error('network'), fallback)).toBe(false)
    expect(ref.submit({ code: 'validation_error' }, fallback)).toBe(false)
    expect(fallback).toHaveBeenCalledTimes(3)
    expect(ref.form.getFieldsError().every((item) => item.errors.length === 0)).toBe(true)
  })

  it('uses the locale of the provider', async () => {
    const ref = setup(undefined, enUS)
    await act(async () => { ref.submit(refused('name', 'required')) })
    expect(await screen.findByText('This field is required')).toBeInTheDocument()
  })

  it('works without the hook (applyFormSubmitError) with a page message function', async () => {
    const ref = setup()
    let marked = false
    await act(async () => { marked = applyFormSubmitError(ref.form, refused('name', 'duplicate'), { message: ({ field, reason }) => `${field}:${reason}` }) })
    expect(marked).toBe(true)
    expect(await screen.findByText('name:duplicate')).toBeInTheDocument()
  })
})

describe('InlineNotice', () => {
  it('shows an error next to its trigger with role=alert and closes', () => {
    const onClose = vi.fn()
    render(<CdncaProvider><InlineNotice onClose={onClose}>请先选择授权</InlineNotice></CdncaProvider>)
    const notice = screen.getByRole('alert')
    expect(notice).toHaveTextContent('请先选择授权')
    expect(notice).toHaveClass('cdnca-inline-notice', 'cdnca-inline-notice-error')
    fireEvent.click(screen.getByRole('button', { name: '关闭' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('has a warning look, no close button without onClose, and renders nothing when empty', () => {
    const { container, rerender } = render(<CdncaProvider><InlineNotice type="warning">文件类型不符</InlineNotice></CdncaProvider>)
    expect(screen.getByRole('alert')).toHaveClass('cdnca-inline-notice-warning')
    expect(screen.queryByRole('button')).toBeNull()
    rerender(<CdncaProvider><InlineNotice>{null}</InlineNotice></CdncaProvider>)
    expect(container.querySelector('.cdnca-inline-notice')).toBeNull()
  })

  it('says Close in English', () => {
    render(<CdncaProvider locale={enUS}><InlineNotice onClose={() => undefined}>Select a license first</InlineNotice></CdncaProvider>)
    expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument()
  })
})
