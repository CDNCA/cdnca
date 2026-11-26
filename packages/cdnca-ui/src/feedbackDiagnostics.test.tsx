import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import enUS from 'antd/locale/en_US'
import { describe, expect, it } from 'vitest'

import { CdncaProvider, FeedbackWhen, useFeedback, type Feedback } from './index'

// 拒绝原因句（i18n/apiError 的「操作被拒绝：原因（错误码 x，请求 ID y）」）
// 在弹窗里只留短标题与正文；错误码与请求 ID 进默认收起的「诊断详情」，可复制；ARIA 名称只取短标题。
const refusal = '操作被拒绝：套餐资源额度不足，请释放资源或增加对应升级包（错误码 package_resource_quota_exceeded，请求 ID ea5e5293-4baa-40cf-9e8b-692d3034e5a6）'

function setup(locale?: typeof enUS) {
  const ref: { current?: Feedback } = {}
  function Probe() {
    ref.current = useFeedback()
    return null
  }
  render(<CdncaProvider locale={locale}><Probe /></CdncaProvider>)
  return ref as { current: Feedback }
}

describe('feedback dialog diagnostics', () => {
  it('keeps the error code and request ID out of the title and the dialog name', async () => {
    const feedback = setup()
    act(() => feedback.current.error(refusal))
    const dialog = await screen.findByRole('dialog', { name: '操作被拒绝：套餐资源额度不足' })
    const title = dialog.querySelector('.cdnca-feedback-title')!.textContent!
    expect(title).toBe('操作被拒绝：套餐资源额度不足')
    expect(title).not.toContain('package_resource_quota_exceeded')
    expect(title).not.toContain('ea5e5293')
    expect(dialog.querySelector('.cdnca-feedback-detail')!.textContent).toBe('请释放资源或增加对应升级包')
  })

  it('shows the diagnostics collapsed, opened by 「诊断详情」, each value copyable', async () => {
    const feedback = setup()
    act(() => feedback.current.error(refusal))
    const dialog = await screen.findByRole('dialog', { name: '操作被拒绝：套餐资源额度不足' })
    const details = dialog.querySelector('details.cdnca-feedback-request-id') as HTMLDetailsElement
    expect(details).not.toBeNull()
    expect(details.open).toBe(false)
    const summary = details.querySelector('summary')!
    expect(summary).toHaveTextContent('诊断详情')
    expect(details).toHaveTextContent('错误码：package_resource_quota_exceeded')
    expect(details).toHaveTextContent('请求 ID：ea5e5293-4baa-40cf-9e8b-692d3034e5a6')
    expect(details.querySelectorAll('[aria-label="复制"], [aria-label="Copy"]')).toHaveLength(2)
    fireEvent.click(summary)
    await waitFor(() => expect(details.open).toBe(true))
  })

  it('takes a code-only suffix and the English refusal text too', async () => {
    const feedback = setup(enUS)
    act(() => feedback.current.error('Save failed', 'The operation was refused (error code site_locked, request ID req-9)'))
    const dialog = await screen.findByRole('dialog', { name: 'Save failed' })
    expect(dialog.querySelector('.cdnca-feedback-detail')!.textContent).toBe('The operation was refused')
    const details = dialog.querySelector('details.cdnca-feedback-request-id')!
    expect(details.querySelector('summary')).toHaveTextContent('Diagnostic details')
    expect(details).toHaveTextContent('Error code: site_locked')
    expect(details).toHaveTextContent('Request ID: req-9')
  })

  it('leaves page-written titles and texts without diagnostics as they are', async () => {
    render(<CdncaProvider><FeedbackWhen title="生成失败，尚未配置 DNS 服务商（如 a，b）" /></CdncaProvider>)
    const dialog = await screen.findByRole('dialog', { name: '生成失败，尚未配置 DNS 服务商（如 a，b）' })
    expect(dialog.querySelector('details')).toBeNull()
  })

  it('moves an error code without a request ID as well', async () => {
    render(<CdncaProvider><FeedbackWhen title="操作被拒绝（错误码 validation_failed）" /></CdncaProvider>)
    const dialog = await screen.findByRole('dialog', { name: '操作被拒绝' })
    expect(dialog.querySelector('details.cdnca-feedback-request-id')).toHaveTextContent('错误码：validation_failed')
  })
})
