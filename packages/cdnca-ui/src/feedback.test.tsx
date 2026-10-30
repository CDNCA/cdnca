import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { Button } from 'antd'
import enUS from 'antd/locale/en_US'
import { describe, expect, it, vi } from 'vitest'

import { useState } from 'react'

import { CdncaProvider, FeedbackWhen, OutcomeUnknown, useFeedback, type Feedback } from './index'

function setup(locale?: typeof enUS) {
  const ref: { current?: Feedback } = {}
  function Probe() {
    ref.current = useFeedback()
    return <Button>page</Button>
  }
  render(<CdncaProvider locale={locale}><Probe /></CdncaProvider>)
  return ref as { current: Feedback }
}

const dialogs = () => document.querySelectorAll('.cdnca-feedback')
const title = (text: string) => waitFor(() => expect(Array.from(document.querySelectorAll('.cdnca-feedback-title')).map((n) => n.textContent)).toContain(text))
// A controlled dialog stays mounted (hidden) after closing.
const hidden = () => waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
const gone = () => waitFor(() => expect(dialogs()).toHaveLength(0))

describe('useFeedback', () => {
  it('opens a centered error dialog with title, reason and 「知道了」', async () => {
    const feedback = setup()
    act(() => feedback.current.error('生成失败', '尚未配置 DNS 服务商'))
    await title('生成失败')
    expect(document.querySelector('.cdnca-feedback-detail')).toHaveTextContent('尚未配置 DNS 服务商')
    expect(document.querySelector('.cdnca-feedback-error')).not.toBeNull()
    expect(document.querySelector('.ant-modal-centered')).not.toBeNull()
    expect(screen.getByRole('dialog', { name: '生成失败' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '知道了' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /close|关闭/i })).toBeInTheDocument()
  })

  it('shows a warning dialog too', async () => {
    const feedback = setup()
    act(() => feedback.current.warning('请先选择节点'))
    await title('请先选择节点')
    expect(document.querySelector('.cdnca-feedback-warning')).not.toBeNull()
  })

  it('closes with 「知道了」', async () => {
    const feedback = setup()
    act(() => feedback.current.error('保存失败'))
    fireEvent.click(await screen.findByRole('button', { name: '知道了' }))
    await gone()
  })

  it('closes with ×', async () => {
    const feedback = setup()
    act(() => feedback.current.error('保存失败'))
    await title('保存失败')
    fireEvent.click(screen.getByRole('button', { name: /close|关闭/i }))
    await gone()
  })

  it('closes with Esc', async () => {
    const feedback = setup()
    act(() => feedback.current.error('保存失败'))
    await title('保存失败')
    fireEvent.keyDown(document.querySelector('.cdnca-feedback')!.closest('.ant-modal-wrap')!, { key: 'Escape', code: 'Escape', keyCode: 27 })
    await gone()
  })

  it('opens one dialog for the same feedback raised repeatedly, and again after closing', async () => {
    const feedback = setup()
    act(() => {
      feedback.current.error('发布失败', '网络错误')
      feedback.current.error('发布失败', '网络错误')
      feedback.current.error('发布失败', '网络错误')
    })
    await title('发布失败')
    expect(dialogs()).toHaveLength(1)
    // A different reason is a different dialog.
    act(() => feedback.current.error('发布失败', '权限不足'))
    await waitFor(() => expect(dialogs()).toHaveLength(2))
    for (const ok of screen.getAllByRole('button', { name: '知道了' })) fireEvent.click(ok)
    await gone()
    act(() => feedback.current.error('发布失败', '网络错误'))
    await waitFor(() => expect(dialogs()).toHaveLength(1))
  })

  it('runs a next-step action, closes the dialog, and keeps 「知道了」', async () => {
    const feedback = setup()
    const goDns = vi.fn()
    const retry = vi.fn()
    act(() => feedback.current.error('生成失败', {
      detail: '尚未配置 DNS 服务商',
      actions: [{ label: '去 DNS 配置', onClick: goDns, primary: true }, { label: '重新生成', onClick: retry }],
    }))
    expect(await screen.findByRole('button', { name: '重新生成' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '知道了' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '去 DNS 配置' }))
    expect(goDns).toHaveBeenCalledTimes(1)
    expect(retry).not.toHaveBeenCalled()
    await gone()
  })

  it('accepts actions as the third argument', async () => {
    const feedback = setup()
    const retry = vi.fn()
    act(() => feedback.current.error('生成失败', '原因', [{ label: '重新生成', onClick: retry }]))
    fireEvent.click(await screen.findByRole('button', { name: '重新生成' }))
    expect(retry).toHaveBeenCalledTimes(1)
    await gone()
  })

  // fix-feedbackui：标题只放简短原因，请求 ID 进正文小字可复制，按钮全在底部同一行。
  it('keeps the title to the short reason and moves the request ID into the body', async () => {
    const feedback = setup()
    act(() => feedback.current.error('请求内容无效，请检查输入（请求 ID：cache-list-fce8551f-9a1b-4c3d）'))
    await title('请求内容无效')
    const dialog = screen.getByRole('dialog', { name: '请求内容无效' })
    expect(dialog.querySelector('.cdnca-feedback-title')!.textContent).not.toContain('cache-list')
    expect(dialog.querySelector('.cdnca-feedback-detail')).toHaveTextContent('请检查输入')
    const meta = dialog.querySelector('.cdnca-feedback-request-id')!
    expect(meta).toHaveTextContent('请求 ID：cache-list-fce8551f-9a1b-4c3d')
    expect(meta.querySelector('[aria-label="复制"], [aria-label="Copy"]')).not.toBeNull()
  })

  it('takes the request ID off a detail line too', async () => {
    const feedback = setup()
    act(() => feedback.current.error('保存失败', '权限不足（请求 ID：req-7）'))
    await title('保存失败')
    expect(document.querySelector('.cdnca-feedback-detail')!.textContent).toBe('权限不足')
    expect(document.querySelector('.cdnca-feedback-request-id')).toHaveTextContent('req-7')
  })

  it('puts every button in one bottom row with the primary one last', async () => {
    const feedback = setup()
    act(() => feedback.current.error('生成失败', {
      detail: '尚未配置 DNS 服务商',
      actions: [{ label: '去 DNS 配置', onClick: vi.fn(), primary: true }, { label: '重新生成', onClick: vi.fn() }],
    }))
    await title('生成失败')
    const dialog = screen.getByRole('dialog')
    expect(dialog.querySelector('.ant-modal-body button')).toBeNull()
    const footer = dialog.querySelector('.ant-modal-footer')!
    const labels = Array.from(footer.querySelectorAll('button')).map((b) => b.textContent)
    expect(labels).toEqual(['知道了', '重新生成', '去 DNS 配置'])
    expect(footer.querySelector('button:last-child')).toHaveClass('ant-btn-primary')
  })

  it('follows the antd locale', async () => {
    const feedback = setup(enUS)
    act(() => feedback.current.error('Save failed'))
    expect(await screen.findByRole('button', { name: 'Got it' })).toBeInTheDocument()
  })
})

describe('FeedbackWhen', () => {
  function Page({ onClose }: { onClose?: () => void }) {
    const [error, setError] = useState<string | null>(null)
    return (
      <>
        <Button onClick={() => setError('网络错误')}>submit</Button>
        <Button onClick={() => setError('权限不足')}>other</Button>
        {error ? <FeedbackWhen title="保存失败" detail={error} action={<Button>重试</Button>} onClose={() => { setError(null); onClose?.() }} /> : null}
      </>
    )
  }

  it('opens where the in-page Alert was, closes with 知道了 and calls onClose', async () => {
    const onClose = vi.fn()
    render(<CdncaProvider><Page onClose={onClose} /></CdncaProvider>)
    fireEvent.click(screen.getByRole('button', { name: 'submit' }))
    await title('保存失败')
    expect(document.querySelector('.cdnca-feedback-detail')).toHaveTextContent('网络错误')
    // The page's action sits in the bottom row beside 「知道了」, not in the body.
    const footer = screen.getByRole('dialog').querySelector('.ant-modal-footer')!
    expect(footer).toContainElement(screen.getByRole('button', { name: '重试' }))
    expect(Array.from(footer.querySelectorAll('button')).map((b) => b.textContent)).toEqual(['重试', '知道了'])
    expect(screen.getByRole('dialog').querySelector('.ant-modal-body button')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '知道了' }))
    await hidden()
    expect(onClose).toHaveBeenCalledTimes(1)
    // The next failure opens it again.
    fireEvent.click(screen.getByRole('button', { name: 'other' }))
    await title('保存失败')
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
  })

  it('reopens when the reason changes while still mounted', async () => {
    function Sticky() {
      const [reason, setReason] = useState('A')
      return <><Button onClick={() => setReason('B')}>next</Button><FeedbackWhen type="warning" title="结果未知" detail={reason} /></>
    }
    render(<CdncaProvider><Sticky /></CdncaProvider>)
    await title('结果未知')
    fireEvent.click(screen.getByRole('button', { name: '知道了' }))
    await hidden()
    fireEvent.click(screen.getByRole('button', { name: 'next' }))
    await title('结果未知')
    expect(document.querySelector('.cdnca-feedback-warning')).not.toBeNull()
  })

  it('shows one dialog when several places hold the same failure', async () => {
    render(<CdncaProvider>
      <FeedbackWhen title="保存失败" detail="网络错误" />
      <FeedbackWhen title="保存失败" detail="网络错误" />
      <FeedbackWhen title="保存失败" detail="网络错误" />
    </CdncaProvider>)
    await title('保存失败')
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: '知道了' }))
    await hidden()
  })
})

describe('OutcomeUnknown', () => {
  function Locked({ onRetry, onAbandon }: { onRetry: () => void; onAbandon: () => void }) {
    const [locked, setLocked] = useState(true)
    return (
      <section aria-label="分组">
        {locked ? <OutcomeUnknown title="写入结果未知" detail="请按原请求重试或放弃并刷新。" action={<>
          <Button size="small" onClick={onRetry}>按原请求重试</Button>
          <Button size="small" onClick={() => { onAbandon(); setLocked(false) }}>放弃并刷新</Button></>} /> : null}
        <table><tbody><tr><td>row</td></tr></tbody></table>
      </section>
    )
  }

  it('opens a closable warning dialog and keeps the recovery bar beside the locked block', async () => {
    const onRetry = vi.fn()
    const onAbandon = vi.fn()
    render(<CdncaProvider><Locked onRetry={onRetry} onAbandon={onAbandon} /></CdncaProvider>)
    await title('写入结果未知')
    expect(document.querySelector('.cdnca-feedback-warning .cdnca-feedback-detail')).toHaveTextContent('请按原请求重试或放弃并刷新。')
    // While the dialog is open its bottom row holds the recovery buttons (one copy on screen).
    const footer = screen.getByRole('dialog').querySelector('.ant-modal-footer')!
    expect(Array.from(footer.querySelectorAll('button')).map((b) => b.textContent)).toEqual(['按原请求重试', '放弃并刷新', '知道了'])
    expect(screen.getAllByRole('button', { name: '按原请求重试' })).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: '知道了' }))
    await hidden()
    // The bar stays inside the section it locks, with the recovery buttons.
    const bar = screen.getByRole('status')
    expect(screen.getByRole('region', { name: '分组' })).toContainElement(bar)
    expect(bar).toHaveTextContent('写入结果未知')
    fireEvent.click(screen.getByRole('button', { name: '按原请求重试' }))
    expect(onRetry).toHaveBeenCalledTimes(1)
    // 「查看说明」 reopens the explanation.
    fireEvent.click(screen.getByRole('button', { name: '查看说明' }))
    await title('写入结果未知')
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape', keyCode: 27 })
    await hidden()
    fireEvent.click(screen.getByRole('button', { name: '放弃并刷新' }))
    expect(onAbandon).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.queryByRole('status')).toBeNull())
  })
})
