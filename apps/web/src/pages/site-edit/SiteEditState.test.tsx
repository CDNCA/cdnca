import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import SiteEditState from './SiteEditState'

// TECH-03: the site-edit panels' load states go through DataState.
describe('SiteEditState', () => {
  it('shows a busy spinner with a visible label', () => {
    render(<SiteEditState status="loading" label="缓存策略加载中" />)
    expect(screen.getByText('缓存策略加载中').closest('[aria-busy="true"]')).not.toBeNull()
  })

  it('shows a load failure with its detail and the shared retry', async () => {
    const retry = vi.fn()
    render(<SiteEditState status="error" title="加载失败" detail="请求失败" onRetry={retry} />)
    const alert = screen.getByRole('alert')
    expect(alert).toHaveClass('data-state-error')
    expect(alert).toHaveTextContent('加载失败')
    expect(alert).toHaveTextContent('请求失败')
    await userEvent.setup().click(screen.getByRole('button', { name: '重试' }))
    expect(retry).toHaveBeenCalledTimes(1)
  })

  it('shows a permission state and an empty state through DataState', () => {
    const { container, rerender } = render(<SiteEditState status="forbidden" title="无权查看" detail="缺少权限" />)
    expect(container.querySelector('.data-state-forbidden')).not.toBeNull()
    expect(screen.getByText('无权查看')).toBeInTheDocument()
    expect(screen.getByText('缺少权限')).toBeInTheDocument()
    rerender(<SiteEditState status="empty" title="尚未发布" />)
    expect(container.querySelector('.data-state')).toHaveTextContent('尚未发布')
  })
})
