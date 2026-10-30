import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { DataState } from '../components/DataState'
import { renderWithProviders } from '../test/render'

describe('DataState', () => {
  it('renders explicit loading, empty, and error states', () => {
    const { rerender } = renderWithProviders(<DataState status="loading" />)
    expect(screen.getByLabelText('数据加载中')).toBeInTheDocument()

    rerender(<DataState status="empty" />)
    expect(screen.getByText('无数据')).toBeInTheDocument()

    rerender(<DataState status="error" />)
    expect(screen.getByRole('alert')).toHaveTextContent('数据加载失败')
  })

  it('renders a recoverable forbidden state and invokes retry', async () => {
    const user = userEvent.setup()
    const onRetry = vi.fn()
    renderWithProviders(
      <DataState
        status="forbidden"
        message="无权查看服务概览"
        description="当前账号无权查看用户服务概览"
        onRetry={onRetry}
      />,
    )

    expect(screen.getByText('无权查看服务概览')).toBeInTheDocument()
    expect(screen.getByText('当前账号无权查看用户服务概览')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(onRetry).toHaveBeenCalledOnce()
  })

  it('supports localized error copy and a retry action', async () => {
    const user = userEvent.setup()
    const onRetry = vi.fn()
    renderWithProviders(<DataState status="error" message="服务数据暂不可用" onRetry={onRetry} />)

    expect(screen.getByRole('alert')).toHaveTextContent('服务数据暂不可用')
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(onRetry).toHaveBeenCalledOnce()
  })
})
