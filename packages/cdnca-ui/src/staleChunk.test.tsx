import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { isStaleChunkError, reloadForStaleChunk, resetStaleChunkReloadForTest, StaleChunkBoundary } from './staleChunk'

const labels = { title: '页面加载失败', hint: '页面可能已更新，请刷新后重试。', retry: '重试', reload: '刷新页面', loading: '页面加载中' }

function StaleChunkRoute(): never {
  throw new TypeError('Failed to fetch dynamically imported module: /console/assets/LicensesPage-0ld.js')
}

function BrokenRoute(): never {
  throw new Error('raw upstream body: secret-token')
}

describe('StaleChunkBoundary（fix-cfl-c：升级后旧标签页切路由不白屏）', () => {
  beforeEach(() => {
    sessionStorage.clear()
    resetStaleChunkReloadForTest()
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })
  afterEach(() => vi.useRealTimers())

  it('识别旧分块加载失败', () => {
    expect(isStaleChunkError(new TypeError('Failed to fetch dynamically imported module: /x.js'))).toBe(true)
    expect(isStaleChunkError(new Error('Loading chunk 42 failed'))).toBe(true)
    expect(isStaleChunkError(new Error('Unable to preload CSS for /assets/a.css'))).toBe(true)
    expect(isStaleChunkError(new TypeError('Importing a module script failed.'))).toBe(true)
    expect(isStaleChunkError(new Error('request failed'))).toBe(false)
  })

  it('旧分块失败：自动整页刷新一次，期间只显示加载中', () => {
    const reload = vi.fn()
    render(<StaleChunkBoundary labels={labels} reload={reload} resetKey="/licenses"><StaleChunkRoute /></StaleChunkBoundary>)
    expect(reload).toHaveBeenCalledOnce()
    expect(screen.getByRole('status', { name: '页面加载中' })).toBeInTheDocument()
    expect(screen.queryByText('页面加载失败')).not.toBeInTheDocument()
  })

  it('刷新后 30 秒内仍失败不再刷新（防循环），显示可手动刷新的提示；30 秒后再遇到发版仍自动刷新', () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-10-27T12:00:00Z'))
    const reload = vi.fn()
    expect(reloadForStaleChunk(reload)).toBe(true)
    resetStaleChunkReloadForTest() // 新的一次整页加载
    const view = render(<StaleChunkBoundary labels={labels} reload={reload} resetKey="/licenses"><StaleChunkRoute /></StaleChunkBoundary>)
    expect(reload).toHaveBeenCalledOnce()
    expect(screen.getByText('页面加载失败')).toBeInTheDocument()
    expect(screen.queryByText(/dynamically imported module/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '刷新页面' }))
    expect(reload).toHaveBeenCalledTimes(2)
    view.unmount()

    resetStaleChunkReloadForTest()
    vi.setSystemTime(new Date('2026-10-27T12:00:31Z'))
    render(<StaleChunkBoundary labels={labels} reload={reload} resetKey="/licenses"><StaleChunkRoute /></StaleChunkBoundary>)
    expect(reload).toHaveBeenCalledTimes(3)
  })

  it('同一页面生命周期只刷新一次（vite:preloadError 与错误边界同时触发）', () => {
    const reload = vi.fn()
    expect(reloadForStaleChunk(reload)).toBe(true)
    expect(reloadForStaleChunk(reload)).toBe(true)
    expect(reload).toHaveBeenCalledOnce()
  })

  it('普通渲染错误不刷新、不泄露原文，可重试；换路由后错误清除', () => {
    const reload = vi.fn()
    let broken = true
    function Route() {
      if (broken) return <BrokenRoute />
      return <div>loaded</div>
    }
    const view = render(<StaleChunkBoundary labels={labels} reload={reload} resetKey="/orders"><Route /></StaleChunkBoundary>)
    expect(reload).not.toHaveBeenCalled()
    expect(screen.getByText('页面加载失败')).toBeInTheDocument()
    expect(screen.queryByText(/secret-token/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '刷新页面' })).not.toBeInTheDocument()
    broken = false
    fireEvent.click(screen.getByRole('button', { name: /重\s*试/ }))
    expect(screen.getByText('loaded')).toBeInTheDocument()

    broken = true
    view.rerender(<StaleChunkBoundary labels={labels} reload={reload} resetKey="/orders?page=2"><Route /></StaleChunkBoundary>)
    expect(screen.getByText('页面加载失败')).toBeInTheDocument()
    broken = false
    view.rerender(<StaleChunkBoundary labels={labels} reload={reload} resetKey="/balance"><Route /></StaleChunkBoundary>)
    expect(screen.getByText('loaded')).toBeInTheDocument()
  })
})
