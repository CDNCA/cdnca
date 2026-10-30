import { Component, Fragment, type ReactNode } from 'react'
import { Button, Result, Space, Spin } from 'antd'

// 升级后已打开的标签页切路由时，旧版本的分块已被删除（404），React.lazy 抛错；没有错误边界时
// 整个应用卸载成白屏。这里整页刷新一次拿新 index.html；同思路见 apps/web RouteErrorBoundary。

// eslint-disable-next-line react-refresh/only-export-components
export function isStaleChunkError(error: unknown): boolean {
  const message = error instanceof Error ? `${error.name} ${error.message}` : String(error)
  return /ChunkLoadError|Loading (?:chunk|CSS chunk)|dynamically imported module|importing a module script failed|unable to preload CSS/i.test(message)
}

const reloadStorageKey = 'cdnca:stale-chunk-reload'
// 标记只在 30 秒内有效：刷新后新页面马上又失败（新版本也缺分块）才拦住防循环；
// 同一标签页以后再遇到发版，仍会自动刷新一次。
const reloadLoopWindowMs = 30_000
let reloading = false

function markReloadAttempt(): boolean {
  try {
    const last = Number(window.sessionStorage.getItem(reloadStorageKey))
    if (last && Date.now() - last < reloadLoopWindowMs) return false
    window.sessionStorage.setItem(reloadStorageKey, String(Date.now()))
    return true
  } catch {
    return false
  }
}

// 同一页面生命周期只刷新一次；返回 true 表示已在刷新。
// eslint-disable-next-line react-refresh/only-export-components
export function reloadForStaleChunk(reload: () => void = () => window.location.reload()): boolean {
  if (reloading) return true
  if (!markReloadAttempt()) return false
  reloading = true
  reload()
  return true
}

// 仅测试用：模拟新的一次整页加载。
// eslint-disable-next-line react-refresh/only-export-components
export function resetStaleChunkReloadForTest(): void {
  reloading = false
}

export interface StaleChunkLabels {
  title: string
  hint: string
  retry: string
  reload: string
  loading: string
}

interface StaleChunkBoundaryProps {
  children: ReactNode
  labels: StaleChunkLabels
  // 路由（pathname+search）变化时清除错误。
  resetKey: string
  reload?: () => void
}

interface StaleChunkBoundaryState {
  error: Error | null
  resetKey: string
  retryKey: number
  reloading: boolean
}

export class StaleChunkBoundary extends Component<StaleChunkBoundaryProps, StaleChunkBoundaryState> {
  state: StaleChunkBoundaryState = { error: null, resetKey: this.props.resetKey, retryKey: 0, reloading: false }

  static getDerivedStateFromProps(props: StaleChunkBoundaryProps, state: StaleChunkBoundaryState): Partial<StaleChunkBoundaryState> | null {
    return props.resetKey === state.resetKey ? null : { error: null, resetKey: props.resetKey, retryKey: state.retryKey + 1, reloading: false }
  }

  static getDerivedStateFromError(error: Error): Partial<StaleChunkBoundaryState> {
    return { error }
  }

  componentDidCatch(error: Error) {
    if (isStaleChunkError(error) && reloadForStaleChunk(this.props.reload)) this.setState({ reloading: true })
  }

  private retry = () => this.setState((state) => ({ error: null, retryKey: state.retryKey + 1 }))

  private manualReload = () => (this.props.reload ?? (() => window.location.reload()))()

  render() {
    const { error, retryKey, reloading } = this.state
    const { labels } = this.props
    if (!error) return <Fragment key={retryKey}>{this.props.children}</Fragment>
    const stale = isStaleChunkError(error)
    if (stale && reloading) {
      return <div role="status" aria-label={labels.loading} style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>
    }
    return (
      <Result
        status="warning"
        title={labels.title}
        subTitle={stale ? labels.hint : undefined}
        extra={(
          <Space>
            {stale ? <Button type="primary" onClick={this.manualReload}>{labels.reload}</Button> : null}
            <Button onClick={this.retry}>{labels.retry}</Button>
          </Space>
        )}
      />
    )
  }
}
