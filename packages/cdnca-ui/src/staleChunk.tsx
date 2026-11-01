import { Component, Fragment, type ReactNode } from 'react'
import { Button, Result, Space, Spin } from 'antd'

import { isStaleChunkError, reloadForStaleChunk } from './staleChunkReload'

// 升级后已打开的标签页切路由时，旧版本的分块已被删除（404），React.lazy 抛错；没有错误边界时
// 整个应用卸载成白屏。这里整页刷新一次拿新 index.html；同思路见 apps/web RouteErrorBoundary。

// eslint-disable-next-line react-refresh/only-export-components
export { isStaleChunkError, reloadForStaleChunk, resetStaleChunkReloadForTest } from './staleChunkReload'

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
