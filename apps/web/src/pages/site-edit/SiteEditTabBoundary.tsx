import { Component, lazy, Suspense, useState, type ComponentProps, type ComponentType, type LazyExoticComponent, type ReactNode } from 'react'
import { Button } from 'antd'
import { FeedbackWhen } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { isLazyRouteError } from '../../components/RouteErrorBoundary'

// React.lazy 会永久缓存一次失败的 import，之后再渲染只会立刻重抛同一个错误。
// retryableLazy 把失败的实例登记下来，标签内点“重试”时（resetFailedLazyTabs）换成新的
// lazy 实例，才会真正重新请求该块；不点重试时保持错误提示，不在后台反复请求。
const failedLazyResets = new Set<() => void>()

function resetFailedLazyTabs() {
  for (const reset of [...failedLazyResets]) reset()
  failedLazyResets.clear()
}

export type PreloadableComponent<P> = ComponentType<P> & { preload: () => void }

// 泛型取组件本身（同 React.lazy）：按 props 取泛型时，.then(m => ({ default: m.X })) 会把 props 推断成 never。
// fix-tabperf：preload() 提前下载分块（悬停标签/空闲时）；已下载的块直接渲染真实组件，不再经 Suspense 闪一次加载态。
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function retryableLazy<C extends ComponentType<any>>(load: () => Promise<{ default: C }>): PreloadableComponent<ComponentProps<C>> {
  let loaded: C | null = null
  let pending: Promise<{ default: C }> | null = null
  const fetchModule = () => {
    pending ??= load().then((module) => {
      loaded = module.default
      return module
    }, (error: unknown) => {
      pending = null
      throw error
    })
    return pending
  }
  const reset = () => { current = create() }
  const create = (): LazyExoticComponent<C> => lazy(() => fetchModule().catch((error: unknown) => {
    failedLazyResets.add(reset)
    throw error
  }))
  let current = create()
  function RetryableLazy(props: ComponentProps<C>) {
    // 挂载时定下组件类型：之后块加载完成也不换类型，否则 React 会把已挂载的标签整棵重建。
    const [Current] = useState(() => (loaded ?? current) as unknown as ComponentType<ComponentProps<C>>)
    return <Current {...props} />
  }
  RetryableLazy.preload = () => { void fetchModule().catch(() => undefined) }
  return RetryableLazy
}

interface TabErrorFallbackProps {
  chunkFailure: boolean
  onRetry: () => void
}

// eslint-disable-next-line react-refresh/only-export-components
function TabErrorFallback({ chunkFailure, onRetry }: TabErrorFallbackProps) {
  const { t } = useTranslation('sites')
  // 加载/渲染失败按 @cdnca/ui 规范用弹窗说明原因；原位保留重试按钮，关掉弹窗后仍能重试。
  return (
    <div className="site-edit-tab-error">
      <FeedbackWhen title={t('edit.tabError.title')} detail={chunkFailure ? t('edit.tabError.chunk') : t('edit.tabError.render')} />
      <Button size="small" onClick={onRetry}>{t('edit.tabError.retry')}</Button>
    </div>
  )
}

interface SiteEditTabBoundaryProps {
  fallback: ReactNode
  children: ReactNode
}

interface SiteEditTabBoundaryState {
  error: Error | null
  retryKey: number
}

/**
 * 每个站点设置标签各自一层 Suspense + 错误边界：某个标签加载或渲染出错时，
 * 只在该标签内容区显示错误和“重试”，不冒泡到路由级错误边界，也不触发整页刷新，
 * 其他标签照常切换。
 */
export class SiteEditTabBoundary extends Component<SiteEditTabBoundaryProps, SiteEditTabBoundaryState> {
  state: SiteEditTabBoundaryState = { error: null, retryKey: 0 }

  static getDerivedStateFromError(error: Error): Partial<SiteEditTabBoundaryState> {
    return { error }
  }

  private retry = () => {
    resetFailedLazyTabs()
    this.setState((state) => ({ error: null, retryKey: state.retryKey + 1 }))
  }

  render() {
    const { error, retryKey } = this.state
    if (error) return <TabErrorFallback chunkFailure={isLazyRouteError(error)} onRetry={this.retry} />
    return (
      <Suspense key={retryKey} fallback={this.props.fallback}>
        {this.props.children}
      </Suspense>
    )
  }
}
