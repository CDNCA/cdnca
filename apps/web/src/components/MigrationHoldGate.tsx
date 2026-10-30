import { lazy, Suspense, useEffect, useState, type PropsWithChildren } from 'react'

import { migrationHoldEvent } from '../api/auth'

// fix-migrollback：任一请求被冻结控制台回 503 control_migration_hold 时，整页切到
// 冻结控制台（迁移进度、日志、停止、回退）。页面按需加载，不进首包。
const FrozenConsolePage = lazy(() => import('../pages/FrozenConsolePage'))

export function MigrationHoldGate({ children }: PropsWithChildren) {
  const [held, setHeld] = useState(false)
  useEffect(() => {
    const mark = () => setHeld(true)
    window.addEventListener(migrationHoldEvent, mark)
    return () => window.removeEventListener(migrationHoldEvent, mark)
  }, [])
  if (!held) return children
  return <Suspense fallback={null}><FrozenConsolePage /></Suspense>
}
