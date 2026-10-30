import { lazy, Suspense, useEffect, useState } from 'react'

import { sessionRegionChangedEvent } from '../api/auth'
import { useSessionStore } from '../auth/session'

// 弹窗（antd Modal/Form/Input）首次需要显示时才加载，不进首包；监听留在这里，加载期间
// 收到的事件不会丢。显示过一次后保持挂载，关闭动画和输入状态与原来一致。
const SessionRegionDialog = lazy(() => import('./SessionRegionDialog').then((module) => ({ default: module.SessionRegionDialog })))

// Session region binding: when the control plane refuses a request because
// the session's IP moved to another country/province, ask for the password
// and reload once the session is re-bound.
export function SessionRegionGate() {
  const accessToken = useSessionStore(state => state.accessToken)
  const [requested, setRequested] = useState(false)
  const open = requested && Boolean(accessToken)
  const [mounted, setMounted] = useState(open)
  if (open && !mounted) setMounted(true)

  useEffect(() => {
    const show = () => setRequested(true)
    window.addEventListener(sessionRegionChangedEvent, show)
    return () => window.removeEventListener(sessionRegionChangedEvent, show)
  }, [])

  if (!mounted) return null
  return (
    <Suspense fallback={null}>
      <SessionRegionDialog open={open} onVerified={() => setRequested(false)} />
    </Suspense>
  )
}
