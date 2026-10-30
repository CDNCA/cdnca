import { lazy, Suspense, useEffect, useState } from 'react'

import { passwordChangeRequiredEvent } from '../api/auth'
import { useSessionStore } from '../auth/session'

// 弹窗（表单、antd Modal/Form/Input）首次需要显示时才加载，不进首包；监听留在这里，
// 加载期间收到的拒绝事件不会丢。显示过一次后保持挂载，关闭动画和表单状态与原来一致。
const PasswordChangeDialog = lazy(() => import('./PasswordChangeDialog').then((module) => ({ default: module.PasswordChangeDialog })))

// "Change the password at the next sign-in": an administrator required it,
// so the control plane refuses everything but the password change (403
// password_change_required). Ask for the current and a new password; the
// change signs the user out everywhere, so continue with a fresh sign-in.
export function PasswordChangeGate() {
  const accessToken = useSessionStore(state => state.accessToken)
  const required = useSessionStore(state => Boolean(state.principal?.password_change_required))
  const [refused, setRefused] = useState(false)
  const open = (required || refused) && Boolean(accessToken)
  const [mounted, setMounted] = useState(open)
  if (open && !mounted) setMounted(true)

  useEffect(() => {
    const show = () => setRefused(true)
    window.addEventListener(passwordChangeRequiredEvent, show)
    return () => window.removeEventListener(passwordChangeRequiredEvent, show)
  }, [])

  if (!mounted) return null
  return (
    <Suspense fallback={null}>
      <PasswordChangeDialog open={open} onChanged={() => setRefused(false)} />
    </Suspense>
  )
}
