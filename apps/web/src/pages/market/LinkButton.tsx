import type { MouseEvent, ReactNode } from 'react'
import { Button, type ButtonProps } from 'antd'
import { useHref, useNavigate } from 'react-router-dom'

/**
 * a button-looking router link that is one native
 * <a> (antd Button with href), not a <Button> nested inside a <Link> — so
 * the keyboard stops once and screen readers see one control. A plain click
 * navigates in-app; modifier and middle clicks are left to the browser.
 */
export function LinkButton({ to, onClick, children, ...rest }: Omit<ButtonProps, 'href' | 'onClick'> & {
  to: string
  onClick?: () => void
  children: ReactNode
}) {
  const href = useHref(to)
  const navigate = useNavigate()
  const follow = (event: MouseEvent<HTMLElement>) => {
    onClick?.()
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
    event.preventDefault()
    navigate(to)
  }
  return <Button {...rest} href={href} onClick={follow}>{children}</Button>
}
