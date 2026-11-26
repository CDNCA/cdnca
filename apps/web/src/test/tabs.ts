import { screen } from '@testing-library/react'

// 按页签名取它 aria-controls 指向的 tabpanel，断言当前页签的正文就在这个面板里。
export function tabPanelOf(name: string | RegExp): HTMLElement {
  const tab = screen.getByRole('tab', { name })
  const id = tab.getAttribute('aria-controls')
  const panel = id ? document.getElementById(id) : null
  if (!panel) throw new Error(`tab ${String(name)} controls no panel`)
  if (panel.getAttribute('role') !== 'tabpanel') throw new Error(`tab ${String(name)} controls a non-tabpanel element`)
  return panel
}
