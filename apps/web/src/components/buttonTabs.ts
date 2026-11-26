import { useId, type KeyboardEvent } from 'react'

// 按钮样式的自绘页签补齐 WAI-ARIA 页签模式（/）：
// 页签 aria-controls 指向 tabpanel，面板 aria-labelledby 指回当前页签；只有当前页签可 Tab 进入，
// 左右方向键 / Home / End 在页签间移动并切换。sharedPanel：几个页签共用同一个面板（切换时正文原地更新、不重挂载）。
export function useButtonTabs<K extends string>(keys: readonly K[], active: K, select: (key: K) => void, sharedPanel = false) {
  const base = useId()
  const tabId = (key: K) => `${base}-tab-${key}`
  const panelId = (key: K) => sharedPanel ? `${base}-panel` : `${base}-panel-${key}`
  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    const index = keys.indexOf(active)
    const next = event.key === 'ArrowRight' ? keys[(index + 1) % keys.length]
      : event.key === 'ArrowLeft' ? keys[(index - 1 + keys.length) % keys.length]
        : event.key === 'Home' ? keys[0] : event.key === 'End' ? keys[keys.length - 1] : undefined
    if (next === undefined) return
    event.preventDefault()
    select(next)
    document.getElementById(tabId(next))?.focus()
  }
  return {
    listProps: { role: 'tablist', onKeyDown },
    tabProps: (key: K) => ({
      id: tabId(key), role: 'tab', 'aria-selected': key === active, 'aria-controls': panelId(key),
      tabIndex: key === active ? 0 : -1, onClick: () => select(key),
    }),
    panelProps: (key: K = active) => ({
      id: panelId(key), role: 'tabpanel', 'aria-labelledby': tabId(sharedPanel ? active : key),
      hidden: !sharedPanel && key !== active, tabIndex: sharedPanel || key === active ? 0 : undefined,
    }),
  }
}
