// jumpTo scrolls a section into view and moves focus to its heading so the
// keyboard and screen readers follow the jump.
export function jumpTo(target: string) {
  const section = document.getElementById(target)
  if (!section) return
  section.scrollIntoView?.({ block: 'start', behavior: 'smooth' })
  // 目标本身不是标题且内部无标题时（如 WAF 总开关的 strong），焦点落在目标上。
  const heading = section.matches('h2, h3') ? section : section.querySelector<HTMLElement>('h2, h3') ?? section
  if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1')
  heading.focus({ preventScroll: true })
}

/**
 * 切到网站编辑页另一个标签（?tab=）后定位到其中一节。标签按需挂载，
 * 等目标出现且不在隐藏的标签里再 jumpTo；约 3 秒内没出现就只切标签。
 */
export function openTabAt(setTab: (tab: string) => void, tab: string, target: string) {
  setTab(tab)
  let tries = 0
  const attempt = () => {
    const element = document.getElementById(target)
    if (element && !element.closest('[hidden]')) { jumpTo(target); return }
    if (++tries < 30) setTimeout(attempt, 100)
  }
  setTimeout(attempt, 0)
}
