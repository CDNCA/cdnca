// jumpTo scrolls a section into view and moves focus to its heading so the
// keyboard and screen readers follow the jump.
export function jumpTo(target: string) {
  const section = document.getElementById(target)
  if (!section) return
  section.scrollIntoView?.({ block: 'start', behavior: 'smooth' })
  const heading = section.matches('h2, h3') ? section : section.querySelector<HTMLElement>('h2, h3')
  if (heading) {
    if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1')
    heading.focus({ preventScroll: true })
  }
}
