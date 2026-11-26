import { useLayoutEffect, useRef, type ReactNode } from 'react'

// the shell-wide banners (impersonation, installation
// lock) are pinned under the fixed header, stacked in DOM order; left in the page
// flow they scrolled under the header and their buttons took no clicks. Their
// measured total height (they wrap on narrow screens) goes to
// --app-banners-height on <html>: .app-main reserves it above the page and the
// document scroll padding keeps in-page scrolling clear of it (styles.css).
export function PinnedBanners({ children }: { children: ReactNode }) {
  const container = useRef<HTMLDivElement>(null)
  useLayoutEffect(() => {
    const element = container.current
    if (!element) return
    const root = document.documentElement
    const clear = () => {
      root.removeAttribute('data-app-banners')
      root.style.removeProperty('--app-banners-height')
    }
    const measure = () => {
      const height = Math.ceil(element.getBoundingClientRect().height)
      if (height <= 0) return clear()
      root.style.setProperty('--app-banners-height', `${height}px`)
      root.setAttribute('data-app-banners', '')
    }
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(element)
    return () => {
      observer.disconnect()
      clear()
    }
  }, [])
  return <div ref={container} className="app-pinned-banners">{children}</div>
}
