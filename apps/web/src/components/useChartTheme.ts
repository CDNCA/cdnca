import { useEffect, useMemo, useState } from 'react'

import { themeColor, themeColorAlpha, useThemeRevision } from '../theme/themeColor'

export function useChartTheme() {
  const [dark, setDark] = useState(() => document.body.classList.contains('i-theme-dark'))
  const revision = useThemeRevision()
  useEffect(() => {
    const update = () => setDark(document.body.classList.contains('i-theme-dark'))
    const observer = new MutationObserver(update)
    observer.observe(document.body, { attributes: true, attributeFilter: ['class'] })
    update()
    return () => observer.disconnect()
  }, [])
  // revision: re-read the theme variables once a theme stylesheet applies.
  return useMemo(() => ({
    text: dark ? themeColor('--cdnca-color-text-dark', '#e5e7eb') : themeColor('--cdnca-color-text', '#515a6e'),
    muted: dark ? themeColor('--cdnca-color-text-secondary-dark', '#98a2b3') : themeColor('--cdnca-color-text-secondary', '#808695'),
    border: dark ? themeColor('--cdnca-color-border-soft-dark', '#1f2a3d') : themeColor('--cdnca-color-border-secondary', '#e8eaec'),
    surface: dark ? themeColor('--cdnca-color-surface-dark', '#172033') : themeColor('--cdnca-color-bg-container', '#fff'),
    primary: dark ? themeColor('--cdnca-color-primary-dark', '#60a5fa') : themeColor('--cdnca-color-primary', '#2d8cf0'),
    area: dark ? themeColorAlpha('--cdnca-color-primary-dark', '#60a5fa', '.18') : themeColor('--cdnca-chart-area', '#BBDEFB'),
    revision,
  }), [dark, revision])
}
