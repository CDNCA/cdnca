import type { ReactNode } from 'react'
import { ChevronRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import '../../i18n/cachePolicy'
import './CacheSiteTab.css'

/** The id of a setting row's one-line brief (for the control's aria-describedby). */
export function cacheSettingBriefId(name: string): string {
  return `cache-setting-${name}-brief`
}

/**
 * One row of the 缓存设置 tab: the label and a one-line brief
 * on the left, the control on the right. The full explanation stays in the
 * DOM under「了解更多」(a native <details>: keyboard and touch work, no hover).
 * `toggle` rows keep the switch on the right on narrow screens; other rows
 * stack the control under the text there. `wide` rows span the whole card.
 */
export default function CacheSettingRow({ name, label, brief, more, wide, toggle, children }: {
  name: string
  label: string
  brief?: string
  more?: string
  wide?: boolean
  toggle?: boolean
  children: ReactNode
}) {
  const { t } = useTranslation('cachePolicy')
  return (
    <div className="cache-setting-row" data-setting={name} data-wide={wide || undefined} data-toggle={toggle || undefined}>
      <div className="cache-setting-text">
        <span className="cache-setting-label">{label}</span>
        {brief ? <p id={cacheSettingBriefId(name)} className="cache-setting-brief">{brief}</p> : null}
        {more ? (
          <details className="cache-setting-more">
            <summary>
              <ChevronRight size={13} aria-hidden="true" />
              {t('actions.learnMore')}
            </summary>
            <p>{more}</p>
          </details>
        ) : null}
      </div>
      <div className="cache-setting-control">{children}</div>
    </div>
  )
}
