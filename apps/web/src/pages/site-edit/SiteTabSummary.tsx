import { useTranslation } from 'react-i18next'

import '../../i18n/siteEditV4'
import { jumpTo } from './siteTabSummaryJump'

export type SummaryTone = 'on' | 'off' | 'warn' | 'error' | 'plain'

export interface SummaryItem {
  key: string
  label: string
  value: React.ReactNode
  tone?: SummaryTone
  // id of the section the item jumps to (its heading gets focus)
  target?: string
}

// SiteTabSummary is the "本页摘要" strip at the top of a site edit tab: the
// values in effect, each one a jump to its section.
export function SiteTabSummary({ items }: { items: SummaryItem[] }) {
  const { t } = useTranslation('siteEditV4')
  return (
    <section className="site-tab-summary" aria-label={t('summary.label')}>
      <ul>
        {items.map((item) => {
          const body = (
            <>
              <span className="site-tab-summary-label">{item.label}</span>
              <strong className={`site-tab-summary-value is-${item.tone ?? 'plain'}`}>{item.value}</strong>
            </>
          )
          return (
            <li key={item.key}>
              {item.target ? (
                <button type="button" title={t('summary.jump', { name: item.label })} onClick={() => jumpTo(item.target!)}>{body}</button>
              ) : <div>{body}</div>}
            </li>
          )
        })}
      </ul>
    </section>
  )
}
