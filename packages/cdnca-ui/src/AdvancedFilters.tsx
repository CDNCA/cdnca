// Filter bar for pages with many conditions: the rarely used ones fold into
// "高级筛选". One row: the page's 1–3 common fields, query, reset
// and, at the right, the "高级筛选" toggle with the number of applied advanced
// conditions. The toggle opens a panel below the row (2–4 column grid, apply /
// clear advanced); applied advanced conditions show under the row as tags
// whose × removes that condition and queries again. Data stays in the page:
// it passes each item's applied value and the callbacks.
import { useContext, useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { Button, ConfigProvider } from 'antd'

export interface AdvancedFilterItem {
  key: string
  label: string
  /** The control shown in the panel (the page's own Input / Select, with its aria-label). */
  field: ReactNode
  /** The applied value as shown in the tag; empty or absent means the condition is off. */
  applied?: string
  /** Takes two grid columns (e.g. match mode + value). */
  wide?: boolean
}

export interface AdvancedFiltersProps {
  /** The always-visible common conditions (time range included). */
  primary: ReactNode
  items: AdvancedFilterItem[]
  onQuery: () => void
  onReset?: () => void
  /** Clears the advanced conditions only, then queries. */
  onClearAdvanced: () => void
  /** Clears one advanced condition, then queries. */
  onRemove: (key: string) => void
  /** Page actions at the far right of the row (export, refresh…). */
  extra?: ReactNode
  /** Remembers the panel's open state in localStorage under this key. */
  storageKey?: string
  /** Opens the panel on mount regardless of the remembered state (e.g. a deep link filled an advanced field). */
  defaultOpen?: boolean
  /** Told the panel's open state on mount and on every change (e.g. load a field's options only while open). */
  onOpenChange?: (open: boolean) => void
  columns?: 2 | 3 | 4
  className?: string
  queryLoading?: boolean
  /** Disables query and apply (e.g. a field fails validation). */
  queryDisabled?: boolean
  /** The query button's text and icon when the page calls it something else (e.g. 刷新 on a live list). */
  queryText?: ReactNode
  queryIcon?: ReactNode
}

const texts = {
  'zh-CN': { query: '查询', reset: '重置', advanced: '高级筛选', apply: '应用', clear: '清空高级条件', applied: '已启用的高级条件', remove: (label: string) => `移除条件 ${label}` },
  'zh-TW': { query: '查詢', reset: '重設', advanced: '進階篩選', apply: '套用', clear: '清空進階條件', applied: '已啟用的進階條件', remove: (label: string) => `移除條件 ${label}` },
  'en-US': { query: 'Search', reset: 'Reset', advanced: 'Advanced filters', apply: 'Apply', clear: 'Clear advanced', applied: 'Applied advanced filters', remove: (label: string) => `Remove filter ${label}` },
}

function useTexts() {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  return texts[locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN']
}

const storagePrefix = 'cdnca.advancedFilters.'

function readOpen(storageKey?: string): boolean {
  if (!storageKey) return false
  try { return window.localStorage.getItem(storagePrefix + storageKey) === '1' } catch { return false }
}

function writeOpen(storageKey: string | undefined, open: boolean) {
  if (!storageKey) return
  try { window.localStorage.setItem(storagePrefix + storageKey, open ? '1' : '0') } catch { /* storage unavailable: keep it in memory */ }
}

const focusable = 'input:not([disabled]), textarea:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])'

// lucide "chevron-down" / "x" (stroke icons, same drawings as lucide-react).
function ChevronIcon() {
  return (
    <svg className="cdnca-adv-filters-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false"><path d="m6 9 6 6 6-6" /></svg>
  )
}
function CloseIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false"><path d="M18 6 6 18" /><path d="m6 6 12 12" /></svg>
  )
}

export function AdvancedFilters({
  primary, items, onQuery, onReset, onClearAdvanced, onRemove, extra, storageKey, columns = 3, className, queryLoading, queryDisabled, queryText, queryIcon, defaultOpen, onOpenChange,
}: AdvancedFiltersProps) {
  const text = useTexts()
  const panelId = useId()
  const [open, setOpen] = useState(() => defaultOpen || readOpen(storageKey))
  const toggleRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const focusPanel = useRef(false)
  const active = items.filter((item) => item.applied?.trim())

  const changeOpen = (next: boolean) => {
    setOpen(next)
    writeOpen(storageKey, next)
  }
  const openChangeRef = useRef(onOpenChange)
  openChangeRef.current = onOpenChange
  useEffect(() => { openChangeRef.current?.(open) }, [open])
  useEffect(() => {
    if (!open || !focusPanel.current) return
    focusPanel.current = false
    panelRef.current?.querySelector<HTMLElement>(focusable)?.focus()
  }, [open])

  // Enter in a text field applies; Escape closes and hands focus back to the
  // toggle. Keys an open Select dropdown handles itself are left to it.
  const onPanelKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement
    if (target.getAttribute('aria-expanded') === 'true') return
    if (event.key === 'Escape') {
      event.preventDefault()
      changeOpen(false)
      toggleRef.current?.focus()
    } else if (event.key === 'Enter' && target.tagName === 'INPUT' && target.getAttribute('role') !== 'combobox') {
      event.preventDefault()
      if (!queryDisabled) onQuery()
    }
  }

  return (
    <div className={['cdnca-adv-filters', open ? 'is-open' : '', className].filter(Boolean).join(' ')}>
      <div className="cdnca-adv-filters-bar">
        <div className="cdnca-adv-filters-primary">{primary}</div>
        <div className="cdnca-adv-filters-actions">
          <Button type="primary" icon={queryIcon} loading={queryLoading} disabled={queryDisabled} onClick={onQuery}>{queryText ?? text.query}</Button>
          {onReset ? <Button onClick={onReset}>{text.reset}</Button> : null}
          {/* No advanced items (e.g. a tab with only common fields): no toggle and no panel. */}
          {items.length ? <button
            ref={toggleRef}
            type="button"
            className={['cdnca-adv-filters-toggle', active.length ? 'has-active' : ''].filter(Boolean).join(' ')}
            aria-expanded={open}
            aria-controls={panelId}
            onClick={() => { focusPanel.current = !open; changeOpen(!open) }}
          >
            <span>{active.length ? `${text.advanced} · ${active.length}` : text.advanced}</span>
            <ChevronIcon />
          </button> : null}
        </div>
        {extra ? <div className="cdnca-adv-filters-extra">{extra}</div> : null}
      </div>
      <div ref={panelRef} id={panelId} role="group" aria-label={text.advanced} className="cdnca-adv-filters-panel" hidden={!open || !items.length} onKeyDown={onPanelKeyDown}>
        <div className={`cdnca-adv-filters-grid cdnca-adv-filters-grid-${columns}`}>
          {items.map((item) => (
            <div key={item.key} className={item.wide ? 'cdnca-adv-filters-field is-wide' : 'cdnca-adv-filters-field'}>
              <span className="cdnca-adv-filters-label">{item.label}</span>
              {item.field}
            </div>
          ))}
        </div>
        <div className="cdnca-adv-filters-panel-footer">
          <Button type="link" disabled={!active.length} onClick={onClearAdvanced}>{text.clear}</Button>
          <Button type="primary" disabled={queryDisabled} onClick={onQuery}>{text.apply}</Button>
        </div>
      </div>
      {active.length ? (
        <ul className="cdnca-adv-filters-tags" aria-label={text.applied}>
          {active.map((item) => (
            <li key={item.key} className="cdnca-adv-filters-tag">
              <span className="cdnca-adv-filters-tag-text" title={item.applied}>{item.label}：{item.applied}</span>
              <button type="button" className="cdnca-adv-filters-tag-remove" aria-label={text.remove(item.label)} onClick={() => onRemove(item.key)}><CloseIcon /></button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
