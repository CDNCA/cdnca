import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Select, Spin } from 'antd'
import { useTranslation } from 'react-i18next'

import type { AudienceDirectoryEntry } from '../api/announcements'
import type { AudienceOption } from './announcementAudience'
import { formatNumber } from '../i18n/formatters'

/**
 * Multi-select that searches the audience directory by name. It never shows
 * raw IDs: options and picked tags render names only.
 */
export default function AnnouncementAudienceSelect({
  value, onChange, search, toOption, placeholder, disabled, ariaLabel, id, maxCount,
}: {
  value?: AudienceOption[]
  onChange?: (value: AudienceOption[]) => void
  search: ((query: string) => Promise<AudienceDirectoryEntry[]>) | null
  toOption: (entry: AudienceDirectoryEntry) => AudienceOption
  placeholder: string
  disabled?: boolean
  ariaLabel: string
  id?: string
  maxCount?: number
}) {
  const { t } = useTranslation('announcements')
  const [options, setOptions] = useState<AudienceOption[]>([])
  const [loading, setLoading] = useState(false)
  const [failed, setFailed] = useState(false)
  const [query, setQuery] = useState('')
  const sequence = useRef(0)

  useEffect(() => {
    if (!search) {
      setOptions([])
      return
    }
    const current = ++sequence.current
    setLoading(true)
    setFailed(false)
    const timer = setTimeout(() => {
      search(query).then((entries) => {
        if (current === sequence.current) setOptions(entries.map(toOption))
      }, () => {
        if (current === sequence.current) {
          setOptions([])
          setFailed(true)
        }
      }).finally(() => {
        if (current === sequence.current) setLoading(false)
      })
    }, 250)
    return () => clearTimeout(timer)
  }, [query, search, toOption])

  return <Select<AudienceOption[]>
    id={id}
    aria-label={ariaLabel}
    mode="multiple"
    maxCount={maxCount}
    labelInValue
    showSearch
    filterOption={false}
    value={value ?? []}
    onChange={(next) => onChange?.(next.map((item) => ({ value: String(item.value), label: String(item.label) })))}
    onSearch={setQuery}
    options={options}
    placeholder={placeholder}
    disabled={disabled || !search}
    loading={loading}
    notFoundContent={loading ? <Spin size="small" /> : failed ? t('form.searchFailed') : t('form.noMatches')}
  />
}

/** Recipient preview inside a publish confirmation; zero or unknown blocks the confirm button. */
export function AudienceCountNotice({ loading, error, count, onRetry }: { loading: boolean; error: string | null; count: number | undefined; onRetry: () => void }) {
  const { t, i18n } = useTranslation('announcements')
  if (loading) return <p className="announcement-audience-count" role="status"><Spin size="small" /> {t('confirm.countingAudience')}</p>
  if (error !== null || count === undefined) {
    return <Alert className="announcement-audience-count" type="error" showIcon message={t('confirm.audienceCountFailed')} description={error ?? undefined} action={<Button size="small" onClick={onRetry}>{t('actions.retry')}</Button>} />
  }
  if (count === 0) return <Alert className="announcement-audience-count" type="warning" showIcon message={t('confirm.emptyAudience')} />
  return <p className="announcement-audience-count" role="status">{t('confirm.audienceCount', { count: formatNumber(count, i18n.resolvedLanguage ?? 'zh-CN') })}</p>
}
