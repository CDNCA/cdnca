import { useState, type ReactNode } from 'react'
import { Alert, Button, Space, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { marketForbidden, marketUnavailable } from '../../../api/market'
import '../../../i18n/marketSupplier'
import { FeedbackWhen } from '@cdnca/ui'

// NotOpen explains in place that this licence does not include the function.
export function NotOpen({ scope }: { scope: 'sell' | 'market' }) {
  const { t } = useTranslation('marketSupplier')
  return <Alert type="info" showIcon className="market-not-open" message={t(scope === 'sell' ? 'common.notSelling' : 'common.notOpen')}
    description={t(scope === 'sell' ? 'common.notSellingDetail' : 'common.notOpenDetail')} />
}

// LoadFailure is the in-page answer to a failed automatic load: a 403 (function not
// in the licence) and an unavailable market are explained in place; anything else
// keeps the error dialog with its code.
export function LoadFailure({ error, title, scope = 'market' }: { error: unknown; title: ReactNode; scope?: 'sell' | 'market' }) {
  const { t } = useTranslation('marketSupplier')
  if (marketForbidden(error)) return <NotOpen scope={scope} />
  if (marketUnavailable(error)) return <Alert type="info" showIcon message={t('common.unavailable')} />
  return <FeedbackWhen title={title} />
}

// useCursorPages keeps the stack of next_cursor values walked so far; the
// current page is requested with the top cursor (none for page 1).
export function useCursorPages() {
  const [cursors, setCursors] = useState<string[]>([])
  return {
    cursor: cursors.at(-1), page: cursors.length + 1,
    prev: () => setCursors((c) => c.slice(0, -1)),
    next: (cursor: string) => setCursors((c) => [...c, cursor]),
    reset: () => setCursors([]),
  }
}

// CursorPager: server-side paging driven by next_cursor. The market returns no
// total, so it shows how many rows the pages walked so far hold (every earlier
// page is full, since next_cursor is only set when more rows exist).
export function CursorPager({ pages, pageSize, count, next, busy }: {
  pages: ReturnType<typeof useCursorPages>; pageSize: number; count: number; next?: string | null; busy: boolean
}) {
  const { t } = useTranslation('marketSupplier')
  return (
    <Space>
      <Button disabled={pages.page === 1 || busy} onClick={pages.prev}>{t('common.prevPage')}</Button>
      <Button disabled={!next || busy} onClick={() => next && pages.next(next)}>{t('common.nextPage')}</Button>
      <Typography.Text type="secondary">{t('common.loaded', { page: pages.page, count: (pages.page - 1) * pageSize + count })}</Typography.Text>
    </Space>
  )
}

export function SupplyStateTag({ value }: { value: string }) {
  const { t } = useTranslation('marketSupplier')
  const color = value === 'serving' ? 'success' : value === 'stopped' || value === 'no_supply' ? 'error' : value === 'paused' ? 'warning' : 'default'
  return <Tag color={color}>{t(`states.${value}`, { defaultValue: value })}</Tag>
}

export function Short({ value }: { value?: string | null }) {
  if (!value) return <>—</>
  return <Typography.Text code copyable={{ text: value }}>{value.length > 12 ? value.slice(0, 8) : value}</Typography.Text>
}
