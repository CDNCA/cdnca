import { App } from 'antd'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../../api/auth'
import { marketUnavailable } from '../../../api/market'
import { supplyInUse } from '../../../api/marketSupplier'
import { useSessionStore } from '../../../auth/session'
import { formatDateTime } from '../../../i18n/formatters'
import '../../../i18n/marketSupplier'
import { useFeedback } from '@cdnca/ui'

export function useToken() {
  return useSessionStore((state) => state.accessToken) ?? ''
}

// errorText explains a market refusal; supply_in_use carries the two counts.
export function useErrorText() {
  const { t } = useTranslation('marketSupplier')
  return (error: unknown) => {
    if (marketUnavailable(error)) return t('common.unavailable')
    const inUse = supplyInUse(error)
    if (inUse) return t('supplyInUse', { online: inUse.online_available, normal: inUse.normal_subscriptions })
    if (error instanceof ApiError && error.code === 'market_managed') return t('marketManaged')
    if (error instanceof ApiError && error.code === 'offer_changed') return t('switches.changed')
    // MC09: quota used up is its own refusal, not a missing permission.
    if (error instanceof ApiError && error.code === 'offer_quota_exceeded') return t('nodeMarket:quota.exceeded')
    return t('common.failed', { code: error instanceof ApiError ? error.code : 'request_failed' })
  }
}

// useWrite runs a market write, toasts success/failure and refreshes the node market queries.
export function useWrite<A, R>(fn: (args: A) => Promise<R>, successKey: string, onDone?: (result: R) => void) {
  const { t } = useTranslation('marketSupplier')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const client = useQueryClient()
  const errorText = useErrorText()
  return useMutation({
    mutationFn: fn,
    onSuccess: (result) => {
      void message.success(t(successKey))
      void client.invalidateQueries({ queryKey: ['nodeMarket'] })
      onDone?.(result)
    },
    onError: (error) => {
      // 卡 11：报价已在别处修改（409 offer_changed），刷新列表让下一次操作基于最新修订。
      if (error instanceof ApiError && error.code === 'offer_changed') void client.invalidateQueries({ queryKey: ['nodeMarket'] })
      void feedback.error(errorText(error))
    },
  })
}

export function useTime() {
  const { i18n } = useTranslation()
  return (value?: string | null) => (value ? formatDateTime(value, i18n.resolvedLanguage ?? 'zh-CN') || value : '—')
}

export function formatBytes(value: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${Number.isInteger(size) ? size : size.toFixed(1)} ${units[unit]}`
}
