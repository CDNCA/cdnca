import type { TFunction } from 'i18next'

import type { SiteAccessReadiness as Readiness } from '../../api/sites'
import '../../i18n/siteAccessReadiness'

// fix-readiness：access_readiness 的文案（列表、详情头与详情卡共用）。

export type Check = Readiness['checks'][number]
export type Translate = TFunction<'siteAccessReadiness'>

export function firstFailing(readiness: Readiness): Check | undefined {
  return readiness.checks.find((check) => !check.ok)
}

// 原因码映射到文案：有该码的文案用它，否则用这一项的通用文案（服务端新增的码也能显示）。
export function lookup(t: Translate, exists: (key: string) => boolean, group: 'short' | 'reasons', check: Check): string {
  const specific = `${group}.${check.code}.${check.detail}`
  if (check.detail && exists(`siteAccessReadiness:${specific}`)) return t(specific as 'title')
  return t(`${group}.${check.code}.default` as 'title')
}

export function accessStatusLabel(readiness: Readiness, t: Translate, exists: (key: string) => boolean): string {
  const failing = firstFailing(readiness)
  if (readiness.state === 'ready' || !failing) return t('state.ready')
  return t(`state.${readiness.state}`, { check: lookup(t, exists, 'short', failing) })
}
