import type { OriginProbeStatus } from '../../api/siteOriginStatus'
import type { SiteAccessReadiness, SiteOperationalStatus } from '../../api/sites'

// 首装验收：网站“正常”只在接入（线路/CNAME/解析/证书/发布）与源站都就绪时显示；“配置已同步”单独展示，不参与判定。
// 只在运行态为 normal 时用它（锁定、流量超限等照旧）。
export type SiteHeadline = 'normal' | 'accessBlocked' | 'accessPending' | 'originUnhealthy'

export function siteHeadline(input: {
  readiness?: SiteAccessReadiness | null
  /** 旧接口没有 access_readiness 时按 siteAccessGap 判定。 */
  accessGap?: string | null
  /** 源站拨测总体状态；没读到时不参与判定。 */
  originOverall?: OriginProbeStatus | null
}): SiteHeadline {
  if (input.readiness) {
    if (input.readiness.state === 'blocked') return 'accessBlocked'
    if (input.readiness.state === 'pending') return 'accessPending'
  } else if (input.accessGap) {
    return 'accessPending'
  }
  return input.originOverall === 'unhealthy' ? 'originUnhealthy' : 'normal'
}

/** 页头主状态的判定（文案键与颜色）。 */
export function siteHeadlineTag(input: {
  statusState: SiteOperationalStatus
  headline: SiteHeadline
}): { labelKey: string; color: 'success' | 'warning' | 'error' } {
  if (input.statusState !== 'normal') {
    return { labelKey: `states.${input.statusState}`, color: input.statusState === 'locked' ? 'error' : 'warning' }
  }
  if (input.headline === 'accessBlocked' || input.headline === 'accessPending') {
    return { labelKey: `states.headline.${input.headline}`, color: input.headline === 'accessPending' ? 'warning' : 'error' }
  }
  if (input.headline === 'originUnhealthy') return { labelKey: 'states.headline.originUnhealthy', color: 'error' }
  return { labelKey: 'states.active', color: 'success' }
}
