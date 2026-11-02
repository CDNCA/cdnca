import type { TFunction } from 'i18next'

import type { SiteAccessReadiness as Readiness } from '../../api/sites'
import '../../i18n/siteAccessReadiness'

// access_readiness 的文案（列表、详情头与详情卡共用）。

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

// 解析指向别处时写出域名、当前值与应改成的 CNAME（旧版本存下的检查结果没有观测值，用通用文案）。
export function dnsMismatchReason(t: Translate, check: Check): string | null {
  const mismatch = check.code === 'dns_resolved' && check.detail === 'dns_points_elsewhere' ? check.dns_mismatch : undefined
  if (!mismatch?.observed.length) return null
  return t('dnsMismatch.reason', {
    domain: mismatch.domain, observed: mismatch.observed.join(t('publishFailure.separator')), cname: mismatch.expected_cname,
  })
}

// 检查项原因：发布失败与解析指向别处有细节时用细节，否则按原因码。
export function checkReason(t: Translate, exists: (key: string) => boolean, check: Check): string {
  return publishFailureReason(t, exists, check) ?? dnsMismatchReason(t, check) ?? lookup(t, exists, 'reasons', check)
}

// 发布失败的原因写出失败节点名与原因（节点上报的 error_code，没有就用部署状态；只有平台管理员
// 拿得到节点明细，租户只有失败节点数与归一化原因），或自动发布在下发前就失败的终态码；服务端没给细节时用通用文案。
export function publishFailureReason(t: Translate, exists: (key: string) => boolean, check: Check): string | null {
  if (check.code !== 'published' || check.detail !== 'publish_failed') return null
  if (check.failed_nodes?.length) {
    const nodes = check.failed_nodes.map((node) => t('publishFailure.node', {
      name: node.node_name,
      reason: node.error_code ?? t(`publishFailure.nodeStates.${node.state}` as 'title'),
    })).join(t('publishFailure.separator'))
    return t('publishFailure.nodes', { nodes })
  }
  // 租户：服务端不给节点明细（平台节点名不给用户看），只写失败节点数与原因。
  if (check.failed_node_count) {
    const reasons = (check.failed_node_reasons ?? []).map((code) => {
      const key = `publishFailure.nodeReasons.${code}`
      return exists(`siteAccessReadiness:${key}`) ? t(key as 'title') : t('publishFailure.nodeReasons.default', { code })
    }).join(t('publishFailure.separator'))
    return reasons ? t('publishFailure.count', { count: check.failed_node_count, reasons })
      : t('publishFailure.countOnly', { count: check.failed_node_count })
  }
  if (check.failure_code) {
    const key = `publishFailure.requestReasons.${check.failure_code}`
    const reason = exists(`siteAccessReadiness:${key}`) ? t(key as 'title')
      : t('publishFailure.requestReasons.default', { code: check.failure_code })
    return t('publishFailure.request', { reason })
  }
  return null
}
