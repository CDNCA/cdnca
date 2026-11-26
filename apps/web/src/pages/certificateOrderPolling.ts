// 证书申请状态轮询：证书页与独立申请记录页共用。
// 只在存在进行中的申请时轮询；到 issued/failed 等终态、或申请已超过卡住阈值后停止。

// 尚未出结果的申请状态。
export const inFlightOrderStatuses: ReadonlySet<string> = new Set(['pending', 'validating', 'issuing'])

// 验证/签发正常几分钟完成；超过 1 小时仍未结束的申请视为卡住，不再轮询。
export const stuckOrderAfterMs = 60 * 60 * 1000

export const certificateOrderPollMs = 4_000

interface PolledOrder {
  status: string
  created_at: string
}

export function certificateOrderPollInterval(items: readonly PolledOrder[] | undefined, now = Date.now()): number | false {
  const polling = (items ?? []).some((order) => inFlightOrderStatuses.has(order.status) &&
    !(now - Date.parse(order.created_at) > stuckOrderAfterMs))
  return polling ? certificateOrderPollMs : false
}
