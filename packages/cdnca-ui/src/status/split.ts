import { duration, fill, messages } from './i18n'
import { SPLIT_ORDER, daySplit, type Day, type Lang } from './model'

/** 「正常 23 小时 4 分，中断 56 分」：当天各状态的时长，为 0 的不写；没有样本的日子返回空串。 */
export function splitText(day: Day, lang: Lang): string {
  const split = daySplit(day)
  if (!split) return ''
  const m = messages(lang)
  const label: Record<(typeof SPLIT_ORDER)[number], string> = {
    operational: m.tipOperational, degraded: m.tipDegraded, outage: m.tipOutage, maintenance: m.tipMaintenance, no_data: m.tipNoDataTime,
  }
  return SPLIT_ORDER.filter((key) => split[key] > 0).map((key) => fill(label[key], { value: duration(split[key], lang) })).join(m.listSeparator)
}
