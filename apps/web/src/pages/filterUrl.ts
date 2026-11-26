// 已生效的筛选条件写进 URL（replace，不进浏览历史），
// 链接可分享；打开带参数的链接时页面用 filterParam 读回初值。只写本页管理的键，其它参数原样保留。
// 换会话（另一个账号）时页面重挂载：URL 里是上一会话自己写进去的条件，不读回（会话间不带条件）；
// 外部打开的链接（不是本标签页写的）照常读。
import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'

import { useSessionStore } from '../auth/session'

export type FilterUrlValues = Record<string, string | number | boolean | undefined | null>

// 本标签页最近写进 URL 的 键=值 及写入时的会话代际。
const written = new Map<string, number>()

function text(value: FilterUrlValues[string]): string {
  return value === undefined || value === null || value === false ? '' : String(value).trim()
}

export function useFilterUrl(values: FilterUrlValues) {
  const [searchParams, setSearchParams] = useSearchParams()
  const epoch = useSessionStore((state) => state.sessionEpoch)
  const key = JSON.stringify(values)
  useEffect(() => {
    const next = new URLSearchParams(searchParams)
    for (const [name, value] of Object.entries(values)) {
      const shown = text(value)
      if (shown) { next.set(name, shown); written.set(`${name}=${shown}`, epoch) }
      else next.delete(name)
    }
    if (next.toString() !== searchParams.toString()) setSearchParams(next, { replace: true })
  // values 以 key 判等；searchParams 变化（他处改 URL）不回写。
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])
}

/** A filter's initial value from the URL ('' when absent or written by an earlier session in this tab). */
export function filterParam(searchParams: URLSearchParams, name: string): string {
  const value = (searchParams.get(name) ?? '').trim()
  if (!value) return ''
  const by = written.get(`${name}=${value}`)
  return by !== undefined && by !== useSessionStore.getState().sessionEpoch ? '' : value
}

/**
 * TimeRangeFilter 的已生效范围写进 URL。
 * 快捷项写 range=<key>（默认项不写），自定义写 from/to（ISO）。
 */
export function timeRangeUrlValues(preset: string, from: string, to: string, defaultPreset = 'today'): FilterUrlValues {
  if (preset === 'custom') return { range: undefined, from, to }
  return { range: preset === defaultPreset ? undefined : preset, from: undefined, to: undefined }
}

/** 读回 timeRangeUrlValues 写的范围：页面提供的快捷项、或两端都能解析的自定义区间；其余（缺省、非法）为 null，用页面默认。 */
export function linkedTimeRange(searchParams: URLSearchParams, presets: readonly string[]): { preset: string; range?: [Date, Date] } | null {
  const preset = filterParam(searchParams, 'range')
  if (preset && presets.includes(preset)) return { preset }
  const from = Date.parse(filterParam(searchParams, 'from'))
  const to = Date.parse(filterParam(searchParams, 'to'))
  return Number.isFinite(from) && Number.isFinite(to) && from < to ? { preset: 'custom', range: [new Date(from), new Date(to)] } : null
}

/** Forgets what this tab wrote (test isolation: each test is a fresh tab). */
export function clearFilterUrlMemory() {
  written.clear()
}
