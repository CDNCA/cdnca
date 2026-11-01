import { useRef, useState } from 'react'
import { keepPreviousData } from '@tanstack/react-query'

// control-log-ui：日志列表类查询的共同读取选项。
// - 30 秒内回到同一代际里看过的页（上一页、切回 tab）直接用缓存，不再打接口。
// - 翻页/改条件时保留上一页的行并盖加载遮罩，表格不闪成空表。换账号/会话代际时
//   SessionQueryBoundary 清空整个缓存，上一账号的行不会被沿用。
//   页面须在 isPlaceholderData 时禁用「下一页」，免得拿上一页的 next_cursor 再翻一次。
export const logListQueryOptions = {
  staleTime: 30_000,
  // 离开的页保留 5 分钟（同 react-query 默认，写明以免被测试/外层的 gcTime 覆盖成立即回收）。
  gcTime: 5 * 60_000,
  placeholderData: keepPreviousData,
} as const

/**
 * 读取代际（放进 queryKey）：筛选条件（不含游标/页码/tab）一变或调用 renew（刷新/查询回第一页）就加一，
 * 于是改条件、移除条件、刷新都按最新数据重读，缓存只在同一代际内的翻页与切 tab 时复用。
 * 在渲染中同步换代，第一帧就用新键，不会先用旧代际多发一次。
 */
export function useLogListGeneration(conditions: unknown): [number, () => void] {
  const key = JSON.stringify(conditions)
  const seen = useRef({ key, generation: 0 })
  const [renewed, setRenewed] = useState(0)
  if (seen.current.key !== key) seen.current = { key, generation: seen.current.generation + 1 }
  return [seen.current.generation + renewed, () => setRenewed((value) => value + 1)]
}
