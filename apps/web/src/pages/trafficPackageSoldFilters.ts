// 已售列表「用量」链接经路由 state 带走当前用户/商品/状态筛选，用量页返回时原样带回。
export type SoldFilters = { search?: string; user?: string; productID?: string; status?: string }

export function soldFiltersFrom(state: unknown): SoldFilters {
  const value = (state as { soldFilters?: Record<string, unknown> } | null)?.soldFilters
  const text = (key: keyof SoldFilters) => typeof value?.[key] === 'string' && value[key] ? value[key] as string : undefined
  return { search: text('search'), user: text('user'), productID: text('productID'), status: text('status') }
}
