// originWeightShare: the share of traffic each origin gets from its weight
// The edge balances within one failover level
// (cdnca_origin.lua compile_pool: level 0 primaries, level n the n-th backup,
// used only when every origin of the levels before it is unusable), and a
// disabled origin is not published (edgepublish: site_origins.enabled), so a
// share is weight / sum of the enabled weights of the same level. Weights do
// not have to add up to 100.

export interface WeightedOrigin {
  weight: number
  enabled: boolean
  level?: number
}

// weightShares: each origin's share in whole percent (null: disabled, no
// traffic). Shares of one level are rounded by largest remainder so they add
// up to exactly 100; ties go to the earlier origin.
export function weightShares(origins: readonly WeightedOrigin[]): Array<number | null> {
  const shares: Array<number | null> = origins.map(() => null)
  const levels = new Map<number, number[]>()
  origins.forEach((origin, index) => {
    if (!origin.enabled || !(origin.weight > 0)) return
    const level = origin.level ?? 0
    levels.set(level, [...(levels.get(level) ?? []), index])
  })
  for (const indexes of levels.values()) {
    const total = indexes.reduce((sum, index) => sum + origins[index].weight, 0)
    const exact = indexes.map((index) => origins[index].weight * 100 / total)
    const floors = exact.map(Math.floor)
    let left = 100 - floors.reduce((sum, value) => sum + value, 0)
    const order = exact.map((value, position) => ({ position, rest: value - floors[position] }))
      .sort((a, b) => b.rest - a.rest || a.position - b.position)
    for (const { position } of order) {
      if (left <= 0) break
      floors[position] += 1
      left -= 1
    }
    indexes.forEach((index, position) => { shares[index] = floors[position] })
  }
  return shares
}

// streamOriginShares: 四层源站列表（tcp/udp v11）。所有源站同一组，down 的渲染为
// nginx "down"（l4runtime v2_compiler.go）不分流量；权重上限 edgeconfig.L4OriginWeightMax（100）。
export function streamOriginShares(origins: ReadonlyArray<{ weight?: number; down?: boolean } | undefined>): Array<number | null> {
  return weightShares(origins.map((origin) => ({ weight: Number(origin?.weight) || 0, enabled: !origin?.down })))
}
