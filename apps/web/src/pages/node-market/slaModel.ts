export interface SlaFormInput {
  target: number
  tiers: Array<{ below: number; credit: number }>
  maxCredit: number
  terminateAfter: number
}

// slaProblem mirrors market internal/sla Policy.Validate so the seller sees
// the reason before the market answers 400 invalid. Percentages in, ratios out.
export function slaProblem(v: SlaFormInput): string | null {
  if (!(v.target > 0 && v.target <= 100)) return 'target'
  if (v.tiers.length > 10) return 'tooMany'
  const seen = new Set<number>()
  for (const t of v.tiers) {
    if (!(t.below > 0 && t.below <= v.target) || !(t.credit > 0 && t.credit <= 100) || seen.has(t.below)) return 'tier'
    seen.add(t.below)
  }
  const sorted = [...v.tiers].sort((a, b) => a.below - b.below)
  for (let i = 1; i < sorted.length; i += 1) if (sorted[i].credit > sorted[i - 1].credit) return 'monotonic'
  if (!(v.maxCredit >= 0 && v.maxCredit <= 100) || !(v.terminateAfter >= 0 && v.terminateAfter <= 365)) return 'range'
  return null
}

