// Pure helpers of the ML-28 pages (kept out of component files for fast refresh).

// sellingFeatures: the lease codes that open the supplier side (market-service subscribers.go:122).
export const sellingFeatures = ['market.sell', 'market.resell']

// commissionDaysLeft from the last 7 days of deductions; null when nothing was deducted.
export function commissionDaysLeft(balance: number, last7: number): number | null {
  if (last7 <= 0) return null
  return Math.max(0, Math.floor(balance / (last7 / 7)))
}

// remaining formats the wait until cancel_available_at as "M:SS" / "H:MM:SS".
export function remaining(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  const pad = (n: number) => String(n).padStart(2, '0')
  return h ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`
}
