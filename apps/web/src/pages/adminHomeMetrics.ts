import type { DashboardAnalyticsOverview } from '../api/dashboard'

// Home page peak bandwidth: the busiest 5-minute window when the analytics
// store provides it (FX36), otherwise the busiest hourly average.
export function peakHourlyBandwidth(analytics: DashboardAnalyticsOverview): number | null {
  if (analytics.peak_bandwidth_bps !== undefined) {
    const peak = Number(analytics.peak_bandwidth_bps)
    if (Number.isFinite(peak) && peak >= 0) return peak
  }
  const values = analytics.trend
    .map((point) => point.average_bandwidth_bps)
    .filter((value) => Number.isFinite(value) && value >= 0)
  return values.length > 0 ? Math.max(...values) : null
}
