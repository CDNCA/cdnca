import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { renderWithProviders } from '../../test/render'
import { planPrice } from './marketModel'
import { PriceTag } from './PriceTag'

const base = { id: 'p', plugin_id: 'r', revision: 1, currency: 'CNY', trial_days: 0, status: 'active', active_revision: 1 }
const plugin = (plan: Record<string, unknown>) => ({ id: 'r', plugin_id: 'acme.x', title: 'x', kind: 'rule_pack', risk_class: 'sandboxed',
  status: 'listed', price_plans: [{ ...base, ...plan }] }) as never
const hours = (h: number) => new Date(Date.now() + h * 3_600_000).toISOString()

// fix-plugpromo: the store card shows the shared @cdnca/ui badges — free, 限免 with time left (days, hours
// under a day) — and the price once the promo ended.
describe('PriceTag 限免', () => {
  it('shows the free and promo badges', () => {
    const { unmount } = renderWithProviders(<PriceTag plugin={plugin({ kind: 'free', price_minor: 0 })} />)
    expect(screen.getByText('免费').closest('[data-price-badge]')?.getAttribute('data-price-badge')).toBe('free')
    unmount()
    const promo = { kind: 'free', price_minor: 0, promo_then_kind: 'subscription', promo_then_interval: 'month', promo_then_price_minor: 990 }
    const second = renderWithProviders(<PriceTag plugin={plugin({ ...promo, promo_until: hours(72.5) })} />)
    expect(screen.getByText('限免 4 天')).toBeInTheDocument()
    second.unmount()
    const third = renderWithProviders(<PriceTag plugin={plugin({ ...promo, promo_until: hours(5.2) })} />)
    expect(screen.getByText('限免 6 小时')).toBeInTheDocument()
    third.unmount()
    renderWithProviders(<PriceTag plugin={plugin({ ...promo, promo_until: hours(-1) })} />)
    expect(screen.queryByText(/限免/)).toBeNull()
    expect(screen.getByText('收费')).toBeInTheDocument()
    expect(screen.getByText('¥9.90/月')).toBeInTheDocument()
  })

  it('names the promo deadline and the later price in the plan list', () => {
    const t = ((key: string, values?: Record<string, string>) => `${key}:${JSON.stringify(values ?? {})}`) as never
    const text = planPrice(t, { ...base, kind: 'free', price_minor: 0, promo_until: hours(24), promo_then_kind: 'one_time',
      promo_then_price_minor: 2900 } as never)
    expect(text).toMatch(/^price\.promo:/)
    expect(text).toContain('price.one_time')
  })
})
