import { render, screen } from '@testing-library/react'
import { ConfigProvider } from 'antd'
import enUS from 'antd/locale/en_US'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

import { PriceBadge, formatPlanPrice, priceBadgeState, type PriceBadgePlan } from './PriceBadge'

const now = Date.parse('2026-10-28T12:00:00Z')
const at = (ms: number) => new Date(now + ms).toISOString()
const H = 3_600_000
const promo = (left: number, thenKind: 'one_time' | 'subscription' = 'subscription'): PriceBadgePlan => ({
  kind: 'free', price_minor: 0, currency: 'CNY', promo_until: at(left), promo_then_kind: thenKind,
  promo_then_interval: thenKind === 'subscription' ? 'month' : null, promo_then_price_minor: 990,
})

describe('priceBadgeState (fix-plugpromo)', () => {
  it('counts a promo down in days, hours under a day, and shows the price once it ended', () => {
    expect(priceBadgeState(promo(3 * 24 * H), now)).toMatchObject({ kind: 'promo', unit: 'day', amount: 3 })
    expect(priceBadgeState(promo(2 * 24 * H + 1), now)).toMatchObject({ kind: 'promo', unit: 'day', amount: 3 })
    expect(priceBadgeState(promo(24 * H), now)).toMatchObject({ kind: 'promo', unit: 'day', amount: 1 })
    expect(priceBadgeState(promo(24 * H - 1), now)).toMatchObject({ kind: 'promo', unit: 'hour', amount: 24 })
    expect(priceBadgeState(promo(5 * H), now)).toMatchObject({ kind: 'promo', unit: 'hour', amount: 5 })
    expect(priceBadgeState(promo(1), now)).toMatchObject({ kind: 'promo', unit: 'hour', amount: 1 })
    expect(priceBadgeState(promo(0), now)).toMatchObject({ kind: 'paid', price: { kind: 'subscription', price_minor: 990 } })
    expect(priceBadgeState({ kind: 'free', price_minor: 0, currency: 'CNY' }, now)).toEqual({ kind: 'free' })
    expect(priceBadgeState({ kind: 'one_time', price_minor: 2900, currency: 'CNY' }, now)).toMatchObject({ kind: 'paid' })
  })

  it('formats the price', () => {
    expect(formatPlanPrice({ kind: 'subscription', interval: 'month', price_minor: 990, currency: 'CNY' })).toBe('¥9.90/月')
    expect(formatPlanPrice({ kind: 'one_time', price_minor: 2900, currency: 'CNY' })).toBe('¥29.00 一次性')
  })
})

describe('PriceBadge', () => {
  it('renders free and promo badges with an icon and the price after the promo', () => {
    const { container, rerender } = render(<PriceBadge plan={{ kind: 'free', price_minor: 0, currency: 'CNY' }} now={now} />)
    expect(screen.getByText('免费').closest('[data-price-badge]')?.getAttribute('data-price-badge')).toBe('free')
    expect(container.querySelector('svg[aria-hidden="true"]')).not.toBeNull()
    rerender(<PriceBadge plan={promo(3 * 24 * H)} now={now} />)
    const badge = screen.getByText('限免 3 天').closest('[data-price-badge]')!
    expect(badge.getAttribute('title')).toBe('限时免费，到期后 ¥9.90/月')
    expect(badge.getAttribute('aria-label')).toBe('限免 3 天，到期后 ¥9.90/月')
    rerender(<PriceBadge plan={promo(5 * H, 'one_time')} now={now} />)
    expect(screen.getByText('限免 5 小时')).toBeTruthy()
  })

  it('drops the badge and shows the price once the promo ended', () => {
    const { container, rerender } = render(<PriceBadge plan={promo(-1)} now={now} />)
    expect(container.querySelector('.cdnca-price-badge')).toBeNull()
    expect(screen.getByText('¥9.90/月')).toBeTruthy()
    rerender(<PriceBadge plan={promo(-1)} now={now} showPrice={false} />)
    expect(container.textContent).toBe('')
  })

  it('follows the antd locale', () => {
    render(<ConfigProvider locale={enUS}><PriceBadge plan={promo(5 * H)} now={now} /></ConfigProvider>)
    expect(screen.getByText('Free for 5 hours')).toBeTruthy()
  })

  it('styles only with --cdnca-* variables and has no motion', () => {
    const css = readFileSync(resolve(__dirname, 'styles.css'), 'utf8')
    const block = css.slice(css.indexOf('/* Price badges'), css.indexOf('.cdnca-price-badge-price:is(.i-theme-dark *)') + 80)
    expect(block).not.toMatch(/#[0-9a-f]{3,8}\b/i)
    expect(block).not.toMatch(/transition|animation/)
    expect(block).toMatch(/var\(--cdnca-color-green17\)/)
  })
})

describe('PromoBillingNote', () => {
  it('states the holder rules of each post-promo charging mode', async () => {
    const { PromoBillingNote } = await import('./PriceBadge')
    const { rerender } = render(<PromoBillingNote thenKind="one_time" priceMinor={2900} />)
    expect(screen.getByText(/到期后新用户按 ¥29\.00 一次性 购买；限免期间已领取的用户继续免费使用/)).toBeTruthy()
    rerender(<PromoBillingNote thenKind="subscription" priceMinor={990} />)
    expect(screen.getByText(/转为按月收费 ¥9\.90\/月：限免期间已领取的用户从到期日起按月扣费/)).toBeTruthy()
  })
})
