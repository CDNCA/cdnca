import { describe, expect, it } from 'vitest'

import { splitText } from './split'
import { MIN_SEGMENT, barBackground, barStops, daySplit, type Day } from './model'

const day = (patch: Partial<Day>): Day => ({ day: '2026-11-12', status: 'operational', uptime: 1, ...patch })

describe('day bar split by the share of each state', () => {
  it('has no split for a day without samples, and a plain green bar for a clean day', () => {
    expect(daySplit(day({ status: 'no_data', uptime: null }))).toBeNull()
    expect(daySplit(day({ status: 'before_monitoring', uptime: null }))).toBeNull()
    expect(barStops(daySplit(day({ sampled: 1440 }))!)).toBeNull()
  })

  it('derives operational minutes from older data that lacks operational and no_data', () => {
    expect(daySplit(day({ sampled: 1440, outage: 56 }))).toEqual({ operational: 1384, degraded: 0, outage: 56, maintenance: 0, no_data: 0 })
  })

  it('stacks bottom to top: operational, degraded, outage, maintenance, no data', () => {
    const stops = barStops({ operational: 600, degraded: 240, outage: 300, maintenance: 100, no_data: 200 })!
    expect(stops.map((stop) => stop.key)).toEqual(['operational', 'degraded', 'outage', 'maintenance', 'no_data'])
    expect(stops[0].from).toBe(0)
    expect(stops[stops.length - 1].to).toBe(1)
    for (let i = 1; i < stops.length; i += 1) expect(stops[i].from).toBeCloseTo(stops[i - 1].to, 10)
  })

  it('gives a short outage a visible minimum height taken from the largest segment', () => {
    const stops = barStops({ operational: 1439, degraded: 0, outage: 1, maintenance: 0, no_data: 0 })!
    const outage = stops.find((stop) => stop.key === 'outage')!
    expect(outage.to - outage.from).toBeCloseTo(MIN_SEGMENT, 6)
    const operational = stops.find((stop) => stop.key === 'operational')!
    expect(operational.to - operational.from).toBeCloseTo(1 - MIN_SEGMENT, 6)
  })

  it('counts today only up to the time that has passed (no data is the passed time nobody sampled)', () => {
    const split = daySplit(day({ sampled: 600, outage: 10, operational: 590, no_data: 30 }))!
    expect(split.no_data).toBe(30)
    expect(Object.values(split).reduce((a, b) => a + b, 0)).toBe(630)
  })

  it('writes the CSS gradient with the status colour variables', () => {
    const css = barBackground({ operational: 1384, degraded: 0, outage: 56, maintenance: 0, no_data: 0 })!
    expect(css).toContain('linear-gradient(to top')
    expect(css).toContain('var(--bar-ok)')
    expect(css).toContain('var(--bar-bad)')
  })

  it('lists the durations of the day in words', () => {
    const text = splitText(day({ sampled: 1440, outage: 56, operational: 1384, no_data: 0 }), 'zh')
    expect(text).toBe('正常 23 小时 4 分钟、中断 56 分钟')
    expect(splitText(day({ status: 'no_data', uptime: null }), 'zh')).toBe('')
  })
})
