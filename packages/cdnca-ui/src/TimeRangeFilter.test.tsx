import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fireEvent, render as rtlRender, screen, within } from '@testing-library/react'
import { useState, type ReactElement } from 'react'
import enUS from 'antd/locale/en_US'
import dayjs from 'dayjs'
import { describe, expect, it, vi } from 'vitest'

import {
  CdncaProvider, TimeRangeFilter, clampTimeRange, resolveTimeRangePreset, type TimeRangeFilterProps, type TimeRangeValue,
} from './index'

const render = (ui: ReactElement, locale?: typeof enUS) => rtlRender(ui, { wrapper: ({ children }) => <CdncaProvider locale={locale}>{children}</CdncaProvider> })
const now = () => dayjs('2026-10-28T10:20:30')
const fmt = (value: TimeRangeValue) => `${value.preset}|${value.range ? value.range.map((item) => item.format('YYYY-MM-DD HH:mm:ss')).join('~') : ''}`

function Probe({ initial, onChange, ...props }: Partial<TimeRangeFilterProps> & { initial: TimeRangeValue }) {
  const [value, setValue] = useState(initial)
  return <><TimeRangeFilter now={now} {...props} value={value} onChange={(next) => { setValue(next); onChange?.(next) }} /><output>{fmt(value)}</output></>
}

const day = (name: string) => screen.getAllByRole('button', { name })[0]

describe('TimeRangeFilter', () => {
  it('shows the default quick ranges and resolves one against the injected clock', () => {
    render(<Probe initial={{ preset: 'last1h', range: resolveTimeRangePreset('last1h', 'minute', now()) }} />)
    const group = screen.getByRole('group', { name: '时间范围' })
    expect(within(group).getAllByRole('radio').map((item) => item.closest('label')?.textContent))
      .toEqual(['今天', '近7天', '近30天', '自定义'])
    expect(screen.getByRole('status')).toHaveTextContent('last1h|2026-10-28 09:21:00~2026-10-28 10:21:00')
    fireEvent.click(screen.getByRole('radio', { name: '今天' }))
    expect(screen.getByRole('status')).toHaveTextContent('today|2026-10-28 00:00:00~2026-10-29 00:00:00')
    fireEvent.click(screen.getByRole('radio', { name: '近7天' }))
    expect(screen.getByRole('status')).toHaveTextContent('last7d|2026-10-21 10:21:00~2026-10-28 10:21:00')
    expect(screen.queryByRole('textbox', { name: '选择时间范围' })).not.toBeInTheDocument()
  })

  it('re-resolves the selected quick range when it is clicked again', () => {
    let clock = dayjs('2026-10-28T10:20:30')
    const onChange = vi.fn()
    render(<Probe now={() => clock} onChange={onChange} initial={{ preset: 'last7d', range: resolveTimeRangePreset('last7d', 'minute', clock) }} />)
    clock = dayjs('2026-10-28T10:40:10')
    fireEvent.click(screen.getByText('近7天'))
    expect(onChange).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('status')).toHaveTextContent('last7d|2026-10-21 10:41:00~2026-10-28 10:41:00')
    // Switching to another quick range still reports once.
    fireEvent.click(screen.getByText('今天'))
    expect(onChange).toHaveBeenCalledTimes(2)
  })

  it('aligns quick ranges to the page precision', () => {
    expect(resolveTimeRangePreset('last6h', 'hour', now())!.map((item) => item.format('HH:mm'))).toEqual(['05:00', '11:00'])
    expect(resolveTimeRangePreset('today', 'hour', now())!.map((item) => item.format('MM-DD HH:mm'))).toEqual(['10-28 00:00', '10-29 00:00'])
    expect(resolveTimeRangePreset('last7d', 'day', now())!.map((item) => item.format('MM-DD'))).toEqual(['10-22', '10-28'])
    expect(resolveTimeRangePreset('unknown', 'hour', now())).toBeNull()
  })

  it('hides quick ranges outside the retention or the longest window', () => {
    render(<Probe presets={['last1h', 'last24h', 'last7d', 'last30d']} maxSpanMs={7 * 86_400_000} minDate={now().subtract(10, 'day')}
      initial={{ preset: 'last1h', range: null }} />)
    expect(screen.getAllByRole('radio').map((item) => item.closest('label')?.textContent)).toEqual(['近1小时', '近24小时', '近7天', '自定义'])
  })

  it('labels a page-computed built-in key with the shared wording', () => {
    const start = dayjs('2026-10-28T00:00')
    render(<Probe presets={[{ key: 'today', range: () => [start, now()] }, { key: 'last7d', range: () => [start.subtract(7, 'day'), now()] }]}
      initial={{ preset: 'custom', range: null }} />)
    expect(screen.getAllByRole('radio').map((item) => item.closest('label')?.textContent)).toEqual(['今天', '近7天', '自定义'])
    fireEvent.click(screen.getByRole('radio', { name: '今天' }))
    expect(screen.getByRole('status')).toHaveTextContent('today|2026-10-28 00:00:00~2026-10-28 10:20:30')
  })

  it('picks a custom range on two months side by side, switches to time and confirms', () => {
    const onChange = vi.fn()
    render(<Probe onChange={onChange} initial={{ preset: 'last1h', range: resolveTimeRangePreset('last1h', 'minute', now()) }} />)
    fireEvent.click(screen.getByRole('radio', { name: '自定义' }))
    fireEvent.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    const dialog = screen.getByRole('dialog', { name: '选择时间范围' })
    expect(dialog).toHaveTextContent('2026年10月')
    expect(dialog).toHaveTextContent('2026年11月')
    expect(day('2026-10-28')).toHaveClass('is-today')
    fireEvent.click(day('2026-10-26'))
    expect(screen.getByRole('button', { name: '选择时间' })).toBeDisabled()
    fireEvent.click(screen.getAllByRole('button', { name: '2026-11-02' }).at(-1)!)
    fireEvent.click(screen.getByRole('button', { name: '选择时间' }))
    fireEvent.click(within(screen.getByRole('group', { name: '开始时间小时' })).getByRole('button', { name: '08' }))
    fireEvent.click(within(screen.getByRole('group', { name: '结束时间分钟' })).getByRole('button', { name: '30' }))
    fireEvent.click(screen.getByRole('button', { name: '选择日期' }))
    onChange.mockClear()
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    expect(screen.getByRole('status')).toHaveTextContent('custom|2026-10-26 08:00:00~2026-11-02 00:30:00')
    expect(onChange).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('textbox', { name: '选择时间范围' })).toHaveValue('2026-10-26 08:00 - 2026-11-02 00:30')
  })

  it('opens the custom range as a popup from the custom button on compact bars', () => {
    const onChange = vi.fn()
    render(<Probe compact onChange={onChange} initial={{ preset: 'last1h', range: resolveTimeRangePreset('last1h', 'minute', now()) }} />)
    fireEvent.click(screen.getByRole('radio', { name: '自定义' }))
    // No inline box widens the bar; the dialog opens from the button and shows the window being edited.
    expect(screen.queryByRole('textbox', { name: '选择时间范围' })).not.toBeInTheDocument()
    const dialog = screen.getByRole('dialog', { name: '选择时间范围' })
    expect(within(dialog).getByRole('status')).toHaveTextContent('2026-10-28 09:21 - 2026-10-28 10:21')
    fireEvent.click(day('2026-10-26'))
    expect(within(dialog).getByRole('status')).toHaveTextContent('选择时间范围')
    fireEvent.click(day('2026-10-27'))
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    expect(document.querySelector('output')).toHaveTextContent('custom|2026-10-26 00:00:00~2026-10-27 00:00:00')
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ preset: 'custom' }))
    const trigger = screen.getByTitle('2026-10-26 00:00 - 2026-10-27 00:00')
    expect(trigger).toHaveTextContent('自定义')
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    // Clicking the selected custom button again reopens the popup on the applied window.
    fireEvent.click(trigger)
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(within(screen.getByRole('dialog', { name: '选择时间范围' })).getByRole('status')).toHaveTextContent('2026-10-26 00:00 - 2026-10-27 00:00')
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
  })

  it('clears the custom range and keeps the old value when the popup is dismissed', () => {
    render(<Probe initial={{ preset: 'custom', range: [dayjs('2026-10-01T00:00'), dayjs('2026-10-02T00:00')] }} />)
    const input = screen.getByRole('textbox', { name: '选择时间范围' })
    fireEvent.click(input)
    fireEvent.click(day('2026-10-10'))
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
    expect(input).toHaveValue('2026-10-01 00:00 - 2026-10-02 00:00')
    fireEvent.click(input)
    fireEvent.click(screen.getByRole('button', { name: '清空' }))
    expect(screen.getByRole('status')).toHaveTextContent(/^custom\|$/)
    expect(input).toHaveValue('')
  })

  it('offers no clear when the page needs a window', () => {
    render(<Probe allowClear={false} initial={{ preset: 'custom', range: [dayjs('2026-10-01T00:00'), dayjs('2026-10-02T00:00')] }} />)
    fireEvent.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    expect(screen.queryByRole('button', { name: '清空' })).not.toBeInTheDocument()
  })

  it('keeps hour alignment, the longest window and the retention when confirming', () => {
    render(<Probe precision="hour" maxSpanMs={2 * 86_400_000} minDate={dayjs('2026-10-20T00:00')} maxDate={now()}
      initial={{ preset: 'custom', range: null }} />)
    fireEvent.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    expect(day('2026-10-19')).toBeDisabled()
    expect(day('2026-10-29')).toBeDisabled()
    fireEvent.click(day('2026-10-21'))
    // Days beyond the longest window from the start are disabled while the end is picked.
    expect(day('2026-10-25')).toBeDisabled()
    fireEvent.click(day('2026-10-23'))
    fireEvent.click(screen.getByRole('button', { name: '选择时间' }))
    // Hour precision offers hours only.
    expect(screen.queryByRole('group', { name: '开始时间分钟' })).not.toBeInTheDocument()
    fireEvent.click(within(screen.getByRole('group', { name: '结束时间小时' })).getByRole('button', { name: '05' }))
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    expect(screen.getByRole('status')).toHaveTextContent('custom|2026-10-21 00:00:00~2026-10-23 00:00:00')
  })

  it('ends a picked day at its last minute on inclusive pages', () => {
    render(<Probe endInclusive initial={{ preset: 'custom', range: null }} />)
    fireEvent.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    fireEvent.click(day('2026-10-21'))
    fireEvent.click(day('2026-10-21'))
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    expect(screen.getByRole('status')).toHaveTextContent('custom|2026-10-21 00:00:00~2026-10-21 23:59:00')
    fireEvent.click(screen.getByRole('radio', { name: '今天' }))
    expect(screen.getByRole('status')).toHaveTextContent('today|2026-10-28 00:00:00~2026-10-28 23:59:00')
  })

  // 今天结束不能落在 maxDate 之后（账户日志后端拒绝未来时间），裁到 maxDate 所在分钟的末尾（与相对快捷项同口径）。
  it('ends today at maxDate when the end may not be in the future', () => {
    render(<Probe maxDate={now()} initial={{ preset: 'custom', range: null }} />)
    fireEvent.click(screen.getByRole('radio', { name: '今天' }))
    expect(screen.getByRole('status')).toHaveTextContent('today|2026-10-28 00:00:00~2026-10-28 10:21:00')
  })

  // 快捷项与自定义框同一行（自定义框是快捷按钮组的同级），桌面不换行、
  // 自定义框约 300px；只有窄屏（<768px）整体允许换行。jsdom 不算布局，规则在样式表里核对。
  it('keeps the quick ranges and the custom box on one row on desktop', () => {
    render(<Probe initial={{ preset: 'custom', range: null }} />)
    const group = screen.getByRole('group', { name: '时间范围' })
    const input = screen.getByRole('textbox', { name: '选择时间范围' })
    expect(group).toHaveClass('cdnca-time-range')
    expect(group.querySelector(':scope > .cdnca-time-range-presets')).not.toBeNull()
    expect(input.closest('.cdnca-time-range-input')?.parentElement).toBe(group)
    const css = readFileSync(join(__dirname, 'styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')
    const phone = [...css.matchAll(/@media \(max-width: 767px\) \{([\s\S]*?)\n\}/g)].map(([, body]) => body).join('\n')
    const desktop = css.replace(/@media[^{]*\{[\s\S]*?\n\}/g, '')
    const rule = (text: string, selector: string) => [...text.matchAll(/([^{}]+)\{([^}]*)\}/g)]
      .filter(([, head]) => head.split(',').some((item) => item.trim() === selector)).map(([, , body]) => body).join('\n')
    expect(rule(desktop, '.cdnca-time-range')).toMatch(/flex-wrap: nowrap/)
    // A page toolbar shrinks its other fields, never the time range (its contents do not wrap).
    expect(rule(desktop, '.cdnca-time-range')).toMatch(/flex: none/)
    expect(rule(desktop, '.cdnca-time-range-presets')).toMatch(/flex-wrap: nowrap/)
    expect(rule(desktop, '.cdnca-time-range-presets')).toMatch(/white-space: nowrap/)
    expect(rule(desktop, '.cdnca-time-range-input')).toMatch(/width: 300px/)
    expect(rule(desktop, '.cdnca-time-range-input')).toMatch(/flex: none/)
    expect(rule(phone, '.cdnca-time-range')).toMatch(/flex-wrap: wrap/)
    // The box stays 32px even when a page toolbar forces `.ant-input { height: 32px }` on the inner input.
    expect(rule(desktop, '.cdnca-time-range .cdnca-time-range-input')).toMatch(/height: 32px/)
    expect(rule(desktop, '.cdnca-time-range .cdnca-time-range-input input.ant-input')).toMatch(/height: auto !important/)
  })

  it('clamps without widening the bounds', () => {
    const bounds = { precision: 'hour' as const, minDate: dayjs('2026-10-20T06:30'), maxDate: dayjs('2026-10-28T10:20'), maxSpanMs: 86_400_000 }
    expect(clampTimeRange([dayjs('2026-10-25T09:45'), dayjs('2026-10-19T00:00')], bounds).map((item) => item.format('MM-DD HH:mm')))
      .toEqual(['10-20 07:00', '10-21 07:00'])
    expect(clampTimeRange([dayjs('2026-10-28T08:10'), dayjs('2026-10-29T00:00')], bounds).map((item) => item.format('MM-DD HH:mm')))
      .toEqual(['10-28 08:00', '10-28 10:00'])
  })

  it('follows the antd locale', () => {
    render(<Probe initial={{ preset: 'custom', range: null }} />, enUS)
    expect(screen.getByRole('radio', { name: 'Last 7 days' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('textbox', { name: 'Select time range' }))
    expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toHaveTextContent('October 2026')
  })

  // jsdom ignores media queries, so the rule is checked in the stylesheet. Desktop keeps antd's
  // small 24px buttons (as on the competitor); under 768px the footer buttons are 32px high with a wider hit area.
  it('enlarges the footer buttons to 32px on phones only', () => {
    const css = readFileSync(join(__dirname, 'styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')
    const footerRules = (text: string) => [...text.matchAll(/([^{}]*\.cdnca-time-range-footer[^{}]*)\{([^}]*)\}/g)]
      .filter(([, selector]) => /\.ant-btn/.test(selector)).map(([, selector, body]) => `${selector.trim()}{${body}}`)
    const phone = [...css.matchAll(/@media \(max-width: 767px\) \{([\s\S]*?)\n\}/g)].map(([, body]) => body).join('\n')
    const phoneRules = footerRules(phone).join('\n')
    expect(phoneRules).toMatch(/height: 32px/)
    expect(phoneRules).toMatch(/min-width: 64px/)
    expect(phoneRules).toMatch(/padding: 0 16px/)
    const desktop = css.replace(/@media[^{]*\{[\s\S]*?\n\}/g, '')
    expect(footerRules(desktop).join('\n')).not.toMatch(/height|padding|min-width/)
    render(<Probe allowClear initial={{ preset: 'custom', range: null }} />)
    fireEvent.click(screen.getByRole('textbox', { name: '选择时间范围' }))
    const footer = screen.getByRole('button', { name: '确定' }).closest('.cdnca-time-range-footer') as HTMLElement
    for (const button of within(footer).getAllByRole('button')) expect(button).toHaveClass('ant-btn-sm')
  })
})
