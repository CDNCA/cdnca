// Time range filter shared by every query page. Quick ranges sit on the left as a button
// group; "custom" adds a "select time range" box whose popup shows two months
// side by side, a "select time" switch to hours/minutes and clear / OK in the
// footer. antd's RangePicker cannot show two months once showTime is on
// (rc-picker renders one month next to the time columns), so the popup is
// built here from antd Popover / Input / Button.
import { useContext, useState, type ReactElement } from 'react'
import { Button, ConfigProvider, Input, Popover, Radio } from 'antd'
import dayjs, { type Dayjs } from 'dayjs'

export type TimeRange = [Dayjs, Dayjs]
/** preset is a preset key or 'custom'; range is the window the page queries (null after clearing a custom range). */
export interface TimeRangeValue { preset: string; range: TimeRange | null }
export type TimeRangePrecision = 'day' | 'hour' | 'minute' | 'second'
export type TimeRangePresetKey = 'today' | 'yesterday' | 'last1h' | 'last6h' | 'last12h' | 'last24h' | 'last7d' | 'last30d'
/** A page-computed quick range; label may be omitted for a built-in key (the shared wording is used). */
export interface TimeRangePreset { key: string; label?: string; range: (now: Dayjs, precision: TimeRangePrecision) => TimeRange }

// Every page offers the same quick ranges plus custom;
// ranges the page's retention or longest window cannot hold are hidden by presetFits.
export const DEFAULT_TIME_RANGE_PRESETS: readonly TimeRangePresetKey[] = ['today', 'last7d', 'last30d']

const texts = {
  'zh-CN': {
    today: '今天', yesterday: '昨天', last1h: '近1小时', last6h: '近6小时', last12h: '近12小时', last24h: '近24小时', last7d: '近7天', last30d: '近30天',
    custom: '自定义', range: '时间范围', placeholder: '选择时间范围', selectTime: '选择时间', selectDate: '选择日期', clear: '清空', confirm: '确定',
    previousYear: '上一年', previousMonth: '上个月', nextMonth: '下个月', nextYear: '下一年', from: '开始时间', to: '结束时间', hour: '小时', minute: '分钟', second: '秒',
  },
  'zh-TW': {
    today: '今天', yesterday: '昨天', last1h: '近1小時', last6h: '近6小時', last12h: '近12小時', last24h: '近24小時', last7d: '近7天', last30d: '近30天',
    custom: '自訂', range: '時間範圍', placeholder: '選擇時間範圍', selectTime: '選擇時間', selectDate: '選擇日期', clear: '清空', confirm: '確定',
    previousYear: '上一年', previousMonth: '上個月', nextMonth: '下個月', nextYear: '下一年', from: '開始時間', to: '結束時間', hour: '小時', minute: '分鐘', second: '秒',
  },
  'en-US': {
    today: 'Today', yesterday: 'Yesterday', last1h: 'Last hour', last6h: 'Last 6 hours', last12h: 'Last 12 hours', last24h: 'Last 24 hours', last7d: 'Last 7 days', last30d: 'Last 30 days',
    custom: 'Custom', range: 'Time range', placeholder: 'Select time range', selectTime: 'Select time', selectDate: 'Select date', clear: 'Clear', confirm: 'OK',
    previousYear: 'Previous year', previousMonth: 'Previous month', nextMonth: 'Next month', nextYear: 'Next year', from: 'Start time', to: 'End time', hour: 'hour', minute: 'minute', second: 'second',
  },
}
type Texts = typeof texts['zh-CN']

function useTexts(): [Texts, string] {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  const key = locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN'
  return [texts[key], key]
}

const units = { day: [], hour: ['hour'], minute: ['hour', 'minute'], second: ['hour', 'minute', 'second'] } as const
const formats = { day: 'YYYY-MM-DD', hour: 'YYYY-MM-DD HH:00', minute: 'YYYY-MM-DD HH:mm', second: 'YYYY-MM-DD HH:mm:ss' } as const

/** Drops everything below the precision (minute precision clears seconds and milliseconds). */
export function alignTime(value: Dayjs, precision: TimeRangePrecision): Dayjs {
  return value.startOf(precision)
}

// Relative presets end at the current bucket's end so it is included (hour precision at 10:20 ends at 11:00);
// today and yesterday are whole days, as the pages' former default windows were.
const presetRanges: Record<TimeRangePresetKey, TimeRangePreset['range']> = {
  today: (now, p) => p === 'day' ? [now.startOf('day'), now.startOf('day')] : [now.startOf('day'), now.add(1, 'day').startOf('day')],
  yesterday: (now, p) => p === 'day' ? [now.subtract(1, 'day').startOf('day'), now.subtract(1, 'day').startOf('day')] : [now.subtract(1, 'day').startOf('day'), now.startOf('day')],
  last1h: (now, p) => hours(now, p, 1),
  last6h: (now, p) => hours(now, p, 6),
  last12h: (now, p) => hours(now, p, 12),
  last24h: (now, p) => hours(now, p, 24),
  last7d: (now, p) => days(now, p, 7),
  last30d: (now, p) => days(now, p, 30),
}
function ceil(now: Dayjs, precision: TimeRangePrecision): Dayjs {
  const floor = alignTime(now, precision)
  return floor.isSame(now) ? floor : floor.add(1, precision)
}
function hours(now: Dayjs, precision: TimeRangePrecision, count: number): TimeRange {
  const end = ceil(now, precision === 'day' ? 'hour' : precision)
  return [end.subtract(count, 'hour'), end]
}
function days(now: Dayjs, precision: TimeRangePrecision, count: number): TimeRange {
  if (precision === 'day') return [now.startOf('day').subtract(count - 1, 'day'), now.startOf('day')]
  const end = ceil(now, precision)
  return [end.subtract(count, 'day'), end]
}

function presetOf(item: TimeRangePresetKey | TimeRangePreset, text: Texts): TimeRangePreset & { label: string } {
  if (typeof item === 'string') return { key: item, label: text[item], range: presetRanges[item] }
  return { ...item, label: item.label ?? (item.key in presetRanges ? text[item.key as TimeRangePresetKey] : item.key) }
}

/** The window of a preset key at `now` (pages re-resolve a relative preset when the user queries again); any built-in key resolves by default. */
export function resolveTimeRangePreset(key: string, precision: TimeRangePrecision = 'minute', now: Dayjs = dayjs(),
  presets: readonly (TimeRangePresetKey | TimeRangePreset)[] = Object.keys(presetRanges) as TimeRangePresetKey[]): TimeRange | null {
  const item = presets.find((preset) => (typeof preset === 'string' ? preset : preset.key) === key)
  return item ? presetOf(item, texts['zh-CN']).range(now, precision) : null
}

export interface TimeRangeBounds {
  precision?: TimeRangePrecision
  /** Earliest selectable moment (data retention). */
  minDate?: Dayjs
  /** Latest selectable moment. */
  maxDate?: Dayjs
  /** Longest allowed window in milliseconds. */
  maxSpanMs?: number
  /** The page's end is inclusive: a picked end day ends at 23:59 (minute) / 23:59:59 (second) instead of the next 00:00. */
  endInclusive?: boolean
}

/** Orders, aligns and clips a custom range into the bounds (never widens them). */
export function clampTimeRange([first, second]: TimeRange, { precision = 'minute', minDate, maxDate, maxSpanMs }: TimeRangeBounds): TimeRange {
  let [start, end] = first.isAfter(second) ? [second, first] : [first, second]
  if (minDate && start.isBefore(minDate)) start = ceil(minDate, precision)
  if (maxDate && end.isAfter(maxDate)) end = maxDate
  if (maxSpanMs !== undefined && end.diff(start) > maxSpanMs) end = start.add(maxSpanMs, 'millisecond')
  start = alignTime(start, precision)
  end = alignTime(end, precision)
  return [start, end.isBefore(start) ? start : end]
}

function presetFits(range: TimeRange, { minDate, maxSpanMs }: TimeRangeBounds) {
  return !(minDate && range[0].isBefore(minDate)) && !(maxSpanMs !== undefined && range[1].diff(range[0]) > maxSpanMs)
}

export interface TimeRangeFilterProps extends TimeRangeBounds {
  value: TimeRangeValue
  onChange: (value: TimeRangeValue) => void
  /** Quick ranges in display order (default DEFAULT_TIME_RANGE_PRESETS); ranges outside the bounds are hidden. */
  presets?: readonly (TimeRangePresetKey | TimeRangePreset)[]
  /** Offer "custom" (default true). */
  custom?: boolean
  /** Show clear in the custom box and popup (default true); pages that need a window pass false. */
  allowClear?: boolean
  /** Group label (default "time range"). */
  label?: string
  className?: string
  /** Form identity: the quick-range radios get it as name, the custom box `${id}-custom` as id. */
  id?: string
  disabled?: boolean
  /** Injectable clock for tests. */
  now?: () => Dayjs
  /**
   * Single-row filter bars: no "select time range" box next to the quick
   * ranges; choosing or clicking "custom" opens the two-month popup from the button itself, and the
   * applied window is the button's title.
   */
  compact?: boolean
}

export function TimeRangeFilter({
  value, onChange, presets = DEFAULT_TIME_RANGE_PRESETS, custom = true, allowClear = true, label, className, id, disabled, now = dayjs, compact, ...bounds
}: TimeRangeFilterProps) {
  const [text] = useTexts()
  const precision = bounds.precision ?? 'minute'
  const current = now()
  const popup = useCustomPopup(value.range, now, disabled)
  const items = presets.map((item) => presetOf(item, text)).filter((item) => presetFits(item.range(current, precision), bounds))
  const customProps = { id: id ? `${id}-custom` : undefined, popup, value: value.range, bounds: { ...bounds, precision }, allowClear, disabled, now,
    onChange: (range: TimeRange | null) => onChange({ preset: 'custom', range }) }
  const customLabel = compact
    ? <CustomRange {...customProps} trigger={<span className="cdnca-time-range-custom-trigger" aria-haspopup="dialog" aria-expanded={popup.open}
      title={value.preset === 'custom' && value.range ? showRange(value.range, precision) : undefined}>{text.custom}</span>} />
    : text.custom
  const options = [...items.map((item) => ({ value: item.key, label: item.label })), ...(custom ? [{ value: 'custom', label: customLabel }] : [])]
  const choose = (key: string) => {
    if (key === 'custom') {
      if (compact) popup.toggle(true)
      onChange({ preset: 'custom', range: value.range })
      return
    }
    const item = items.find((preset) => preset.key === key)
    if (!item) return
    const [from, to] = item.range(now(), precision)
    // Inclusive pages stop one unit before the next window starts (today ends at 23:59:59).
    let end = bounds.endInclusive && precision !== 'day' ? to.subtract(1, precision) : to
    // Pages whose end may not be in the future (maxDate) end today at the current bucket instead of midnight.
    if (bounds.maxDate && end.isAfter(ceil(bounds.maxDate, precision))) end = ceil(bounds.maxDate, precision)
    onChange({ preset: key, range: [from, end] })
  }
  return <div className={['cdnca-time-range', className].filter(Boolean).join(' ')} role="group" aria-label={label ?? text.range}>
    {/* Clicking the selected quick range again re-resolves it against the clock (a radio fires no change then). */}
    <Radio.Group className="cdnca-time-range-presets" name={id} optionType="button" buttonStyle="solid" disabled={disabled}
      value={value.preset} onChange={(event) => choose(event.target.value as string)}
      options={options.map((option) => option.value === value.preset && option.value !== 'custom'
        ? { ...option, label: <span onClick={() => choose(option.value)}>{option.label}</span> } : option)} />
    {custom && !compact && value.preset === 'custom' ? <CustomRange {...customProps} /> : null}
  </div>
}

type Draft = [Dayjs | null, Dayjs | null]

const showRange = (range: Draft, precision: TimeRangePrecision) => range[0] && range[1] ? `${range[0].format(formats[precision])} - ${range[1].format(formats[precision])}` : ''

/** Open state and the draft being edited; opening starts the draft from the applied window. */
function useCustomPopup(value: TimeRange | null, now: () => Dayjs, disabled?: boolean) {
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState<Draft>([null, null])
  const [month, setMonth] = useState(() => now().startOf('month'))
  const [timeMode, setTimeMode] = useState(false)
  const toggle = (next: boolean) => {
    if (disabled) return
    if (next) {
      setDraft(value ? [value[0], value[1]] : [null, null])
      setMonth((value?.[0] ?? now()).startOf('month'))
      setTimeMode(false)
    }
    setOpen(next)
  }
  return { open, setOpen, draft, setDraft, month, setMonth, timeMode, setTimeMode, toggle }
}

function Chevron({ double, left }: { double?: boolean; left?: boolean }) {
  const path = double ? (left ? 'M11 17l-5-5 5-5M18 17l-5-5 5-5' : 'M13 17l5-5-5-5M6 17l5-5-5-5') : (left ? 'M15 18l-6-6 6-6' : 'M9 18l6-6-6-6')
  return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={path} /></svg>
}

function CustomRange({ id, popup, value, bounds, allowClear, disabled, now, onChange, trigger }: {
  id?: string
  popup: ReturnType<typeof useCustomPopup>
  value: TimeRange | null
  bounds: TimeRangeBounds & { precision: TimeRangePrecision }
  allowClear: boolean
  disabled?: boolean
  now: () => Dayjs
  onChange: (range: TimeRange | null) => void
  /** Compact bars: the popup opens from this element (the "custom" button) instead of a "select time range" box. */
  trigger?: ReactElement
}) {
  const [text, locale] = useTexts()
  const { precision, minDate, maxDate, maxSpanMs, endInclusive } = bounds
  const { open, setOpen, draft, setDraft, month, setMonth, timeMode, setTimeMode, toggle } = popup
  const complete = Boolean(draft[0] && draft[1])
  const show = (range: Draft) => showRange(range, precision)
  const clear = () => { onChange(null); setDraft([null, null]); setOpen(false) }
  const dayDisabled = (day: Dayjs) => Boolean((minDate && day.isBefore(minDate, 'day')) || (maxDate && day.isAfter(maxDate, 'day'))
    || (maxSpanMs !== undefined && draft[0] && !draft[1] && Math.abs(day.startOf('day').diff(draft[0].startOf('day'))) > maxSpanMs))
  // Picked days start at 00:00 and the user sets hours under "select time" (as on the competitor);
  // endInclusive pages end a picked day at its last minute / second instead.
  const dayEnd = (day: Dayjs) => endInclusive && precision !== 'day' ? day.add(1, 'day').startOf('day').subtract(1, precision) : day.startOf('day')
  const selectDay = (day: Dayjs) => {
    const [start, end] = draft
    if (!start || end) setDraft([day.startOf('day'), null])
    else if (day.isBefore(start, 'day')) setDraft([day.startOf('day'), dayEnd(start)])
    else setDraft([start, dayEnd(day)])
  }
  const changeTime = (side: 0 | 1, unit: 'hour' | 'minute' | 'second', next: number) => {
    setDraft((range) => {
      const copy: Draft = [...range]
      copy[side] = range[side]?.set(unit, next) ?? null
      return copy
    })
  }
  const confirm = () => {
    onChange(clampTimeRange([draft[0]!, draft[1]!], bounds))
    setOpen(false)
  }
  const sides = [0, 1] as const
  const panel = <div className="cdnca-time-range-panel" role="dialog" aria-label={text.placeholder}
    onKeyDown={(event) => { if (event.key === 'Escape') setOpen(false) }}>
    {/* Compact bars have no box showing the window, so the popup heads with it. */}
    {trigger ? <div className="cdnca-time-range-summary" role="status">{show(draft) || text.placeholder}</div> : null}
    {!timeMode ? <div className="cdnca-time-range-calendars">
      {sides.map((offset) => {
        const visible = month.add(offset, 'month')
        const first = visible.startOf('month').subtract(visible.startOf('month').day(), 'day')
        return <div className="cdnca-time-range-month" key={offset}>
          <div className="cdnca-time-range-month-header">
            <span>{offset === 0 ? <>
              <button type="button" aria-label={text.previousYear} onClick={() => setMonth(month.subtract(1, 'year'))}><Chevron double left /></button>
              <button type="button" aria-label={text.previousMonth} onClick={() => setMonth(month.subtract(1, 'month'))}><Chevron left /></button>
            </> : null}</span>
            <span>{new Intl.DateTimeFormat(locale, { year: 'numeric', month: 'long' }).format(visible.toDate())}</span>
            <span>{offset === 1 ? <>
              <button type="button" aria-label={text.nextMonth} onClick={() => setMonth(month.add(1, 'month'))}><Chevron /></button>
              <button type="button" aria-label={text.nextYear} onClick={() => setMonth(month.add(1, 'year'))}><Chevron double /></button>
            </> : null}</span>
          </div>
          <div className="cdnca-time-range-days">
            {Array.from({ length: 7 }, (_, index) => <span className="cdnca-time-range-weekday" key={index}>
              {new Intl.DateTimeFormat(locale, { weekday: 'narrow' }).format(dayjs('2026-09-20').add(index, 'day').toDate())}
            </span>)}
            {Array.from({ length: 42 }, (_, index) => {
              const day = first.add(index, 'day')
              const selected = draft.some((item) => item?.isSame(day, 'day'))
              const between = draft[0] && draft[1] && day.isAfter(draft[0], 'day') && day.isBefore(draft[1], 'day')
              const outside = day.month() !== visible.month()
              return <button type="button" key={day.format('YYYY-MM-DD')} aria-label={day.format('YYYY-MM-DD')} aria-pressed={selected}
                disabled={dayDisabled(day)} tabIndex={outside ? -1 : 0}
                className={[outside ? 'is-outside' : '', selected ? 'is-selected' : '', between ? 'is-between' : '', day.isSame(now(), 'day') ? 'is-today' : ''].filter(Boolean).join(' ')}
                onClick={() => selectDay(day)}>{day.date()}</button>
            })}
          </div>
        </div>
      })}
    </div> : <div className="cdnca-time-range-times">
      {sides.map((side) => <div className="cdnca-time-range-time" key={side}>
        <div className="cdnca-time-range-time-heading">{side === 0 ? text.from : text.to}</div>
        <div className="cdnca-time-range-time-columns" style={{ gridTemplateColumns: `repeat(${units[precision].length}, minmax(0, 1fr))` }}>
          {units[precision].map((unit) => <div key={unit} role="group" aria-label={`${side === 0 ? text.from : text.to}${text[unit]}`}>
            {Array.from({ length: unit === 'hour' ? 24 : 60 }, (_, item) => <button type="button" key={item}
              aria-pressed={draft[side]?.get(unit) === item} onClick={() => changeTime(side, unit, item)}>
              {String(item).padStart(2, '0')}
            </button>)}
          </div>)}
        </div>
      </div>)}
    </div>}
    <div className="cdnca-time-range-footer">
      {precision !== 'day' ? <Button type="text" size="small" disabled={!complete} onClick={() => setTimeMode(!timeMode)}>{timeMode ? text.selectDate : text.selectTime}</Button> : <span />}
      <span>
        {allowClear ? <Button size="small" onClick={clear}>{text.clear}</Button> : null}
        <Button type="primary" size="small" disabled={!complete} onClick={confirm}>{text.confirm}</Button>
      </span>
    </div>
  </div>
  return <Popover trigger="click" placement="bottomLeft" arrow={false} open={open} onOpenChange={toggle}
    classNames={{ root: 'cdnca-time-range-popover' }} content={panel}>
    {trigger ?? <Input id={id} className="cdnca-time-range-input" readOnly disabled={disabled} aria-label={text.placeholder} aria-haspopup="dialog" aria-expanded={open}
      placeholder={text.placeholder} allowClear={allowClear && !open}
      suffix={<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><rect x="3" y="4" width="18" height="18" rx="2" /><path d="M16 2v4M8 2v4M3 10h18" /></svg>}
      value={open ? show(draft) : show(value ?? [null, null])}
      onChange={(event) => { if (!event.target.value) clear() }}
      onKeyDown={(event) => { if (event.key === 'Enter' || event.key === 'ArrowDown') toggle(true); if (event.key === 'Escape') toggle(false) }} />}
  </Popover>
}
