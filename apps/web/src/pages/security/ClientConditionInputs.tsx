import { useState } from 'react'
import { AutoComplete, Button, Checkbox, Input, Modal, Radio, Space, TimePicker, Typography } from 'antd'
import dayjs, { type Dayjs } from 'dayjs'
import { Plus, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { parseUserAgent, type ParsedUserAgent } from '../../api/securityStringSets'
import '../../i18n/securityPoliciesConditionFields'
import { InlineNotice, MODAL_WIDTH, TimeRangeFilter, type TimeRange } from '@cdnca/ui'
import { conditionValues } from './conditionValues'

// Value inputs of the WAF rule editor. The
// condition keeps its values as one string per line (the editor's form
// shape); these inputs read and write that string.

const weekdays = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const
type Weekday = (typeof weekdays)[number]
const maxWeekly = 7
const maxRanges = 4
const rangeLayout = 'YYYY-MM-DDTHH:mm:ss'

/** Common IANA zones offered in the zone box (any other name may be typed). */
export const commonTimeZones = [
  'Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Taipei', 'Asia/Tokyo', 'Asia/Seoul', 'Asia/Singapore', 'Asia/Kuala_Lumpur',
  'Asia/Bangkok', 'Asia/Jakarta', 'Asia/Manila', 'Asia/Ho_Chi_Minh', 'Asia/Kolkata', 'Asia/Dubai', 'Asia/Riyadh',
  'Asia/Karachi', 'Asia/Dhaka', 'Asia/Tehran', 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Madrid',
  'Europe/Rome', 'Europe/Amsterdam', 'Europe/Moscow', 'Europe/Istanbul', 'Africa/Cairo', 'Africa/Johannesburg',
  'Africa/Lagos', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'America/Toronto',
  'America/Mexico_City', 'America/Sao_Paulo', 'America/Buenos_Aires', 'Australia/Sydney', 'Australia/Perth',
  'Pacific/Auckland', 'UTC',
]

interface WeeklySlot { days: Weekday[]; from: string; to: string }

function parseWeekly(line: string): WeeklySlot {
  const match = /^([a-z,]*) (\d{2}:\d{2})-(\d{2}:\d{2})$/.exec(line.trim())
  if (!match) return { days: [], from: '09:00', to: '18:00' }
  return { days: match[1].split(',').filter((day): day is Weekday => (weekdays as readonly string[]).includes(day)), from: match[2], to: match[3] }
}

function weeklyLine(slot: WeeklySlot): string {
  return `${weekdays.filter((day) => slot.days.includes(day)).join(',')} ${slot.from}-${slot.to}`
}

// YYYY-MM-DDTHH:mm:ss, a wall-clock time in the condition's zone (no customParseFormat plugin is loaded).
const rangePartPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/

function parseRangePart(part: string): Dayjs | null {
  const value = part.trim()
  if (!rangePartPattern.test(value)) return null
  const parsed = dayjs(value)
  return parsed.isValid() && parsed.format(rangeLayout) === value ? parsed : null
}

function parseRange(line: string): TimeRange | null {
  const parts = line.split('/')
  if (parts.length !== 2) return null
  const from = parseRangePart(parts[0])
  const to = parseRangePart(parts[1])
  return from && to && from.isBefore(to) ? [from, to] : null
}

function rangeLine(range: TimeRange | null): string {
  return range ? `${range[0].format(rangeLayout)} / ${range[1].format(rangeLayout)}` : ' / '
}

/** The request_time values' form: weekly unless the first value is a date range. */
export function timeWindowForm(text: string): 'weekly' | 'ranges' {
  return conditionValues(text)[0]?.includes('/') ? 'ranges' : 'weekly'
}

/** The first problem of request_time values (i18n key under conditionFields.time), or null. */
export function timeWindowProblem(text: string): string | null {
  const lines = conditionValues(text)
  if (lines.length === 0) return 'noDay'
  if (timeWindowForm(text) === 'ranges') {
    if (lines.length > maxRanges) return 'maxRanges'
    return lines.every((line) => parseRange(line)) ? null : 'noRange'
  }
  if (lines.length > maxWeekly) return 'maxWeekly'
  for (const line of lines) {
    const slot = parseWeekly(line)
    if (slot.days.length === 0) return 'noDay'
    if (slot.from === slot.to) return 'sameTime'
  }
  return null
}

/** 请求时间 values: weekly slots (day buttons + from/to) or date ranges (custom calendar), at most 7 / 4. */
export function TimeWindowInput({ value, onChange, id }: { value?: string; onChange?: (value: string) => void; id?: string }) {
  const { t } = useTranslation('securityPolicies')
  const text = value ?? ''
  const form = timeWindowForm(text)
  const lines = conditionValues(text)
  const set = (next: string[]) => onChange?.(next.join('\n'))
  const weekly = form === 'weekly' ? (lines.length ? lines : ['mon,tue,wed,thu,fri 09:00-18:00']).map(parseWeekly) : []
  const ranges = form === 'ranges' ? lines.map(parseRange) : []
  const time = (clock: string) => dayjs(`2000-01-01T${clock}:00`)
  const updateSlot = (index: number, patch: Partial<WeeklySlot>) =>
    set(weekly.map((slot, at) => weeklyLine(at === index ? { ...slot, ...patch } : slot)))

  return (
    <div className="sp-time-window" id={id}>
      <Radio.Group size="small" value={form} aria-label={t('fields.request_time')}
        onChange={(event) => set(event.target.value === 'weekly' ? ['mon,tue,wed,thu,fri 09:00-18:00'] : [' / '])}>
        <Radio value="weekly">{t('conditionFields.time.weekly')}</Radio>
        <Radio value="ranges">{t('conditionFields.time.ranges')}</Radio>
      </Radio.Group>
      {form === 'weekly' ? weekly.map((slot, index) => (
        <div key={index} className="sp-time-slot">
          <Checkbox.Group className="sp-weekday-group" value={slot.days} onChange={(days) => updateSlot(index, { days: days as Weekday[] })}
            options={weekdays.map((day) => ({ value: day, label: <span aria-label={t(`conditionFields.time.dayNames.${day}`)}>{t(`conditionFields.time.days.${day}`)}</span> }))} />
          <Space size={4}>
            <TimePicker size="small" format="HH:mm" allowClear={false} needConfirm={false} aria-label={t('conditionFields.time.from')}
              value={time(slot.from)} onChange={(picked: Dayjs | null) => picked && updateSlot(index, { from: picked.format('HH:mm') })} />
            <span aria-hidden>–</span>
            <TimePicker size="small" format="HH:mm" allowClear={false} needConfirm={false} aria-label={t('conditionFields.time.to')}
              value={time(slot.to)} onChange={(picked: Dayjs | null) => picked && updateSlot(index, { to: picked.format('HH:mm') })} />
            <Button size="small" type="text" aria-label={t('conditionFields.time.remove')} icon={<Trash2 size={13} aria-hidden />}
              disabled={weekly.length === 1} onClick={() => set(weekly.filter((_, at) => at !== index).map(weeklyLine))} />
          </Space>
        </div>
      )) : ranges.map((range, index) => (
        <div key={index} className="sp-time-slot">
          <TimeRangeFilter presets={[]} precision="second" allowClear={false} value={{ preset: 'custom', range }}
            onChange={(next) => set(ranges.map((current, at) => rangeLine(at === index ? next.range : current)))} />
          <Button size="small" type="text" aria-label={t('conditionFields.time.remove')} icon={<Trash2 size={13} aria-hidden />}
            disabled={ranges.length === 1} onClick={() => set(ranges.filter((_, at) => at !== index).map(rangeLine))} />
        </div>
      ))}
      <Button size="small" type="link" icon={<Plus size={13} aria-hidden />}
        disabled={form === 'weekly' ? weekly.length >= maxWeekly : ranges.length >= maxRanges}
        onClick={() => set(form === 'weekly' ? [...weekly.map(weeklyLine), 'sat,sun 00:00-23:59'] : [...ranges.map(rangeLine), ' / '])}>
        {t('conditionFields.time.addSlot')}
      </Button>
      <Typography.Text className="sp-cond-help">{t('conditionFields.help.request_time')}</Typography.Text>
    </div>
  )
}

/** The zone key of a request_time condition: common zones, or any IANA name typed. */
export function TimeZoneInput({ value, onChange }: { value?: string; onChange?: (value: string) => void }) {
  const { t } = useTranslation('securityPolicies')
  return (
    <AutoComplete aria-label={t('conditionFields.time.zone')} placeholder={t('conditionFields.time.zone')} value={value} onChange={onChange}
      options={commonTimeZones.map((zone) => ({ value: zone }))}
      filterOption={(input, option) => String(option?.value ?? '').toLowerCase().includes(input.toLowerCase())} />
  )
}

/** 试一下: what the browser / device conditions see for one User-Agent. */
export function UserAgentTryDialog({ open, accessToken, onClose }: { open: boolean; accessToken: string; onClose: () => void }) {
  const { t } = useTranslation('securityPolicies')
  const [userAgent, setUserAgent] = useState(() => (typeof navigator === 'undefined' ? '' : navigator.userAgent))
  const [result, setResult] = useState<ParsedUserAgent | null>(null)
  const [failed, setFailed] = useState(false)
  const [busy, setBusy] = useState(false)
  const parse = async () => {
    setBusy(true)
    setFailed(false)
    try {
      setResult(await parseUserAgent(accessToken, userAgent))
    } catch {
      setResult(null)
      setFailed(true)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal open={open} title={t('conditionFields.tryUA.title')} width={MODAL_WIDTH.S} onCancel={onClose} destroyOnHidden
      footer={<Button type="primary" loading={busy} onClick={() => void parse()}>{t('conditionFields.tryUA.parse')}</Button>}>
      <Input.TextArea aria-label={t('conditionFields.tryUA.input')} autoSize={{ minRows: 3, maxRows: 6 }} maxLength={2048}
        value={userAgent} onChange={(event) => setUserAgent(event.target.value)} />
      {result ? (
        <p className="sp-ua-result" role="status">
          {t('conditionFields.tryUA.result', {
            browser: t(`conditionFields.browsers.${result.browser}`, { defaultValue: result.browser }),
            version: result.version ?? '', device: t(`conditionFields.devices.${result.device}`, { defaultValue: result.device }),
          })}
        </p>
      ) : null}
      <InlineNotice>{failed ? t('conditionFields.tryUA.failed') : null}</InlineNotice>
    </Modal>
  )
}
