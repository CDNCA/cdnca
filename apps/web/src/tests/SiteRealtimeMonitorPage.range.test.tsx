import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiError } from '../api/auth'
import { siteRealtimeApi } from '../api/siteRealtime'
import { useSessionStore } from '../auth/session'
import SiteRealtimeMonitorPage from '../pages/SiteRealtimeMonitorPage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

const picker = vi.hoisted(() => ({ from: '', to: '' }))
// The page validates whatever wall-clock strings it holds; inject them through the shared picker's onChange.
vi.mock('@cdnca/ui', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cdnca/ui')>()
  const { default: dayjs } = await import('dayjs')
  return {
    ...actual,
    TimeRangeFilter: (props: import('@cdnca/ui').TimeRangeFilterProps) => <>
      <actual.TimeRangeFilter {...props} />
      <button onClick={() => props.onChange({ preset: 'custom', range: [{ format: () => picker.from, isValid: () => true } as unknown as ReturnType<typeof dayjs>, { format: () => picker.to } as unknown as ReturnType<typeof dayjs>] })}>inject range</button>
    </>,
  }
})

async function queryRange(from: string, to: string) {
  picker.from = from
  picker.to = to
  const actor = principal({ scope_kind: 'platform', scope_id: 'platform', tenant_id: null, permissions: ['sites.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  const read = vi.spyOn(siteRealtimeApi, 'read').mockRejectedValue(new ApiError('unavailable', 500, 'unavailable'))
  const user = userEvent.setup()
  renderWithProviders(<SiteRealtimeMonitorPage />)
  await screen.findByText('实时监控加载失败，请稍后重试。')
  await user.click(screen.getByText('自定义'))
  await user.click(screen.getByText('inject range'))
  await user.click(screen.getByRole('button', { name: '查询' }))
  return read
}

describe('SiteRealtimeMonitorPage strict local-minute boundaries', () => {
  it.each([
    '2026-02-30T01:15', '2026-02-29T01:15', '2026-04-31T01:15',
    '2026-09-01T24:00', '2026-09-01T01:60', '2026-13-01T01:15',
    '2026-9-01T01:15', '2026-09-01 01:15', '2026-09-01T01:15:00',
    '2026-09-01T01:15Z', '',
  ])('rejects invalid or rolled-over local time %s before querying', async (from) => {
    const read = await queryRange(from, '2026-09-02T01:45')
    expect(screen.getByText('请选择有效的分钟时间范围，结束时间须晚于开始时间。')).toBeInTheDocument()
    expect(read).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['2026-09-01T01:15', '2026-09-01T01:15'],
    ['2026-09-02T01:15', '2026-09-01T01:15'],
  ])('rejects non-increasing ranges %s to %s', async (from, to) => {
    const read = await queryRange(from, to)
    expect(screen.getByText('请选择有效的分钟时间范围，结束时间须晚于开始时间。')).toBeInTheDocument()
    expect(read).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['2024-02-29T01:15', '2024-02-29T01:16'],
    ['2026-08-01T01:15', '2026-09-01T01:15'],
  ])('preserves valid minute or maximum-length range %s to %s', async (from, to) => {
    const read = await queryRange(from, to)
    await waitFor(() => expect(read).toHaveBeenCalledTimes(2))
    expect(read.mock.calls[1][2]).toEqual({
      from: new Date(`${from}:00+08:00`).toISOString(), to: new Date(`${to}:00+08:00`).toISOString(),
    })
    expect(screen.getByText(/自定义范围按北京时间精确到分钟/)).toBeInTheDocument()
  })

  it('rejects 31 days plus one minute', async () => {
    const read = await queryRange('2026-08-01T01:15', '2026-09-01T01:16')
    expect(screen.getByText('时间范围最长为 31 天。')).toBeInTheDocument()
    expect(read).toHaveBeenCalledTimes(1)
  })
})
