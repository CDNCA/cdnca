import { useState } from 'react'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { DashboardAnalyticsView } from '../components/DashboardOverview'
import { RouteErrorBoundary } from '../components/RouteErrorBoundary'
import type { DashboardAnalyticsOverview } from '../api/dashboard'
import i18n from '../i18n'
import { renderWithProviders } from '../test/render'

vi.mock('../components/echartsRuntime', () => ({
  init: (host: HTMLElement) => {
    host.replaceChildren(document.createElement('canvas'))
    return { setOption: () => undefined, resize: () => undefined, dispose: () => host.replaceChildren() }
  },
}))

const summary: DashboardAnalyticsOverview['summary'] = {
  metric_version: 1, request_count: '0', request_bytes: '0', response_bytes: '0', total_bytes: '0',
  average_bandwidth_bps: 0, status_2xx: '0', status_3xx: '0', status_4xx: '0', status_5xx: '0', security_events: '0',
}

function TrendProbe({ variant }: { variant: 'admin' | 'default' }) {
  const [populated, setPopulated] = useState(false)
  return <>
    <button onClick={() => setPopulated((value) => !value)}>Toggle fixture</button>
    <output data-testid="fixture-state">{populated ? 'populated' : 'empty'}</output>
    <DashboardAnalyticsView variant={variant} mode="trend" locale="zh-CN" analytics={{
      summary,
      trend: populated ? [{ ...summary, hour: '2026-09-25T08:00:00Z', average_bandwidth_bps: 10 }] : [],
      top: [],
    }} />
  </>
}

describe('dashboard trend DOM ownership', () => {
  it.each(['admin', 'default'] as const)('preserves React empty text across repeated renderer updates for %s', async (variant) => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const view = renderWithProviders(<RouteErrorBoundary><TrendProbe variant={variant} /></RouteErrorBoundary>, ['/admin-home'])
    const host = view.container.querySelector('.analytics-trend-chart')!
    // Empty charts skip initialization in Vitest; model the production renderer taking ownership.
    host.replaceChildren(document.createElement('canvas'))
    const user = userEvent.setup()
    for (const expected of ['populated', 'empty', 'populated', 'empty']) {
      await user.click(screen.getByRole('button', { name: 'Toggle fixture' }))
      await waitFor(() => expect(screen.getByTestId('fixture-state')).toHaveTextContent(expected))
      expect(screen.queryByText('服务异常')).not.toBeInTheDocument()
    }
    expect(view.container.querySelector('.analytics-trend-chart + .visually-hidden')).toHaveTextContent(i18n.t('dashboardOverview:charts.empty'))
  })
})
