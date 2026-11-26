import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import dayjs from 'dayjs'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { StatusPageAdminView, StatusPageIncident } from '../api/statusPage'
import { StatusPageIncidents } from '../pages/StatusPageIncidents'
import incidentsCss from '../pages/StatusPageIncidents.css?raw'
import { renderWithProviders } from '../test/render'

afterEach(() => { vi.restoreAllMocks() })

const incident: StatusPageIncident = {
  id: 'inc-1', kind: 'incident', title: '华东访问变慢', impact: 'degraded', status: 'investigating', component_ids: [],
  started_at: '2026-11-21T00:00:00Z', updates: [{ id: 'up-1', status: 'investigating', message: '正在排查', created_at: '2026-11-21T00:00:00Z' }],
}
const view: StatusPageAdminView = {
  revision: 1, settings: { enabled: true, title: '', description: '', show_logo: true }, groups: [],
  components: [{ id: 'c-1', name: '主控 API', name_en: '', description: '', source: 'control_api', line_group_missing: false, note: { zh: '', en: '' },
    manual_status: 'operational', hidden: false, status: 'operational' }],
  incidents: [incident], line_groups: [], nodes: [], updated_at: '2026-11-21T00:00:00Z',
}

function mockApi() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => new Response(JSON.stringify(init?.method === 'POST' ? incident : view), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  }))
}
const posts = (fetchMock: ReturnType<typeof mockApi>) => fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')
const submit = () => screen.getByRole('button', { name: /^发\s*布$/ })

describe('StatusPageIncidents drawers', () => {
  // 发布事件抽屉五个字段都以可见标签为无障碍名称，点标签聚焦字段；必填未填提交时错误挂到字段上且不发请求。
  it('names every incident field by its label and ties required errors to the empty field', async () => {
    const user = userEvent.setup()
    const fetchMock = mockApi()
    renderWithProviders(<StatusPageIncidents token="t" canManage />)
    await user.click(await screen.findByRole('button', { name: '发布事件' }))

    const title = screen.getByRole('textbox', { name: '标题' })
    const impact = screen.getByRole('combobox', { name: '影响' })
    const state = screen.getByRole('combobox', { name: '状态' })
    const affected = screen.getByRole('combobox', { name: '受影响组件' })
    const message = screen.getByRole('textbox', { name: '进展说明' })
    for (const field of [title, impact, state, message]) expect(field).toHaveAttribute('aria-required', 'true')
    expect(affected).not.toHaveAttribute('aria-required')
    expect(message).toHaveAccessibleDescription('访客会看到这段文字')
    await user.click(screen.getByText('进展说明'))
    expect(message).toHaveFocus()

    await user.click(submit())
    expect(posts(fetchMock)).toHaveLength(0)
    expect(title).toHaveAttribute('aria-invalid', 'true')
    expect(title).toHaveAccessibleDescription('必填')
    expect(title).toHaveFocus()
    expect(message).toHaveAccessibleDescription('访客会看到这段文字 必填')

    await user.type(title, '华东访问变慢')
    expect(title).not.toHaveAttribute('aria-invalid')
    await user.click(submit())
    expect(message).toHaveFocus()
    expect(posts(fetchMock)).toHaveLength(0)

    await user.type(message, '正在排查')
    expect(message).toHaveAccessibleDescription('访客会看到这段文字')
    await user.click(submit())
    await waitFor(() => expect(posts(fetchMock)).toHaveLength(1))
    const [url, init] = posts(fetchMock)[0]!
    expect(String(url)).toMatch(/\/v1\/admin\/status-page\/incidents$/)
    expect(JSON.parse(String(init!.body))).toEqual({ kind: 'incident', title: '华东访问变慢', impact: 'degraded', status: 'investigating', message: '正在排查', component_ids: [] })
  })

  // 安排维护：维护时间的两个输入框分别可定位，点「维护时间」聚焦开始输入框；未选时间提交时错误挂在维护时间上。
  it('names the maintenance window inputs and reports a missing window on the field', async () => {
    const user = userEvent.setup()
    const fetchMock = mockApi()
    renderWithProviders(<StatusPageIncidents token="t" canManage />)
    await user.click(await screen.findByRole('button', { name: '安排维护' }))

    const start = screen.getByRole('textbox', { name: '维护时间' })
    const end = screen.getByRole('textbox', { name: '维护结束时间' })
    expect(start).toHaveAttribute('aria-required', 'true')
    expect(end).toHaveAttribute('aria-required', 'true')
    for (const name of ['状态', '受影响组件']) expect(screen.getByRole('combobox', { name })).toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: '影响' })).toBeNull()
    fireEvent.click(screen.getByText('维护时间'))
    expect(start).toHaveFocus()

    await user.type(screen.getByRole('textbox', { name: '标题' }), '数据库升级')
    await user.type(screen.getByRole('textbox', { name: '进展说明' }), '期间控制台只读')
    await user.click(submit())
    expect(posts(fetchMock)).toHaveLength(0)
    expect(start).toHaveAttribute('aria-invalid', 'true')
    expect(start).toHaveAccessibleDescription('必填')
    expect(start).toHaveFocus()
  })

  // STATUS-1 补充：必填星号是装饰，aria-hidden 排出可访问名称；每个必填标签可见一个星号，选填标签没有，aria-required 仍在。
  it('keeps the required star visible but out of every required label name', async () => {
    const user = userEvent.setup()
    mockApi()
    renderWithProviders(<StatusPageIncidents token="t" canManage />)
    const expectStars = (required: string[], optional: string[]) => {
      const drawer = screen.getByRole('dialog')
      for (const name of required) {
        const label = within(drawer).getByText(name, { selector: 'label' })
        expect(label.textContent).toBe(`*${name}`)
        // antd hides its own ::before star on this class, so only the aria-hidden span shows.
        expect(label).toHaveClass('ant-form-item-required', 'ant-form-item-required-mark-optional')
        expect([...label.querySelectorAll('[aria-hidden="true"]')].map((node) => node.textContent)).toEqual(['*'])
        const field = document.getElementById(label.getAttribute('for')!)!
        expect(field).toHaveAccessibleName(name)
        expect(field).toHaveAttribute('aria-required', 'true')
      }
      for (const name of optional) expect(within(drawer).getByText(name, { selector: 'label' }).textContent).toBe(name)
    }

    await user.click(await screen.findByRole('button', { name: '发布事件' }))
    expectStars(['标题', '影响', '状态', '进展说明'], ['受影响组件'])
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }))
    await user.click(screen.getByRole('button', { name: '安排维护' }))
    expectStars(['标题', '维护时间', '状态', '进展说明'], ['受影响组件'])
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }))
    await user.click(screen.getByRole('button', { name: '更新进展' }))
    expectStars(['状态', '进展说明'], [])
  })

  // 更新进展：状态与进展说明可定位，说明带访客提示；未填说明提交时错误挂到字段上，填好后照常提交同一份请求。
  it('names the post-update fields and keeps the update request unchanged', async () => {
    const user = userEvent.setup()
    const fetchMock = mockApi()
    renderWithProviders(<StatusPageIncidents token="t" canManage />)
    await user.click(await screen.findByRole('button', { name: '更新进展' }))

    const drawer = screen.getByRole('dialog')
    expect(within(drawer).getByRole('combobox', { name: '状态' })).toHaveAttribute('aria-required', 'true')
    const message = within(drawer).getByRole('textbox', { name: '进展说明' })
    expect(message).toHaveAccessibleDescription('访客会看到这段文字')

    await user.click(submit())
    expect(posts(fetchMock)).toHaveLength(0)
    expect(message).toHaveAttribute('aria-invalid', 'true')
    expect(message).toHaveAccessibleDescription('访客会看到这段文字 必填')
    expect(message).toHaveFocus()

    await user.type(message, '已定位到故障链路')
    await user.click(submit())
    await waitFor(() => expect(posts(fetchMock)).toHaveLength(1))
    const [url, init] = posts(fetchMock)[0]!
    expect(String(url)).toMatch(/\/incidents\/inc-1\/updates$/)
    expect(JSON.parse(String(init!.body))).toEqual({ status: 'investigating', message: '已定位到故障链路' })
  })

  // 390px 下维护时间拆成上下两个单独的选择器（各带可访问名称，弹层
  // 单日历宽、时间列叠在下方）；空提交聚焦第一个出错字段，结束不晚于开始时错误挂在结束时间上，提交的起止与原来一致。
  it('splits the maintenance window into two named pickers on a narrow screen and keeps the order check and request', async () => {
    const original = window.matchMedia
    window.matchMedia = ((query: string) => ({ ...original(query), matches: /max-width:\s*575/.test(query) })) as typeof window.matchMedia
    try {
      const user = userEvent.setup()
      const fetchMock = mockApi()
      renderWithProviders(<StatusPageIncidents token="t" canManage />)
      await user.click(await screen.findByRole('button', { name: '安排维护' }))

      const drawer = screen.getByRole('dialog')
      expect(drawer.querySelector('.ant-picker-range')).toBeNull()
      const start = within(drawer).getByRole('textbox', { name: '维护开始时间' })
      const end = within(drawer).getByRole('textbox', { name: '维护结束时间' })
      for (const field of [start, end]) expect(field).toHaveAttribute('aria-required', 'true')
      expectStarsOn(drawer, ['维护开始时间', '维护结束时间'])

      await user.type(within(drawer).getByRole('textbox', { name: '标题' }), '数据库升级')
      await user.type(within(drawer).getByRole('textbox', { name: '进展说明' }), '期间控制台只读')
      await user.click(submit())
      expect(posts(fetchMock)).toHaveLength(0)
      expect(start).toHaveAttribute('aria-invalid', 'true')
      expect(start).toHaveAccessibleDescription('必填')
      expect(start).toHaveFocus()

      await pick(user, start, '2026-12-01 10:00:00')
      // The stylesheet stacks the time columns under the calendar through these classes (status-window-picker-popup).
      expect(document.querySelector('.status-window-picker-popup .ant-picker-datetime-panel .ant-picker-time-panel .ant-picker-content')).not.toBeNull()
      expect(start).not.toHaveAttribute('aria-invalid', 'true')
      await user.click(submit())
      expect(end).toHaveAttribute('aria-invalid', 'true')
      expect(end).toHaveAccessibleDescription('必填')
      expect(end).toHaveFocus()

      await pick(user, end, '2026-12-01 09:00:00')
      await user.click(submit())
      expect(posts(fetchMock)).toHaveLength(0)
      expect(end).toHaveAttribute('aria-invalid', 'true')
      expect(end).toHaveAccessibleDescription('结束时间须晚于开始时间')
      expect(end).toHaveFocus()

      await user.clear(end)
      await pick(user, end, '2026-12-01 12:00:00')
      expect(end).not.toHaveAttribute('aria-invalid', 'true')
      await user.click(submit())
      await waitFor(() => expect(posts(fetchMock)).toHaveLength(1))
      expect(JSON.parse(String(posts(fetchMock)[0]![1]!.body))).toEqual({
        kind: 'maintenance', title: '数据库升级', impact: 'maintenance', status: 'scheduled', message: '期间控制台只读', component_ids: [],
        scheduled_start: dayjs('2026-12-01 10:00:00').toISOString(), scheduled_end: dayjs('2026-12-01 12:00:00').toISOString(),
      })
    } finally {
      window.matchMedia = original
    }
  })

  // 残留：窄屏日期弹层里按 Escape 只关弹层，抽屉与草稿保留；
  // 弹层固定在视口底部（整个弹层在视口内）。
  it('closes only the date popup on Escape and pins the narrow popup inside the viewport', async () => {
    const original = window.matchMedia
    window.matchMedia = ((query: string) => ({ ...original(query), matches: /max-width:\s*575/.test(query) })) as typeof window.matchMedia
    try {
      const user = userEvent.setup()
      mockApi()
      renderWithProviders(<StatusPageIncidents token="t" canManage />)
      await user.click(await screen.findByRole('button', { name: '安排维护' }))
      const drawer = screen.getByRole('dialog')
      await user.type(within(drawer).getByRole('textbox', { name: '标题' }), '数据库升级')
      const end = within(drawer).getByRole('textbox', { name: '维护结束时间' })
      await user.click(end)
      const popup = document.querySelector<HTMLElement>('.status-window-picker-sheet')!
      expect(popup).not.toBeNull()
      // jsdom 不让样式表的 !important 盖过 rc-trigger 写的行内定位，这里核对样式规则本身。
      expect(incidentsCss).toMatch(/\.status-window-picker-sheet\.ant-picker-dropdown \{[^}]*position: fixed !important;[^}]*bottom: 8px !important;[^}]*max-height: calc\(100dvh - 16px\)/)
      // user-event 的 Escape 不带 keyCode，rc-drawer 按 keyCode 关抽屉：用带 keyCode 的真实按键事件。
      fireEvent.keyDown(end, { key: 'Escape', code: 'Escape', keyCode: 27 })
      await waitFor(() => expect(document.querySelector('.status-window-picker-sheet')).toHaveClass('ant-picker-dropdown-hidden'))
      expect(screen.getByRole('dialog')).toBe(drawer)
      expect(within(drawer).getByRole('textbox', { name: '标题' })).toHaveValue('数据库升级')
      // 弹层关闭后的 Escape 照常关闭抽屉（草稿随之丢弃）。
      fireEvent.keyDown(end, { key: 'Escape', code: 'Escape', keyCode: 27 })
      await waitFor(() => expect(within(drawer).queryByRole('textbox', { name: '标题' })).toBeNull())
    } finally {
      window.matchMedia = original
    }
  })

  // 桌面仍是一个区间选择器，提交的起止不变。
  it('keeps the range picker on a desktop screen and sends the same window', async () => {
    const user = userEvent.setup()
    const fetchMock = mockApi()
    renderWithProviders(<StatusPageIncidents token="t" canManage />)
    await user.click(await screen.findByRole('button', { name: '安排维护' }))

    const drawer = screen.getByRole('dialog')
    expect(drawer.querySelector('.ant-picker-range')).not.toBeNull()
    expect(within(drawer).queryByRole('textbox', { name: '维护开始时间' })).toBeNull()
    await user.type(within(drawer).getByRole('textbox', { name: '标题' }), '数据库升级')
    await user.type(within(drawer).getByRole('textbox', { name: '进展说明' }), '期间控制台只读')
    await pick(user, within(drawer).getByRole('textbox', { name: '维护时间' }), '2026-12-01 10:00:00')
    await pick(user, within(drawer).getByRole('textbox', { name: '维护结束时间' }), '2026-12-01 12:00:00')
    expect(document.querySelector('.status-window-picker-popup')).toBeNull()
    await user.click(submit())
    await waitFor(() => expect(posts(fetchMock)).toHaveLength(1))
    const body = JSON.parse(String(posts(fetchMock)[0]![1]!.body))
    expect([body.scheduled_start, body.scheduled_end]).toEqual([dayjs('2026-12-01 10:00:00').toISOString(), dayjs('2026-12-01 12:00:00').toISOString()])
  })
})

// Types a full date-time into a picker input and confirms it with Enter.
async function pick(user: ReturnType<typeof userEvent.setup>, input: HTMLElement, value: string) {
  await user.click(input)
  await user.type(input, value)
  await user.keyboard('{Enter}')
}

function expectStarsOn(drawer: HTMLElement, names: string[]) {
  for (const name of names) {
    const label = within(drawer).getByText(name, { selector: 'label' })
    expect(label.textContent).toBe(`*${name}`)
    expect(document.getElementById(label.getAttribute('for')!)).toHaveAccessibleName(name)
  }
}
