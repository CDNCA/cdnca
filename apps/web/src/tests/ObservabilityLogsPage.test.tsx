import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, vi } from 'vitest'
import { observabilityLogsApi } from '../api/observabilityLogs'
import ObservabilityLogsPage from '../pages/ObservabilityLogsPage'
import { useSessionStore } from '../auth/session'
import { changeLocale, type UserLocale } from '../i18n'
import { observabilityLogCodeMessage, observabilityLogMessage, observabilityLogMessages } from '../i18n/observabilityLogs'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'

vi.mock('../api/observabilityLogs', async () => {
  const actual = await vi.importActual<typeof import('../api/observabilityLogs')>('../api/observabilityLogs')
  return { ...actual, observabilityLogsApi: { ...actual.observabilityLogsApi, list: vi.fn().mockResolvedValue({ items:[{ event_id:'event-1', occurred_at:'2026-08-07T09:00:00Z', kind:'login', action:'auth.login', reason_code:'credentials_accepted', result_code:'success', source_ip:'192.0.2.1', geo_code:'unknown' }], snapshot_at:'2026-08-07T10:00:00Z' }), exportCSV: vi.fn() } }
})

beforeEach(async () => {
  vi.clearAllMocks()
  await changeLocale('zh-CN')
})

it.each([
  ['zh-CN', '用户登录', '登录凭据已接受', '成功', '未知操作', '未知原因', '未知结果'],
  ['en-US', 'User login', 'Login credentials accepted', 'Succeeded', 'Unknown action', 'Unknown reason', 'Unknown result'],
  ['qps-ploc', '[!! Üšêr lögïñ !!]', '[!! Lögïñ çrêðêñţïålš åççêþţêð !!]', '[!! Šüççêêðêð !!]', '[!! Üñkñöwñ åçţïöñ !!]', '[!! Üñkñöwñ rêåšöñ !!]', '[!! Üñkñöwñ rêšülţ !!]'],
] as const)(
  'localizes known observability codes and hides unknown raw codes in %s',
  async (locale: UserLocale, knownAction, knownReason, knownResult, unknownAction, unknownReason, unknownResult) => {
    await changeLocale(locale)
    const actor = principal({ permissions:['identity.self.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.mocked(observabilityLogsApi.list).mockResolvedValueOnce({
      items: [
        { event_id:'event-known', occurred_at:'2026-08-07T09:00:00Z', kind:'login', action:'auth.login', reason_code:'credentials_accepted', result_code:'success', source_ip:'192.0.2.1', geo_code:'unknown' },
        { event_id:'event-unknown', occurred_at:'2026-08-07T08:59:00Z', kind:'operation', action:'audit.future_action', reason_code:'future_reason', result_code:'future_result', source_ip:'192.0.2.2', geo_code:'unknown' },
      ],
      snapshot_at:'2026-08-07T10:00:00Z',
    })

    renderWithProviders(<ObservabilityLogsPage audience="tenant" />)

    expect(await screen.findByText(knownAction)).toBeInTheDocument()
    expect(screen.getByText(knownReason)).toBeInTheDocument()
    expect(screen.getByText(knownResult)).toBeInTheDocument()
    expect(screen.getByText(unknownAction)).toBeInTheDocument()
    expect(screen.getByText(unknownReason)).toBeInTheDocument()
    expect(screen.getByText(unknownResult)).toBeInTheDocument()
    for (const raw of ['auth.login', 'credentials_accepted', 'success', 'audit.future_action', 'future_reason', 'future_result']) {
      expect(screen.queryByText(raw)).not.toBeInTheDocument()
    }
    if (locale === 'zh-CN') {
      fireEvent.mouseDown(screen.getByRole('combobox', { name: '结果' }))
      expect(await screen.findByText('永久失败')).toBeInTheDocument()
      expect(screen.queryByText('permanent_failed')).not.toBeInTheDocument()
    }
  },
)

  it('renders scoped OBS-09 facts without raw payload fields', async () => {
    const actor = principal({ permissions:['identity.self.read'] })
    useSessionStore.getState().setSession(authResponse(actor), actor)
    vi.mocked(observabilityLogsApi.list).mockResolvedValue({
      items: [
        {
          event_id: 'event-1',
          occurred_at: '2026-08-07T09:00:00Z',
          kind: 'login',
          action: 'auth.login',
          reason_code: 'credentials_accepted',
          result_code: 'success',
          source_ip: '192.0.2.1',
          geo_code: 'unknown',
        },
      ],
      snapshot_at: '2026-08-07T10:00:00Z',
    })
    renderWithProviders(<ObservabilityLogsPage audience="tenant" initialKinds={['login']} />)
  expect(await screen.findByText('用户登录')).toBeInTheDocument()
  expect(screen.getByText('192.0.2.1')).toBeInTheDocument()
  expect(screen.queryByText(/password|secret/i)).not.toBeInTheDocument()
})

it('applies action and time filters while resetting stable pagination', async () => {
  const actor = principal({ permissions:['identity.self.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  vi.mocked(observabilityLogsApi.list).mockResolvedValue({ items:[{ event_id:'event-1', occurred_at:'2026-08-07T09:00:00Z', kind:'operation', action:'auth.login', reason_code:'credentials_accepted', result_code:'success', source_ip:'192.0.2.1', geo_code:'unknown' }], snapshot_at:'2026-08-07T10:00:00Z' })
  renderWithProviders(<ObservabilityLogsPage audience="tenant" initialKinds={['operation']} />)
  await screen.findByText('用户登录')
  const list = vi.mocked(observabilityLogsApi.list)
  list.mockClear()
  fireEvent.change(screen.getByLabelText('操作'), { target:{ value:'site.update' } })
  // fix-rangepicker：共享时间范围组件的快捷项，选中即按当前时间取窗口。
  vi.useFakeTimers({ toFake: ['Date'], now: new Date('2026-08-07T10:00') })
  // fix-rangecompact：快捷项统一为今天/近7天/近30天。
  fireEvent.click(screen.getByRole('radio', { name: '近7天' }))
  vi.useRealTimers()
  await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.any(String), expect.objectContaining({
    action:'site.update',
    from:new Date('2026-07-31T10:00').toISOString(),
    to:new Date('2026-08-07T10:00').toISOString(),
    cursor:undefined,
  })))
})

it('does not query or export platform logs before a canonical target scope is supplied', async () => {
  const actor = principal({ scope_kind:'platform', scope_id:'00000000-0000-0000-0000-000000000000', tenant_id:null, permissions:['platform.admin'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  renderWithProviders(<ObservabilityLogsPage audience="platform" />)

  expect(screen.getByText('请先输入目标租户作用域。')).toBeInTheDocument()
  expect(screen.getByRole('button', { name:'导出 CSV' })).toBeDisabled()
  expect(observabilityLogsApi.list).not.toHaveBeenCalled()

  fireEvent.change(screen.getByLabelText('目标租户作用域'), { target:{ value:'33333333-3333-4333-8333-333333333333' } })
  await waitFor(() => expect(observabilityLogsApi.list).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({
    targetScopeId:'33333333-3333-4333-8333-333333333333',
  })))
})

it('keeps the complete qps-Ploc alias case-insensitive for log copy and codes', () => {
  expect(observabilityLogMessages['qps-Ploc']).toEqual(observabilityLogMessages['qps-ploc'])
  expect(observabilityLogMessage('QPS-PLOC', 'title')).toBe(observabilityLogMessage('qps-Ploc', 'title'))
  expect(observabilityLogCodeMessage('qps-Ploc', 'result', 'future_result'))
    .toBe(observabilityLogCodeMessage('QPS-PLOC', 'result', 'future_result'))

  expect(observabilityLogCodeMessage('zh-CN', 'action', 'stream.create')).toBe('创建四层转发流')
  expect(observabilityLogCodeMessage('en-US', 'action', 'platform_brand_asset.upload')).toBe('Upload platform brand asset')
})

// TEL-UX-EXPORT-OWNER：导出响应迟到时账号已切换，旧账号的文件不能再下载，也不报错。
it('drops a late export after the account changed (TEL-UX-EXPORT-OWNER)', async () => {
  const actor = principal({ permissions:['identity.self.read'] })
  useSessionStore.getState().setSession(authResponse(actor), actor)
  let finish!: (value: { content: string; sha256: string }) => void
  vi.mocked(observabilityLogsApi.exportCSV).mockImplementationOnce((_token, _filters, options) => new Promise((resolve) => {
    finish = resolve
    expect(options?.signal).toBeInstanceOf(AbortSignal)
  }))
  const createURL = vi.fn(() => 'blob:x')
  Object.assign(URL, { createObjectURL: createURL, revokeObjectURL: vi.fn() })
  renderWithProviders(<ObservabilityLogsPage audience="tenant" />)
  fireEvent.click(await screen.findByRole('button', { name:'导出 CSV' }))
  await waitFor(() => expect(observabilityLogsApi.exportCSV).toHaveBeenCalled())
  const other = principal({ user_id:'44444444-4444-4444-8444-444444444444', permissions:['identity.self.read'] })
  useSessionStore.getState().setSession(authResponse(other), other)
  finish({ content:'a,b', sha256:'0'.repeat(64) })
  await new Promise((resolve) => setTimeout(resolve, 20))
  expect(createURL).not.toHaveBeenCalled()
  expect(screen.queryByText(observabilityLogMessage('zh-CN', 'exportFailed'))).not.toBeInTheDocument()
})
