import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiError } from '../api/auth'
import { nativeControlUpgradesApi, type NativeUpgradeOption, type NativeUpgradeStatus } from '../api/controlUpgrades.native'
import { nativeBundleFixture, nativePublicationFixture, nativeStatusFixture } from '../api/controlUpgrades.native.fixtures'
import { useSessionStore } from '../auth/session'
import { changeLocale } from '../i18n'
import { maintenanceUpgradeMessage } from '../i18n/maintenanceUpgrade'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import ControlUpgradesNative from './ControlUpgradesPage.native'

// 结果未知改为 OutcomeUnknown 后，弹窗标题与原位恢复条（或表单内 Alert）同文案；断言原位提示
const OUTCOME_BAR = '.ant-alert-message'

const mt = (key: Parameters<typeof maintenanceUpgradeMessage>[1]) => maintenanceUpgradeMessage('zh-CN', key)
function authenticate(permissions = ['control.upgrades.manage']) {
  const actor = principal({ scope_kind: 'platform', tenant_id: null, permissions })
  useSessionStore.getState().setSession(authResponse(actor), actor)
}

function file(raw = JSON.stringify(nativeBundleFixture(), null, 2)) {
  const result = new File([raw], 'signed-upgrade.json', { type: 'application/json' })
  Object.defineProperty(result, 'arrayBuffer', { value: () => Promise.resolve(new TextEncoder().encode(raw).buffer) })
  return result
}

// openDraft: 打开弹窗后触发 /issue 503 降级到手工上传，再上传文件
async function openDraft() {
  vi.spyOn(nativeControlUpgradesApi, 'issue').mockRejectedValueOnce(new ApiError('plan_source_unavailable', 503, 'plan_source_unavailable'))
  const user = userEvent.setup()
  const button = await screen.findByRole('button', { name: '升级主控' })
  await waitFor(() => expect(button).toBeEnabled())
  await user.click(button)
  // 点击确认触发 issue，503 后显示上传界面
  await user.click(screen.getByRole('checkbox'))
  await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
  await waitFor(() => expect(screen.getByLabelText('上传已签名升级计划')).toBeInTheDocument())
  await user.upload(screen.getByLabelText('上传已签名升级计划'), file())
  await screen.findByText('待服务器验签')
  return user
}

beforeEach(() => {
  authenticate()
  vi.spyOn(nativeControlUpgradesApi, 'status').mockImplementation(async () => nativeStatusFixture())
  vi.spyOn(nativeControlUpgradesApi, 'options').mockResolvedValue({
    schema: 'cdnca.native-control-upgrade-options/v1', observed_at: new Date().toISOString(),
    options: { current_version: '1.0.35', current_schema_head: 299, target_mode: 'follow_channel', items: [] } })
})

describe('native control upgrade panel', () => {
  it('allows the platform administrator without a delegated upgrade permission', async () => {
    authenticate(['platform.admin'])
    const target = document.createElement('div')
    document.body.append(target)
    const view = renderWithProviders(<ControlUpgradesNative actionsTarget={target} />)
    try {
      await waitFor(() => expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled())
    } finally {
      view.unmount()
      target.remove()
    }
  })

  it('moves only idle actions, returns draft and unknown-result attention inline, and replays the original request', async () => {
    const target = document.createElement('div')
    document.body.append(target)
    const publish = vi.spyOn(nativeControlUpgradesApi, 'publish')
      .mockRejectedValueOnce(new ApiError('private backend text', 503, 'service_unavailable'))
      .mockResolvedValue(nativePublicationFixture())
    const view = renderWithProviders(<ControlUpgradesNative actionsTarget={target} />)
    try {
      await waitFor(() => expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled())
      expect(within(view.container).queryByRole('button', { name: '升级主控' })).not.toBeInTheDocument()
      expect(view.container.querySelector('.native-upgrade-panel')).toHaveClass('native-upgrade-panel--idle')
      const user = await openDraft()
      expect(within(view.container).getByRole('button', { name: '升级主控' })).toBeInTheDocument()
      expect(target).toBeEmptyDOMElement()
      target.hidden = true
      expect(screen.getByRole('dialog')).toHaveTextContent('待服务器验签')
      await user.click(screen.getByRole('checkbox'))
      await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
      expect(await within(view.container).findByText(mt('nativeOutcomeUnknown'))).toBeInTheDocument()
      expect(within(view.container).getByRole('button', { name: '升级主控' })).toBeDisabled()
      expect(target).toBeEmptyDOMElement()
      target.hidden = false
      await user.click(screen.getByRole('button', { name: '重试同一发布请求' }))
      expect(await within(view.container).findByText(mt('nativePublished'))).toBeInTheDocument()
      expect(publish).toHaveBeenCalledTimes(2)
      expect(publish.mock.calls[1][1]).toEqual(publish.mock.calls[0][1])
      expect(within(view.container).getByText(nativePublicationFixture().receipt_id)).toBeInTheDocument()
      expect(target).toBeEmptyDOMElement()
      expect(document.body.textContent).not.toContain('private backend text')
    } finally {
      view.unmount()
      target.remove()
    }
  })

  it('returns idle actions to their slot after closing a draft without remounting the status query', async () => {
    const target = document.createElement('div')
    document.body.append(target)
    const publish = vi.spyOn(nativeControlUpgradesApi, 'publish')
    const view = renderWithProviders(<ControlUpgradesNative actionsTarget={target} />)
    try {
      await waitFor(() => expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled())
      const user = await openDraft()
      expect(target).toBeEmptyDOMElement()
      const reads = vi.mocked(nativeControlUpgradesApi.status).mock.calls.length
      await user.click(screen.getByRole('button', { name: '关闭升级确认' }))
      await waitFor(() => expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled())
      expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(reads)
      expect(publish).not.toHaveBeenCalled()
    } finally {
      view.unmount()
      target.remove()
    }
  })

  it.each(['stale', 'read-failed', 'runtime', 'running', 'unknown', 'failed'] as const)(
    'keeps %s attention outside the idle action slot', async (condition) => {
      const target = document.createElement('div')
      document.body.append(target)
      const status: NativeUpgradeStatus = nativeStatusFixture()
      if (condition === 'stale') status.observed_at = '2000-01-01T00:00:00Z'
      if (condition === 'runtime') status.runtime = { ready: false, reason: 'execution_unavailable' }
      if (condition === 'running' || condition === 'unknown' || condition === 'failed') {
        status.publication = nativePublicationFixture()
        status.publication_revision = 1
        status.execution = { state: condition === 'running' ? 'running' : condition === 'failed' ? 'completed' : 'unavailable', phase: null, receipt: null }
        if (condition === 'failed') status.execution = { state: 'completed', phase: 'failed', receipt: {
          id: 'failed-receipt', plan_id: status.publication.plan_id, bundle_sha256: status.publication.bundle_sha256,
          sequence: status.publication.release_sequence, target: 'native-standalone', current_version: '1.0.0',
          target_version: '1.1.0', result: 'failed', error_code: 'target_health_failed', completed_at: 1780000001,
        } }
      }
      if (condition === 'read-failed') vi.mocked(nativeControlUpgradesApi.status).mockRejectedValue(new ApiError('private failure', 503, 'unavailable'))
      else vi.mocked(nativeControlUpgradesApi.status).mockResolvedValue(status)
      const view = renderWithProviders(<ControlUpgradesNative actionsTarget={target} />)
      try {
        const labels = { stale: 'nativeStatusStale', 'read-failed': 'nativeStatusFailed', runtime: 'reason_control_upgrade_execution_unavailable', running: 'nativeRunning', unknown: 'nativeExecutionUnknown', failed: 'nativeFailed' } as const
        // 状态过期/读取失败改为 FeedbackWhen 弹窗（挂在 body），其余状态仍在面板内
        const attention = condition === 'stale' || condition === 'read-failed' ? within(await screen.findByRole('dialog')) : within(view.container)
        expect(await attention.findByText(mt(labels[condition]))).toBeInTheDocument()
        expect(within(view.container).getByRole('button', { name: '刷新主控发布状态' })).toBeInTheDocument()
        expect(target).toBeEmptyDOMElement()
      } finally {
        view.unmount()
        target.remove()
      }
    },
  )

  it('shows a failed refresh inline and only returns to the slot after a successful manual read', async () => {
    const target = document.createElement('div')
    document.body.append(target)
    const view = renderWithProviders(<ControlUpgradesNative actionsTarget={target} />)
    try {
      await waitFor(() => expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled())
      vi.mocked(nativeControlUpgradesApi.status).mockRejectedValueOnce(new ApiError('private failure', 503, 'unavailable'))
      await userEvent.click(within(target).getByRole('button', { name: '刷新主控发布状态' }))
      expect(await within(await screen.findByRole('dialog')).findByText(mt('nativeStatusFailed'))).toBeInTheDocument()
      expect(target).toBeEmptyDOMElement()
      await userEvent.click(within(view.container).getByRole('button', { name: '刷新主控发布状态' }))
      await waitFor(() => expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled())
      expect(within(view.container).queryByRole('alert')).not.toBeInTheDocument()
      expect(screen.queryByText(mt('nativeStatusFailed'))).not.toBeInTheDocument()
    } finally {
      view.unmount()
      target.remove()
    }
  })

  it('removes portaled actions immediately on permission loss without sending a new status read', async () => {
    const target = document.createElement('div')
    document.body.append(target)
    const view = renderWithProviders(<ControlUpgradesNative actionsTarget={target} />)
    try {
      await waitFor(() => expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled())
      const reads = vi.mocked(nativeControlUpgradesApi.status).mock.calls.length
      act(() => useSessionStore.setState((state) => ({ principal: { ...state.principal!, permissions: [] } })))
      expect(target).toBeEmptyDOMElement()
      expect(within(view.container).getByRole('button', { name: '升级主控' })).toBeDisabled()
      expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(reads)
    } finally {
      view.unmount()
      target.remove()
    }
  })

  it('stays enabled while the background poll is refetching (isFetching=true)', async () => {
    vi.useFakeTimers()
    const status = nativeStatusFixture()
    let resolveSecond: (v: NativeUpgradeStatus) => void
    vi.mocked(nativeControlUpgradesApi.status)
      .mockResolvedValueOnce(status)
      .mockImplementationOnce(() => new Promise((resolve) => { resolveSecond = resolve }))
    const view = renderWithProviders(<ControlUpgradesNative />)
    try {
      await act(async () => { await vi.advanceTimersByTimeAsync(50) })
      const button = screen.getByRole('button', { name: '升级主控' })
      expect(button).toBeEnabled()
      // trigger second poll
      await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
      expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(2)
      // button stays enabled during refetch
      expect(button).toBeEnabled()
      await act(async () => { resolveSecond(status); await vi.advanceTimersByTimeAsync(50) })
      expect(button).toBeEnabled()
    } finally {
      view.unmount()
      vi.useRealTimers()
    }
  })

  it('keeps actions in their idle slot during polling, but restores stale status attention without a click', async () => {
    vi.useFakeTimers()
    const target = document.createElement('div')
    document.body.append(target)
    const status = nativeStatusFixture()
    vi.mocked(nativeControlUpgradesApi.status).mockResolvedValue(status)
    const view = renderWithProviders(<ControlUpgradesNative actionsTarget={target} />)
    try {
      await act(async () => { await vi.advanceTimersByTimeAsync(50) })
      expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled()
      let finish!: (value: NativeUpgradeStatus) => void
      vi.mocked(nativeControlUpgradesApi.status).mockImplementationOnce(() => new Promise((resolve) => { finish = resolve }))
      await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
      // button stays enabled during refetch (isFetching no longer gates ready)
      expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled()
      expect(within(view.container).queryByRole('button', { name: '升级主控' })).not.toBeInTheDocument()
      await act(async () => { finish(status); await vi.advanceTimersByTimeAsync(50) })
      expect(within(target).getByRole('button', { name: '升级主控' })).toBeEnabled()
      await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
      expect(within(screen.getByRole('dialog')).getByText(mt('nativeStatusStale'))).toBeInTheDocument()
      expect(within(view.container).getByRole('button', { name: '升级主控' })).toBeDisabled()
      expect(target).toBeEmptyDOMElement()
    } finally {
      view.unmount()
      target.remove()
      vi.useRealTimers()
    }
  })

  describe('status polling', () => {
    it.each([
      ['text/plain', '404 page not found: private endpoint error'],
      ['text/html', '<html><body>404 private endpoint error</body></html>'],
    ])('stops after a non-JSON 404 (%s) while preserving the error, disabled upgrade and manual refresh', async (contentType, body) => {
      vi.useFakeTimers()
      vi.mocked(nativeControlUpgradesApi.status).mockRestore()
      const status = vi.spyOn(nativeControlUpgradesApi, 'status')
      const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(body, {
        status: 404, headers: { 'Content-Type': contentType },
      }))
      const view = renderWithProviders(<ControlUpgradesNative />)
      try {
        await act(async () => { await vi.advanceTimersByTimeAsync(1) })
        expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(1)
        expect(fetch).toHaveBeenCalledWith('/v1/admin/control-upgrade-plan', expect.objectContaining({ cache: 'no-store' }))
        await expect(status.mock.results[0].value).rejects.toBeInstanceOf(ApiError)
        await expect(status.mock.results[0].value).rejects.toMatchObject({ status: 404, code: 'request_failed' })
        expect(screen.getByRole('dialog')).toHaveTextContent(mt('nativeStatusFailed'))
        expect(screen.getByRole('button', { name: '升级主控' })).toBeDisabled()
        expect(screen.getByRole('button', { name: '刷新主控发布状态' })).toBeEnabled()
        expect(document.body.textContent).not.toContain('private endpoint error')
        for (let interval = 0; interval < 3; interval += 1) {
          await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
          expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(1)
        }
        fireEvent.click(screen.getByRole('button', { name: '刷新主控发布状态' }))
        await act(async () => { await vi.advanceTimersByTimeAsync(1) })
        expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(2)
        await act(async () => { await vi.advanceTimersByTimeAsync(15000) })
        expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(2)
        expect(screen.getByRole('dialog')).toHaveTextContent(mt('nativeStatusFailed'))
        expect(screen.getByRole('button', { name: '升级主控' })).toBeDisabled()
      } finally {
        view.unmount()
        vi.useRealTimers()
      }
    })

    it('resumes five-second polling after a successful manual refresh of a 404', async () => {
      vi.useFakeTimers()
      vi.mocked(nativeControlUpgradesApi.status).mockRejectedValueOnce(new ApiError('not found', 404, 'not_found'))
      const view = renderWithProviders(<ControlUpgradesNative />)
      try {
        await act(async () => { await vi.advanceTimersByTimeAsync(1) })
        expect(screen.getByRole('button', { name: '升级主控' })).toBeDisabled()
        fireEvent.click(screen.getByRole('button', { name: '刷新主控发布状态' }))
        await act(async () => { await vi.advanceTimersByTimeAsync(1) })
        expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(2)
        expect(screen.queryByRole('alert')).not.toBeInTheDocument()
        expect(screen.queryByText(mt('nativeStatusFailed'))).not.toBeInTheDocument()
        expect(screen.getByRole('button', { name: '升级主控' })).toBeEnabled()
        for (let interval = 1; interval <= 3; interval += 1) {
          await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
          expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(2 + interval)
        }
      } finally {
        view.unmount()
        vi.useRealTimers()
      }
    })

    it.each([503, 0])('continues polling after transient status %s', async (status) => {
      vi.useFakeTimers()
      vi.mocked(nativeControlUpgradesApi.status).mockRejectedValue(new ApiError('transient error', status, status === 0 ? 'network_error' : 'service_unavailable'))
      const view = renderWithProviders(<ControlUpgradesNative />)
      try {
        await act(async () => { await vi.advanceTimersByTimeAsync(1) })
        expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(1)
        for (let interval = 1; interval <= 3; interval += 1) {
          await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
          expect(nativeControlUpgradesApi.status).toHaveBeenCalledTimes(1 + interval)
        }
        expect(screen.getByRole('dialog')).toHaveTextContent(mt('nativeStatusFailed'))
        expect(screen.getByRole('button', { name: '升级主控' })).toBeDisabled()
      } finally {
        view.unmount()
        vi.useRealTimers()
      }
    })
  })

  it('keeps unavailable, stale and permissionless execution disabled', async () => {
    vi.mocked(nativeControlUpgradesApi.status).mockResolvedValue({ ...nativeStatusFixture(), observed_at: '2020-01-01T00:00:00Z' })
    renderWithProviders(<ControlUpgradesNative />)
    expect(await screen.findByText('主控发布状态已过期，请刷新。')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '升级主控' })).toBeDisabled()
    act(() => authenticate([]))
    expect(screen.getByRole('button', { name: '升级主控' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: '刷新主控发布状态' })).not.toBeInTheDocument()
  })

  it.each(['execution_unavailable', 'control_upgrade_execution_unavailable'])('explains unavailable native execution for %s', async (reason) => {
    vi.mocked(nativeControlUpgradesApi.status).mockResolvedValue({ ...nativeStatusFixture(), runtime: { ready: false, reason } })
    renderWithProviders(<ControlUpgradesNative />)
    expect(await screen.findByText('主控升级执行器未就绪')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '升级主控' })).toBeDisabled()
    expect(document.body.textContent).not.toContain(reason)
  })

  it('requires an explicit maintenance confirmation and never displays or stores signed payload secrets', async () => {
    const publish = vi.spyOn(nativeControlUpgradesApi, 'publish').mockResolvedValue(nativePublicationFixture())
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    renderWithProviders(<ControlUpgradesNative />)
    const user = await openDraft()
    expect(screen.getByRole('button', { name: '确认发布升级计划' })).toBeDisabled()
    expect(document.body.textContent).not.toMatch(/DO-NOT-DISPLAY|download_url|Ed25519/)
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1))
    expect(publish.mock.calls[0][1]).toMatchObject({ rawJSON: JSON.stringify(nativeBundleFixture(), null, 2), expectedRevision: 0 })
    expect(await screen.findByText('计划已发布；这不代表升级执行成功。')).toBeInTheDocument()
    expect(screen.queryByText('升级已完成')).not.toBeInTheDocument()
    expect(storage).not.toHaveBeenCalled()
  })

  it('retries an unknown write with the exact original request even while runtime is draining', async () => {
    let status: NativeUpgradeStatus = nativeStatusFixture()
    vi.mocked(nativeControlUpgradesApi.status).mockImplementation(async () => status)
    const publish = vi.spyOn(nativeControlUpgradesApi, 'publish').mockImplementationOnce(async () => {
      status = { ...status, runtime: { ready: false, reason: 'control_upgrade_draining' } }
      throw new ApiError('private backend text', 503, 'control_upgrade_draining')
    }).mockResolvedValueOnce(nativePublicationFixture())
    renderWithProviders(<ControlUpgradesNative />)
    const user = await openDraft()
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
    await screen.findByText('发布结果未知。请使用同一请求重试，勿重复创建计划。', { selector: OUTCOME_BAR })
    expect(document.body.textContent).not.toContain('private backend text')
    expect(screen.getByRole('button', { name: '升级主控' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '重试同一发布请求' }))
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(2))
    expect(publish.mock.calls[1][1]).toEqual(publish.mock.calls[0][1])
  })

  it('discards a pending upload when session ownership changes', async () => {
    vi.spyOn(nativeControlUpgradesApi, 'issue').mockRejectedValue(new ApiError('plan_source_unavailable', 503, 'plan_source_unavailable'))
    renderWithProviders(<ControlUpgradesNative />)
    const user = userEvent.setup()
    await waitFor(() => expect(screen.getByRole('button', { name: '升级主控' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '升级主控' }))
    // 触发 issue 503 fallback
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
    await waitFor(() => expect(screen.getByLabelText('上传已签名升级计划')).toBeInTheDocument())
    let finish!: (value: ArrayBuffer) => void
    const pending = new File(['{}'], 'pending.json', { type: 'application/json' })
    Object.defineProperty(pending, 'arrayBuffer', { value: () => new Promise<ArrayBuffer>((resolve) => { finish = resolve }) })
    await user.upload(screen.getByLabelText('上传已签名升级计划'), pending)
    act(() => authenticate())
    await act(async () => finish(new TextEncoder().encode(JSON.stringify(nativeBundleFixture())).buffer))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText('待服务器验签')).not.toBeInTheDocument()
  })

  it('clears unknown requests on permission loss and ignores late success from the previous session', async () => {
    let finish!: (value: ReturnType<typeof nativePublicationFixture>) => void
    vi.spyOn(nativeControlUpgradesApi, 'publish').mockImplementation(() => new Promise((resolve) => { finish = resolve }))
    renderWithProviders(<ControlUpgradesNative />)
    const user = await openDraft()
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
    act(() => authenticate([]))
    await act(async () => finish(nativePublicationFixture()))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText('计划已发布；这不代表升级执行成功。')).not.toBeInTheDocument()
  })

  it('requires a new read and confirmation after a revision conflict', async () => {
    vi.spyOn(nativeControlUpgradesApi, 'publish').mockRejectedValue(new ApiError('raw English conflict', 409, 'version_conflict'))
    renderWithProviders(<ControlUpgradesNative />)
    const user = await openDraft()
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
    expect(await screen.findByText('发布修订已变化，请刷新状态并重新上传、确认计划。')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重试同一发布请求' })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain('raw English conflict')
  })

  it('blocks an already confirmed draft when a refreshed revision changes', async () => {
    const publish = vi.spyOn(nativeControlUpgradesApi, 'publish')
    renderWithProviders(<ControlUpgradesNative />)
    const user = await openDraft()
    await user.click(screen.getByRole('checkbox'))
    expect(screen.getByRole('button', { name: '确认发布升级计划' })).toBeEnabled()
    vi.mocked(nativeControlUpgradesApi.status).mockResolvedValue({ ...nativeStatusFixture(), publication_revision: 1, publication: nativePublicationFixture() })
    fireEvent.click(screen.getByRole('button', { name: '刷新主控发布状态' }))
    expect(await screen.findByText('发布修订已变化，请刷新状态并重新上传、确认计划。')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '确认发布升级计划' })).toBeDisabled()
    expect(publish).not.toHaveBeenCalled()
  })

  it('rejects invalid UTF-8 without replacing bytes or attempting a write', async () => {
    const publish = vi.spyOn(nativeControlUpgradesApi, 'publish')
    renderWithProviders(<ControlUpgradesNative />)
    const user = await openDraft()
    const invalid = new File([new Uint8Array([0xff])], 'invalid.json', { type: 'application/json' })
    Object.defineProperty(invalid, 'arrayBuffer', { value: async () => new Uint8Array([0xff]).buffer })
    await user.upload(screen.getByLabelText('上传已签名升级计划'), invalid)
    expect(await screen.findByText('文件格式、大小或数字范围无效，请使用授权端签发的完整升级计划。')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '确认发布升级计划' })).toBeDisabled()
    expect(publish).not.toHaveBeenCalled()
  })

  it('immediately discards an unknown request if management permission is revoked', async () => {
    vi.spyOn(nativeControlUpgradesApi, 'publish').mockRejectedValue(new ApiError('network', 0, 'network_error'))
    renderWithProviders(<ControlUpgradesNative />)
    const user = await openDraft()
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
    await screen.findByRole('button', { name: '重试同一发布请求' })
    act(() => useSessionStore.setState((state) => ({ principal: { ...state.principal!, permissions: [] } })))
    expect(screen.queryByRole('button', { name: '重试同一发布请求' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '升级主控' })).toBeDisabled()
  })

  it.each(['target_health_failed', 'health_failed'])('shows rollback health failure for %s instead of success', async (errorCode) => {
    const publication = nativePublicationFixture()
    vi.mocked(nativeControlUpgradesApi.status).mockResolvedValue({
      ...nativeStatusFixture(), publication_revision: 1, publication,
      execution: { state: 'completed', phase: 'rolled_back', receipt: {
        id: 'receipt-1', plan_id: publication.plan_id, bundle_sha256: publication.bundle_sha256,
        sequence: publication.release_sequence, target: 'native-standalone', current_version: '1.0.0',
        target_version: '1.1.0', result: 'rolled_back', error_code: errorCode, completed_at: 1780000001,
      } },
    })
    renderWithProviders(<ControlUpgradesNative />)
    expect(await screen.findByText('升级失败，已回滚')).toBeInTheDocument()
    expect(screen.getByText('升级后健康检查未通过')).toBeInTheDocument()
    expect(screen.queryByText('升级已完成')).not.toBeInTheDocument()
    expect(screen.getByText('receipt-1')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain(errorCode)
  })

  it('renders pseudo locale copy and rejects malformed input without submitting', async () => {
    await changeLocale('qps-ploc')
    const publish = vi.spyOn(nativeControlUpgradesApi, 'publish')
    vi.spyOn(nativeControlUpgradesApi, 'issue').mockRejectedValue(new ApiError('plan_source_unavailable', 503, 'plan_source_unavailable'))
    renderWithProviders(<ControlUpgradesNative />)
    const message = (key: Parameters<typeof maintenanceUpgradeMessage>[1]) => maintenanceUpgradeMessage('qps-ploc', key)
    const user = userEvent.setup()
    await waitFor(() => expect(screen.getByRole('button', { name: message('upgradeControl') })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: message('upgradeControl') }))
    // 触发 issue 503 fallback
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: message('nativePublish') }))
    await waitFor(() => expect(screen.getByLabelText(message('nativeUpload'))).toBeEnabled())
    fireEvent.change(screen.getByLabelText(message('nativeUpload')), { target: { files: [file('{}')] } })
    expect(await screen.findByText(message('nativeInvalidFile'))).toBeInTheDocument()
    expect(publish).not.toHaveBeenCalled()
    expect(document.body.textContent).not.toContain(mt('nativeInvalidFile'))
  })

  it('issue API 成功时直接发布，不显示上传控件', async () => {
    vi.spyOn(nativeControlUpgradesApi, 'issue').mockResolvedValue(nativePublicationFixture())
    renderWithProviders(<ControlUpgradesNative />)
    const user = userEvent.setup()
    await waitFor(() => expect(screen.getByRole('button', { name: '升级主控' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '升级主控' }))
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
    expect(await screen.findByText(mt('nativePublished'))).toBeInTheDocument()
    expect(screen.queryByLabelText('上传已签名升级计划')).not.toBeInTheDocument()
  })

  it('issue API 返回 503 时显示文件上传界面', async () => {
    vi.spyOn(nativeControlUpgradesApi, 'issue').mockRejectedValue(new ApiError('plan_source_unavailable', 503, 'plan_source_unavailable'))
    renderWithProviders(<ControlUpgradesNative />)
    const user = userEvent.setup()
    await waitFor(() => expect(screen.getByRole('button', { name: '升级主控' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: '升级主控' }))
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
    expect(await screen.findByLabelText('上传已签名升级计划')).toBeInTheDocument()
    expect(screen.getByText(mt('nativeFallbackUpload'))).toBeInTheDocument()
  })

  describe('version picker', () => {
    const option = (version: string, extra: Partial<NativeUpgradeOption> = {}): NativeUpgradeOption => ({
      artifact_id: `00000000-0000-4000-8000-0000000001${version.replaceAll('.', '').padStart(2, '0').slice(-2)}`,
      version, release_notes: `说明 ${version}`, published_at: 1780000000, operation: 'upgrade', control_schema_head: 300,
      channel_target: false, pinned: false, selectable: true, reason: '', ...extra,
    })
    const listed = (items: NativeUpgradeOption[], target_mode: 'follow_channel' | 'pinned' = 'follow_channel') =>
      vi.mocked(nativeControlUpgradesApi.options).mockResolvedValue({ schema: 'cdnca.native-control-upgrade-options/v1',
        observed_at: new Date().toISOString(),
        options: { current_version: '1.0.35', current_schema_head: 299, target_mode, items } })
    const openPicker = async (picker = true) => {
      renderWithProviders(<ControlUpgradesNative />)
      const user = userEvent.setup()
      await waitFor(() => expect(screen.getByRole('button', { name: '升级主控' })).toBeEnabled())
      await user.click(screen.getByRole('button', { name: '升级主控' }))
      if (picker) await waitFor(() => expect(screen.getByRole('combobox', { name: mt('nativeVersionPick') })).toBeEnabled())
      return user
    }

    it('lists versions with notes, downgrade tags and why the others cannot be chosen, then issues the choice', async () => {
      const chosen = option('1.0.36', { release_notes: '修复若干问题' })
      listed([option('1.0.37', { selectable: false, reason: 'above_channel_target' }), chosen,
        option('1.0.35', { operation: 'reinstall', selectable: false, reason: 'same_version' }),
        option('1.0.34', { operation: 'rollback', selectable: false, reason: 'schema_downgrade', control_schema_head: 290 })])
      const issue = vi.spyOn(nativeControlUpgradesApi, 'issue').mockResolvedValue(nativePublicationFixture())
      const user = await openPicker()
      expect(screen.getByText(mt('nativeVersionDowngradeNote'))).toBeInTheDocument()
      await user.click(screen.getByRole('combobox', { name: mt('nativeVersionPick') }))
      const listbox = await screen.findByRole('listbox')
      expect(document.body).toHaveTextContent('数据库结构比当前旧，且不在本版本声明的可回退范围内')
      expect(document.body).toHaveTextContent('高于渠道当前推荐版本')
      expect(within(document.body).getAllByText(mt('nativeVersionDowngradeTag')).length).toBeGreaterThan(0)
      expect(listbox).toBeInTheDocument()
      const blockedRow = document.querySelector('[data-version="1.0.34"]')!.closest('.ant-select-item-option')!
      expect(blockedRow).toHaveClass('ant-select-item-option-disabled')
      fireEvent.click(document.querySelector('[data-version="1.0.36"]')!)
      expect(await screen.findByText('修复若干问题')).toBeInTheDocument()
      expect(screen.getByText('299 → 300')).toBeInTheDocument()
      await user.click(screen.getByRole('checkbox'))
      await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
      expect(await screen.findByText(mt('nativePublished'))).toBeInTheDocument()
      expect(issue).toHaveBeenCalledWith(expect.any(String), expect.any(String), chosen.artifact_id)
    })

    it('keeps the channel latest by default and sends no requested version', async () => {
      listed([option('1.0.36', { channel_target: true })])
      const issue = vi.spyOn(nativeControlUpgradesApi, 'issue').mockResolvedValue(nativePublicationFixture())
      const user = await openPicker()
      expect(screen.getByRole('combobox', { name: mt('nativeVersionPick') }).closest('.ant-select')).toHaveTextContent(mt('nativeVersionLatest'))
      await user.click(screen.getByRole('checkbox'))
      await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
      await screen.findByText(mt('nativePublished'))
      expect(issue).toHaveBeenCalledWith(expect.any(String), expect.any(String), undefined)
    })

    it('shows a provider lock when the operator pinned a version', async () => {
      listed([option('1.0.36', { pinned: true }), option('1.0.37', { selectable: false, reason: 'target_locked' })], 'pinned')
      await openPicker()
      expect(screen.getByRole('combobox', { name: mt('nativeVersionPick') }).closest('.ant-select')).toHaveTextContent(mt('nativeVersionLocked'))
    })

    it('reports a failed version list as an error and does not publish the channel latest instead', async () => {
      vi.mocked(nativeControlUpgradesApi.options).mockRejectedValue(new ApiError('unavailable', 503, 'upgrade_options_unavailable'))
      const issue = vi.spyOn(nativeControlUpgradesApi, 'issue').mockResolvedValue(nativePublicationFixture())
      const user = await openPicker(false)
      expect(await screen.findByText(mt('nativeVersionListFailed'))).toBeInTheDocument()
      await user.click(screen.getByRole('checkbox'))
      expect(screen.getByRole('button', { name: '确认发布升级计划' })).toBeDisabled()
      expect(issue).not.toHaveBeenCalled()
    })

    it('refreshes the list after a blocked grant', async () => {
      listed([option('1.0.36')])
      await openPicker()
      vi.spyOn(nativeControlUpgradesApi, 'issue').mockRejectedValue(new ApiError('blocked', 409, 'upgrade_target_blocked'))
      const reads = vi.mocked(nativeControlUpgradesApi.options).mock.calls.length
      const user = userEvent.setup()
      await user.click(screen.getByRole('checkbox'))
      await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
      expect(await screen.findByText(mt('nativeVersionBlocked'))).toBeInTheDocument()
      await waitFor(() => expect(vi.mocked(nativeControlUpgradesApi.options).mock.calls.length).toBeGreaterThan(reads))
    })

    // 73 实测：同版本重出时授权端拒签计划包，页面只显示「发布失败」。
    it('pops up the readable reason when the license service refuses the plan', async () => {
      listed([option('1.0.36')])
      await openPicker()
      const refusal = Object.assign(new ApiError('blocked', 409, 'upgrade_target_blocked'), { reasonCode: 'same_version' })
      vi.spyOn(nativeControlUpgradesApi, 'issue').mockRejectedValue(refusal)
      const user = userEvent.setup()
      await user.click(screen.getByRole('checkbox'))
      await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
      // The confirmation modal is still open, so query the feedback dialog by its class.
      const dialog = await waitFor(() => { const node = document.querySelector<HTMLElement>('.cdnca-feedback-error'); expect(node).not.toBeNull(); return node! })
      expect(dialog).toHaveTextContent(mt('nativeIssueRefusedTitle'))
      expect(dialog).toHaveTextContent(mt('issueRefused_same_version'))
      expect(dialog).toHaveTextContent('(same_version)')
    })

    it('pops up a passed-through license code, not the generic publish failure', async () => {
      listed([option('1.0.36')])
      await openPicker()
      vi.spyOn(nativeControlUpgradesApi, 'issue').mockRejectedValue(new ApiError('refused', 409, 'upgrade_plan_artifact_bundle_unavailable'))
      const user = userEvent.setup()
      await user.click(screen.getByRole('checkbox'))
      await user.click(screen.getByRole('button', { name: '确认发布升级计划' }))
      // The confirmation modal is still open, so query the feedback dialog by its class.
      const dialog = await waitFor(() => { const node = document.querySelector<HTMLElement>('.cdnca-feedback-error'); expect(node).not.toBeNull(); return node! })
      expect(dialog).toHaveTextContent(mt('nativeIssueRefusedTitle'))
      expect(dialog).toHaveTextContent(mt('issueRefused_upgrade_plan_artifact_bundle_unavailable'))
      expect(screen.queryByText(mt('nativePublishFailed'))).not.toBeInTheDocument()
    })
  })
})
