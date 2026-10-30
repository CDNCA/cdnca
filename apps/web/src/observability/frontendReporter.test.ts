import { observabilityLogsApi } from '../api/observabilityLogs'
import { useSessionStore } from '../auth/session'
import type { Principal } from '../api/auth'
import { reportFrontendRouteError } from './frontendReporter'

afterEach(() => {
  useSessionStore.setState({ principal:null })
  window.history.replaceState({}, '', '/')
})

it('classifies lazy failures without accepting raw error details', async () => {
  const record = vi.spyOn(observabilityLogsApi, 'recordFrontend').mockResolvedValue()
  reportFrontendRouteError('token', '/account/log?secret=value#fragment', true)

  await vi.waitFor(() => expect(record).toHaveBeenCalledWith('token', {
    event_code:'route_error',
    route:'/account/log',
    reason_code:'lazy_route_load_failed',
    result_code:'failure',
    release:expect.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/),
  }, undefined))
})


it('skips platform events without an explicit tenant target and binds a canonical target when present', async () => {
  const record = vi.spyOn(observabilityLogsApi, 'recordFrontend').mockResolvedValue()
  useSessionStore.setState({ principal:{
    scope_kind:'platform', scope_id:'11111111-1111-4111-8111-111111111111', tenant_id:null,
    user_id:'33333333-3333-4333-8333-333333333333', username:'admin', display_name:'Admin',
    roles:['platform_admin'], permissions:['platform.admin'],
  } satisfies Principal })

  reportFrontendRouteError('token', '/admin-home', false)
  await Promise.resolve()
  expect(record).not.toHaveBeenCalled()

  const targetScopeId = '22222222-2222-4222-8222-222222222222'
  window.history.replaceState({}, '', `/?target_scope_id=${targetScopeId}`)
  reportFrontendRouteError('token', '/admin-home', false)
  await vi.waitFor(() => expect(record).toHaveBeenCalledWith('token', {
    event_code:'render_error',
    route:'/admin-home',
    reason_code:'route_render_failed',
    result_code:'failure',
    release:expect.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/),
  }, targetScopeId))
})
