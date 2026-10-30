import { ApiError, setApiErrorObserver } from '../api/auth'
import { observabilityLogsApi } from '../api/observabilityLogs'
import { createGlobalApiErrorReporter } from './apiErrorBootstrap'
import { reportFrontendApiError } from './frontendReporter'

describe('OBS-09 global API error reporting', () => {
  it('emits only a normalized stable signal without changing the error result', () => {
    const observe = vi.fn()
    const release = setApiErrorObserver(observe)

    const error = new ApiError('raw token=secret and stack detail', 503, 'analytics_unavailable', 'request-secret')

    expect(error).toMatchObject({ status:503, code:'analytics_unavailable', requestId:'request-secret' })
    expect(observe).toHaveBeenCalledWith({ status:503, code:'analytics_unavailable' })
    expect(JSON.stringify(observe.mock.calls)).not.toContain('token=secret')
    expect(JSON.stringify(observe.mock.calls)).not.toContain('request-secret')
    release()
  })

  it('does not let a broken observer replace the original API error', () => {
    const release = setApiErrorObserver(() => { throw new Error('observer unavailable') })
    const error = new ApiError('request failed', 502, 'invalid_response')
    expect(error).toBeInstanceOf(ApiError)
    expect(error.code).toBe('invalid_response')
    release()
  })

  it('filters expected failures and bounds duplicate stable errors', async () => {
    let now = 1_000
    const report = vi.fn().mockResolvedValue(undefined)
    const handle = createGlobalApiErrorReporter({
      getAccessToken:()=> 'session-token',
      getPathname:()=> '/account/log?secret=value#fragment',
      now:()=> now,
      report,
    })

    handle({ status:401, code:'session_expired' })
    handle({ status:0, code:'stale_session' })
    handle({ status:0, code:'origin_auth_edge_publication_request_canceled' })
    handle({ status:503, code:'analytics_unavailable' })
    handle({ status:503, code:'analytics_unavailable' })
    expect(report).toHaveBeenCalledTimes(1)
    expect(report).toHaveBeenLastCalledWith('session-token', '/account/log', {
      status:503,
      code:'analytics_unavailable',
    })

    now += 30_001
    handle({ status:503, code:'analytics_unavailable' })
    expect(report).toHaveBeenCalledTimes(2)
    await Promise.resolve()
  })

  it('reports only bounded stable frontend fields and ignores reporting failure', async () => {
    const record = vi.spyOn(observabilityLogsApi, 'recordFrontend').mockRejectedValue(new Error('collector secret'))
    expect(() => reportFrontendApiError('session-token', '/sys/log?token=secret#hash', {
      status:503,
      code:'analytics_unavailable',
    })).not.toThrow()

    await vi.waitFor(() => expect(record).toHaveBeenCalledWith('session-token', {
      event_code:'api_error',
      route:'/sys/log',
      reason_code:'api_503_analytics_unavailable',
      result_code:'failure',
      release:expect.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/),
    }, undefined))
    expect(JSON.stringify(record.mock.calls)).not.toMatch(/collector secret|token=secret|#hash/)
  })
})
