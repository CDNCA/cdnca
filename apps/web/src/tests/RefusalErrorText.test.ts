import { describe, expect, it } from 'vitest'

import { ApiError, responseApiError } from '../api/auth'
import i18n from '../i18n'
import { localizedUnknownApiError } from '../i18n/apiError'

// 规则：4xx（408/429 除外）且页面传的是通用「稍后重试」兜底时，
// 先查已登记的 errors:<code>；没有登记就只显示「操作被拒绝（错误码 x，请求 ID y）」，不显示后端原文。
const generic = { 'zh-CN': '请求失败，请稍后重试', 'en-US': 'Request failed. Try again later.' } as const

describe('4xx refusal text without server message', () => {
  it.each(['zh-CN', 'en-US'] as const)('shows the registered text for a registered code in %s', async (locale) => {
    await i18n.changeLanguage(locale)
    const text = localizedUnknownApiError(new ApiError('raw backend text', 401, 'invalid_credentials', 'req-1'), generic[locale])
    expect(text).toContain(i18n.t('errors:invalid_credentials'))
    expect(text).toContain('invalid_credentials')
    expect(text).toContain('req-1')
    expect(text).not.toContain('raw backend text')
  })

  it('shows only the refusal, code and request ID for an unregistered code (zh-CN)', async () => {
    await i18n.changeLanguage('zh-CN')
    expect(localizedUnknownApiError(new ApiError('raw backend text', 422, 'no_such_code', 'req-2'), generic['zh-CN']))
      .toBe('操作被拒绝（错误码 no_such_code，请求 ID req-2）')
    expect(localizedUnknownApiError(new ApiError('raw backend text', 422, 'no_such_code'), generic['zh-CN']))
      .toBe('操作被拒绝（错误码 no_such_code）')
  })

  it('shows only the refusal, code and request ID for an unregistered code (en-US)', async () => {
    await i18n.changeLanguage('en-US')
    expect(localizedUnknownApiError(new ApiError('raw backend text', 409, 'no_such_code', 'req-3'), generic['en-US']))
      .toBe('The operation was refused (error code no_such_code, request ID req-3)')
    expect(localizedUnknownApiError(new ApiError('raw backend text', 409, 'no_such_code'), generic['en-US']))
      .toBe('The operation was refused (error code no_such_code)')
  })

  it('keeps "try again later" for 5xx, network errors, 408 and 429', async () => {
    await i18n.changeLanguage('zh-CN')
    for (const [status, code] of [[500, 'internal_error'], [503, 'directory_unavailable'], [0, 'network_error'], [408, 'request_timeout'], [429, 'rate_limited']] as const) {
      expect(localizedUnknownApiError(new ApiError('raw backend text', status, code), generic['zh-CN']), `${status} ${code}`)
        .toBe(generic['zh-CN'])
    }
  })

  it('keeps a page-specific text instead of the generic refusal', async () => {
    await i18n.changeLanguage('zh-CN')
    expect(localizedUnknownApiError(new ApiError('raw backend text', 422, 'no_such_code'), '保存失败：域名已存在')).toBe('保存失败：域名已存在')
  })

  it('never keeps the server message on the parsed error', async () => {
    const error = await responseApiError(new Response(JSON.stringify({ error: { code: 'no_such_code', message: 'secret replica topology' } }), { status: 422 }))
    expect(JSON.stringify(error)).not.toContain('secret replica topology')
    expect(Object.keys(error)).not.toContain('serverMessage')
  })
})
