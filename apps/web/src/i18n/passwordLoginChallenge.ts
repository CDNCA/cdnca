import i18n from './index'

const zhCN = {
  email: '此账户需要邮箱验证，请发送验证码后继续登录。',
  sms: '此账户需要短信验证，请发送验证码后继续登录。',
  code: '登录验证码', send: '发送验证码', retrySend: '使用同一请求重试发送', sent: '验证码已发送',
  retryLogin: '重试登录验证',
  codeRequired: '请输入登录验证码', codeFormat: '请输入六位数字验证码',
  retryAfter: '{{seconds}} 秒后可重试', human: '请完成人机验证',
  humanDone: '人机验证已完成', humanUnavailable: '验证组件加载失败，请重试或联系管理员',
  captcha: '图形验证码', captchaPlaceholder: '请输入图中字符', captchaRefresh: '看不清，换一张', captchaImage: '图形验证码图片',
  captchaHint: '登录失败次数较多，请输入图形验证码。',
  errors: {
    login_throttled: '登录失败次数过多，请 {{minutes}} 分钟后再试，或换一个网络登录。',
    login_captcha_required: '登录失败次数较多，请输入图形验证码后重试。',
    login_captcha_invalid: '图形验证码错误或已过期，请重新输入。',
    login_captcha_rate_limited: '验证码获取过于频繁，请稍后再试。',
    login_verification_required: '登录验证信息无效，请重新登录。',
    login_source_denied: '当前登录来源不在允许范围内。',
    account_login_verification_invalid: '验证码无效或已过期，请重新输入或发送。',
    account_login_idempotency_conflict: '此验证请求已变化，请重新发送验证码。',
    account_login_method_disabled: '此登录验证方式暂未启用，请联系管理员。',
    login_security_unavailable: '登录安全服务暂不可用，请稍后重试。',
    account_login_invalid_request: '登录验证请求无效，请检查输入。',
    account_login_human_verification_required: '请完成人机验证后发送验证码。',
    account_login_human_verification_invalid: '人机验证已失效，请重新验证。',
    account_login_rate_limited: '发送过于频繁，请稍后重试。',
    account_login_unavailable: '验证码服务暂不可用，请稍后重试。',
    crypto_unavailable: '浏览器缺少安全随机数能力，请使用受支持的浏览器。',
    invalid_response: '登录服务响应无效，请稍后重试。',
  },
}
const enUS: typeof zhCN = {
  email: 'This account requires email verification. Send a code to continue signing in.',
  sms: 'This account requires SMS verification. Send a code to continue signing in.',
  code: 'Login verification code', send: 'Send verification code', retrySend: 'Retry the same code request', sent: 'Verification code sent',
  retryLogin: 'Retry login verification',
  codeRequired: 'Enter the login verification code', codeFormat: 'Enter a six-digit code',
  retryAfter: 'Retry in {{seconds}} seconds', human: 'Complete human verification',
  humanDone: 'Human verification complete', humanUnavailable: 'The verification widget failed to load. Try again or contact your administrator.',
  captcha: 'Image code', captchaPlaceholder: 'Enter the characters in the image', captchaRefresh: 'New image', captchaImage: 'Image verification code',
  captchaHint: 'Too many failed sign-ins. Enter the image code.',
  errors: {
    login_throttled: 'Too many failed sign-ins. Try again in {{minutes}} minutes or from another network.',
    login_captcha_required: 'Too many failed sign-ins. Enter the image code and try again.',
    login_captcha_invalid: 'The image code is wrong or expired. Enter it again.',
    login_captcha_rate_limited: 'Too many image code requests. Try again later.',
    login_verification_required: 'Login verification details are invalid. Sign in again.',
    login_source_denied: 'The current login source is not allowed.',
    account_login_verification_invalid: 'The code is invalid or expired. Enter it again or send a new code.',
    account_login_idempotency_conflict: 'This verification request changed. Send a new code.',
    account_login_method_disabled: 'This verification method is unavailable. Contact your administrator.',
    login_security_unavailable: 'Login security is temporarily unavailable. Try again later.',
    account_login_invalid_request: 'The login verification request is invalid. Check your input.',
    account_login_human_verification_required: 'Complete human verification before sending a code.',
    account_login_human_verification_invalid: 'Human verification expired. Complete it again.',
    account_login_rate_limited: 'Too many code requests. Try again later.',
    account_login_unavailable: 'The verification service is temporarily unavailable. Try again later.',
    crypto_unavailable: 'Secure randomness is unavailable. Use a supported browser.',
    invalid_response: 'The login service returned an invalid response. Try again later.',
  },
}
function pseudo(value: unknown): unknown {
  if (typeof value === 'string') return `［${value.split(/(\{\{[^{}]+\}\})/g).map(part => part.startsWith('{{') ? part : part.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&~')).join('')}］`
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]))
}
export const passwordLoginChallengeMessages = { 'zh-CN': zhCN, 'en-US': enUS, 'qps-ploc': pseudo(zhCN), 'qps-Ploc': pseudo(zhCN) }
for (const [locale, messages] of Object.entries(passwordLoginChallengeMessages)) {
  i18n.addResourceBundle(locale, 'passwordLoginChallenge', messages, true, true)
}
