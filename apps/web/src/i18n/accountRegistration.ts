import i18n from './index'

const zhCN = {
  title: '注册账号',
  fields: {
    username: '用户名',
    displayName: '显示名称',
    password: '密码',
    email: '邮箱',
    phone: '手机号',
    channel: '验证方式',
    otp: '验证码',
    terms: '我已阅读并同意服务条款（{{version}}）',
  },
  channels: { email: '邮箱验证', sms: '短信验证' },
  actions: {
    sendCode: '发送验证码',
    verifyAndRegister: '验证并注册',
    retrySame: '使用原请求重试',
    startOver: '重新开始',
  },
  states: {
    humanRequired: '请先完成人机验证',
    deliveryQueued: '验证码已提交发送，请查看所选验证渠道。',
    expiresAt: '验证码有效期至 {{value}}',
    cooldown: '验证码有效期及重新获取冷却剩余 {{seconds}} 秒',
    remainingAttempts: '本页面剩余验证次数：{{count}}',
    expired: '验证码已过期，请重新开始。',
    registering: '验证成功，正在提交注册请求。',
    pendingVerification: '注册请求已受理。',
    replayed: '原注册请求已确认受理。',
  },
  validation: {
    username: '用户名须为 3 至 128 位小写字母、数字、点、下划线或连字符',
    displayName: '请输入显示名称',
    password: '密码须为 8–1024 位，至少包含大写字母、小写字母、数字、符号中的两种',
    email: '请输入有效邮箱',
    phone: '请输入 6 至 20 位有效手机号',
    otp: '请输入 6 位数字验证码',
    terms: '请阅读并同意服务条款',
  },
  errors: {
    account_registration_challenge_invalid: '验证码不正确或已失效，请重试。',
    account_registration_challenge_rate_limited: '验证码请求过于频繁，请在 {{seconds}} 秒后重试。',
    account_registration_challenge_conflict: '验证码请求与原请求不一致，请重新开始。',
    account_registration_challenge_unavailable: '验证码服务暂不可用，请稍后重试。',
    account_registration_invalid_input: '注册信息无效，请检查后重试。',
    password_policy_unmet: '密码须为 8–1024 位，至少包含大写字母、小写字母、数字、符号中的两种，且不能含空格、中文或全角字符。',
    account_registration_terms_required: '必须同意当前服务条款后才能注册。',
    account_registration_rate_limited: '注册请求过于频繁，请稍后再试。',
    account_registration_idempotency_conflict: '本次注册请求与原请求不一致，请重新填写。',
    account_registration_unavailable: '注册服务暂不可用，请稍后重试。',
    permission_denied: '当前请求无权执行，请重新开始。',
    forbidden: '当前请求无权执行，请重新开始。',
    challengeUnknown: '验证码请求结果尚未确认，请使用原请求重试或重新开始。',
    verificationUnknown: '验证结果尚未确认，请使用原请求重试或重新开始。',
    registrationUnknown: '注册结果尚未确认，请使用原请求重试或重新开始。',
    turnstileUnavailable: '人机验证暂不可用，请刷新后重试。',
    requestFailed: '注册请求失败，请稍后重试。',
  },
}

const enUS: typeof zhCN = {
  title: 'Create account',
  fields: {
    username: 'Username',
    displayName: 'Display name',
    password: 'Password',
    email: 'Email',
    phone: 'Phone number',
    channel: 'Verification method',
    otp: 'Verification code',
    terms: 'I have read and accept the Terms of Service ({{version}})',
  },
  channels: { email: 'Verify by email', sms: 'Verify by SMS' },
  actions: {
    sendCode: 'Send verification code',
    verifyAndRegister: 'Verify and register',
    retrySame: 'Retry the original request',
    startOver: 'Start over',
  },
  states: {
    humanRequired: 'Complete the human verification first.',
    deliveryQueued: 'The verification code was queued. Check the selected verification channel.',
    expiresAt: 'The verification code expires at {{value}}.',
    cooldown: 'Code validity and resend cooldown: {{seconds}} seconds remaining.',
    remainingAttempts: 'Verification attempts remaining on this page: {{count}}',
    expired: 'The verification code has expired. Start over.',
    registering: 'Verification succeeded. Submitting registration.',
    pendingVerification: 'Registration accepted.',
    replayed: 'The original registration request is confirmed.',
  },
  validation: {
    username: 'Use 3 to 128 lowercase letters, numbers, dots, underscores, or hyphens.',
    displayName: 'Enter a display name.',
    password: 'The password needs 8–1024 characters with at least two of upper case, lower case, digits and symbols.',
    email: 'Enter a valid email address.',
    phone: 'Enter a valid phone number containing 6 to 20 digits.',
    otp: 'Enter the six-digit verification code.',
    terms: 'Read and accept the Terms of Service.',
  },
  errors: {
    account_registration_challenge_invalid: 'The verification code is incorrect or expired. Try again.',
    account_registration_challenge_rate_limited: 'Too many verification requests. Try again in {{seconds}} seconds.',
    account_registration_challenge_conflict: 'This verification request differs from the original request. Start over.',
    account_registration_challenge_unavailable: 'Verification is temporarily unavailable. Try again later.',
    account_registration_invalid_input: 'The registration details are invalid. Check them and try again.',
    password_policy_unmet: 'The password needs 8–1024 characters with at least two of upper case, lower case, digits and symbols, with no spaces or non-ASCII characters.',
    account_registration_terms_required: 'Accept the current Terms of Service before registering.',
    account_registration_rate_limited: 'Too many registration requests. Try again later.',
    account_registration_idempotency_conflict: 'This registration differs from the original request. Enter the details again.',
    account_registration_unavailable: 'Registration is temporarily unavailable. Try again later.',
    permission_denied: 'This request is not allowed. Start over.',
    forbidden: 'This request is not allowed. Start over.',
    challengeUnknown: 'The verification request result is unknown. Retry the original request or start over.',
    verificationUnknown: 'The verification result is unknown. Retry the original request or start over.',
    registrationUnknown: 'The registration result is unknown. Retry the original request or start over.',
    turnstileUnavailable: 'Human verification is temporarily unavailable. Refresh and try again.',
    requestFailed: 'Registration failed. Try again later.',
  },
}

type Messages = typeof zhCN

function pseudo(value: unknown): unknown {
  if (typeof value === 'string') {
    const tokens: string[] = []
    const protectedValue = value.replace(/\{\{[^{}]+\}\}/g, (token) => {
      tokens.push(token)
      return `__TOKEN_${tokens.length - 1}__`
    })
    return `［¡¡ ${protectedValue.replace(/[A-Za-z\u4e00-\u9fff]/g, '$&$&')} !!］`
      .replace(/__TOKEN_(\d+)__/g, (_match, index: string) => tokens[Number(index)] ?? '')
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, pseudo(child)]),
  )
}

const pseudoCN = pseudo(zhCN) as Messages

export const accountRegistrationMessages: Record<
  'zh-CN' | 'en-US' | 'qps-ploc' | 'qps-Ploc',
  Messages
> = {
  'zh-CN': zhCN,
  'en-US': enUS,
  'qps-ploc': pseudoCN,
  'qps-Ploc': pseudoCN,
}

for (const [locale, messages] of Object.entries(accountRegistrationMessages)) {
  i18n.addResourceBundle(locale, 'accountRegistration', messages, true, true)
}
