// Account password rule shared by every console.
// Mirrors libs/passwordpolicy on the servers: 8 to 1024 bytes, at least two of
// upper case, lower case, digits and ASCII symbols, and nothing else (no space,
// control or non-ASCII character). A server rejection is password_policy_unmet
// with error.details.unmet listing the same items as checkPassword.

export const PASSWORD_MIN_LENGTH = 8
export const PASSWORD_MAX_LENGTH = 1024
export const PASSWORD_SYMBOLS = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
export const PASSWORD_POLICY_ERROR_CODE = 'password_policy_unmet'

export type PasswordPolicyUnmet = 'length' | 'character_classes' | 'invalid_character'
export type PasswordPolicyLocale = 'zh-CN' | 'en-US'

/** Maps an i18n language tag to a policy locale (English only for en*). */
export function passwordPolicyLocale(language?: string): PasswordPolicyLocale {
  return language?.toLowerCase().startsWith('en') ? 'en-US' : 'zh-CN'
}

/** The one-line rule every new-password field shows. */
export const PASSWORD_POLICY_HINT: Record<PasswordPolicyLocale, string> = {
  'zh-CN': '8–1024 位，至少包含大写字母、小写字母、数字、符号中的两种；不能含空格、中文或全角字符',
  'en-US': '8–1024 characters with at least two of upper case, lower case, digits and symbols; no spaces or non-ASCII characters',
}

const UNMET_TEXT: Record<PasswordPolicyLocale, Record<PasswordPolicyUnmet, string>> = {
  'zh-CN': {
    length: '密码长度须为 8–1024 位',
    character_classes: '密码须至少包含大写字母、小写字母、数字、符号中的两种',
    invalid_character: '密码不能含空格、中文、全角或其他非英文符号',
  },
  'en-US': {
    length: 'The password must contain 8–1024 characters',
    character_classes: 'The password needs at least two of upper case, lower case, digits and symbols',
    invalid_character: 'The password must not contain spaces or non-ASCII characters',
  },
}

/** Unmet items of password, in server order; empty means acceptable. */
export function checkPassword(password: string): PasswordPolicyUnmet[] {
  let upper = false
  let lower = false
  let digit = false
  let symbol = false
  let invalid = false
  for (const char of password) {
    if (char >= 'A' && char <= 'Z') upper = true
    else if (char >= 'a' && char <= 'z') lower = true
    else if (char >= '0' && char <= '9') digit = true
    else if (char.length === 1 && PASSWORD_SYMBOLS.includes(char)) symbol = true
    else invalid = true
  }
  // Byte length, as on the server; only ASCII passes, but count UTF-8 for the length item too.
  const bytes = new TextEncoder().encode(password).length
  const unmet: PasswordPolicyUnmet[] = []
  if (bytes < PASSWORD_MIN_LENGTH || bytes > PASSWORD_MAX_LENGTH) unmet.push('length')
  if ([upper, lower, digit, symbol].filter(Boolean).length < 2) unmet.push('character_classes')
  if (invalid) unmet.push('invalid_character')
  return unmet
}

export type PasswordStrength = 'weak' | 'medium' | 'strong'
/** Length (bytes) from which a policy-compliant password with 3+ character classes counts as strong. */
export const PASSWORD_STRONG_LENGTH = 12

/**
 * Strength shown next to new-password fields, derived from the same rule as
 * checkPassword: weak = the server would reject it; medium = accepted;
 * strong = accepted, 3+ character classes and PASSWORD_STRONG_LENGTH+ bytes.
 */
export function passwordStrength(password: string): PasswordStrength {
  if (checkPassword(password).length > 0) return 'weak'
  const classes = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(password)).length
  return classes >= 3 && new TextEncoder().encode(password).length >= PASSWORD_STRONG_LENGTH ? 'strong' : 'medium'
}

/** Message for the first unmet item (or the hint when the list is empty or unknown). */
export function passwordPolicyMessage(unmet: readonly string[], locale: PasswordPolicyLocale = 'zh-CN'): string {
  const first = unmet.find((item): item is PasswordPolicyUnmet => item in UNMET_TEXT[locale])
  return first ? UNMET_TEXT[locale][first] : PASSWORD_POLICY_HINT[locale]
}

/** Form validator (antd Form.Item rules shape): rejects with the first unmet message. */
export function passwordPolicyRule(locale: PasswordPolicyLocale = 'zh-CN') {
  return {
    validator: async (_rule: unknown, value?: string) => {
      if (!value) return
      const unmet = checkPassword(value)
      if (unmet.length > 0) throw new Error(passwordPolicyMessage(unmet, locale))
    },
  }
}

/** Unmet items of a password_policy_unmet API error body, if it is one. */
export function passwordPolicyUnmetOf(error: unknown): PasswordPolicyUnmet[] | undefined {
  if (!error || typeof error !== 'object') return undefined
  const record = error as Record<string, unknown>
  const body = (record.error && typeof record.error === 'object' ? record.error : record) as Record<string, unknown>
  if (body.code !== PASSWORD_POLICY_ERROR_CODE) return undefined
  const details = body.details as { unmet?: unknown } | undefined
  return Array.isArray(details?.unmet) ? details.unmet.filter((item): item is PasswordPolicyUnmet => typeof item === 'string' && item in UNMET_TEXT['zh-CN']) : []
}
