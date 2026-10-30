// Submit errors shown where they belong (usage: ../COMPONENTS.md "字段错误就地显示").
// A refused field (validation_error / invalid_request with field, or a field
// list) is marked on the same-named Form.Item and scrolled into view; only an
// error no field on the form can take goes to the shared dialog.
// InlineNotice is the in-place line for checks that have no field to hang on
// (「请先选择授权」「文件类型不符」), shown right next to the button / action area.
import { useCallback, useContext, type ReactNode } from 'react'
import { ConfigProvider, type FormInstance } from 'antd'

type NamePath = string | number | (string | number)[]

/** Where a backend field lands: a Form name, optionally with page texts per reason (already translated). */
export type FormErrorTarget = NamePath | { name: NamePath; messages?: Partial<Record<string, string>> }

/** Backend field (as sent, e.g. display_name or origins[0].host) -> form field. Unmapped fields use their own path. */
export type FormErrorMap = Record<string, FormErrorTarget>

export interface SubmitFieldError { field: string; reason: string }

export interface FormSubmitErrorOptions {
  map?: FormErrorMap
  /** Page text for a field error; return undefined to use the built-in reason text. */
  message?: (error: SubmitFieldError) => string | undefined
  /** antd locale code (zh-cn / zh-tw / en); the hook reads it from ConfigProvider. */
  locale?: string
}

const reasonTexts = {
  'zh-CN': {
    required: '此项为必填', too_short: '长度太短', too_long: '长度超过上限', invalid_format: '格式不正确',
    not_https: '必须以 https:// 开头', duplicate: '与已有内容重复', out_of_range: '超出允许的范围', invalid: '填写的内容不符合要求',
  },
  'zh-TW': {
    required: '此項為必填', too_short: '長度太短', too_long: '長度超過上限', invalid_format: '格式不正確',
    not_https: '必須以 https:// 開頭', duplicate: '與已有內容重複', out_of_range: '超出允許的範圍', invalid: '填寫的內容不符合要求',
  },
  'en-US': {
    required: 'This field is required', too_short: 'Too short', too_long: 'Too long', invalid_format: 'Invalid format',
    not_https: 'Must start with https://', duplicate: 'Duplicates an existing value', out_of_range: 'Outside the allowed range',
    invalid: 'The value is not accepted',
  },
}
const closeText = { 'zh-CN': '关闭', 'zh-TW': '關閉', 'en-US': 'Close' }

const localeKey = (locale?: string) => (locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN')

/** Built-in text for a field error reason (unknown reasons read as "not accepted"). */
export function fieldReasonText(reason: string, locale?: string): string {
  const texts: Record<string, string> = reasonTexts[localeKey(locale)]
  return texts[reason] ?? texts.invalid
}

// snake_case segments joined by dots, with optional [n] indexes: name, origins[0].host, origins.0.host.
const fieldPattern = /^[a-z][a-z0-9_]{0,63}(?:\.[a-z0-9_]{1,64}|\[\d{1,4}\])*$/
const reasonPattern = /^[a-z][a-z0-9_]{0,63}$/

function isValidationCode(code: unknown): boolean {
  // invalid: market-service's field refusal ({"error":"invalid","field","reason"}).
  return code === 'validation_error' || code === 'invalid_request' || code === 'invalid' ||
    (typeof code === 'string' && (code.endsWith('_validation_error') || code.endsWith('_invalid_request')))
}

function entry(value: unknown, reason?: unknown): SubmitFieldError | null {
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const item = value as { field?: unknown; reason?: unknown }
    return entry(item.field, item.reason)
  }
  if (typeof value !== 'string' || value.length > 256 || !fieldPattern.test(value)) return null
  return { field: value, reason: typeof reason === 'string' && reasonPattern.test(reason) ? reason : '' }
}

/**
 * The refused fields of a submit error: error.field / error.reason, an
 * error.fields list (strings or { field, reason }), or the same under
 * error.details. Only validation errors (validation_error, invalid_request,
 * invalid, *_validation_error, *_invalid_request) count; first occurrence of a field wins.
 */
export function submitErrorFields(error: unknown): SubmitFieldError[] {
  if (typeof error !== 'object' || error === null) return []
  const source = error as { code?: unknown; field?: unknown; reason?: unknown; fields?: unknown; details?: unknown }
  if (!isValidationCode(source.code)) return []
  const details = typeof source.details === 'object' && source.details !== null ? source.details as { field?: unknown; reason?: unknown; fields?: unknown } : {}
  const found = [
    entry(source.field, source.reason),
    ...(Array.isArray(source.fields) ? source.fields.map((item) => entry(item)) : []),
    entry(details.field, details.reason),
    ...(Array.isArray(details.fields) ? details.fields.map((item) => entry(item)) : []),
  ]
  const seen = new Set<string>()
  return found.filter((item): item is SubmitFieldError => {
    if (!item || seen.has(item.field)) return false
    seen.add(item.field)
    return true
  })
}

/** origins[0].host / origins.0.host -> ['origins', 0, 'host']; a single segment stays a string. */
export function fieldNamePath(field: string): NamePath {
  const parts = field.replace(/\[(\d+)\]/g, '.$1').split('.').map((part) => (/^\d+$/.test(part) ? Number(part) : part))
  return parts.length === 1 ? parts[0] : parts
}

const pathKey = (name: NamePath) => JSON.stringify(Array.isArray(name) ? name : [name])

/**
 * Marks every refused field the form shows (status error + the reason under it)
 * and scrolls to the first. Returns true when at least one was marked: the
 * caller then shows no dialog. False: no field, or none on this form.
 */
export function applyFormSubmitError(form: FormInstance, error: unknown, options: FormSubmitErrorOptions = {}): boolean {
  const refused = submitErrorFields(error)
  if (refused.length === 0) return false
  const shown = new Set(form.getFieldsError().map((item) => pathKey(item.name)))
  const marks: { name: NamePath; errors: string[] }[] = []
  for (const item of refused) {
    const target = options.map && Object.prototype.hasOwnProperty.call(options.map, item.field) ? options.map[item.field] : fieldNamePath(item.field)
    const { name, messages } = typeof target === 'object' && !Array.isArray(target) ? target : { name: target, messages: undefined }
    if (!shown.has(pathKey(name)) || marks.some((mark) => pathKey(mark.name) === pathKey(name))) continue
    const text = messages?.[item.reason] ?? options.message?.(item) ?? fieldReasonText(item.reason, options.locale)
    marks.push({ name, errors: [text] })
  }
  if (marks.length === 0) return false
  form.setFields(marks)
  try {
    form.scrollToField(marks[0].name, { block: 'center' })
  } catch {
    // Scrolling is best effort (detached or hidden forms).
  }
  return true
}

/**
 * useFormSubmitError(form, map?, options?) -> (error, fallback?) => boolean.
 * Call it in a submit's onError: a refused field is marked on the form;
 * otherwise fallback (the shared dialog) runs and it returns false.
 */
export function useFormSubmitError(form: FormInstance, map?: FormErrorMap, options: Omit<FormSubmitErrorOptions, 'map' | 'locale'> = {}) {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  const { message } = options
  return useCallback((error: unknown, fallback?: () => void): boolean => {
    if (applyFormSubmitError(form, error, { map, message, locale })) return true
    fallback?.()
    return false
  }, [form, map, message, locale])
}

// Exclamation in a circle, sized to the text (decorative: the text carries the meaning).
function NoticeIcon() {
  return (
    <svg className="cdnca-inline-notice-icon" viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="11" fill="currentColor" />
      <rect x="11" y="6" width="2" height="8" rx="1" fill="#fff" />
      <circle cx="12" cy="17.5" r="1.25" fill="#fff" />
    </svg>
  )
}

/**
 * An error / warning line placed next to the button or action area it is about
 * (role=alert, read out when it appears). For checks with no field to mark;
 * a field error goes under its Form.Item instead. Renders nothing when empty.
 */
export function InlineNotice({ type = 'error', children, onClose, className, id }: {
  type?: 'error' | 'warning'
  children?: ReactNode
  /** Shows a × that calls it; the page clears its state. */
  onClose?: () => void
  className?: string
  id?: string
}) {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  if (children === undefined || children === null || children === false || children === '') return null
  return (
    <div id={id} role="alert" className={['cdnca-inline-notice', `cdnca-inline-notice-${type}`, className].filter(Boolean).join(' ')}>
      <NoticeIcon />
      <span className="cdnca-inline-notice-text">{children}</span>
      {onClose ? (
        <button type="button" className="cdnca-inline-notice-close" aria-label={closeText[localeKey(locale)]} onClick={onClose}>
          <svg viewBox="0 0 24 24" width="12" height="12" aria-hidden="true" focusable="false">
            <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </button>
      ) : null}
    </div>
  )
}
