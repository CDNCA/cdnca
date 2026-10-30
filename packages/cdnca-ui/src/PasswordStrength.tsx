// New-password strength popover: while the field has focus a
// panel under it shows 弱/中/强, a bar and the rule hints. Strength and rules
// come from passwordPolicy.ts (the same rule as libs/passwordpolicy), so the
// panel never accepts what the server rejects.
import { cloneElement, useId, useState, type FocusEvent, type ReactElement } from 'react'
import { Popover } from 'antd'
import {
  checkPassword, PASSWORD_MIN_LENGTH, passwordStrength, type PasswordPolicyLocale, type PasswordPolicyUnmet,
  type PasswordStrength,
} from './passwordPolicy'

const TEXT: Record<PasswordPolicyLocale, {
  label: string
  levels: Record<PasswordStrength, string>
  rules: Record<PasswordPolicyUnmet | 'guess', string>
}> = {
  'zh-CN': {
    label: '强度：',
    levels: { weak: '弱', medium: '中', strong: '强' },
    rules: {
      length: `请至少输入 ${PASSWORD_MIN_LENGTH} 个字符。`,
      character_classes: '至少包含大写字母、小写字母、数字、符号中的两种。',
      invalid_character: '不能含空格、中文或全角字符。',
      guess: '请不要使用容易被猜到的密码。',
    },
  },
  'en-US': {
    label: 'Strength: ',
    levels: { weak: 'Weak', medium: 'Medium', strong: 'Strong' },
    rules: {
      length: `Enter at least ${PASSWORD_MIN_LENGTH} characters.`,
      character_classes: 'Use at least two of upper case, lower case, digits and symbols.',
      invalid_character: 'No spaces or non-ASCII characters.',
      guess: 'Do not use a password that is easy to guess.',
    },
  },
}

const LEVEL_STEPS: Record<PasswordStrength, number> = { weak: 1, medium: 2, strong: 3 }

/** The panel content: strength, a three-step bar and each rule with met / unmet state. */
export function PasswordStrengthPanel({ value, locale = 'zh-CN', id }: { value: string; locale?: PasswordPolicyLocale; id?: string }) {
  const text = TEXT[locale]
  const strength = passwordStrength(value)
  const unmet = new Set(checkPassword(value))
  const rules: (PasswordPolicyUnmet | 'guess')[] = ['length', 'character_classes', 'invalid_character', 'guess']
  return (
    <div className={`cdnca-password-strength is-${strength}`} id={id}>
      <div className="cdnca-password-strength-head" aria-live="polite">
        {text.label}<strong>{text.levels[strength]}</strong>
      </div>
      <div className="cdnca-password-strength-bar" role="meter" aria-label={text.label.replace(/[：:]\s*$/, '')}
        aria-valuemin={0} aria-valuemax={3} aria-valuenow={LEVEL_STEPS[strength]} aria-valuetext={text.levels[strength]}>
        {[1, 2, 3].map((step) => <span key={step} className={step <= LEVEL_STEPS[strength] ? 'is-on' : undefined} />)}
      </div>
      <ul className="cdnca-password-strength-rules">
        {rules.map((rule) => {
          // "guess" is advice, not a checked rule; the others follow checkPassword.
          const state = rule === 'guess' ? 'advice' : unmet.has(rule) ? 'unmet' : 'met'
          return <li key={rule} className={`is-${state}`}>
            <span className="cdnca-password-strength-mark" aria-hidden="true">{state === 'met' ? '✓' : state === 'unmet' ? '✕' : '•'}</span>
            {text.rules[rule]}
          </li>
        })}
      </ul>
    </div>
  )
}

/**
 * Wraps a password input (antd Input.Password or any input taking value /
 * onFocus / onBlur / aria-describedby). Use as the Form.Item child so the
 * form still injects value and onChange.
 */
export function PasswordStrengthPopover({ children, locale = 'zh-CN', value, ...rest }: {
  children: ReactElement<{ value?: string; onFocus?: (event: FocusEvent<HTMLInputElement>) => void;
    onBlur?: (event: FocusEvent<HTMLInputElement>) => void; 'aria-describedby'?: string }>
  locale?: PasswordPolicyLocale
  value?: string
  [key: string]: unknown
}) {
  const [focused, setFocused] = useState(false)
  const id = useId()
  const props = children.props
  const current = value ?? props.value ?? ''
  const input = cloneElement(children, {
    ...rest,
    value,
    'aria-describedby': [props['aria-describedby'], focused ? id : undefined].filter(Boolean).join(' ') || undefined,
    onFocus: (event: FocusEvent<HTMLInputElement>) => { setFocused(true); props.onFocus?.(event) },
    onBlur: (event: FocusEvent<HTMLInputElement>) => { setFocused(false); props.onBlur?.(event) },
  })
  return (
    <Popover open={focused} placement="bottomLeft" arrow={false} trigger={[]} destroyOnHidden
      content={<PasswordStrengthPanel value={String(current)} locale={locale} id={id} />}
      rootClassName="cdnca-password-strength-popover">
      {input}
    </Popover>
  )
}
