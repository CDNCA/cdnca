import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'

// rc-input-number hardcodes its step buttons' aria-label ("Increase Value" / "Decrease Value"):
// antd's locale does not reach them, so every number field in the console read as English and
// the buttons of several fields in one form could not be told apart.
// One observer names them after the field for the whole console instead of each form.
const UP = 'ant-input-number-handler-up'
const DOWN = 'ant-input-number-handler-down'
const HANDLERS = `.${UP}, .${DOWN}`

function fieldName(handler: Element): string {
  const input = handler.closest('.ant-input-number')?.querySelector('input')
  if (!input) return ''
  const own = input.getAttribute('aria-label')?.trim()
  if (own) return own
  const labelledBy = (input.getAttribute('aria-labelledby') ?? '').split(/\s+/).filter(Boolean)
    .map((id) => document.getElementById(id)?.textContent?.trim() ?? '').filter(Boolean).join(' ')
  if (labelledBy) return labelledBy
  return input.id ? document.querySelector(`label[for="${CSS.escape(input.id)}"]`)?.textContent?.trim() ?? '' : ''
}

function nameHandler(handler: Element, t: TFunction) {
  const up = handler.classList.contains(UP)
  const name = fieldName(handler)
  const label = name ? t(up ? 'stepper.increase' : 'stepper.decrease', { name }) : t(up ? 'stepper.increaseUnnamed' : 'stepper.decreaseUnnamed')
  if (handler.getAttribute('aria-label') !== label) handler.setAttribute('aria-label', label)
}

function renameField(input: HTMLInputElement, t: TFunction) {
  const root = input.closest('.ant-input-number')
  if (root) nameStepHandlers(root, t)
}

/** Names every number field's step buttons in scope. */
function nameStepHandlers(scope: ParentNode, t: TFunction) {
  if (scope instanceof Element && scope.matches(HANDLERS)) nameHandler(scope, t)
  scope.querySelectorAll(HANDLERS).forEach((handler) => nameHandler(handler, t))
}

export function InputNumberStepNames() {
  const { t, i18n } = useTranslation('common')
  useEffect(() => {
    nameStepHandlers(document.body, t)
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        const target = mutation.target instanceof Element ? mutation.target : mutation.target.parentElement
        if (!target) continue
        if (mutation.type === 'attributes') {
          // A handler: rc-input-number wrote its English name back on remount. The field's input: renamed in
          // place (状态码 → 起始状态码), so its own two buttons follow.
          if (target.matches(HANDLERS)) nameHandler(target, t)
          else if (target instanceof HTMLInputElement) renameField(target, t)
          continue
        }
        // A label's text changed in place: the field it names follows.
        const label = target.closest('label')
        if (label?.htmlFor) {
          const input = document.getElementById(label.htmlFor)
          if (input instanceof HTMLInputElement) renameField(input, t)
        }
        mutation.addedNodes.forEach((node) => { if (node instanceof Element) nameStepHandlers(node, t) })
      }
    })
    observer.observe(document.body, { childList: true, subtree: true, characterData: true, attributes: true,
      attributeFilter: ['aria-label', 'aria-labelledby'] })
    return () => observer.disconnect()
  }, [t, i18n.resolvedLanguage])
  return null
}
