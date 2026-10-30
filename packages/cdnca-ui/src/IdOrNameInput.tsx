// "ID 或名称" filter field: every ID filter also takes the
// name. Typing suggests matches from the page's existing list API, shown as
// 名称（ID）; picking one filters by its ID. A complete ID typed directly
// filters at once, and so does a name that exactly matches one suggestion.
// Other free text only suggests (unless freeText: the backend matches names). Without a
// search function, or when the list answers 403, the field takes IDs only.
import { AutoComplete, Input } from 'antd'
import { useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { ConfigProvider } from 'antd'

export interface IdOrNameOption {
  /** The value the page filters on. */
  id: string
  name: string
  /** The ID shown to people when it differs from the filter value (e.g. a user's display ID). */
  code?: string
  /** A second line, e.g. a node IP or certificate domains. */
  detail?: string
}

export interface IdOrNameInputProps {
  /** The applied ID (from the page / URL). */
  value: string
  onChange: (id: string) => void
  /** Suggestions for the typed text; omitted when the user cannot read the list. */
  search?: (text: string, signal: AbortSignal) => Promise<IdOrNameOption[]>
  /** Whether typed text is a complete ID. Default: digits, or a UUID. */
  isId?: (text: string) => boolean
  /** The backend also matches free text by name (e.g. CC owner): any text filters as typed. */
  freeText?: boolean
  'aria-label': string
  placeholder?: string
  status?: 'error' | 'warning'
  className?: string
  style?: React.CSSProperties
  addonBefore?: ReactNode
  /** Enter with the suggestions closed (the page's 立即查询). */
  onPressEnter?: () => void
  /** Suggest delay; tests inject 0. */
  delay?: number
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export const defaultIsId = (text: string) => /^\d+$/.test(text) || uuid.test(text)

const texts = {
  'zh-CN': { idOnly: '只能按 ID 筛选（无权读取名称列表）', none: '没有匹配的名称', pick: '从联想中选择以按名称筛选' },
  'zh-TW': { idOnly: '只能依 ID 篩選（無權讀取名稱清單）', none: '沒有相符的名稱', pick: '從建議中選擇以依名稱篩選' },
  'en-US': { idOnly: 'ID only (no access to the name list)', none: 'No matching names', pick: 'Pick a suggestion to filter by name' },
}

function useTexts() {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  return texts[locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN']
}

const optionLabel = (option: IdOrNameOption) => {
  const code = option.code || option.id
  return option.name && option.name !== code ? `${option.name}（${code}）` : code
}

export function IdOrNameInput({
  value, onChange, search, isId = defaultIsId, freeText = false, placeholder, status, className, style, addonBefore, delay = 300, onPressEnter, ...rest
}: IdOrNameInputProps) {
  const text = useTexts()
  const [input, setInput] = useState(value)
  const [options, setOptions] = useState<IdOrNameOption[]>([])
  const [searched, setSearched] = useState('')
  const [forbidden, setForbidden] = useState(false)
  const [composing, setComposing] = useState(false)
  const shown = useRef(value)
  const onChangeRef = useRef(onChange)
  onChangeRef.current = onChange

  // The page cleared or replaced the filter (reset, tag ×, URL): show it.
  useEffect(() => {
    if (value === shown.current) return
    shown.current = value
    setInput(value)
  }, [value])

  const emit = (id: string) => {
    if (id === shown.current) return
    shown.current = id
    onChangeRef.current(id)
  }

  const typed = input.trim()
  const canSearch = Boolean(search) && !forbidden
  useEffect(() => {
    if (!canSearch || composing || !typed || options.some((option) => optionLabel(option) === typed)) return
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      search!(typed, controller.signal).then((found) => {
        if (controller.signal.aborted) return
        setOptions(found)
        setSearched(typed)
        const lower = typed.toLowerCase()
        const exact = found.filter((option) => option.name.toLowerCase() === lower || option.code?.toLowerCase() === lower)
        if (exact.length === 1 && !isId(typed)) emit(exact[0].id)
      }, (error: unknown) => {
        if (controller.signal.aborted) return
        if ((error as { status?: number } | null)?.status === 403) setForbidden(true)
        setOptions([])
        setSearched(typed)
      })
    }, delay)
    // A newer text (or unmount) aborts the older request and drops its late result.
    return () => { window.clearTimeout(timer); controller.abort() }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [typed, canSearch, composing, delay])

  const change = (next: string) => {
    setInput(next)
    const trimmed = next.trim()
    if (!trimmed) { setOptions([]); emit(''); return }
    const picked = options.find((option) => optionLabel(option) === trimmed)
    if (picked) { emit(picked.id); return }
    if (isId(trimmed) || !canSearch || freeText) emit(trimmed)
  }

  const hint = forbidden ? text.idOnly
    : canSearch && !freeText && typed && searched === typed && !isId(typed) && typed !== optionLabel(options[0] ?? { id: '', name: '' })
      ? options.length ? text.pick : text.none : undefined

  return (
    <AutoComplete
      className={['cdnca-id-or-name', className].filter(Boolean).join(' ')}
      style={style}
      value={input}
      options={canSearch && typed ? options.map((option) => ({
        value: optionLabel(option),
        label: <span className="cdnca-id-or-name-option"><span>{optionLabel(option)}</span>{option.detail ? <small>{option.detail}</small> : null}</span>,
      })) : []}
      onChange={(next) => change(String(next ?? ''))}
      onSelect={(label) => change(String(label))}
      popupMatchSelectWidth={false}
    >
      <Input
        aria-label={rest['aria-label']}
        addonBefore={addonBefore}
        placeholder={placeholder}
        status={status}
        allowClear
        title={hint}
        aria-description={hint}
        onPressEnter={(event) => { if (event.currentTarget.getAttribute('aria-expanded') !== 'true') onPressEnter?.() }}
        onCompositionStart={() => setComposing(true)}
        onCompositionEnd={(event) => { setComposing(false); change(event.currentTarget.value) }}
      />
    </AutoComplete>
  )
}
