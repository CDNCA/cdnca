import { useEffect, useMemo, useRef, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Select } from 'antd'
import type { IdOrNameOption } from '@cdnca/ui'

// 管理员按名称选对象（网站按域名、节点按名称或 IP、线路组按名称），值仍是接口要的 UUID，服务端照旧校验归属与权限。
// 搜索来源是页面已有的只读列表（pages/idNameSources.ts 等）；选过的对象记住名称，已保存但不在当前结果里的值显示原 ID，可照常移除。
// 给了 resolve 时，已保存的值按 ID 读回名称；读取期间显示 resolvingLabel，查不到的显示 missingLabel(id)。
export interface SearchSelectProps {
  /** Suggestions for the typed text ('' = the first page, when preload is on). */
  search: (text: string, signal: AbortSignal) => Promise<IdOrNameOption[]>
  /** Query key root; include the session owner so a session switch never reuses results. */
  queryKey: readonly unknown[]
  value: string[] | string
  onChange: (value: string[] | string) => void
  mode?: 'multiple'
  /** Also load the first page with no text (lists whose search accepts an empty term). */
  preload?: boolean
  /** Names the selected IDs the results have not named (a saved value after a reload); an ID it leaves out no longer exists. */
  resolve?: (ids: string[], signal: AbortSignal) => Promise<IdOrNameOption[]>
  /** Label of a selected ID while resolve runs. */
  resolvingLabel?: string
  /** Label of a selected ID resolve did not find. */
  missingLabel?: (id: string) => string
  ariaLabel: string
  placeholder?: string
  emptyText?: string
  id?: string
  status?: 'error'
  allowClear?: boolean
  disabled?: boolean
  className?: string
  'aria-invalid'?: boolean
  'aria-describedby'?: string
}

// 键入停顿这么久才查（一次输完一个 IP 只发最终一次），
// 清空立即生效；等待与查询期间保留上一批候选，过期响应不会覆盖新结果（查询键跟着生效的词走）。
export const searchDebounceMs = 250

export const searchOptionLabel = (option: IdOrNameOption) => {
  const code = option.code || option.id
  return option.name && option.name !== code ? `${option.name}（${code}）` : code
}

export default function SearchSelect({
  search, queryKey, value, onChange, mode, preload = false, resolve, resolvingLabel, missingLabel,
  ariaLabel, placeholder, emptyText, id, status, allowClear, disabled, className, ...aria
}: SearchSelectProps) {
  const [text, setText] = useState('')
  const [opened, setOpened] = useState(false)
  const typed = text.trim()
  const [term, setTerm] = useState('')
  useEffect(() => {
    if (typed === '') { setTerm(''); return }
    const timer = window.setTimeout(() => setTerm(typed), searchDebounceMs)
    return () => window.clearTimeout(timer)
  }, [typed])
  const query = useQuery({
    queryKey: [...queryKey, term],
    queryFn: ({ signal }) => search(term, signal),
    enabled: opened && (preload || term !== ''),
    placeholderData: keepPreviousData,
    retry: false,
  })
  const known = useRef(new Map<string, IdOrNameOption>())
  const missing = useRef(new Set<string>())
  for (const option of query.data ?? []) known.current.set(option.id, option)
  const selectedKey = JSON.stringify(Array.isArray(value) ? value : value ? [value] : [])
  const selected = useMemo(() => JSON.parse(selectedKey) as string[], [selectedKey])
  const unnamed = selected.filter((current) => !known.current.has(current) && !missing.current.has(current))
  const resolved = useQuery({
    queryKey: [...queryKey, 'resolve', unnamed],
    queryFn: ({ signal }) => resolve ? resolve(unnamed, signal) : Promise.resolve([]),
    enabled: Boolean(resolve) && unnamed.length > 0,
    retry: false,
  })
  if (resolved.data) {
    for (const option of resolved.data) known.current.set(option.id, option)
    for (const current of unnamed) if (!known.current.has(current)) missing.current.add(current)
  }
  const resolving = Boolean(resolve) && unnamed.length > 0 && resolved.isPending
  const options = (() => {
    const items = (query.data ?? []).map((option) => ({ value: option.id, label: searchOptionLabel(option), detail: option.detail }))
    for (const current of selected) {
      if (!items.some((item) => item.value === current)) {
        const option = known.current.get(current)
        const label = option ? searchOptionLabel(option)
          : missing.current.has(current) && missingLabel ? missingLabel(current)
            : resolving && resolvingLabel ? resolvingLabel : current
        items.push({ value: current, label, detail: option?.detail })
      }
    }
    return items
  })()
  return (
    <Select
      id={id}
      className={className}
      aria-label={ariaLabel}
      {...aria}
      mode={mode}
      showSearch
      allowClear={allowClear}
      disabled={disabled}
      filterOption={false}
      placeholder={placeholder}
      status={status}
      loading={query.isFetching}
      value={mode === 'multiple' ? selected : selected[0]}
      options={options.map(({ value: optionValue, label, detail }) => ({ value: optionValue, label, title: detail ? `${label} · ${detail}` : label }))}
      onSearch={setText}
      onOpenChange={(open) => { if (open) setOpened(true); else setText('') }}
      onChange={(next: string[] | string | undefined) => { setText(''); onChange(mode === 'multiple' ? (next as string[] | undefined) ?? [] : (next as string | undefined) ?? '') }}
      notFoundContent={query.isFetching ? undefined : emptyText}
    />
  )
}
