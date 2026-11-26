import { useEffect, useState, type ReactNode } from 'react'

// 筛选栏（不在 antd Form 里）的字段级错误，共用：封禁名单、WAF/拦截/访问日志、四层访问日志与实时连接、网站与四层实时监控。
// 输入框带稳定 id、aria-invalid，aria-describedby 指向紧挨字段的错误文字；点查询或回车校验不过时焦点移到第一个出错字段，
// 边输入边生效的自动校验只标错、不抢焦点。错误只说字段，不替换页面已有的结果。

/** 输入框上的错误关联属性；没有错误时只给 id。 */
export function filterFieldProps(id: string, error?: string | null) {
  return {
    id,
    status: error ? 'error' as const : undefined,
    'aria-invalid': error ? true : undefined,
    'aria-describedby': error ? `${id}-error` : undefined,
  }
}

/**
 * 错误文字本身（id 与 filterFieldProps 的 aria-describedby 对应）。常显筛选行里的字段不包裹（行内对齐与定宽样式按直接子元素写），
 * 错误文字放在筛选行下方。
 */
export function FieldErrorText({ id, error }: { id: string; error?: string | null }) {
  return error ? <small id={`${id}-error`} className="filter-field-error" role="alert">{error}</small> : null
}

/** 字段和它下方的错误文字（高级筛选面板、标签在上的纵向字段）。 */
export function FilterField({ id, error, className, children }: { id: string; error?: string | null; className?: string; children: ReactNode }) {
  return (
    <span className={['filter-field', className].filter(Boolean).join(' ')}>
      {children}
      <FieldErrorText id={id} error={error} />
    </span>
  )
}

/**
 * focus(id)：在本次状态更新提交之后把焦点移到该输入框（错误文字与高级筛选面板已经渲染出来）。
 * 同一 id 连续两次出错也会再次聚焦。
 */
export function useFieldFocus(): (id: string) => void {
  const [target, setTarget] = useState<{ id: string } | null>(null)
  useEffect(() => {
    if (target) document.getElementById(target.id)?.focus()
  }, [target])
  return (id: string) => setTarget({ id })
}
