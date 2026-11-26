import { cloneElement, isValidElement, useContext, type ReactElement } from 'react'
import { ConfigProvider, Pagination as AntPagination, Table as AntTable, type PaginationProps, type TableProps } from 'antd'

type ItemRender = NonNullable<PaginationProps['itemRender']>

// antd 的上一页/下一页按钮只有箭头图标，读屏名取自图标英文名 left/right；ConfigProvider 的 pagination
// 只收样式与 showSizeChanger，图标上下文也不收 aria-label，所以没有全局开关。四端的 Table 与 Pagination
// 都从这里取（guard: pagination-names.guard.test.ts）：按当前 antd locale 给这两个按钮命名，页面自己的 itemRender 先执行。
export function useNamedItemRender(itemRender?: PaginationProps['itemRender']): ItemRender {
  const { locale } = useContext(ConfigProvider.ConfigContext)
  const names = { prev: locale?.Pagination?.prev_page, next: locale?.Pagination?.next_page }
  return (page, type, original) => {
    const element = itemRender ? itemRender(page, type, original) : original
    const name = type === 'prev' || type === 'next' ? names[type] : undefined
    return name && isValidElement(element) ? cloneElement(element as ReactElement<{ 'aria-label'?: string }>, { 'aria-label': name }) : element
  }
}

export function Pagination({ itemRender, ...props }: PaginationProps) {
  return <AntPagination {...props} itemRender={useNamedItemRender(itemRender)} />
}

export function Table<T extends object>({ pagination, ...props }: TableProps<T>) {
  const itemRender = useNamedItemRender(pagination ? pagination.itemRender : undefined)
  return <AntTable<T> {...props} pagination={pagination === false ? false : { ...pagination, itemRender }} />
}
