// Shared page building blocks (ported from apps/operator-console
// src/components/page.tsx). They fix layout, sizes and wording only; data and
// business logic stay in each page. Usage: ../COMPONENTS.md. Styles:
// styles.css "Page building blocks" (classic) and apps/web tech-look.css.
import { useContext, type ReactNode } from 'react'
import { Button, ConfigProvider, Popconfirm, Table, Tag, type ButtonProps, type TableProps } from 'antd'

/** Modal widths: S simple forms / confirms, M ordinary forms, L wide forms and tables. */
export const MODAL_WIDTH = { S: 520, M: 720, L: 960 } as const
/** Drawer widths: S short detail, L long detail or form. */
export const DRAWER_WIDTH = { S: 520, L: 720 } as const
/** Toolbar control widths (TableToolbar sets them on direct children). */
export const TOOLBAR_SEARCH_WIDTH = 240
export const TOOLBAR_SELECT_WIDTH = 150

const texts = {
  'zh-CN': { add: '添加', cancel: '取消', ok: '确定', prev: '上一页', next: '下一页', total: (n: number) => `共 ${n} 条` },
  'zh-TW': { add: '新增', cancel: '取消', ok: '確定', prev: '上一頁', next: '下一頁', total: (n: number) => `共 ${n} 條` },
  'en-US': { add: 'Add ', cancel: 'Cancel', ok: 'OK', prev: 'Previous', next: 'Next', total: (n: number) => `${n} in total` },
}

/** Built-in wording, chosen by the antd locale of the nearest ConfigProvider (Chinese without one). */
export function useCdncaText() {
  const locale = useContext(ConfigProvider.ConfigContext).locale?.locale
  return texts[locale === 'en' ? 'en-US' : locale === 'zh-tw' ? 'zh-TW' : 'zh-CN']
}

const cx = (...names: (string | false | undefined)[]) => names.filter(Boolean).join(' ')

/** Page title row: h1 on the left, actions (extra) on the same row at the right, description below. */
export function PageHeader({ title, description, extra, className }: {
  title: ReactNode
  description?: ReactNode
  extra?: ReactNode
  className?: string
}) {
  return (
    <div className={cx('cdnca-page-header', className)}>
      <div className="cdnca-page-header-row">
        <h1 className="cdnca-page-title">{title}</h1>
        {extra ? <div className="cdnca-page-header-extra">{extra}</div> : null}
      </div>
      {description ? <p className="cdnca-page-description">{description}</p> : null}
    </div>
  )
}

/** A 4px card (secondary border, shadow, 16px padding); consecutive sections sit 16px apart. */
export function PageSection({ title, extra, className, children }: {
  title?: ReactNode
  extra?: ReactNode
  className?: string
  children: ReactNode
}) {
  return (
    <section className={cx('cdnca-page-section', className)}>
      {title || extra ? (
        <div className="cdnca-page-section-head">
          {title ? <h2 className="cdnca-page-section-title">{title}</h2> : <span />}
          {extra ? <div className="cdnca-page-section-extra">{extra}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  )
}

/** Above a table: primary and batch actions on the left, filters and search on the right. */
export function TableToolbar({ actions, filters, className }: { actions?: ReactNode; filters?: ReactNode; className?: string }) {
  return (
    <div className={cx('cdnca-table-toolbar', className)}>
      <div className="cdnca-table-toolbar-actions">{actions}</div>
      {filters ? <div className="cdnca-table-toolbar-filters">{filters}</div> : null}
    </div>
  )
}

/** Modal footer: cancel on the left, the primary button on the right (danger for destructive actions). */
export function ModalFooter({ onCancel, onOk, okText, cancelText, loading, okDisabled, danger, okButtonProps }: {
  onCancel: () => void
  onOk?: () => void
  okText?: ReactNode
  cancelText?: ReactNode
  loading?: boolean
  okDisabled?: boolean
  danger?: boolean
  /** e.g. { htmlType: 'submit', form: 'my-form' } to submit a form outside the footer. */
  okButtonProps?: ButtonProps
}) {
  const text = useCdncaText()
  return (
    <div className="cdnca-modal-footer">
      <Button onClick={onCancel}>{cancelText ?? text.cancel}</Button>
      <Button type="primary" danger={danger} loading={loading} disabled={okDisabled} onClick={onOk} {...okButtonProps}>{okText ?? text.ok}</Button>
    </div>
  )
}

export type StatusTagStatus = 'success' | 'processing' | 'warning' | 'error' | 'default'

/** A status label in one of the five semantic colors (no palette names). */
export function StatusTag({ status, children, className }: { status: StatusTagStatus; children: ReactNode; className?: string }) {
  return <Tag color={status} className={cx('cdnca-status-tag', className)}>{children}</Tag>
}

/** Cursor paging: total (when known) and previous / next, aligned right under a table. */
export function CursorPager({ hasPrev, hasNext, onPrev, onNext, total, loading, className }: {
  hasPrev: boolean
  hasNext: boolean
  onPrev: () => void
  onNext: () => void
  total?: number
  loading?: boolean
  className?: string
}) {
  const text = useCdncaText()
  return (
    <nav className={cx('cdnca-cursor-pager', className)} aria-label="pagination">
      {total !== undefined ? <span className="cdnca-cursor-pager-total">{text.total(total)}</span> : null}
      <Button size="small" disabled={!hasPrev || loading} onClick={onPrev}>{text.prev}</Button>
      <Button size="small" disabled={!hasNext || loading} onClick={onNext}>{text.next}</Button>
    </nav>
  )
}

// lucide "plus" (stroke icon, same drawing as the apps' lucide-react Plus).
function PlusIcon() {
  return (
    <svg className="cdnca-add-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      <path d="M5 12h14" />
      <path d="M12 5v14" />
    </svg>
  )
}

/** The page's create button: primary, Plus icon, "添加{name}". */
export function AddButton({ name, type = 'primary', icon, children, ...props }: ButtonProps & { name: ReactNode }) {
  const text = useCdncaText()
  return <Button type={type} icon={icon ?? <PlusIcon />} {...props}>{children ?? <>{text.add}{name}</>}</Button>
}

/** Destructive action: default + danger button behind a confirm popover. */
export function DangerButton({ confirmTitle, confirmDescription, okText, onConfirm, disabled, children, ...props }: Omit<ButtonProps, 'danger' | 'type' | 'onClick'> & {
  confirmTitle: ReactNode
  confirmDescription?: ReactNode
  okText?: ReactNode
  onConfirm: () => void | Promise<unknown>
  children: ReactNode
}) {
  const text = useCdncaText()
  return (
    <Popconfirm title={confirmTitle} description={confirmDescription} okText={okText ?? text.ok} cancelText={text.cancel}
      okButtonProps={{ danger: true }} onConfirm={onConfirm} disabled={disabled}>
      <Button danger disabled={disabled} {...props}>{children}</Button>
    </Popconfirm>
  )
}

/**
 * antd Table with the shared defaults: small size, horizontal scroll, paging
 * on the right with the total (20 per page) unless the caller passes its own
 * pagination (false for CursorPager).
 */
export function DataTable<T extends object>({ pagination, scroll, size, className, ...props }: TableProps<T>) {
  const text = useCdncaText()
  return (
    <Table<T>
      className={cx('cdnca-data-table', className)}
      size={size ?? 'small'}
      scroll={scroll ?? { x: 'max-content' }}
      pagination={pagination === undefined ? { pageSize: 20, showSizeChanger: false, position: ['bottomRight'], showTotal: (total) => text.total(total) } : pagination}
      {...props}
    />
  )
}

/** Form fields on an aligned grid; <FormGrid.Full> takes a whole row. */
export function FormGrid({ columns = 2, className, children }: { columns?: 2 | 3 | 4; className?: string; children: ReactNode }) {
  return <div className={cx('cdnca-form-grid', `cdnca-form-grid-${columns}`, className)}>{children}</div>
}
FormGrid.Full = function FormGridFull({ children }: { children: ReactNode }) {
  return <div className="cdnca-form-grid-full">{children}</div>
}
