import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import type { TableRowSelection } from 'antd/es/table/interface'

// antd 5 names the header checkbox "Select all" in English (table/hooks/useSelection.js) and leaves every
// row checkbox unnamed, so keyboard and screen reader users could not tell whom a bulk disable or delete
// would hit. Each table names its rows after the field people recognize the
// row by, and the header after the objects it selects on the current page.

export type RowName<T> = (row: T) => string | number | null | undefined

/**
 * Adds row and header checkbox names to an antd rowSelection. `t` must be bound to the common namespace.
 * The page's own getCheckboxProps / getTitleCheckboxProps are kept (disabled and the rest); only the
 * aria-label is ours. `scope` is the page's plural noun for its rows (用户 / users); without it the
 * header reads 选择当前页全部.
 */
export function namedRowSelection<T>(t: TFunction, selection: TableRowSelection<T>, nameOf: RowName<T>, scope?: string): TableRowSelection<T> {
  const { getCheckboxProps, getTitleCheckboxProps } = selection
  const pageAll = scope?.trim() ? t('rowSelection.pageAll', { scope: scope.trim() }) : t('rowSelection.pageAllUnnamed')
  return {
    ...selection,
    getCheckboxProps: (row) => {
      const name = String(nameOf(row) ?? '').trim()
      return { ...getCheckboxProps?.(row), 'aria-label': name ? t('rowSelection.row', { name }) : t('rowSelection.rowUnnamed') }
    },
    getTitleCheckboxProps: () => ({ ...getTitleCheckboxProps?.(), 'aria-label': pageAll }),
  }
}

/** namedRowSelection bound to the common namespace, following language switches. */
export function useNamedRowSelection() {
  const { t } = useTranslation('common')
  return useCallback(<T,>(selection: TableRowSelection<T>, nameOf: RowName<T>, scope?: string) => namedRowSelection(t, selection, nameOf, scope), [t])
}
