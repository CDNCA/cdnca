import { fireEvent, screen } from '@testing-library/react'
import { Table } from 'antd'
import { useState, type Key } from 'react'
import { afterEach, describe, expect, it } from 'vitest'

import i18n, { changeLocale } from '../i18n'
import { renderWithProviders } from '../test/render'
import { namedRowSelection, useNamedRowSelection } from './namedRowSelection'

type Row = { id: string; name: string; locked?: boolean }
const rows: Row[] = [{ id: 'a', name: 'alice' }, { id: 'b', name: 'bob', locked: true }, { id: 'c', name: ' ' }]

function Demo({ scope }: { scope?: string }) {
  const named = useNamedRowSelection()
  const [selected, setSelected] = useState<Key[]>([])
  return (
    <>
      <Table<Row> rowKey="id" dataSource={rows} pagination={false} columns={[{ title: 'Name', dataIndex: 'name' }]}
        rowSelection={named({ selectedRowKeys: selected, onChange: setSelected, getCheckboxProps: (row) => ({ disabled: row.locked }) }, (row) => row.name, scope)} />
      <output>{selected.join(',')}</output>
    </>
  )
}

afterEach(async () => { await changeLocale('zh-CN') })

describe('namedRowSelection', () => {
  it('names rows and the header in Chinese, keeping the page disabled rule', async () => {
    await changeLocale('zh-CN')
    renderWithProviders(<Demo scope="用户" />)
    expect(screen.getByRole('checkbox', { name: '选择当前页全部用户' })).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: 'Select all' })).toBeNull()
    expect(screen.getByRole('checkbox', { name: '选择 alice' })).toBeEnabled()
    expect(screen.getByRole('checkbox', { name: '选择 bob' })).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: '选择此行' })).toBeEnabled()
  })

  it('names rows and the header in English and without a scope noun', async () => {
    await changeLocale('en-US')
    renderWithProviders(<Demo />)
    expect(screen.getByRole('checkbox', { name: 'Select all on this page' })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Select alice' })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Select bob' })).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: 'Select this row' })).toBeInTheDocument()
  })

  it('keeps selection behavior: a row toggles itself, the header selects the enabled rows of the page', async () => {
    await changeLocale('zh-CN')
    renderWithProviders(<Demo scope="用户" />)
    fireEvent.click(screen.getByRole('checkbox', { name: '选择 alice' }))
    expect(screen.getByRole('status')).toHaveTextContent(/^a$/)
    fireEvent.click(screen.getByRole('checkbox', { name: '选择 alice' }))
    fireEvent.click(screen.getByRole('checkbox', { name: '选择当前页全部用户' }))
    expect(screen.getByRole('status')).toHaveTextContent(/^a,c$/)
  })

  it('merges the original checkbox props and overrides only aria-label', () => {
    const t = i18n.getFixedT('en-US', 'common')
    const merged = namedRowSelection<Row>(t, {
      columnWidth: 40,
      getCheckboxProps: (row) => ({ disabled: row.locked, name: 'pick', 'aria-label': 'old' } as never),
      getTitleCheckboxProps: () => ({ disabled: true, 'aria-label': 'Select all' }),
    }, (row) => row.name, 'users')
    expect(merged.columnWidth).toBe(40)
    expect(merged.getCheckboxProps?.(rows[1])).toEqual({ disabled: true, name: 'pick', 'aria-label': 'Select bob' })
    expect(merged.getTitleCheckboxProps?.()).toEqual({ disabled: true, 'aria-label': 'Select all users on this page' })
    const zh = namedRowSelection<Row>(i18n.getFixedT('zh-CN', 'common'), {}, (row) => row.name)
    expect(zh.getCheckboxProps?.(rows[0])).toEqual({ 'aria-label': '选择 alice' })
    expect(zh.getTitleCheckboxProps?.()).toEqual({ 'aria-label': '选择当前页全部' })
  })
})
