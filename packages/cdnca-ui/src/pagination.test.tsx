import { render, screen, within } from '@testing-library/react'
import { ConfigProvider } from 'antd'
import enUS from 'antd/locale/en_US'
import zhCN from 'antd/locale/zh_CN'
import { describe, expect, it } from 'vitest'

import { CdncaProvider, DataTable, Pagination, Table } from './index'

// 上一页/下一页按钮按 antd locale 命名，不读图标英文名 left/right（全站延伸）。
const rows = Array.from({ length: 30 }, (_, index) => ({ id: index + 1 }))
const columns = [{ title: 'ID', dataIndex: 'id' }]

describe('pagination button names', () => {
  it('names the previous and next buttons of a standalone Pagination', () => {
    render(<CdncaProvider locale={zhCN}><Pagination current={1} pageSize={10} total={30} /></CdncaProvider>)
    expect(screen.getByRole('button', { name: '上一页' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '下一页' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'left' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'right' })).toBeNull()
  })

  it('keeps a page-provided itemRender', () => {
    render(<ConfigProvider locale={zhCN}><Pagination current={1} pageSize={10} total={30}
      itemRender={(page, type, original) => type === 'page' ? <a>第{page}页</a> : original} /></ConfigProvider>)
    expect(screen.getByText('第2页')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '下一页' })).toBeInTheDocument()
  })

  it('names the built-in pagination of a Table, with and without a pagination config', () => {
    const { unmount } = render(<CdncaProvider locale={zhCN}><Table rowKey="id" columns={columns} dataSource={rows} /></CdncaProvider>)
    expect(screen.getByRole('button', { name: '上一页' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '下一页' })).toBeInTheDocument()
    unmount()
    render(<CdncaProvider locale={zhCN}><Table rowKey="id" columns={columns} dataSource={rows}
      pagination={{ pageSize: 20, itemRender: (_page, type, original) => type === 'prev' ? <span>前</span> : original }} /></CdncaProvider>)
    expect(screen.getByRole('table')).toBeInTheDocument()
    expect(within(screen.getByRole('list')).getByText('前')).toHaveAttribute('aria-label', '上一页')
    expect(screen.getByRole('button', { name: '下一页' })).toBeInTheDocument()
    expect(screen.getAllByRole('row')).toHaveLength(21)
  })

  it('follows the active locale and leaves pagination={false} without paging', () => {
    const { unmount } = render(<CdncaProvider locale={enUS}><DataTable rowKey="id" columns={columns} dataSource={rows} /></CdncaProvider>)
    expect(screen.getByRole('button', { name: 'Previous Page' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Next Page' })).toBeInTheDocument()
    unmount()
    render(<CdncaProvider locale={zhCN}><Table rowKey="id" columns={columns} dataSource={rows} pagination={false} /></CdncaProvider>)
    expect(screen.queryByRole('button', { name: '上一页' })).toBeNull()
    expect(screen.getAllByRole('row')).toHaveLength(31)
  })
})
