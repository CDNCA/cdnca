import { fireEvent, render as rtlRender, screen, waitFor, within } from '@testing-library/react'
import type { ReactElement } from 'react'
import { Drawer, Input, Modal, Select } from 'antd'
import enUS from 'antd/locale/en_US'
import zhCN from 'antd/locale/zh_CN'
import { describe, expect, it, vi } from 'vitest'

import {
  AddButton, CdncaProvider, CursorPager, DangerButton, DataTable, DRAWER_WIDTH, FormGrid, MODAL_WIDTH, ModalFooter, PageHeader, PageSection,
  StatusTag, TableToolbar, cdncaTheme, defaultAntdTokens, defaultCSSTokens,
} from './index'

// Every end renders under CdncaProvider (no space inserted between two CJK characters).
const render = (ui: ReactElement) => rtlRender(ui, { wrapper: ({ children }) => <CdncaProvider>{children}</CdncaProvider> })

describe('tokens', () => {
  it('passes the status colors to antd with the css values (K1)', () => {
    expect(cdncaTheme().token).toMatchObject({
      colorSuccess: defaultCSSTokens.colorSuccess, colorWarning: defaultCSSTokens.colorWarning,
      colorError: defaultCSSTokens.colorError, colorInfo: defaultAntdTokens.colorPrimary,
    })
    expect(cdncaTheme().token).toMatchObject({ colorSuccess: '#19be6b', colorWarning: '#ff9900', colorError: '#ed4014', colorInfo: '#2d8cf0' })
    // Info follows a white-label primary; the console look keeps its own palette.
    expect(cdncaTheme({ ...defaultAntdTokens, colorPrimary: '#0f766e' }).token?.colorInfo).toBe('#0f766e')
    expect(cdncaTheme(defaultAntdTokens, false, 'console').token?.colorSuccess).toBe('#16a34a')
  })

  it('reads the table header background from --cdnca-color-table-header (K2)', () => {
    expect(defaultCSSTokens.colorTableHeader).toBe('#f8f8f9')
    expect(cdncaTheme().components?.Table?.headerBg).toBe('var(--cdnca-color-table-header, #f8f8f9)')
  })
})

describe('size constants', () => {
  it('has three modal widths and two drawer widths', () => {
    expect(MODAL_WIDTH).toEqual({ S: 520, M: 720, L: 960 })
    expect(DRAWER_WIDTH).toEqual({ S: 520, L: 720 })
  })
})

describe('PageHeader', () => {
  it('renders an h1 title, the actions in the same row and the description below', () => {
    const { container } = render(<PageHeader title="节点列表" description="管理全部节点" extra={<button type="button">刷新</button>} />)
    expect(screen.getByRole('heading', { level: 1, name: '节点列表' })).toHaveClass('cdnca-page-title')
    const row = container.querySelector('.cdnca-page-header-row')!
    expect(within(row as HTMLElement).getByRole('button', { name: '刷新' }).parentElement).toHaveClass('cdnca-page-header-extra')
    expect(screen.getByText('管理全部节点')).toHaveClass('cdnca-page-description')
  })

  it('leaves out empty description and actions', () => {
    const { container } = render(<PageHeader title="标题" />)
    expect(container.querySelector('.cdnca-page-description')).toBeNull()
    expect(container.querySelector('.cdnca-page-header-extra')).toBeNull()
  })
})

describe('PageSection', () => {
  it('wraps content in the card, with an optional head', () => {
    const { container } = render(<><PageSection title="基本信息" extra={<span>x</span>}>A</PageSection><PageSection className="extra">B</PageSection></>)
    const sections = container.querySelectorAll('section.cdnca-page-section')
    expect(sections).toHaveLength(2)
    expect(screen.getByRole('heading', { level: 2, name: '基本信息' })).toBeInTheDocument()
    expect(sections[1]).toHaveClass('extra')
    expect(sections[1].querySelector('.cdnca-page-section-head')).toBeNull()
  })
})

describe('TableToolbar', () => {
  it('puts actions on the left and filters on the right', () => {
    const { container } = render(<TableToolbar actions={<button type="button">添加</button>} filters={<><Input.Search placeholder="搜索" /><Select /></>} />)
    const [left, right] = Array.from(container.querySelector('.cdnca-table-toolbar')!.children)
    expect(left).toHaveClass('cdnca-table-toolbar-actions')
    expect(within(left as HTMLElement).getByRole('button', { name: '添加' })).toBeInTheDocument()
    expect(right).toHaveClass('cdnca-table-toolbar-filters')
    expect(within(right as HTMLElement).getByPlaceholderText('搜索')).toBeInTheDocument()
  })
})

describe('ModalFooter', () => {
  it('puts cancel first and the primary button last', () => {
    const onCancel = vi.fn()
    const onOk = vi.fn()
    render(<ModalFooter onCancel={onCancel} onOk={onOk} />)
    const buttons = screen.getAllByRole('button')
    expect(buttons.map((button) => button.textContent)).toEqual(['取消', '确定'])
    expect(buttons[1]).toHaveClass('ant-btn-primary')
    expect(buttons[1]).not.toHaveClass('ant-btn-dangerous')
    fireEvent.click(buttons[0])
    fireEvent.click(buttons[1])
    expect(onCancel).toHaveBeenCalledOnce()
    expect(onOk).toHaveBeenCalledOnce()
  })

  it('marks the primary button danger and honours custom text and loading', () => {
    render(<ModalFooter onCancel={() => undefined} danger okText="删除" loading />)
    const ok = screen.getByRole('button', { name: /删除/ })
    expect(ok).toHaveClass('ant-btn-primary', 'ant-btn-dangerous', 'ant-btn-loading')
  })

  it('follows the antd locale', () => {
    rtlRender(<CdncaProvider locale={enUS}><ModalFooter onCancel={() => undefined} /></CdncaProvider>)
    expect(screen.getAllByRole('button').map((button) => button.textContent)).toEqual(['Cancel', 'OK'])
  })
})

// MSG-M04: the Modal × is named by the antd locale, not rc-dialog's built-in "Close".
describe('modal close button name', () => {
  it('reads 关闭 under zh_CN and keeps closable={false} closed off', () => {
    rtlRender(
      <CdncaProvider locale={zhCN}>
        <Modal open title="甲">内容</Modal>
        <Modal open title="乙" closable={false}>内容</Modal>
        <Drawer open title="丙">内容</Drawer>
      </CdncaProvider>,
    )
    expect(screen.getAllByRole('button', { name: '关闭' })).toHaveLength(2)
    expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument()
  })

  it('keeps an explicit per-modal name and follows en_US', () => {
    rtlRender(
      <CdncaProvider locale={enUS}>
        <Modal open title="A" closable={{ 'aria-label': 'Close allocations' }}>x</Modal>
        <Modal open title="B">x</Modal>
      </CdncaProvider>,
    )
    expect(screen.getByRole('button', { name: 'Close allocations' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument()
  })
})

describe('StatusTag', () => {
  it.each(['success', 'processing', 'warning', 'error', 'default'] as const)('renders the %s semantic color', (status) => {
    render(<StatusTag status={status}>状态</StatusTag>)
    const tag = screen.getByText('状态')
    expect(tag).toHaveClass('cdnca-status-tag')
    if (status !== 'default') expect(tag).toHaveClass(`ant-tag-${status}`)
  })

  it('accepts only the five statuses', () => {
    // @ts-expect-error palette names are not statuses
    render(<StatusTag status="green">x</StatusTag>)
  })
})

describe('CursorPager', () => {
  it('shows the total and pages with previous / next', () => {
    const onPrev = vi.fn()
    const onNext = vi.fn()
    render(<CursorPager hasPrev={false} hasNext onPrev={onPrev} onNext={onNext} total={42} />)
    expect(screen.getByText('共 42 条')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))
    expect(onNext).toHaveBeenCalledOnce()
    expect(onPrev).not.toHaveBeenCalled()
  })

  it('disables both buttons while loading and hides an unknown total', () => {
    const { container } = render(<CursorPager hasPrev hasNext onPrev={() => undefined} onNext={() => undefined} loading />)
    expect(container.querySelector('.cdnca-cursor-pager-total')).toBeNull()
    expect(screen.getByRole('button', { name: '上一页' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '下一页' })).toBeDisabled()
  })
})

describe('AddButton', () => {
  it('is a primary button with the Plus icon reading 添加{name}', () => {
    const onClick = vi.fn()
    render(<AddButton name="节点" onClick={onClick} />)
    const button = screen.getByRole('button', { name: '添加节点' })
    expect(button).toHaveClass('ant-btn-primary')
    expect(button.querySelector('svg.cdnca-add-icon')).not.toBeNull()
    fireEvent.click(button)
    expect(onClick).toHaveBeenCalledOnce()
  })

  it('reads "Add {name}" in English', () => {
    rtlRender(<CdncaProvider locale={enUS}><AddButton name="node" /></CdncaProvider>)
    expect(screen.getByRole('button', { name: 'Add node' })).toBeInTheDocument()
  })
})

describe('DangerButton', () => {
  it('is default + danger and confirms before acting', async () => {
    const onConfirm = vi.fn()
    render(<DangerButton confirmTitle="确定删除选中的 3 项？" onConfirm={onConfirm}>批量删除</DangerButton>)
    const button = screen.getByRole('button', { name: '批量删除' })
    expect(button).toHaveClass('ant-btn-default', 'ant-btn-dangerous')
    expect(button).not.toHaveClass('ant-btn-primary')
    fireEvent.click(button)
    expect(onConfirm).not.toHaveBeenCalled()
    expect(await screen.findByText('确定删除选中的 3 项？')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '确定' }))
    await waitFor(() => expect(onConfirm).toHaveBeenCalledOnce())
  })

  it('does not open the confirm when disabled', () => {
    render(<DangerButton confirmTitle="确认？" onConfirm={() => undefined} disabled>删除</DangerButton>)
    expect(screen.getByRole('button', { name: '删除' })).toBeDisabled()
  })
})

describe('DataTable', () => {
  const columns = [{ title: '名称', dataIndex: 'name' }]
  const rows = Array.from({ length: 25 }, (_, index) => ({ id: index, name: `n${index}` }))

  it('is small and pages 20 per page on the right with the total', () => {
    const { container } = render(<DataTable rowKey="id" columns={columns} dataSource={rows} />)
    expect(container.querySelector('.ant-table-small')).not.toBeNull()
    expect(container.querySelector('.ant-pagination-end, .ant-table-pagination-right, .ant-table-pagination-end')).not.toBeNull()
    expect(screen.getByText('共 25 条')).toBeInTheDocument()
    expect(container.querySelectorAll('tbody tr.ant-table-row')).toHaveLength(20)
  })

  it('keeps the caller pagination (false for a CursorPager)', () => {
    const { container } = render(<DataTable rowKey="id" columns={columns} dataSource={rows} pagination={false} />)
    expect(container.querySelector('.ant-pagination')).toBeNull()
  })
})

describe('FormGrid', () => {
  it('lays fields on a column grid with full-width rows', () => {
    const { container } = render(<FormGrid columns={3}><span>a</span><FormGrid.Full><span>b</span></FormGrid.Full></FormGrid>)
    expect(container.querySelector('.cdnca-form-grid')).toHaveClass('cdnca-form-grid-3')
    expect(screen.getByText('b').parentElement).toHaveClass('cdnca-form-grid-full')
  })
})
