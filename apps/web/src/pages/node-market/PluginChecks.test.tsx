import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { PluginChecks } from './PluginChecks'

const options = [{ value: 'ipintel', label: 'IP 情报库' }, { value: 'ja4', label: 'JA4 指纹' }, { value: 'module.autodefense', label: '智能自动防御' }]

describe('PluginChecks', () => {
  it('selects every plugin, then clears them, from 全选', () => {
    const onChange = vi.fn()
    const { rerender } = render(<PluginChecks options={options} value={['ja4']} onChange={onChange} />)
    const all = screen.getByRole('checkbox', { name: '全选' })
    expect(all).not.toBeChecked()
    fireEvent.click(all)
    expect(onChange).toHaveBeenLastCalledWith(['ja4', 'ipintel', 'module.autodefense'])
    rerender(<PluginChecks options={options} value={['ipintel', 'ja4', 'module.autodefense']} onChange={onChange} />)
    expect(screen.getByRole('checkbox', { name: '全选' })).toBeChecked()
    fireEvent.click(screen.getByRole('checkbox', { name: '全选' }))
    expect(onChange).toHaveBeenLastCalledWith([])
  })

  it('has no 全选 when there is nothing to pick', () => {
    render(<PluginChecks options={[]} value={[]} />)
    expect(screen.queryByRole('checkbox', { name: '全选' })).toBeNull()
  })
})
