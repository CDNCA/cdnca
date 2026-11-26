import { fireEvent, screen } from '@testing-library/react'

// Picks a value in a TenantScopeSelect (components/TenantScopeSelect.tsx) by pasting the canonical UUID it offers as-is;
// works while the select sits in a closed 高级筛选 panel.
export async function pickTenantByID(id: string, name = '租户') {
  const box = screen.getByRole('combobox', { name, hidden: true })
  fireEvent.mouseDown(box)
  fireEvent.change(box, { target: { value: id } })
  fireEvent.click(await screen.findByTitle(id))
}
