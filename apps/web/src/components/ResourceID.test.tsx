import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { getResourceIDCopyValues, ResourceID } from './ResourceID'

const internalID = '5d901dd2-75b5-4aca-9c26-e96d9aee78e5'

describe('ResourceID', () => {
  it('shows the persistent display ID by default without exposing a fake UUID prefix', () => {
    render(<ResourceID internalId={internalID} displayId="S-1024" />)

    const value = screen.getByText('S-1024')
    const root = value.closest('.resource-id')
    expect(root).toHaveAttribute('data-resource-id-variant', 'baseline')
    expect(root).toHaveAttribute('title', 'S-1024')
    expect(screen.queryByText(internalID)).not.toBeInTheDocument()
  })

  it('falls back to the complete internal ID when display ID is absent', () => {
    render(<ResourceID internalId={internalID} displayId={null} />)

    const value = screen.getByText(internalID)
    expect(value).toHaveClass('resource-id__primary')
    expect(value.closest('.resource-id')).toHaveAttribute('title', internalID)
    expect(getResourceIDCopyValues(internalID, null)).toEqual({
      displayId: null,
      internalId: internalID,
      primary: internalID,
    })
  })

  it('shows both stable identifiers in qualified mode and exposes exact copy values', () => {
    render(<ResourceID internalId={internalID} displayId=" S-1024 " variant="qualified" />)

    expect(screen.getByText('S-1024')).toBeInTheDocument()
    expect(screen.getByText(internalID)).toBeInTheDocument()
    expect(screen.getByText('S-1024').closest('.resource-id')).toHaveAttribute(
      'title',
      `S-1024 · ${internalID}`,
    )
    expect(getResourceIDCopyValues(internalID, ' S-1024 ')).toEqual({
      displayId: 'S-1024',
      internalId: internalID,
      primary: 'S-1024',
    })
  })

  it('fails closed for an empty internal ID and treats an empty display ID as absent', () => {
    const { rerender } = render(<ResourceID internalId="   " displayId="S-1024" />)

    const empty = screen.getByText('—')
    expect(empty.closest('.resource-id')).toHaveAttribute('aria-disabled', 'true')
    expect(screen.queryByText('S-1024')).not.toBeInTheDocument()
    expect(getResourceIDCopyValues('   ', 'S-1024')).toEqual({
      displayId: null,
      internalId: null,
      primary: null,
    })

    rerender(<ResourceID internalId={internalID} displayId="   " />)
    expect(screen.getByText(internalID)).toBeInTheDocument()
  })

  it('keeps the complete value keyboard focusable when CSS visually elides it', async () => {
    const user = userEvent.setup()
    render(<ResourceID internalId={internalID} displayId={null} />)

    const root = screen.getByText(internalID).closest('.resource-id')
    expect(root).toHaveAttribute('tabindex', '0')
    await user.tab()
    expect(root).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(root).toHaveFocus()
    expect(root).toHaveAttribute('title', internalID)
  })
})
