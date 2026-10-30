import type { HTMLAttributes } from 'react'

import './ResourceID.css'

export type ResourceIDVariant = 'baseline' | 'qualified'

export interface ResourceIDCopyValues {
  displayId: string | null
  internalId: string | null
  primary: string | null
}

export interface ResourceIDProps extends Omit<HTMLAttributes<HTMLSpanElement>, 'children' | 'title'> {
  internalId: string
  displayId?: string | null
  variant?: ResourceIDVariant
}

function normalizedID(value: string | null | undefined): string | null {
  const normalized = value?.trim()
  return normalized ? normalized : null
}

// Kept beside the component so this owned slice exposes exact copy values without a fourth shared utility file.
// eslint-disable-next-line react-refresh/only-export-components
export function getResourceIDCopyValues(
  internalId: string,
  displayId?: string | null,
): ResourceIDCopyValues {
  const normalizedInternalID = normalizedID(internalId)
  if (!normalizedInternalID) {
    return { displayId: null, internalId: null, primary: null }
  }

  const normalizedDisplayID = normalizedID(displayId)
  return {
    displayId: normalizedDisplayID,
    internalId: normalizedInternalID,
    primary: normalizedDisplayID ?? normalizedInternalID,
  }
}

export function ResourceID({
  internalId,
  displayId = null,
  variant = 'baseline',
  className,
  ...spanProps
}: ResourceIDProps) {
  const values = getResourceIDCopyValues(internalId, displayId)
  const qualified = variant === 'qualified' && values.displayId !== null

  if (!values.internalId || !values.primary) {
    return (
      <span
        {...spanProps}
        className={['resource-id', 'resource-id--empty', className].filter(Boolean).join(' ')}
        data-resource-id-variant={variant}
        aria-disabled="true"
      >
        <span className="resource-id__primary">—</span>
      </span>
    )
  }

  const title = qualified
    ? `${values.primary} · ${values.internalId}`
    : values.primary

  return (
    <span
      {...spanProps}
      className={['resource-id', `resource-id--${variant}`, className].filter(Boolean).join(' ')}
      data-resource-id-variant={variant}
      title={title}
      aria-label={title}
      tabIndex={0}
    >
      <span className="resource-id__primary">{values.primary}</span>
      {qualified ? (
        <>
          <span className="resource-id__separator" aria-hidden="true">·</span>
          <span className="resource-id__internal">{values.internalId}</span>
        </>
      ) : null}
    </span>
  )
}
