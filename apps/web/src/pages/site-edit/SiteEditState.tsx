import type { ReactNode } from 'react'
import { Spin } from 'antd'

import { DataState } from '../../components/DataState'
import './SiteEditState.css'

// TECH-03: one load / permission / failure state for the site-edit panels.
// DataState itself is shared by many pages and stays unchanged; this wrapper
// only adds what the panels need on top of it: a visible loading label
// (DataState's loading state is a bare spinner) and an optional detail line
// under a load failure.
export type SiteEditStateProps =
  | { status: 'loading'; label: ReactNode; className?: string }
  | { status: 'forbidden'; title: ReactNode; detail?: ReactNode; onRetry?: () => void; className?: string }
  | { status: 'error'; title: ReactNode; detail?: ReactNode; onRetry?: () => void; className?: string }
  | { status: 'empty'; title: ReactNode; detail?: ReactNode; className?: string }

// title with its detail line under it (DataState shows a single message)
function withDetail(title: ReactNode, detail?: ReactNode): ReactNode {
  return detail ? <span className="site-edit-state-message"><span>{title}</span><span className="site-edit-state-detail">{detail}</span></span> : title
}

export default function SiteEditState(props: SiteEditStateProps) {
  const className = ['site-edit-state', props.className].filter(Boolean).join(' ')
  switch (props.status) {
    case 'loading':
      return (
        <div className={`${className} site-edit-state-loading`} aria-busy="true">
          <Spin size="small" />
          <span>{props.label}</span>
        </div>
      )
    case 'forbidden':
      return <DataState className={className} status="forbidden" message={props.title} description={props.detail} onRetry={props.onRetry} />
    case 'error':
      return <DataState className={className} status="error" onRetry={props.onRetry} message={withDetail(props.title, props.detail)} />
    default:
      return <DataState className={className} status="empty" message={withDetail(props.title, props.detail)} />
  }
}
