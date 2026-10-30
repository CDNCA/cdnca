import type { ReactNode } from 'react'
import { Button, Result, Spin } from 'antd'
import { CircleAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'

export type DataStatus = 'loading' | 'empty' | 'error' | 'forbidden'

export interface DataStateProps {
  status: DataStatus
  onRetry?: () => void
  className?: string
  message?: ReactNode
  description?: ReactNode
}

export function DataState({ status, onRetry, className, message, description }: DataStateProps) {
  const { t } = useTranslation('common')
  const rootClassName = ['data-state', className].filter(Boolean).join(' ')

  if (status === 'loading') {
    return (
      <div className={rootClassName} aria-label={typeof message === 'string' ? message : t('dataLoading')}>
        <Spin size="small" />
      </div>
    )
  }

  if (status === 'forbidden') {
    return (
      <Result
        className={[className, 'data-state-forbidden'].filter(Boolean).join(' ')}
        status="403"
        title={message ?? t('forbidden')}
        subTitle={description}
        extra={onRetry ? (
          <Button type="primary" size="small" onClick={onRetry}>
            {t('retry')}
          </Button>
        ) : undefined}
      />
    )
  }

  if (status === 'error') {
    return (
      <div className={`${rootClassName} data-state-error`} role="alert">
        <CircleAlert size={16} aria-hidden="true" />
        <span>{message ?? t('dataLoadFailed')}</span>
        {onRetry ? (
          <Button type="link" size="small" onClick={onRetry}>
            {t('retry')}
          </Button>
        ) : null}
      </div>
    )
  }

  return <div className={rootClassName}>{message ?? t('noData')}</div>
}
