import { Alert, Tag, Tooltip } from 'antd'
import { useTranslation } from 'react-i18next'
import type { NodeStaleConfiguration } from '../api/nodes'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/nodeStaleConfiguration'

// A node whose Agent predates SITE_SELECTION (capability 82)
// was left out of a tenant's latest release because its key document did
// not fit. It still runs the previous configuration of that tenant.

function useStaleText(items: readonly NodeStaleConfiguration[] | undefined): string[] {
  const { t, i18n: active } = useTranslation('nodeStaleConfiguration')
  if (!items?.length) return []
  return [
    ...items.map((item) => t('reason', {
      tenant: item.tenant_name || t('platform'), revision: item.source_revision,
      time: formatDateTime(item.left_out_at, active.resolvedLanguage),
    })),
    t('effect'), t('remedy'),
  ]
}

/** The 旧配置仍生效 tag of the node list, details on hover/focus; nothing when the node is up to date. */
export function NodeStaleConfigurationTag({ items }: { items: readonly NodeStaleConfiguration[] | undefined }) {
  const { t } = useTranslation('nodeStaleConfiguration')
  const details = useStaleText(items)
  if (details.length === 0) return null
  return (
    <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{details.join('\n')}</span>} trigger={['hover', 'focus', 'click']}>
      <Tag color="warning" className="node-stale-configuration-tag" tabIndex={0} aria-label={`${t('tag')}。${details.join(' ')}`}>
        {t('tag')}
      </Tag>
    </Tooltip>
  )
}

/** The node detail's warning for the same state. */
export function NodeStaleConfigurationAlert({ items }: { items: readonly NodeStaleConfiguration[] | undefined }) {
  const { t } = useTranslation('nodeStaleConfiguration')
  const details = useStaleText(items)
  if (details.length === 0) return null
  return (
    <Alert className="node-inventory-stale-configuration" type="warning" showIcon role="alert" message={t('title')}
      description={details.map((line) => <div key={line}>{line}</div>)} />
  )
}
