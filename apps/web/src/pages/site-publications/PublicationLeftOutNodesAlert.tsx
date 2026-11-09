import { Alert, Tag, Tooltip } from 'antd'
import { useTranslation } from 'react-i18next'
import type { AdminSitePublication } from '../../api/sitePublications'
import '../../i18n/sitePublicationLeftOutNodes'

// A publication names the nodes it did not reach as intended
// (AdminPublication key_envelope_oversized_node_ids /
// site_selection_unsupported_node_ids, kept on the publication by migration
// 649 for every channel). Same wording as the node list's 旧配置仍生效
// (NodeStaleConfigurationTag).

// Any publication row (a tenant one has neither list): id keeps it from being a weak type.
type LeftOutNodes = Pick<AdminSitePublication, 'id' | 'key_envelope_oversized_node_ids' | 'site_selection_unsupported_node_ids'>

function leftOutGroups(publication: LeftOutNodes) {
  return ([
    ['oversized', 'tag', publication.key_envelope_oversized_node_ids],
    ['unsupported', 'unsupportedTag', publication.site_selection_unsupported_node_ids],
  ] as const).filter(([, , nodes]) => nodes?.length) as [string, string, string[]][]
}

/** The publication list row's warning tags (details on hover/focus); nothing when there are none. */
export function PublicationLeftOutNodesTag({ publication }: { publication: LeftOutNodes }) {
  const { t } = useTranslation('sitePublicationLeftOutNodes')
  return <>{leftOutGroups(publication).map(([key, tag, nodes]) => (
    <Tooltip key={key} title={`${t(key, { count: nodes.length })}。${t('nodes', { nodes: nodes.join(', ') })}`}>
      <Tag color="warning" tabIndex={0}>{t(tag, { count: nodes.length })}</Tag>
    </Tooltip>
  ))}</>
}

/** Warning for the nodes a publication left on the old configuration; nothing when there are none. */
export default function PublicationLeftOutNodesAlert({ publication }: { publication: LeftOutNodes }) {
  const { t } = useTranslation('sitePublicationLeftOutNodes')
  const lines = leftOutGroups(publication).flatMap(([key, , nodes]) => [
    t(key, { count: nodes.length }), t('nodes', { nodes: nodes.join(', ') }),
  ])
  if (lines.length === 0) return null
  return (
    <Alert className="site-publications-alert" type="warning" showIcon role="alert"
      data-testid="site-publication-left-out-nodes" message={t('title')}
      description={lines.map((line) => <div key={line}>{line}</div>)} />
  )
}
