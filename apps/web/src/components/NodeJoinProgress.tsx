import { Steps } from 'antd'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import type { NodeLineGroup } from '../api/nodeScheduling'
import '../pages/NodeListPage.locale'
import './NodeJoinProgress.css'
import { lineResolutionPath, nodeJoinState, type JoinNode } from './nodeJoin'

export function NodeJoinProgress({ node, groups }: { node: JoinNode; groups: NodeLineGroup[] }) {
  const { t } = useTranslation('nodes')
  const state = nodeJoinState(node, groups)
  const done = [state.connected, state.inLineGroup, state.inDNS]
  const current = done.indexOf(false)
  const action = state.target
    ? <Link to={lineResolutionPath(state.target.id, node.id)}>{t('join.toResolution', { name: state.target.name })}</Link>
    : <Link to="/node/line-group">{t('join.createLineGroup')}</Link>
  const items = (['connected', 'inLineGroup', 'inDNS'] as const).map((key, index) => ({
    title: t(`join.${key}`),
    status: done[index] ? 'finish' as const : index === current ? 'process' as const : 'wait' as const,
    description: index === current && index > 0 ? action : undefined,
  }))
  return (
    <div className="node-join-progress" data-testid="node-join-progress">
      <Steps size="small" current={current < 0 ? 3 : current} items={items} />
    </div>
  )
}
