import { useLocation } from 'react-router-dom'

import NodeL2NodesPage from './NodeL2NodesPage'
import NodeLineResolutionPage from './NodeLineResolutionPage'

export default function NodeL2TopologyDetailPage() {
  const location = useLocation()
  return location.pathname.startsWith('/node/line-group/')
    ? <NodeLineResolutionPage />
    : <NodeL2NodesPage />
}
