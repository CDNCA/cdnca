import type { NodeLineGroup } from '../api/nodeScheduling'
import type { NodeInventoryItem } from '../api/nodes'

export type JoinNode = Pick<NodeInventoryItem, 'id' | 'region'> & { presence: Pick<NodeInventoryItem['presence'], 'status'> }

export interface NodeJoinState {
  connected: boolean
  inLineGroup: boolean
  inDNS: boolean
  /** Where the next missing step is done: a line group's resolution page, or null to create a line group. */
  target: NodeLineGroup | null
}

// The three things a new node needs to take traffic, read from the node
// (presence) and the general line groups (endpoints and their published
// flag, node_line_endpoint_published): Agent connected, an endpoint in a line
// group, and DNS publishing one of its IPs.
export function nodeJoinState(node: JoinNode, groups: NodeLineGroup[]): NodeJoinState {
  const own = (group: NodeLineGroup) => group.endpoints.filter((endpoint) => endpoint.node_id === node.id)
  const member = groups.filter((group) => own(group).length > 0)
  const inDNS = member.some((group) => own(group).some((endpoint) => endpoint.published === true))
  const target = member.find((group) => !own(group).some((endpoint) => endpoint.published === true)) ??
    member[0] ?? groups.find((group) => group.region === node.region) ?? null
  return { connected: node.presence.status === 'online', inLineGroup: member.length > 0, inDNS, target }
}

/** The resolution page of a line group with the node preselected among its unset IPs. */
export function lineResolutionPath(groupID: string, nodeID: string): string {
  return `/node/line-group/line/${encodeURIComponent(groupID)}?node=${encodeURIComponent(nodeID)}`
}
