// Package l4live holds the transport contract of L4 live connection
// requests (CAPABILITY_NAME_L4_LIVE_CONNECTIONS): control-api sends an
// L4LiveConnectionsCommand on the node's request subject, the gateway holding
// the node's session relays it and replies with the Agent's
// L4LiveConnectionsResult, or an empty body when it refused.
package l4live

const (
	RequestSubjectPrefix = "cdnca.agent.l4-live.requests"
	QueueGroup           = "agent_gateway_l4_live"
	// MaxCarrierBytes bounds a command or result (1000 connections fit).
	MaxCarrierBytes = 512 << 10
	MaxConnections  = 1000
	MaxCloseKeys    = 1000
	// MaxTTLMillis bounds expire_time - now.
	MaxTTLMillis = 15_000
)

func Subject(nodeID string) string { return RequestSubjectPrefix + "." + nodeID }
