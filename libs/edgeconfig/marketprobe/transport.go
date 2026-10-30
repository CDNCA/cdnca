// Package marketprobe is the node-market probe contract shared by control-api
// (sends commands), agent-gateway (relays them on the node's session) and the
// edge Agent (executes them).
//
// Probes are ephemeral: a command is useful only until its market round
// expires, so it travels as a core NATS request/reply, not a durable stream.
// No responder means the node has no live session; control-api skips it.
package marketprobe

const (
	// RequestSubjectPrefix is followed by ".<node-id>". The gateway holding the
	// node's session subscribes; control-api sends MarketProbeCommand requests.
	// The reply is a MarketProbeResult, or an empty body if the gateway refused.
	RequestSubjectPrefix = "cdnca.agent.market-probe.requests"
	// QueueGroup lets exactly one gateway replica answer for a node.
	QueueGroup = "agent_gateway_market_probe"

	// Path is the market probe path edges answer with 204.
	Path = "/.well-known/cdnca-market-probe"

	// BenchmarkPath serves the fixed benchmark object on market-pool edges
	// (CAPABILITY_NAME_MARKET_BENCHMARK v1); probers download it in parallel
	// to grade a node at admission.
	BenchmarkPath = "/.well-known/cdnca-market-benchmark"
	// BenchmarkBytes is the size of the benchmark object; one connection
	// reads at most this much.
	BenchmarkBytes = 8 << 20
	// MaxBenchmarkConnections a benchmark may open to one target.
	MaxBenchmarkConnections = 8

	MaxTargets       = 64
	MaxTimeoutMillis = 10_000
	MinTimeoutMillis = 100
	// MaxCarrierBytes bounds one MarketProbeCommand or MarketProbeResult.
	MaxCarrierBytes = 64 << 10
	// MaxCAPEMBytes bounds the custom CA of one MARKET_PROBE v3 origin
	// target; a larger CA is probed by the control plane.
	MaxCAPEMBytes = 16 << 10
)

// Subject returns the request subject for nodeID.
func Subject(nodeID string) string { return RequestSubjectPrefix + "." + nodeID }
