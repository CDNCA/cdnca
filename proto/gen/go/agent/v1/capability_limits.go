package agentv1

// MaxCapabilities is the single upper bound on AgentCapabilities.Features
// (and command required capabilities) shared by edge-agent, agent-gateway
// and control-api. Hand-written (not generated) so every component reads
// the same value instead of drifting copies of a literal.
const MaxCapabilities = 128
