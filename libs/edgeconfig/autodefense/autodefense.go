// Package autodefense is the intelligent automatic defense contract (ADR 0010,
// official module module.autodefense, AD-00) shared by control-api
// (builds and signs a node's snapshot), agent-gateway (routes the carrier,
// never verifies) and edge-agent (verifies, composes, applies, answers).
//
// A snapshot (cdnca.autodefense/v1) is everything one node holds for
// automatic defense: per enabled site its mode, baseline bands (ADR 0010
// section 4.3/4.4), mined signatures and their stage (section 6), the
// mitigation table (section 7.1), the whitelist (section 7.2), the module
// auto overlay with per-item manual locks (section 7A) and the control plane
// circuit state (section 10.2); per node its layer 4 port groups. Revision
// grows per node; a node applies a snapshot only when it is newer than the
// one it holds. A revision may be split into parts (one carrier each) that
// the node assembles before applying. The control plane signs
// Domain + the canonical part without its signature (Ed25519, the edge
// publication key). See docs/edge/autodefense-contract.md.
package autodefense

import (
	"errors"
	"regexp"
)

const (
	Schema = "cdnca.autodefense/v1"
	Domain = Schema + "\n"
	// APIVersion is the CAPABILITY_NAME_AUTO_DEFENSE version.
	APIVersion = 1
	// Algorithm is the only signature algorithm.
	Algorithm = "ed25519"

	// MaxPartBytes bounds one part's wire size so a carrier stays under the
	// 1 MiB default command limit of agent and gateway; MaxParts bounds a
	// revision.
	MaxPartBytes    = 896 << 10
	MaxParts        = 64
	MaxCarrierBytes = MaxPartBytes + 4<<10
	// MaxSites bounds the sites of one revision (ADR 0010 section 10.4).
	MaxSites = 10000
	// Per site bounds. Signatures: 8 selected per mining round (section 6.1
	// step 5) plus standby ones (section 6.2).
	MaxSignaturesPerSite  = 32
	MaxSignatureItems     = 3
	MaxMitigationsPerSite = 4096
	// MaxReleasesPerSite bounds Site.Releases (the newest are kept).
	MaxReleasesPerSite = 256
	MaxWhitelistNetworks  = 256
	MaxJA4Allow           = 64
	MaxLoginEndpoints     = 32
	MaxDistributionValues = 64
	// MaxPortGroups bounds the layer 4 port groups of one node.
	MaxPortGroups    = 256
	MaxPortRanges    = 64
	MaxPlatformAllow = 1024
	MaxReasonBytes   = 512
	// MaxMitigationSeconds bounds one mitigation entry (section 7.1: the
	// longest temporary ban is 24 hours).
	MaxMitigationSeconds = 24 * 3600
	// MaxObserveSeconds bounds an "observe only" hold after a one-click
	// release (section 7.4, default 30 minutes).
	MaxObserveSeconds = 24 * 3600
	// MaxValue bounds every integer of the snapshot so Lua numbers (double)
	// hold it exactly.
	MaxValue = 1 << 50
)

// Receipt error codes (AutoDefenseReceipt.error_code).
const (
	ErrorUntrusted    = "untrusted_signature"
	ErrorInvalid      = "invalid_snapshot"
	ErrorWrongNode    = "wrong_node"
	ErrorStale        = "stale_revision"
	ErrorIncomplete   = "incomplete_parts"
	ErrorRuntime      = "runtime_unavailable"
	ErrorNotSupported = "not_supported"
)

var (
	ErrInvalid    = errors.New("auto defense snapshot is invalid")
	ErrUntrusted  = errors.New("auto defense snapshot signature is not trusted")
	ErrIncomplete = errors.New("auto defense snapshot parts are incomplete")
)

var (
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	actorPattern = regexp.MustCompile(`^[a-z]+:[A-Za-z0-9._@:-]{1,128}$`)
	slugPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// Snapshot is one signed part of one node's automatic defense state.
type Snapshot struct {
	Schema   string `json:"schema"`
	NodeID   string `json:"node_id"`
	Revision uint64 `json:"revision"`
	// Part is 1-based; Parts is the number of parts of the revision. Every
	// part repeats IssuedAt and AutoMitigation; PlatformAllow and PortGroups
	// are node-level and only part 1 carries them. Sites are disjoint across
	// parts and ascending across the assembled revision.
	Part     uint32 `json:"part"`
	Parts    uint32 `json:"parts"`
	IssuedAt int64  `json:"issued_at"` // Unix seconds
	// AutoMitigation: module.autodefense.auto is licensed (ADR 0010 Q1/Q2).
	// False: every site only learns and observes whatever its mode says.
	AutoMitigation bool `json:"auto_mitigation"`
	// AttackFragments: the platform setting "向官方贡献规则情报" is on (ADR 0011
	// Q1: on by default, the platform administrator may turn it off); only
	// then do waf_evidence reports carry fragments (section 4.4). Every part
	// repeats it.
	AttackFragments bool `json:"attack_fragments,omitempty"`
	// PlatformAllow: platform service, probe and node networks that are
	// never mitigated (section 7.2 items 2 and 4), canonical CIDRs.
	PlatformAllow []string    `json:"platform_allow,omitempty"`
	PortGroups    []PortGroup `json:"port_groups,omitempty"`
	// Prior is the platform's global prior (ADR 0010 section 4.3 item 1):
	// one file for every site, node-level, only part 1 carries it. A site the node has never learned starts from
	// it (3x wide bands, challenge and rate limit only) instead of learning blind.
	Prior *Prior `json:"prior,omitempty"`
	// WAFBudget: the automatic exclusion budget (waf-exclcap2); node-level,
	// only part 1 carries it.
	WAFBudget *WAFBudget `json:"waf_budget,omitempty"`
	// Limits: the platform settings the node enforces;
	// node-level, only part 1 carries it. nil: the node's defaults
	// (DefaultLimits).
	Limits    *Limits `json:"limits,omitempty"`
	Sites     []Site  `json:"sites,omitempty"`
	Algorithm string  `json:"algorithm"`
	KeyID     string  `json:"key_id"`
	Signature string  `json:"signature,omitempty"`
}

// JetStream names (AD-07): agent-gateway owns the streams; control-api
// publishes parts and consumes receipts; nodes publish reports. Subjects end
// with the node ID.
const (
	CommandStream         = "AUTODEFENSE_COMMANDS"
	ReceiptStream         = "AUTODEFENSE_RECEIPTS"
	CommandSubjectPrefix  = "cdnca.agent.autodefense.commands"
	ReceiptSubjectPrefix  = "cdnca.agent.autodefense.receipts"
	GatewayConsumerPrefix = "autodefense"
	ReceiptConsumer       = "control_api_autodefense_receipts"
	// ReportSubjectPrefix is the upstream telemetry topic (section 8.1).
	ReportStream        = "AUTODEFENSE_REPORTS"
	ReportSubjectPrefix = "cdnca.security.autodefense.v1"
)
