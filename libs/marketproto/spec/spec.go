// Package spec holds the resource and compliance vocabulary shared by offers,
// subscriptions and supply grants (docs/marketplace/02-supply-model.md §3).
package spec

import "errors"

var ErrInvalid = errors.New("invalid market spec")

// Allocation is the non-metered part of a grant: port counts and protocol
// switches. Domains, bandwidth and monthly traffic are supply limits
// (LimitSet, ADR 0012 §3.1) since 1.0.35. Field names follow control-api
// packagecatalog.ResourceLimits. Port counts are literal: 0 grants none.
type Allocation struct {
	HTTPPorts   int64 `json:"http_ports"`
	StreamPorts int64 `json:"stream_ports"`
	WebSocket   bool  `json:"websocket"`
	HTTP3       bool  `json:"http3"`
}

const MaxPorts = 65_535

func (a Allocation) Validate() error {
	if a.HTTPPorts < 0 || a.StreamPorts < 0 || a.HTTPPorts > MaxPorts || a.StreamPorts > MaxPorts {
		return ErrInvalid
	}
	return nil
}

// Min returns the tighter of two allocations: the smaller count and AND for
// every switch. A resold subscription can never grant more than any hop on
// its path allows.
func (a Allocation) Min(b Allocation) Allocation {
	return Allocation{
		HTTPPorts:   min(a.HTTPPorts, b.HTTPPorts),
		StreamPorts: min(a.StreamPorts, b.StreamPorts),
		WebSocket:   a.WebSocket && b.WebSocket,
		HTTP3:       a.HTTP3 && b.HTTP3,
	}
}

// Compliance requirements accumulate along a resale path: if any hop requires
// ICP filing or real-name verification, the leaf enforces it.
type Compliance struct {
	RequireICP bool `json:"require_icp"`
	RequireKYC bool `json:"require_kyc"`
}

func (c Compliance) Union(o Compliance) Compliance {
	return Compliance{RequireICP: c.RequireICP || o.RequireICP, RequireKYC: c.RequireKYC || o.RequireKYC}
}
