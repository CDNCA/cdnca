package systemconfig

import (
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// EffectiveDDoSProtection is the ddos_protection category value: the stored
// one, or the default when the platform never saved one
// (edgeconfig.DefaultDDoSProtection: every connection limit off; the TCP
// flag combinations no stack sends and conntrack INVALID packets dropped).
// A saved value is taken as it is: its absent filter fields are off.
func EffectiveDDoSProtection(value *edgeconfig.DDoSProtection) edgeconfig.DDoSProtection {
	if value != nil {
		return *cloneDDoSProtection(value)
	}
	return edgeconfig.DefaultDDoSProtection()
}

func cloneDDoSProtection(input *edgeconfig.DDoSProtection) *edgeconfig.DDoSProtection {
	if input == nil {
		return nil
	}
	result := *input
	result.AllowNetworks = slices.Clone(input.AllowNetworks)
	result.TCPFlagTypes = slices.Clone(input.TCPFlagTypes)
	if input.EmptyConnection != nil {
		empty := *input.EmptyConnection
		result.EmptyConnection = &empty
	}
	return &result
}
