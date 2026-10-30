package nodemetrics

import (
	"math/bits"
	"slices"
)

func externalInterface(telemetry *Telemetry, name string) bool {
	return telemetry != nil && telemetry.NetworkSelection != nil && telemetry.NetworkSelection.Source == "default_route" &&
		slices.Contains(telemetry.NetworkSelection.Interfaces, name)
}

// Difference each NIC before selecting the current route. Subtracting sums
// across a route change would turn a newly selected NIC's lifetime counter into
// a fabricated traffic spike. Unknown samples and new NICs break the baseline.
func externalTrafficIntervals(history []HistoryView, excluded map[string]struct{}) ([]TrafficPoint, error) {
	items := []TrafficPoint{}
	for index := 1; index < len(history); index++ {
		previous, current := history[index-1], history[index]
		if !previous.Known || !current.Known || previous.Telemetry == nil || current.Telemetry == nil || !current.ObservedAt.After(previous.ObservedAt) {
			continue
		}
		old := map[string]NetworkInterface{}
		for _, network := range previous.Telemetry.NetworkInterfaces {
			old[network.Name] = network
		}
		item := TrafficPoint{ObservedAt: current.ObservedAt}
		found := false
		for _, network := range current.Telemetry.NetworkInterfaces {
			if !externalInterface(current.Telemetry, network.Name) {
				continue
			}
			baseline, exists := old[network.Name]
			if !exists {
				found = false
				break
			}
			found = true
			if _, skip := excluded[network.Name]; skip {
				continue
			}
			var carry uint64
			item.BytesReceived, carry = bits.Add64(item.BytesReceived, counterDelta(baseline.RXBytes, network.RXBytes), 0)
			if carry != 0 {
				return nil, ErrInvalidSample
			}
			item.BytesSent, carry = bits.Add64(item.BytesSent, counterDelta(baseline.TXBytes, network.TXBytes), 0)
			if carry != 0 {
				return nil, ErrInvalidSample
			}
		}
		if found {
			items = append(items, item)
		}
	}
	return items, nil
}
