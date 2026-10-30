package packageperiod

import (
	"math/bits"
	"strings"
)

const (
	MaxTrafficFactorComponent = uint64(1_000_000)
	MaxTrafficMultiplier      = uint64(1_000)
)

// TrafficFactor is a reduced positive rational. Apply always rounds up to a byte.
type TrafficFactor struct {
	numerator   uint64
	denominator uint64
}

func NewTrafficFactor(numerator, denominator uint64) (TrafficFactor, error) {
	if numerator == 0 || denominator == 0 {
		return TrafficFactor{}, ErrInvalidFactor
	}
	divisor := greatestCommonDivisor(numerator, denominator)
	numerator /= divisor
	denominator /= divisor
	if numerator > MaxTrafficFactorComponent || denominator > MaxTrafficFactorComponent ||
		numerator > denominator*MaxTrafficMultiplier {
		return TrafficFactor{}, ErrInvalidFactor
	}
	return TrafficFactor{numerator: numerator, denominator: denominator}, nil
}

func (f TrafficFactor) Numerator() uint64 {
	return f.numerator
}

func (f TrafficFactor) Denominator() uint64 {
	return f.denominator
}

func (f TrafficFactor) Apply(rawBytes uint64) (uint64, error) {
	if !f.valid() {
		return 0, ErrInvalidFactor
	}
	high, low := bits.Mul64(rawBytes, f.numerator)
	upperQuotient, remainder := bits.Div64(0, high, f.denominator)
	if upperQuotient != 0 {
		return 0, ErrTrafficOverflow
	}
	quotient, remainder := bits.Div64(remainder, low, f.denominator)
	if remainder != 0 {
		if quotient == ^uint64(0) {
			return 0, ErrTrafficOverflow
		}
		quotient++
	}
	return quotient, nil
}

func (f TrafficFactor) valid() bool {
	return f.numerator > 0 && f.denominator > 0 && greatestCommonDivisor(f.numerator, f.denominator) == 1
}

func greatestCommonDivisor(left, right uint64) uint64 {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}

// CycleSnapshot freezes settlement-affecting configuration for one quota cycle.
type CycleSnapshot struct {
	cycle          Cycle
	trafficFactor  TrafficFactor
	configRevision string
}

func NewCycleSnapshot(cycle Cycle, factor TrafficFactor, configRevision string) (CycleSnapshot, error) {
	if !cycle.valid() || !factor.valid() || configRevision == "" ||
		strings.TrimSpace(configRevision) != configRevision || len(configRevision) > 128 {
		return CycleSnapshot{}, ErrInvalidSnapshot
	}
	return CycleSnapshot{cycle: cycle, trafficFactor: factor, configRevision: configRevision}, nil
}

// ResolveCycleSnapshot preserves an existing cycle snapshot and applies current
// configuration only when a different reset key is reached.
func ResolveCycleSnapshot(cycle Cycle, factor TrafficFactor, configRevision string,
	existing *CycleSnapshot,
) (CycleSnapshot, error) {
	current, err := NewCycleSnapshot(cycle, factor, configRevision)
	if err != nil {
		return CycleSnapshot{}, err
	}
	if existing == nil {
		return current, nil
	}
	if !existing.valid() {
		return CycleSnapshot{}, ErrInvalidSnapshot
	}
	if existing.cycle.resetKey == cycle.resetKey {
		if existing.cycle.startsAt != cycle.startsAt || existing.cycle.endsAt != cycle.endsAt ||
			existing.cycle.timeZone != cycle.timeZone {
			return CycleSnapshot{}, ErrInvalidSnapshot
		}
		return *existing, nil
	}
	return current, nil
}

func (s CycleSnapshot) ResetKey() string {
	return s.cycle.resetKey
}

func (s CycleSnapshot) ConfigRevision() string {
	return s.configRevision
}

func (s CycleSnapshot) TrafficFactor() TrafficFactor {
	return s.trafficFactor
}

func (s CycleSnapshot) BillTCP(rawBytes uint64) (uint64, error) {
	if !s.valid() {
		return 0, ErrInvalidSnapshot
	}
	return s.trafficFactor.Apply(rawBytes)
}

func (s CycleSnapshot) valid() bool {
	return s.cycle.valid() && s.trafficFactor.valid() && s.configRevision != "" &&
		strings.TrimSpace(s.configRevision) == s.configRevision && len(s.configRevision) <= 128
}
