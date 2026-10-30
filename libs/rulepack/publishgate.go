package rulepack

import (
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// CheckPublishable is the publisher's quality gate (license service before
// it publishes, market review), the same for packs that will be sealed and
// plaintext ones: the compiled pack mounted alone must resolve (Resolve:
// parameters, budget, rule conflicts within the pack). A modsecurity pack
// must also yield its CRS rule IDs in crs (ComputeCRSRuleIDs), returned so
// the caller can show them; the sealer computes them again from the same
// plaintext (Seal). The replay of the pack against real OpenResty is the
// license service's evaluation worker (ADR 0011 RI-11, not built yet).
func CheckPublishable(compiled *CompiledPack, crs *edgeconfig.CRSManifest) ([]int, error) {
	if compiled == nil || compiled.Sealed {
		return nil, fmt.Errorf("%w: the quality gate needs the plaintext pack", ErrInvalidPack)
	}
	resolution := Resolve([]MountRequest{{Pack: compiled, Priority: DefaultPriority}}, Target{})
	if resolution.Security == nil {
		message := "does not resolve"
		if len(resolution.Conflicts) != 0 {
			message = resolution.Conflicts[0].Code + ": " + resolution.Conflicts[0].Message
		}
		return nil, fmt.Errorf("%w: pack %s mounted alone: %s", ErrInvalidPack, compiled.Pack.PackID, message)
	}
	if IsCRSTuningPack(compiled.Pack.PackID) {
		return nil, checkTuningRules(compiled.Pack, crs)
	}
	if compiled.Pack.Engine != EngineModSecurity {
		return nil, nil
	}
	return ComputeCRSRuleIDs(crs, compiled.Pack)
}
