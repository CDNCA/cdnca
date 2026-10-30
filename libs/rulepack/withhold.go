package rulepack

// Withhold is security without the mounts withheld reports true for (ADR
// 0012 §20, U14: a market tenant's site whose supply does not include the
// plugin a pack belongs to runs without that pack; the site's published
// mounts stay as they are). The remaining mounts keep their order and
// params and get the resolved_sha256 Resolve would give them
// (SecurityOf); nothing left gives the empty document (no mounts, no
// digest). packs holds the compiled packs of the remaining mounts by
// digest. ok is false when nothing was withheld (security is returned as
// it is).
func Withhold(security Security, packs map[string]*CompiledPack, withheld func(Mount) bool) (Security, bool, error) {
	kept := make([]Mount, 0, len(security.Mounts))
	for _, mount := range security.Mounts {
		if !withheld(mount) {
			kept = append(kept, mount)
		}
	}
	if len(kept) == len(security.Mounts) {
		return security, false, nil
	}
	if len(kept) == 0 {
		return Security{}, true, nil
	}
	out, err := SecurityOf(kept, packs)
	return out, true, err
}
