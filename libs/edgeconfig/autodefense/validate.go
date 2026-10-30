package autodefense

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
	"unicode/utf8"
)

// Canonical sorts every list into its canonical order so equal content is
// equal bytes. It does not fix invalid content; Validate rejects it.
func (snapshot *Snapshot) Canonical() {
	sortStrings(snapshot.PlatformAllow)
	sort.Slice(snapshot.PortGroups, func(i, j int) bool { return snapshot.PortGroups[i].ID < snapshot.PortGroups[j].ID })
	for index := range snapshot.PortGroups {
		group := &snapshot.PortGroups[index]
		sort.Slice(group.Ports, func(i, j int) bool { return group.Ports[i].From < group.Ports[j].From })
		group.Baseline.canonical()
		group.Module.canonical()
	}
	if snapshot.Prior != nil {
		for index := range snapshot.Prior.Classes {
			bands := snapshot.Prior.Classes[index].Bands
			sort.Slice(bands, func(i, j int) bool { return bands[i].Metric < bands[j].Metric })
		}
	}
	sort.Slice(snapshot.Sites, func(i, j int) bool { return snapshot.Sites[i].SiteID < snapshot.Sites[j].SiteID })
	for index := range snapshot.Sites {
		snapshot.Sites[index].canonical()
	}
}

func (site *Site) canonical() {
	site.Baseline.canonical()
	sort.Slice(site.Whitelist.Networks, func(i, j int) bool { return site.Whitelist.Networks[i].CIDR < site.Whitelist.Networks[j].CIDR })
	sort.Slice(site.Whitelist.JA4, func(i, j int) bool { return site.Whitelist.JA4[i].JA4 < site.Whitelist.JA4[j].JA4 })
	sort.Slice(site.Login, func(i, j int) bool {
		if site.Login[i].PathTemplate != site.Login[j].PathTemplate {
			return site.Login[i].PathTemplate < site.Login[j].PathTemplate
		}
		return site.Login[i].Method < site.Login[j].Method
	})
	sort.Slice(site.Modules, func(i, j int) bool { return site.Modules[i].Name < site.Modules[j].Name })
	for index := range site.Modules {
		site.Modules[index].canonical()
	}
	sort.Slice(site.Releases, func(i, j int) bool {
		a, b := site.Releases[i], site.Releases[j]
		return a.Kind < b.Kind || a.Kind == b.Kind && a.Target < b.Target
	})
	for index := range site.Signatures {
		signature := &site.Signatures[index]
		sort.Slice(signature.Conditions, func(i, j int) bool { return conditionLess(signature.Conditions[i], signature.Conditions[j]) })
	}
	sort.Slice(site.Signatures, func(i, j int) bool { return site.Signatures[i].ID < site.Signatures[j].ID })
	sort.Slice(site.Mitigations, func(i, j int) bool { return mitigationLess(site.Mitigations[i], site.Mitigations[j]) })
	if site.WAFAdapt != nil {
		site.WAFAdapt.canonical()
	}
}

func (baseline *Baseline) canonical() {
	sort.Slice(baseline.Slots, func(i, j int) bool { return baseline.Slots[i].Slot < baseline.Slots[j].Slot })
	for index := range baseline.Slots {
		slot := &baseline.Slots[index]
		sort.Slice(slot.Bands, func(i, j int) bool { return slot.Bands[i].Feature < slot.Bands[j].Feature })
		sort.Slice(slot.Distributions, func(i, j int) bool { return slot.Distributions[i].Feature < slot.Distributions[j].Feature })
		for d := range slot.Distributions {
			values := slot.Distributions[d].Values
			sort.Slice(values, func(i, j int) bool { return values[i].Value < values[j].Value })
		}
	}
}

func (module *Module) canonical() {
	sort.Slice(module.Items, func(i, j int) bool { return module.Items[i].Field < module.Items[j].Field })
}

func conditionLess(a, b Condition) bool {
	if a.Dim != b.Dim {
		return a.Dim < b.Dim
	}
	return a.Value < b.Value
}

func mitigationLess(a, b Mitigation) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Target < b.Target
}

func sortStrings(values []string) { sort.Strings(values) }

// SignatureID is the identity of a signature: the first 16 hex of SHA-256
// over its canonical conditions "dim=value" joined by "\n".
func SignatureID(conditions []Condition) string {
	sorted := append([]Condition(nil), conditions...)
	sort.Slice(sorted, func(i, j int) bool { return conditionLess(sorted[i], sorted[j]) })
	var builder strings.Builder
	for index, condition := range sorted {
		if index > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(condition.Dim + "=" + condition.Value)
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:8])
}

// Validate checks one part on its own (structure, bounds, canonical order).
func (snapshot Snapshot) Validate() error {
	if !snapshot.valid() {
		return ErrInvalid
	}
	return nil
}

func (snapshot Snapshot) valid() bool {
	if snapshot.Schema != Schema || !uuidPattern.MatchString(snapshot.NodeID) || snapshot.Revision == 0 ||
		snapshot.Revision > MaxValue || snapshot.Parts == 0 || snapshot.Parts > MaxParts || snapshot.Part == 0 ||
		snapshot.Part > snapshot.Parts || !validTime(snapshot.IssuedAt, false) || snapshot.Algorithm != Algorithm ||
		!keyIDPattern.MatchString(snapshot.KeyID) || len(snapshot.Sites) > MaxSites {
		return false
	}
	if snapshot.Part != 1 && (snapshot.PlatformAllow != nil || snapshot.PortGroups != nil || snapshot.Prior != nil || snapshot.WAFBudget != nil || snapshot.Limits != nil) {
		return false
	}
	if !validWAFBudget(snapshot.WAFBudget) || !validLimits(snapshot.Limits) {
		return false
	}
	if snapshot.Prior != nil && !validPrior(*snapshot.Prior) {
		return false
	}
	if len(snapshot.PlatformAllow) > MaxPlatformAllow || len(snapshot.PortGroups) > MaxPortGroups {
		return false
	}
	for index, network := range snapshot.PlatformAllow {
		if canonical, ok := CanonicalPrefix(network); !ok || canonical != network ||
			(index > 0 && snapshot.PlatformAllow[index-1] >= network) {
			return false
		}
	}
	for index, group := range snapshot.PortGroups {
		if !validPortGroup(group) || (index > 0 && snapshot.PortGroups[index-1].ID >= group.ID) {
			return false
		}
	}
	for index, site := range snapshot.Sites {
		if !validSite(site, snapshot.AutoMitigation) || (index > 0 && snapshot.Sites[index-1].SiteID >= site.SiteID) {
			return false
		}
	}
	return true
}

// validPrior: version set, 1-MaxPriorClasses classes with unique slugs ascending by bound (the unbounded class
// last), each band a known metric once (canonical order) with bounded values.
func validPrior(prior Prior) bool {
	if prior.Version == 0 || prior.Version > MaxValue || len(prior.Classes) == 0 || len(prior.Classes) > MaxPriorClasses {
		return false
	}
	seen := map[string]bool{}
	for index, class := range prior.Classes {
		last := index == len(prior.Classes)-1
		if !slugPattern.MatchString(class.Class) || seen[class.Class] || !validInt(class.MaxRequestMilli) ||
			(class.MaxRequestMilli == 0) != last ||
			(index > 0 && !last && prior.Classes[index-1].MaxRequestMilli >= class.MaxRequestMilli) ||
			len(class.Bands) == 0 || len(class.Bands) > len(PriorMetrics) {
			return false
		}
		seen[class.Class] = true
		for b, band := range class.Bands {
			if !contains(PriorMetrics, band.Metric) || (b > 0 && class.Bands[b-1].Metric >= band.Metric) ||
				!validInt(band.P50) || !validInt(band.MAD) {
				return false
			}
		}
	}
	return true
}

func validPortGroup(group PortGroup) bool {
	if !slugPattern.MatchString(group.ID) || (group.Protocol != "tcp" && group.Protocol != "udp") ||
		len(group.Ports) == 0 || len(group.Ports) > MaxPortRanges || !validBaseline(group.Baseline, PortGroupFeatures, PortGroupDistributions) ||
		!validModule(group.Module, ModuleL4) {
		return false
	}
	for index, ports := range group.Ports {
		if ports.From < 1 || ports.To > 65535 || ports.From > ports.To || (index > 0 && group.Ports[index-1].To >= ports.From) {
			return false
		}
	}
	return true
}

var siteModules = map[ModuleName]bool{ModuleCC: true, ModuleWAF: true, ModuleScan: true, ModuleBot: true}

func validSite(site Site, autoMitigation bool) bool {
	if !uuidPattern.MatchString(site.SiteID) || !uuidPattern.MatchString(site.TenantID) || site.Sensitivity.BandK() == 0 ||
		!validItem(site.MaxLevel, "") || site.MaxLevel.Field != "site.max_level" || !validTime(site.ObserveUntil, true) ||
		!validCircuit(site.Circuit) || !validBaseline(site.Baseline, SiteFeatures, SiteDistributions) ||
		(site.PriorClass != "" && !slugPattern.MatchString(site.PriorClass)) {
		return false
	}
	switch site.Mode {
	case SiteLearning, SiteObserve:
		// Nothing is mitigated outside protect.
		if len(site.Mitigations) != 0 {
			return false
		}
	case SiteProtect:
		if !autoMitigation && len(site.Mitigations) != 0 {
			return false
		}
	default:
		return false
	}
	if len(site.Whitelist.Networks) > MaxWhitelistNetworks || len(site.Whitelist.JA4) > MaxJA4Allow ||
		len(site.Login) > MaxLoginEndpoints || len(site.Modules) > len(siteModules) ||
		len(site.Signatures) > MaxSignaturesPerSite || len(site.Mitigations) > MaxMitigationsPerSite {
		return false
	}
	for index, network := range site.Whitelist.Networks {
		if canonical, ok := CanonicalPrefix(network.CIDR); !ok || canonical != network.CIDR || !validTime(network.Until, true) ||
			!contains([]string{"user", "admin_login", "release"}, network.Source) ||
			(index > 0 && site.Whitelist.Networks[index-1].CIDR >= network.CIDR) {
			return false
		}
	}
	for index, allow := range site.Whitelist.JA4 {
		if !ja4Pattern.MatchString(allow.JA4) || !validTime(allow.Until, true) || // 0 = permanent (解除并加白)
			(index > 0 && site.Whitelist.JA4[index-1].JA4 >= allow.JA4) {
			return false
		}
	}
	for index, endpoint := range site.Login {
		if !methodPattern.MatchString(endpoint.Method) || !templatePattern.MatchString(endpoint.PathTemplate) ||
			(endpoint.Source != "auto" && endpoint.Source != "user") {
			return false
		}
		if index > 0 {
			previous := site.Login[index-1]
			if previous.PathTemplate > endpoint.PathTemplate ||
				previous.PathTemplate == endpoint.PathTemplate && previous.Method >= endpoint.Method {
				return false
			}
		}
	}
	for index, module := range site.Modules {
		if !siteModules[module.Name] || !validModule(module, module.Name) || (index > 0 && site.Modules[index-1].Name >= module.Name) {
			return false
		}
	}
	for index, signature := range site.Signatures {
		if !validSignature(signature) || (index > 0 && site.Signatures[index-1].ID >= signature.ID) {
			return false
		}
	}
	if site.WAFAdapt != nil && !validWAFAdapt(*site.WAFAdapt) {
		return false
	}
	ceiling := site.MaxLevelOf()
	for index, mitigation := range site.Mitigations {
		if !validMitigation(mitigation, ceiling, site.Baseline.CanBan) ||
			(index > 0 && !mitigationLess(site.Mitigations[index-1], mitigation)) {
			return false
		}
	}
	if len(site.Releases) > MaxReleasesPerSite {
		return false
	}
	for index, release := range site.Releases {
		// one entry per target (kind, target ascending); a ja4 is checked as an L1 target
		if release.Kind == TargetSite || !validTarget(release.Kind, release.Target, LevelChallenge) || !validTime(release.At, false) ||
			release.Retry < 0 || release.Retry > MaxReleaseRetry ||
			(index > 0 && !mitigationLess(Mitigation{Kind: site.Releases[index-1].Kind, Target: site.Releases[index-1].Target},
				Mitigation{Kind: release.Kind, Target: release.Target})) {
			return false
		}
	}
	return true
}

func validCircuit(circuit Circuit) bool {
	switch circuit.State {
	case CircuitClosed:
		return circuit.Reason == "" && circuit.Since == 0 && !circuit.ManualResume
	case CircuitOpen:
		return contains([]string{CircuitReasonAgent, CircuitReasonBaselineStale, CircuitReasonDelivery,
			CircuitReasonFalsePositive, CircuitReasonWholeSite}, circuit.Reason) && validTime(circuit.Since, false)
	}
	return false
}

// Omitted reports whether baseline is the zero value: the control plane does
// not deliver baselines (node autonomy; nodes learn and
// keep them locally). An omitted baseline cannot ban (CanBan false).
func (baseline Baseline) Omitted() bool {
	return baseline.Version == 0 && baseline.GeneratedAt == 0 && baseline.Maturity == "" && !baseline.CanBan &&
		baseline.SharePermille == 0 && baseline.AbsoluteRequestMilli == 0 && baseline.Slots == nil
}

func validBaseline(baseline Baseline, features, distributions []string) bool {
	if baseline.Omitted() {
		return true
	}
	switch baseline.Maturity {
	case MaturityPrior, MaturityHour, MaturityDay, MaturityWeek:
	default:
		return false
	}
	if baseline.Version == 0 || baseline.Version > MaxValue || !validTime(baseline.GeneratedAt, false) ||
		baseline.SharePermille < 0 || baseline.SharePermille > 1000 || !validInt(baseline.AbsoluteRequestMilli) ||
		len(baseline.Slots) == 0 || len(baseline.Slots) > 2 || (baseline.Maturity == MaturityPrior && baseline.CanBan) {
		return false
	}
	for index, slot := range baseline.Slots {
		if slot.Slot < 0 || slot.Slot > 167 || (index > 0 && baseline.Slots[index-1].Slot >= slot.Slot) ||
			len(slot.Bands) == 0 || len(slot.Bands) > len(features) || len(slot.Distributions) > len(distributions) {
			return false
		}
		for b, band := range slot.Bands {
			if !contains(features, band.Feature) || (b > 0 && slot.Bands[b-1].Feature >= band.Feature) ||
				!validInt(band.P50) || !validInt(band.MAD) || !validInt(band.P99) || !validInt(band.Samples) || band.P99 < band.P50 {
				return false
			}
		}
		for d, distribution := range slot.Distributions {
			if !contains(distributions, distribution.Feature) || (d > 0 && slot.Distributions[d-1].Feature >= distribution.Feature) ||
				len(distribution.Values) == 0 || len(distribution.Values) > MaxDistributionValues {
				return false
			}
			var total int64
			for v, share := range distribution.Values {
				if share.Value == "" || len(share.Value) > 128 || !utf8.ValidString(share.Value) || share.Permille < 0 ||
					(v > 0 && distribution.Values[v-1].Value >= share.Value) {
					return false
				}
				total += share.Permille
			}
			if total > 1000 {
				return false
			}
		}
	}
	return true
}

func validSignature(signature Signature) bool {
	if len(signature.Conditions) == 0 || len(signature.Conditions) > MaxSignatureItems ||
		signature.ID != SignatureID(signature.Conditions) || !validReason(signature.Reason) ||
		!validTime(signature.GeneratedAt, false) || !validTime(signature.CooldownUntil, true) ||
		signature.CoverPermille < 0 || signature.CoverPermille > 1000 || signature.FPRPPM < 0 || signature.FPRPPM > 1000000 ||
		!validInt(signature.LiftMilli) || !validInt(signature.AttackSamples) || !validInt(signature.NormalSamples) {
		return false
	}
	dims := map[string]bool{}
	for index, condition := range signature.Conditions {
		if !ValidCondition(condition.Dim, condition.Value) || dims[condition.Dim] ||
			(index > 0 && !conditionLess(signature.Conditions[index-1], condition)) {
			return false
		}
		dims[condition.Dim] = true
	}
	switch signature.Origin {
	case "node":
		if !uuidPattern.MatchString(signature.OriginNodeID) {
			return false
		}
	case "control":
		if signature.OriginNodeID != "" {
			return false
		}
	default:
		return false
	}
	switch signature.Stage {
	case StageShadow, StageChallenge, StageBlock:
		return signature.Resume == "" && signature.ExpiresAt == 0
	case StageStandby:
		return (signature.Resume == StageShadow || signature.Resume == StageChallenge || signature.Resume == StageBlock) &&
			validTime(signature.ExpiresAt, false)
	}
	return false
}

func validMitigation(mitigation Mitigation, ceiling Level, canBan bool) bool {
	if mitigation.Level < LevelChallenge || mitigation.Level > LevelXDP || mitigation.Level > ceiling ||
		(!canBan && mitigation.Level >= LevelBan) || !validTime(mitigation.Since, false) ||
		mitigation.Until <= mitigation.Since || mitigation.Until-mitigation.Since > MaxMitigationSeconds ||
		mitigation.Offences < 1 || mitigation.Offences > 64 || mitigation.Score < 0 || mitigation.Score > 100 ||
		!validReason(mitigation.Reason) {
		return false
	}
	if (mitigation.Level == LevelRateLimit) != (mitigation.RateMilli > 0) || !validInt(mitigation.RateMilli) {
		return false
	}
	switch mitigation.Scope {
	case ScopeSite:
	case ScopeTenant:
		if mitigation.Level > LevelRateLimit {
			return false
		}
	default:
		return false
	}
	return validTarget(mitigation.Kind, mitigation.Target, mitigation.Level)
}

func validTarget(kind TargetKind, target string, level Level) bool {
	switch kind {
	case TargetIP:
		canonical, ok := CanonicalAddress(target)
		return ok && canonical == target
	case TargetCIDR:
		canonical, ok := CanonicalPrefix(target)
		if !ok || canonical != target {
			return false
		}
		prefix := netip.MustParsePrefix(canonical)
		if prefix.Addr().Is6() {
			return prefix.Bits() >= 48 // /48-/128
		}
		return prefix.Bits() >= 24 // /24-/32
	case TargetJA4:
		return ja4Pattern.MatchString(target) && level <= LevelRateLimit
	case TargetSite:
		return target == "*" && level == LevelChallenge
	}
	return false
}

func validReason(reason string) bool {
	return reason != "" && len(reason) <= MaxReasonBytes && utf8.ValidString(reason) && !strings.ContainsAny(reason, "\x00\n\r")
}

func validInt(value int64) bool { return value >= 0 && value <= MaxValue }

func validTime(value int64, zero bool) bool {
	if value == 0 {
		return zero
	}
	return value > 0 && value <= MaxValue
}
