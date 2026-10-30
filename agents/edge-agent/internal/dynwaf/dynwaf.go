// Package dynwaf prepares the managed WAF (OWASP CRS on libmodsecurity) of a
// dynamic routing node (ADR 0009 PoC section 5, task D11,
// docs/edge/dynroute-managed-waf.md): from the node's site objects, the CRS
// rule text and the CRS profile packs they select, it writes the node rule
// file, one rule file per tier and the CRS text into a content-addressed
// directory, and returns the node skeleton's ManagedWAF input.
//
// Nothing written depends on a site: a site's exclusions, allow CIDRs and
// inspection mode travel per request in the ModSecurity transaction ID
// (cdnca_managed_waf.lua). The directory name is the digest of what it
// holds, so the skeleton (and nginx) changes only when the CRS text, a
// profile pack or the set of tiers the sites use changes.
package dynwaf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// ErrUnavailable: a site needs the managed WAF and the node cannot run it
// (no engine extension, a profile pack it does not hold, a site the release
// does not accept). The publication must be refused (ADR 0009: no silent
// fallback).
var ErrUnavailable = errors.New("managed WAF unavailable")

// Engine is the installed, verified engine extension (wafengine.Manager).
type Engine struct {
	ModulePath     string // ngx_http_modsecurity_module.so
	UnicodeMapPath string // unicode.mapping
}

// Input is everything the node's managed WAF depends on.
type Input struct {
	Sites []edgesite.Site
	// CRSText is the signed catalog's CRS rule text; Profiles are the CRS
	// profile packs the node holds (rulepack.LoadCRSProfile), by digest.
	CRSText  *edgeconfig.CRSRuleText
	Profiles map[string]edgeconfig.CRSProfile
	// Apps are the application exclusion packs the node holds
	// (rulepack.LoadCRSApp), by digest.
	Apps   map[string]edgeconfig.CRSApp
	Engine *Engine
	// Root is the agent's managed WAF directory (worker readable); each
	// configuration is the subdirectory named by its digest.
	Root string
	// AuditLog is ModSecurity's audit log file (in the skeleton's shared
	// root, worker writable).
	AuditLog string
	// Targets are the automatic exclusions in force by site ID (ADR 0011
	// 3.4, RI-04: autodefense WAFAdapt.ActiveTargets), each in
	// DynamicWAFTarget order; nil: none. A site listed here runs in an
	// exclusion bucket location of its tier (RenderDynamicWAFBucket), so a
	// change reloads. No node-wide bound.
	Targets map[string][]edgeconfig.DynamicWAFTarget
	// Tuning are the official CRS tuning entries (ADR 0011 RI-13: the
	// system/crs-tuning pack the node holds, rulepack.TuningEntries); nil:
	// none. A new pack version reloads (the node rules change).
	Tuning []edgeconfig.CRSTuningEntry
}

// Result is the skeleton input (nil without any managed WAF site) and the
// directory it reads.
type Result struct {
	Skeleton  *edgeskeleton.ManagedWAF
	Directory string
	Digest    string
	// Tiers are the tiers in use, by key.
	Tiers map[string]edgeconfig.DynamicWAFTier
	// Probe is what the exclusion cost self test (wafprobe, waf-exclcap2)
	// runs: one tier in use with its rule file; nil without a managed WAF.
	Probe *Probe
}

// Probe is a tier in use for the exclusion cost self test: its rule file,
// the node rules and the engine, and a bucket file of n exclusions over
// the tier's exported rules (ProbeBucket).
type Probe struct {
	Engine    Engine
	RulesPath string
	TierFile  string
	release   *edgeconfig.DynamicWAFRelease
	tier      edgeconfig.DynamicWAFTier
}

// ProbeBucket is the rule file of a bucket with one site (siteID) holding
// n exclusions spread over the tier's exported rules (synthetic parameter
// names, so they never match a request), as RenderDynamicWAFBucket renders
// a real site's.
func (probe *Probe) ProbeBucket(siteID string, n int) ([]byte, error) {
	targets, err := probe.Targets(n)
	if err != nil {
		return nil, err
	}
	return edgeconfig.RenderDynamicWAFBucket(probe.release, probe.tier, probe.TierFile,
		[]edgeconfig.DynamicWAFBucketSite{{SiteID: siteID, Targets: targets}})
}

// Targets are the probe's n exclusions (DynamicWAFTarget order).
func (probe *Probe) Targets(n int) ([]edgeconfig.DynamicWAFTarget, error) {
	var rules []int
	for _, id := range probe.release.Exports() {
		if probe.release.Exported(probe.tier.Profile.SHA256, id) {
			rules = append(rules, id)
		}
	}
	if len(rules) == 0 || n < 1 || n > edgeconfig.DynamicWAFMaxTargets {
		return nil, fmt.Errorf("%w: no exported rule to probe", ErrUnavailable)
	}
	targets := make([]edgeconfig.DynamicWAFTarget, 0, n)
	for index := range n {
		targets = append(targets, edgeconfig.DynamicWAFTarget{Rule: rules[index%len(rules)], Location: "args",
			Name: fmt.Sprintf("cdnca_probe_%04d", index)})
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Rule != targets[j].Rule {
			return targets[i].Rule < targets[j].Rule
		}
		return targets[i].Name < targets[j].Name
	})
	return targets, nil
}

const (
	rulesFile = "main.conf"
	tierDir   = "tiers"
	bucketDir = "buckets"
)

// Prepare checks every site's managed WAF against the CRS text and the
// profiles, renders the configuration and writes it under Root (once: an
// existing directory of the same digest is kept).
func Prepare(input Input) (Result, error) {
	tiers := map[string]edgeconfig.DynamicWAFTier{}
	siteTiers := map[string]edgeconfig.DynamicWAFTier{}
	used := map[string]edgeconfig.CRSProfile{}
	usedApps := map[string]edgeconfig.CRSApp{}
	var managed []edgeconfig.ManagedWAF
	for _, site := range input.Sites {
		if site.Security.ManagedWAF == nil {
			continue
		}
		value := site.Security.ManagedWAF.Edge()
		profile, ok := input.Profiles[value.Profile.SHA256]
		if !ok || profile.Ref != value.Profile {
			return Result{}, fmt.Errorf("%w: site %s: CRS profile %s %s is not on this node", ErrUnavailable,
				site.SiteID, value.Profile.PackID, value.Profile.Version)
		}
		used[value.Profile.SHA256] = profile
		for _, ref := range value.Apps {
			app, ok := input.Apps[ref.SHA256]
			if !ok || app.Ref != ref {
				return Result{}, fmt.Errorf("%w: site %s: application exclusion pack %s %s is not on this node", ErrUnavailable,
					site.SiteID, ref.PackID, ref.Version)
			}
			usedApps[ref.SHA256] = app
		}
		tier := value.TierOf()
		tiers[tier.Key()] = tier
		if len(input.Targets[site.SiteID]) > 0 {
			siteTiers[site.SiteID] = tier
		}
		managed = append(managed, value)
	}
	if len(managed) == 0 {
		return Result{}, nil
	}
	if input.Engine == nil {
		return Result{}, fmt.Errorf("%w: the engine extension is not installed", ErrUnavailable)
	}
	if len(tiers) > edgeconfig.DynamicWAFMaxTiers {
		return Result{}, fmt.Errorf("%w: %d tiers (at most %d)", ErrUnavailable, len(tiers), edgeconfig.DynamicWAFMaxTiers)
	}
	digests := make([]string, 0, len(used))
	for digest := range used {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	profiles := make([]edgeconfig.CRSProfile, 0, len(digests))
	for _, digest := range digests {
		profiles = append(profiles, used[digest])
	}
	appDigests := make([]string, 0, len(usedApps))
	for digest := range usedApps {
		appDigests = append(appDigests, digest)
	}
	sort.Strings(appDigests)
	apps := make([]edgeconfig.CRSApp, 0, len(appDigests))
	for _, digest := range appDigests {
		apps = append(apps, usedApps[digest])
	}
	release, err := edgeconfig.ResolveDynamicWAFRelease(input.CRSText, profiles, apps...)
	if err != nil {
		return Result{}, fmt.Errorf("%w: CRS rule text, profiles and application packs: %v", ErrUnavailable, err)
	}
	for _, value := range managed {
		if err := release.CheckSite(value); err != nil {
			return Result{}, fmt.Errorf("%w: a site's managed WAF does not fit its profile: %v", ErrUnavailable, err)
		}
	}
	files := map[string][]byte{}
	for name, content := range release.Files() {
		files[filepath.ToSlash(filepath.Join("crs", name))] = content
	}
	keys := make([]string, 0, len(tiers))
	for key := range tiers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		content, err := edgeconfig.RenderDynamicWAFTier(release, tiers[key])
		if err != nil {
			return Result{}, fmt.Errorf("%w: tier %s: %v", ErrUnavailable, key, err)
		}
		files[tierDir+"/"+key+".conf"] = content
		if release.TwoLevel(tiers[key]) {
			if content, err = edgeconfig.RenderDynamicWAFTierCookies(release, tiers[key]); err != nil {
				return Result{}, fmt.Errorf("%w: tier %s cookie variant: %v", ErrUnavailable, key, err)
			}
			files[tierDir+"/"+key+edgeconfig.DynamicWAFCookieSuffix+".conf"] = content
		}
	}
	rules, err := edgeconfig.RenderDynamicWAFRulesTuned(release, input.AuditLog, input.Tuning)
	if err != nil {
		return Result{}, fmt.Errorf("%w: node rules: %v", ErrUnavailable, err)
	}
	files[rulesFile] = rules
	// The exclusion buckets: per tier its sites with exclusions in force,
	// by site ID, DynamicWAFBucketSites a location. Their files include
	// their tier's by absolute path, which depends on the digest: the
	// digest is taken over everything else plus each bucket's tier and
	// sites (exactly what its file says).
	sites := make([]string, 0, len(siteTiers))
	for site := range siteTiers {
		sites = append(sites, site)
	}
	sort.Strings(sites)
	type bucket struct {
		tier     edgeconfig.DynamicWAFTier
		location string
		sites    []edgeconfig.DynamicWAFBucketSite
	}
	var buckets []*bucket
	byTier := map[string]*bucket{}
	counts := map[string]int{}
	for _, site := range sites {
		tier := siteTiers[site]
		current := byTier[tier.Key()]
		if current == nil || len(current.sites) == edgeconfig.DynamicWAFBucketSites {
			current = &bucket{tier: tier, location: edgeconfig.DynamicWAFBucketLocation(tier, counts[tier.Key()])}
			counts[tier.Key()]++
			byTier[tier.Key()] = current
			buckets = append(buckets, current)
		}
		current.sites = append(current.sites, edgeconfig.DynamicWAFBucketSite{SiteID: site, Targets: input.Targets[site]})
	}
	digestInput := map[string][]byte{}
	for name, content := range files {
		digestInput[name] = content
	}
	for _, b := range buckets {
		probe, err := edgeconfig.RenderDynamicWAFBucket(release, b.tier, "/tier.conf", b.sites)
		if err != nil {
			return Result{}, fmt.Errorf("%w: automatic exclusions of %s: %v", ErrUnavailable, b.location, err)
		}
		digestInput[bucketDir+"/"+b.location[1:]+".conf"] = append([]byte(b.tier.Key()+"\n"), probe...)
	}
	digest := edgeconfig.DynamicWAFDigest(digestInput)
	directory := filepath.Join(input.Root, digest)
	bucketFiles := map[string]string{}
	cookieBuckets := map[string]string{}
	siteBuckets := map[string]string{}
	for _, b := range buckets {
		tierFile := filepath.Join(directory, tierDir, b.tier.Key()+".conf")
		content, err := edgeconfig.RenderDynamicWAFBucket(release, b.tier, tierFile, b.sites)
		if err != nil {
			return Result{}, fmt.Errorf("%w: automatic exclusions of %s: %v", ErrUnavailable, b.location, err)
		}
		name := bucketDir + "/" + b.location[1:] + ".conf"
		files[name] = content
		bucketFiles[b.location] = filepath.Join(directory, name)
		if release.TwoLevel(b.tier) {
			// the bucket's cookie variant: the same site rules over the
			// tier's cookie variant (a site with exclusions in force still
			// gets the adaptive cookie reading); its content follows from
			// what the digest already covers
			variantTier := filepath.Join(directory, tierDir, b.tier.Key()+edgeconfig.DynamicWAFCookieSuffix+".conf")
			if content, err = edgeconfig.RenderDynamicWAFBucket(release, b.tier, variantTier, b.sites); err != nil {
				return Result{}, fmt.Errorf("%w: automatic exclusions of %s cookie variant: %v", ErrUnavailable, b.location, err)
			}
			name = bucketDir + "/" + b.location[1:] + edgeconfig.DynamicWAFCookieSuffix + ".conf"
			files[name] = content
			cookieBuckets[b.location] = filepath.Join(directory, name)
		}
		for _, site := range b.sites {
			siteBuckets[site.SiteID] = b.location
		}
	}
	if err := write(directory, files); err != nil {
		return Result{}, err
	}
	skeleton := &edgeskeleton.ManagedWAF{ModulePath: input.Engine.ModulePath, UnicodeMapPath: input.Engine.UnicodeMapPath,
		RulesPath: filepath.Join(directory, rulesFile), Tiers: map[string]string{}, CookieTiers: map[string]string{},
		DetectProfiles: release.TwoLevelProfiles(), GreyProfiles: release.GreyChallengeProfiles(), Buckets: bucketFiles,
		CookieBuckets: cookieBuckets, SiteBuckets: siteBuckets}
	for _, key := range keys {
		skeleton.Tiers[key] = filepath.Join(directory, tierDir, key+".conf")
		if release.TwoLevel(tiers[key]) {
			skeleton.CookieTiers[key] = filepath.Join(directory, tierDir, key+edgeconfig.DynamicWAFCookieSuffix+".conf")
		}
	}
	// the self test runs the busiest kind of tier in use: two-level first
	// (严格防护 and above), then by key
	probeKey := keys[0]
	for _, key := range keys {
		if release.TwoLevel(tiers[key]) {
			probeKey = key
			break
		}
	}
	probe := &Probe{Engine: *input.Engine, RulesPath: skeleton.RulesPath, TierFile: skeleton.Tiers[probeKey], release: release,
		tier: tiers[probeKey]}
	return Result{Skeleton: skeleton, Directory: directory, Digest: digest, Tiers: tiers, Probe: probe}, nil
}

// write materializes files under directory through a temporary sibling and
// one rename, so a reader never sees a partial configuration.
func write(directory string, files map[string][]byte) error {
	if _, err := os.Stat(filepath.Join(directory, rulesFile)); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(directory), 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(directory), ".staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for name, content := range files {
		target := filepath.Join(staging, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			return err
		}
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		return err
	}
	if err := os.Rename(staging, directory); err != nil && !errors.Is(err, os.ErrExist) {
		if _, statErr := os.Stat(filepath.Join(directory, rulesFile)); statErr == nil {
			return nil // a concurrent writer of the same digest
		}
		return err
	}
	return nil
}

// Retain removes every configuration directory under root except keep
// (the active and the previous skeleton's).
func Retain(root string, keep ...string) error {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	kept := map[string]bool{}
	for _, digest := range keep {
		kept[digest] = true
	}
	for _, entry := range entries {
		if entry.IsDir() && !kept[entry.Name()] {
			if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
