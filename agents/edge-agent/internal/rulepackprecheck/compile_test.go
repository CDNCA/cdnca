package rulepackprecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
)

const (
	testScope = "0d130000-0000-4000-8000-000000000001"
	testSite  = "0d130000-0000-4000-8000-000000000006"
)

func goldenDocument(t *testing.T) []byte {
	document, err := os.ReadFile(filepath.Join(golden, "security.json"))
	if err != nil {
		t.Fatal(err)
	}
	return document
}

// The golden mounts a user WAF pack, a system CC pack and a system WAF pack:
// the WAF/ACL rules become the layered plan, the CC rules the site's CC pack
// policy (pack rule IDs and priorities as the compiler assigned them).
func TestCompileSplitsCCPackRulesIntoTheSitePolicy(t *testing.T) {
	document := goldenDocument(t)
	compiled, err := Compile(document, objects(t), rulepack.Load, Identity{ScopeID: testScope, SiteID: testSite}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Rules.Segments) != 2 || compiled.Rules.Segments[0].Layer != edgeconfig.RulePlanLayerUser ||
		compiled.Rules.Segments[1].Layer != edgeconfig.RulePlanLayerSystem {
		t.Fatalf("rule plan segments = %+v", compiled.Rules.Segments)
	}
	policy := compiled.CC
	if policy == nil || len(policy.Rules) != 1 || policy.Rules[0].Limit.Requests != 300 || policy.Rules[0].Priority != 1 {
		t.Fatalf("CC policy = %+v", policy)
	}
	if policy.TenantScopeID != testScope || policy.SiteID != testSite || !policy.Enabled ||
		len(policy.TrustedProxies) != 0 || len(policy.Allowlist) != 0 || policy.AutoSwitch != nil {
		t.Fatalf("CC policy envelope = %+v", policy)
	}
	if _, err := edgeconfig.CanonicalCCV2Policy(*policy); err != nil {
		t.Fatalf("CC policy is not one the engine accepts: %v", err)
	}
	// The envelope is the site's, stable across pack versions: counters,
	// bans and passes survive an upgrade; the publication ID follows the
	// mounts.
	again, err := Compile(document, objects(t), rulepack.Load, Identity{ScopeID: testScope, SiteID: testSite}, false)
	if err != nil || again.CC.PolicyID != policy.PolicyID || again.CC.PublicationID != policy.PublicationID {
		t.Fatalf("recompiled = %+v, %v", again.CC, err)
	}
	other, err := Compile(document, objects(t), rulepack.Load, Identity{ScopeID: testScope, SiteID: "0d130000-0000-4000-8000-000000000007"}, false)
	if err != nil || other.CC.PolicyID == policy.PolicyID {
		t.Fatalf("another site shares the CC pack policy identity: %+v, %v", other.CC, err)
	}
	// Plan (no site identity) cannot build a CC policy and says so.
	if _, err := Plan(document, objects(t), rulepack.Load, false); !errors.Is(err, ErrRejected) {
		t.Fatalf("Plan with CC mounts: %v", err)
	}
	// A site object without a valid scope cannot be the CC policy's envelope.
	if _, err := Compile(document, objects(t), rulepack.Load, Identity{SiteID: testSite}, false); !errors.Is(err, ErrRejected) {
		t.Fatalf("CC policy without scope: %v", err)
	}
}

// The challenge engine is CC v2 with the challenge action: its pack rules go
// into the same policy (the CC engine renders the page and verifies it; no
// JS challenge policy of the site is needed).
func TestCompileRunsChallengePacksInTheCCPolicy(t *testing.T) {
	pack := compilePack(t, `{"schema":"cdnca.rule-pack/v1","pack_id":"system/login-challenge","version":"1.0.0","layer":"system",`+
		`"engine":"challenge","engine_min_version":3,"name":"login","description":"","params_schema":{},"exports":[],"rules":[`+
		`{"id":"r010","name":"login","cc":{"flow":"stop","match":{"path":{"kind":"prefix","value":"/login"}},"dimension":"client_ip",`+
		`"limit":{"algorithm":"always"},"action":{"kind":"challenge","ban_seconds":60,"challenge":{"mode":"js",`+
		`"failure_window_seconds":60,"max_failures":5,"pass_seconds":600,"pow_bits":8,"challenge_seconds":120,`+
		`"bind_ipv4_prefix":32,"bind_ipv6_prefix":64,"key_rotate_seconds":3600}}}}],"defaults":{}}`)
	document, store := resolve(t, pack)
	compiled, err := Compile(document, store, rulepack.Load, Identity{ScopeID: testScope, SiteID: testSite}, false)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.CC == nil || len(compiled.CC.Rules) != 1 || compiled.CC.Rules[0].Action.Kind != edgeconfig.CCV2ActionChallenge ||
		len(compiled.Rules.Segments) != 0 {
		t.Fatalf("compiled = %+v", compiled)
	}
}

func compilePack(t *testing.T, text string) *rulepack.CompiledPack {
	t.Helper()
	pack, err := rulepack.Compile([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return pack
}

func resolve(t *testing.T, packs ...*rulepack.CompiledPack) ([]byte, Objects) {
	t.Helper()
	requests := make([]rulepack.MountRequest, len(packs))
	store := map[string][]byte{}
	for index, pack := range packs {
		requests[index] = rulepack.MountRequest{Pack: pack, Priority: rulepack.DefaultPriority}
		store[pack.SHA256] = pack.Canonical
	}
	resolution := rulepack.Resolve(requests, rulepack.Target{})
	if resolution.Security == nil {
		t.Fatalf("conflicts: %+v", resolution.Conflicts)
	}
	document, _ := json.Marshal(resolution.Security)
	return document, func(sha string) ([]byte, error) {
		if content, ok := store[sha]; ok {
			return content, nil
		}
		return nil, os.ErrNotExist
	}
}

type memoryVault struct {
	objects Objects
	plans   map[string][]byte
}

func (vault *memoryVault) Object(sha string) ([]byte, error) { return vault.objects(sha) }
func (vault *memoryVault) Load(content []byte, sha string) (*rulepack.CompiledPack, error) {
	return rulepack.Load(content, sha)
}
func (vault *memoryVault) PlanDir() string { return "/plans" }
func (vault *memoryVault) WritePlan(resolved string, plan []byte) error {
	vault.plans[resolved+".json"] = plan
	return nil
}
func (vault *memoryVault) WriteCCPlan(resolved, siteID string, policy []byte) error {
	vault.plans[resolved+"."+siteID+".cc.json"] = policy
	return nil
}
func (vault *memoryVault) RetainPlans(map[string]bool) error { return nil }

// Two sites with the same mounts share the rule plan and each get their own
// CC pack policy file (canonical bytes the CC engine accepts by digest).
func TestPlansWritesOneCCPolicyPerSite(t *testing.T) {
	document := goldenDocument(t)
	var security struct {
		Mounts         []edgesite.RuleMount `json:"mounts"`
		ResolvedSHA256 string               `json:"resolved_sha256"`
	}
	if err := json.Unmarshal(document, &security); err != nil {
		t.Fatal(err)
	}
	site := func(id string) edgesite.Site {
		return edgesite.Site{ConfigurationScopeID: testScope, SiteID: id,
			Security: edgesite.Security{Mounts: security.Mounts, ResolvedSHA256: security.ResolvedSHA256}}
	}
	vault := &memoryVault{objects: objects(t), plans: map[string][]byte{}}
	second := "0d130000-0000-4000-8000-000000000007"
	if _, err := (Plans{Vault: vault}).Prepare([]edgesite.Site{site(testSite), site(second)}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(vault.plans) != 3 || vault.plans[security.ResolvedSHA256+".json"] == nil {
		t.Fatalf("plans = %v", keysOf(vault.plans))
	}
	for _, id := range []string{testSite, second} {
		raw := vault.plans[security.ResolvedSHA256+"."+id+".cc.json"]
		policy, err := edgeconfig.DecodeCCV2Policy(raw)
		if err != nil || policy.SiteID != id {
			t.Fatalf("site %s CC policy = %s, %v", id, raw, err)
		}
	}
}

// A modsecurity pack narrowing crs-pl1 to its crs_sqli set (942100 off):
// accepted only when the site's managed WAF excludes every other rule the
// profile evaluates (what the control plane wrote), refused otherwise.
func TestPlansChecksModSecurityPackAgainstTheManagedWAF(t *testing.T) {
	libs := filepath.Join("..", "..", "..", "..", "libs")
	golden, err := os.ReadFile(filepath.Join(libs, "rulepack", "testdata", "crs-profiles", "crs-pl1.json"))
	if err != nil {
		t.Fatal(err)
	}
	profilePack := compilePack(t, string(golden))
	profile, err := rulepack.CRSProfileOf(profilePack)
	if err != nil {
		t.Fatal(err)
	}
	pack := compilePack(t, `{"schema":"cdnca.rule-pack/v1","pack_id":"system/sqli-narrow","version":"1.0.0","layer":"system",
		"engine":"modsecurity","engine_min_version":1,"name":"sqli","description":"","license_spdx":"Apache-2.0",
		"params_schema":{},"exports":[],"defaults":{},"rules":[{"id":"crs_sqli","name":"sqli","crs":{"engine":"owasp_crs",
		"files":["REQUEST-942"],"include_ids":[],"exclude_ids":[942100],"action":"block","paranoia":1,"threshold":5}}]}`)
	document, store := resolve(t, pack)
	compiled, err := Compile(document, store, rulepack.Load, Identity{ScopeID: testScope, SiteID: testSite}, false)
	if err != nil || len(compiled.ModSecurity) != 1 || compiled.CC != nil {
		t.Fatalf("compile: %+v %v", compiled.ModSecurity, err)
	}
	if _, err := Plan(document, store, rulepack.Load, false); !errors.Is(err, ErrRejected) {
		t.Fatalf("Plan without the managed WAF: %v", err)
	}
	bundle := rulecatalog.CRSRulesBundle()
	files, err := rulecatalog.DecodeWAFEngineBundle(*bundle)
	if err != nil {
		t.Fatal(err)
	}
	text := &edgeconfig.CRSRuleText{Version: bundle.Version, Files: files}
	manifest, err := edgeconfig.DeriveCRSManifest(text)
	if err != nil {
		t.Fatal(err)
	}
	exclusions, err := rulepack.NarrowCRSProfile(manifest, profile, nil, compiled.ModSecurity)
	if err != nil {
		t.Fatal(err)
	}
	var security struct {
		Mounts         []edgesite.RuleMount `json:"mounts"`
		ResolvedSHA256 string               `json:"resolved_sha256"`
	}
	if err := json.Unmarshal(document, &security); err != nil {
		t.Fatal(err)
	}
	site := func(excluded []int, managed bool) edgesite.Site {
		value := edgesite.Site{ConfigurationScopeID: testScope, SiteID: testSite,
			Security: edgesite.Security{Mounts: security.Mounts, ResolvedSHA256: security.ResolvedSHA256}}
		if managed {
			value.Security.ManagedWAF = &edgesite.ManagedWAF{CRSProfile: profile.Ref, Exclusions: excluded}
		}
		return value
	}
	profiles := map[string]edgeconfig.CRSProfile{profile.Ref.SHA256: profile}
	vault := &memoryVault{objects: store, plans: map[string][]byte{}}
	if _, err := (Plans{Vault: vault}).Prepare([]edgesite.Site{site(exclusions, true)}, nil, text, profiles); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]edgesite.Site{
		"missing exclusion": site(exclusions[1:], true),
		"no managed WAF":    site(nil, false),
	} {
		if _, err := (Plans{Vault: vault}).Prepare([]edgesite.Site{value}, nil, text, profiles); !errors.Is(err, ErrRejected) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := (Plans{Vault: vault}).Prepare([]edgesite.Site{site(exclusions, true)}, nil, text, nil); !errors.Is(err, ErrRejected) ||
		!strings.Contains(err.Error(), "not on this node") {
		t.Fatalf("profile not on the node: %v", err)
	}
}

func keysOf(values map[string][]byte) []string {
	out := []string{}
	for key := range values {
		out = append(out, key)
	}
	return out
}

// A sealed modsecurity pack the control plane checked by the crs_rule_ids
// the license service computed into its manifest: the node opens it and
// applies the site only when the rules evaluate exactly the listed IDs (a
// list that leaves a rule out, or no list, is refused before anything is
// written).
func TestPlansChecksSealedModSecurityRuleIDs(t *testing.T) {
	libs := filepath.Join("..", "..", "..", "..", "libs")
	golden, err := os.ReadFile(filepath.Join(libs, "rulepack", "testdata", "crs-profiles", "crs-pl1.json"))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := rulepack.CRSProfileOf(compilePack(t, string(golden)))
	if err != nil {
		t.Fatal(err)
	}
	bundle := rulecatalog.CRSRulesBundle()
	files, err := rulecatalog.DecodeWAFEngineBundle(*bundle)
	if err != nil {
		t.Fatal(err)
	}
	text := &edgeconfig.CRSRuleText{Version: bundle.Version, Files: files}
	manifest, err := edgeconfig.DeriveCRSManifest(text)
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"schema":"cdnca.rule-pack/v1","pack_id":"system/sqli-sealed","version":"1.0.0","layer":"system",
		"engine":"modsecurity","engine_min_version":1,"name":"sqli","description":"","license_spdx":"Apache-2.0",
		"params_schema":{},"exports":[],"defaults":{},"rules":[{"id":"crs_sqli","name":"sqli","crs":{"engine":"owasp_crs",
		"files":["REQUEST-942"],"include_ids":[],"exclude_ids":[942100],"action":"block","paranoia":1,"threshold":5}}]}`
	plain := compilePack(t, body)
	honest := rulepack.CRSRuns(manifest, []rulepack.NodeRule{{CRS: plain.Pack.Rules[0].CRS}})
	cek := make([]byte, rulepack.CEKSize)
	for index := range cek {
		cek[index] = byte(index + 1)
	}
	prepare := func(ids []int) error {
		t.Helper()
		sealed, err := rulepack.SealWithCRSRuleIDs(plain.Canonical, cek, ids)
		if ids == nil {
			sealed, err = rulepack.Seal(plain.Canonical, cek, manifest)
		}
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256Hex(sealed)
		control, err := rulepack.OpenManifest(sealed, digest)
		if err != nil {
			t.Fatal(err)
		}
		resolution := rulepack.Resolve([]rulepack.MountRequest{{Pack: control, Priority: rulepack.DefaultPriority}}, rulepack.Target{})
		// The control plane narrows by the honest list: a forged one would
		// narrow differently, so the site carries the honest exclusions.
		exclusions, err := rulepack.NarrowCRSProfileByIDs(manifest, profile, nil, "system/sqli-sealed", honest)
		if err != nil {
			t.Fatalf("control plane: %v", err)
		}
		mounts := make([]edgesite.RuleMount, 0, 1)
		raw, _ := json.Marshal(resolution.Security.Mounts)
		_ = json.Unmarshal(raw, &mounts)
		site := edgesite.Site{ConfigurationScopeID: testScope, SiteID: testSite, Security: edgesite.Security{Mounts: mounts,
			ResolvedSHA256: resolution.Security.ResolvedSHA256,
			ManagedWAF:     &edgesite.ManagedWAF{CRSProfile: profile.Ref, Exclusions: exclusions}}}
		vault := &memoryVault{objects: func(sha string) ([]byte, error) {
			if sha == digest {
				return sealed, nil
			}
			return nil, os.ErrNotExist
		}, plans: map[string][]byte{}}
		load := func(content []byte, sha string) (*rulepack.CompiledPack, error) {
			return rulepack.Open(content, sha, cek)
		}
		_, err = (Plans{Vault: &openingVault{memoryVault: vault, load: load}}).Prepare([]edgesite.Site{site}, nil, text, map[string]edgeconfig.CRSProfile{profile.Ref.SHA256: profile})
		return err
	}
	if err := prepare(nil); err != nil {
		t.Fatalf("sealed by the license service: %v", err)
	}
	if err := prepare(honest); err != nil {
		t.Fatalf("matching list: %v", err)
	}
	if err := prepare([]int{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("no list: %v", err)
	}
	if err := prepare(honest[1:]); !errors.Is(err, ErrRejected) || !errors.Is(err, rulepack.ErrCRSRuleIDsMismatch) &&
		!strings.Contains(err.Error(), "do not match its listed CRS rule IDs") {
		t.Fatalf("list leaving a rule out: %v", err)
	}
}

type openingVault struct {
	*memoryVault
	load Loader
}

func (vault *openingVault) Load(content []byte, sha string) (*rulepack.CompiledPack, error) {
	return vault.load(content, sha)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
