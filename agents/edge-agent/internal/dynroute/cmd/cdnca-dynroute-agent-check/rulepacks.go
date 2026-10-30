package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/rulepackprecheck"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/rulepackvault"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// sqliPack is libs/rulepack testdata system-sqli.json (exports r020 /wp-admin block, r010 args sqli block).
const sqliPack = `{"schema":"cdnca.rule-pack/v1","pack_id":"system/sqli-basic","version":"1.0.0","layer":"system",` +
	`"engine":"waf_v2","engine_min_version":1,"name":"sqli","description":"",` +
	`"params_schema":{"action":{"type":"string","enum":["log","block"],"bind":{"target":"waf.action","rules":["r010"]}}},` +
	`"exports":["r020","r010"],"rules":[` +
	`{"id":"r020","name":"admin","waf":{"match":{"path":{"kind":"prefix","value":"/wp-admin"}},"action":"block","flow":"stop"}},` +
	`{"id":"r010","name":"args","waf":{"match":{"inspect":[{"target":"args","operator":"detect","values":["sqli"]}]},"action":"block","flow":"stop"}}],` +
	`"defaults":{"action":"block"}}`

// rulePackFixture is a sealed pack as the node receives it: the sealed
// object in an object directory and its content key wrapped to the node.
type rulePackFixture struct {
	vault    *rulepackvault.Vault
	security edgesite.Security
	objects  map[string][]byte
	// wraps is the vault's delivered set (the sqli pack's, plus sealed
	// modsecurity packs added by addSealedModSecurityPack).
	wraps  []rulepackvault.Wrap
	wrapTo *ecdh.PublicKey
}

func newRulePackFixture(root string, runtimeRoot string, wrapTo *ecdh.PublicKey, node *ecdh.PrivateKey) (*rulePackFixture, error) {
	compiled, err := rulepack.Compile([]byte(sqliPack))
	if err != nil {
		return nil, err
	}
	cek := make([]byte, rulepack.CEKSize)
	_, _ = rand.Read(cek)
	sealed, err := rulepack.Seal(compiled.Canonical, cek, nil)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(sealed)
	digest := hex.EncodeToString(sum[:])
	keyID := rulepack.X25519KeyID(wrapTo.Bytes())
	wrapped, err := rulepack.WrapKey(wrapTo.Bytes(), cek, rulepack.WrapContext{Purpose: rulepack.WrapPurposeNode,
		RecipientKeyID: keyID, PackID: compiled.Pack.PackID, Version: compiled.Pack.Version, SealedSHA256: digest})
	if err != nil {
		return nil, err
	}
	fixture := &rulePackFixture{objects: map[string][]byte{digest: sealed}, wrapTo: wrapTo}
	fixture.vault, err = rulepackvault.Open(rulepackvault.Config{PrivateKey: node.Bytes(), StateDir: filepath.Join(root, "keys"),
		Objects: func(sha string) ([]byte, error) {
			if content, ok := fixture.objects[sha]; ok {
				return content, nil
			}
			return nil, os.ErrNotExist
		}, ModSecurityDir: filepath.Join(runtimeRoot, "modsecurity"), OwnerUID: -1, OwnerGID: -1,
		PlanDir: filepath.Join(runtimeRoot, "plans"), PlanGID: workerGID()})
	if err != nil {
		return nil, err
	}
	// The node's vault takes the wrap only when it is for its own key
	// (artifact set installer: install_rejected otherwise).
	if wrapTo.Equal(node.PublicKey()) {
		fixture.wraps = []rulepackvault.Wrap{{SealedSHA256: digest, PackID: compiled.Pack.PackID,
			Version: compiled.Pack.Version, RecipientKeyID: keyID, WrappedKey: wrapped}}
		if err := fixture.vault.Replace(fixture.wraps); err != nil {
			return nil, err
		}
	} else if _, err := fixture.vault.Check(sealed, digest, keyID, wrapped); err == nil {
		return nil, errors.New("a key wrapped to another node was accepted")
	}
	manifest, err := rulepack.OpenManifest(sealed, digest)
	if err != nil {
		return nil, err
	}
	resolution := rulepack.Resolve([]rulepack.MountRequest{{Pack: manifest}}, rulepack.Target{})
	if resolution.Security == nil {
		return nil, errors.New("pack resolution conflicts")
	}
	encoded, _ := json.Marshal(resolution.Security)
	var mounts struct {
		Mounts         []edgesite.RuleMount `json:"mounts"`
		ResolvedSHA256 string               `json:"resolved_sha256"`
	}
	if err := json.Unmarshal(encoded, &mounts); err != nil {
		return nil, err
	}
	fixture.security = edgesite.Security{Mounts: mounts.Mounts, ResolvedSHA256: mounts.ResolvedSHA256}
	return fixture, nil
}

func (fixture *rulePackFixture) plans() rulepackprecheck.Plans {
	return rulepackprecheck.Plans{Vault: fixture.vault}
}

func withMounts(site edgesite.Site, security edgesite.Security) edgesite.Site {
	site.Security.Mounts, site.Security.ResolvedSHA256 = security.Mounts, security.ResolvedSHA256
	return site
}

func x25519() *ecdh.PrivateKey {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

// ccPacks are two plain CC packs, run in one CC policy in the published
// order (user first): the system pack limits /limited* to 2 requests a
// minute per client (429 after); the user pack's /limited/open rule logs
// and stops once a client passes 1 request a minute, so the system limit no
// longer counts or refuses that path (CC v2 has no allow action: an
// exception is a log rule with flow stop).
var ccPacks = []string{
	`{"schema":"cdnca.rule-pack/v1","pack_id":"system/cc-limited","version":"1.0.0","layer":"system",` +
		`"engine":"cc_v2","engine_min_version":2,"name":"limited","description":"","params_schema":{},"exports":[],"rules":[` +
		`{"id":"r010","name":"limited","cc":{"flow":"stop","match":{"path":{"kind":"prefix","value":"/limited"}},` +
		`"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":2,"window_seconds":60},` +
		`"action":{"kind":"reject_429"}}}],"defaults":{}}`,
	`{"schema":"cdnca.rule-pack/v1","pack_id":"user/0d130000-0000-4000-8000-000000000002/open","version":"1.0.0","layer":"user",` +
		`"engine":"cc_v2","engine_min_version":2,"name":"open","description":"","params_schema":{},"exports":[],"rules":[` +
		`{"id":"r010","name":"open","cc":{"flow":"stop","match":{"path":{"kind":"exact","value":"/limited/open"}},` +
		`"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},` +
		`"action":{"kind":"log"}}}],"defaults":{}}`,
}

// addCCPacks puts the CC packs into the fixture's object directory and
// returns the site security of mounting both.
func (fixture *rulePackFixture) addCCPacks() (edgesite.Security, error) {
	requests := make([]rulepack.MountRequest, 0, len(ccPacks))
	for _, text := range ccPacks {
		compiled, err := rulepack.Compile([]byte(text))
		if err != nil {
			return edgesite.Security{}, err
		}
		fixture.objects[compiled.SHA256] = compiled.Canonical
		requests = append(requests, rulepack.MountRequest{Pack: compiled, Priority: rulepack.DefaultPriority})
	}
	resolution := rulepack.Resolve(requests, rulepack.Target{})
	if resolution.Security == nil {
		return edgesite.Security{}, errors.New("CC pack resolution conflicts")
	}
	encoded, _ := json.Marshal(resolution.Security)
	var mounts struct {
		Mounts         []edgesite.RuleMount `json:"mounts"`
		ResolvedSHA256 string               `json:"resolved_sha256"`
	}
	if err := json.Unmarshal(encoded, &mounts); err != nil {
		return edgesite.Security{}, err
	}
	return edgesite.Security{Mounts: mounts.Mounts, ResolvedSHA256: mounts.ResolvedSHA256}, nil
}

// xssOnlyPack narrows a CRS profile to its XSS set (paranoia as given): on
// crs-pl2 every other set's rules become the site's exclusions (方案 A), so
// SQL injection passes and XSS is still blocked; paranoia 3 is outside
// crs-pl2 and the node refuses it.
func xssOnlyPack(paranoia int) string {
	return `{"schema":"cdnca.rule-pack/v1","pack_id":"system/xss-only","version":"1.0.0","layer":"system",` +
		`"engine":"modsecurity","engine_min_version":1,"name":"xss","description":"","license_spdx":"Apache-2.0",` +
		`"params_schema":{},"exports":[],"defaults":{},"rules":[{"id":"crs_xss","name":"xss","crs":{"engine":"owasp_crs",` +
		`"files":["REQUEST-941"],"include_ids":[],"exclude_ids":[],"action":"block","paranoia":` + string(rune('0'+paranoia)) +
		`,"threshold":5}}]}`
}

// addModSecurityPack puts the XSS-only pack into the object directory and
// returns its mounts and the managed WAF exclusions the control plane
// computes for it on profile (rulepack.NarrowCRSProfile; nil when outside).
func (fixture *rulePackFixture) addModSecurityPack(paranoia int, manifest *edgeconfig.CRSManifest,
	profile edgeconfig.CRSProfile) (edgesite.Security, []int, error) {
	compiled, err := rulepack.Compile([]byte(xssOnlyPack(paranoia)))
	if err != nil {
		return edgesite.Security{}, nil, err
	}
	fixture.objects[compiled.SHA256] = compiled.Canonical
	resolution := rulepack.Resolve([]rulepack.MountRequest{{Pack: compiled, Priority: rulepack.DefaultPriority}}, rulepack.Target{})
	if resolution.Security == nil {
		return edgesite.Security{}, nil, errors.New("modsecurity pack resolution conflicts")
	}
	encoded, _ := json.Marshal(resolution.Security)
	var mounts struct {
		Mounts         []edgesite.RuleMount `json:"mounts"`
		ResolvedSHA256 string               `json:"resolved_sha256"`
	}
	if err := json.Unmarshal(encoded, &mounts); err != nil {
		return edgesite.Security{}, nil, err
	}
	security := edgesite.Security{Mounts: mounts.Mounts, ResolvedSHA256: mounts.ResolvedSHA256}
	rules, err := rulepack.ModSecurityRules(resolution.Security.Mounts[0], compiled)
	if err != nil {
		return edgesite.Security{}, nil, err
	}
	exclusions, err := rulepack.NarrowCRSProfile(manifest, profile, nil, rules)
	if err != nil {
		return security, nil, nil
	}
	return security, exclusions, nil
}

// addSealedModSecurityPack seals the XSS-only pack (paranoia 2) as the
// license service delivers it: the manifest's crs_rule_ids computed from the
// plaintext (rulepack.Seal), or forged when ids is given (a list the rules
// do not evaluate). The CEK is wrapped to the node and added to the vault.
// It returns the mounts and the exclusions the control plane computes from
// the manifest alone (rulepack.SiteCRSExclusions on the sealed manifest).
func (fixture *rulePackFixture) addSealedModSecurityPack(packID string, ids []int, manifest *edgeconfig.CRSManifest,
	profile edgeconfig.CRSProfile) (edgesite.Security, []int, error) {
	document := strings.Replace(xssOnlyPack(2), `"system/xss-only"`, `"`+packID+`"`, 1)
	compiled, err := rulepack.Compile([]byte(document))
	if err != nil {
		return edgesite.Security{}, nil, err
	}
	cek := make([]byte, rulepack.CEKSize)
	_, _ = rand.Read(cek)
	var sealed []byte
	if ids == nil {
		sealed, err = rulepack.Seal(compiled.Canonical, cek, manifest)
	} else {
		sealed, err = rulepack.SealWithCRSRuleIDs(compiled.Canonical, cek, ids)
	}
	if err != nil {
		return edgesite.Security{}, nil, err
	}
	sum := sha256.Sum256(sealed)
	digest := hex.EncodeToString(sum[:])
	keyID := rulepack.X25519KeyID(fixture.wrapTo.Bytes())
	wrapped, err := rulepack.WrapKey(fixture.wrapTo.Bytes(), cek, rulepack.WrapContext{Purpose: rulepack.WrapPurposeNode,
		RecipientKeyID: keyID, PackID: compiled.Pack.PackID, Version: compiled.Pack.Version, SealedSHA256: digest})
	if err != nil {
		return edgesite.Security{}, nil, err
	}
	fixture.objects[digest] = sealed
	fixture.wraps = append(fixture.wraps, rulepackvault.Wrap{SealedSHA256: digest, PackID: compiled.Pack.PackID,
		Version: compiled.Pack.Version, RecipientKeyID: keyID, WrappedKey: wrapped})
	if err := fixture.vault.Replace(fixture.wraps); err != nil {
		return edgesite.Security{}, nil, err
	}
	control, err := rulepack.OpenManifest(sealed, digest)
	if err != nil {
		return edgesite.Security{}, nil, err
	}
	resolution := rulepack.Resolve([]rulepack.MountRequest{{Pack: control, Priority: rulepack.DefaultPriority}}, rulepack.Target{})
	if resolution.Security == nil {
		return edgesite.Security{}, nil, errors.New("sealed modsecurity pack resolution conflicts")
	}
	exclusions, _, err := rulepack.SiteCRSExclusions(resolution.Security.Mounts,
		map[string]*rulepack.CompiledPack{digest: control}, manifest, &profile, nil)
	if err != nil {
		return edgesite.Security{}, nil, err
	}
	encoded, _ := json.Marshal(resolution.Security)
	var mounts struct {
		Mounts         []edgesite.RuleMount `json:"mounts"`
		ResolvedSHA256 string               `json:"resolved_sha256"`
	}
	if err := json.Unmarshal(encoded, &mounts); err != nil {
		return edgesite.Security{}, nil, err
	}
	return edgesite.Security{Mounts: mounts.Mounts, ResolvedSHA256: mounts.ResolvedSHA256}, exclusions, nil
}

// xssRuleIDs is what the license service computes for the XSS-only pack
// (paranoia 2).
func xssRuleIDs(manifest *edgeconfig.CRSManifest) []int {
	compiled, err := rulepack.Compile([]byte(xssOnlyPack(2)))
	if err != nil {
		return nil
	}
	return rulepack.PackCRSRuleIDs(manifest, compiled.Pack)
}
