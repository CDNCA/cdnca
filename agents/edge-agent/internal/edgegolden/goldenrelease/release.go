// Package goldenrelease builds a golden scenario's signed site runtime v2
// release (the control plane's output) and installs its node-side facts
// (challenge policies, CRS profile packs) for the dynamic routing renderer
// (goldendyn) and its agent checks.
package goldenrelease

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"unicode/utf16"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/httppolicy"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// Release file paths (the site runtime v2 bundle layout).
const (
	DocumentPath    = "site-runtime.v2.json"
	HTTPPolicyPath  = "http-policy.v1.json"
	OriginRoutePath = "origin-route.v1.json"
)

// Release is a scenario's signed release.
type Release struct {
	Bundle edgeconfig.Bundle
	// Document is the canonical v2 document (Bundle.Files[DocumentPath]).
	Document []byte
	// TenantID is the telemetry tenant ("" without telemetry).
	TenantID string
}

// document is what the release builder reads of the v2 document.
type document struct {
	ConfigVersionID string `json:"config_version_id"`
	SourceRevision  uint64 `json:"source_revision"`
	Sites           []struct {
		ID        string   `json:"id"`
		Domains   []string `json:"domains"`
		Listeners []struct {
			Port     uint16                       `json:"port"`
			TLS      json.RawMessage              `json:"tls"`
			Security *edgeconfig.ListenerSecurity `json:"security"`
		} `json:"listeners"`
	} `json:"sites"`
}

// Build turns the scenario's site facts into the signed release the control
// plane would publish: placeholders expanded, derived digests filled in,
// documents canonical, manifest content addressed. It does not validate the
// document beyond what canonical encoding needs: the consuming runtime does.
func Build(env edgegolden.Env, scenario *edgegolden.Scenario, deploymentRoot string) (*Release, error) {
	values := env.PKI.Placeholders()
	values["deployment_root"] = deploymentRoot
	files := map[string][]byte{}
	if len(scenario.Facts.HTTPPolicy) != 0 {
		raw, err := edgegolden.Expand(scenario.Facts.HTTPPolicy, values)
		if err != nil {
			return nil, fmt.Errorf("http_policy: %w", err)
		}
		artifact, err := httppolicy.CompileJSON(compact(raw))
		if err != nil {
			return nil, fmt.Errorf("http_policy: %w", err)
		}
		files[HTTPPolicyPath] = artifact.Canonical
		values["http_policy_sha256"] = hex.EncodeToString(artifact.Digest[:])
	}
	raw, err := edgegolden.Expand(scenario.Facts.Document, values)
	if err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}
	var generic map[string]any
	if err := DecodeNumbers(raw, &generic); err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}
	if err := fillSecurity(generic); err != nil {
		return nil, err
	}
	var canonical bytes.Buffer
	if err := writeCanonical(&canonical, generic); err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}
	var parsed document
	if err := json.Unmarshal(canonical.Bytes(), &parsed); err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}
	files[DocumentPath] = canonical.Bytes()
	for _, name := range scenario.Facts.OriginTrust {
		ca, err := env.PKI.CA(name)
		if err != nil {
			return nil, err
		}
		files["origin-trust/"+ca.TrustDigest()+".pem"] = ca.PEM
	}
	for _, name := range scenario.Facts.ClientCAs {
		ca, err := env.PKI.CA(name)
		if err != nil {
			return nil, err
		}
		files[edgeconfig.ClientCAPath("sha256:"+ca.TrustDigest())] = ca.PEM
	}
	if len(scenario.Facts.OriginRoute) != 0 {
		route, err := edgegolden.Expand(scenario.Facts.OriginRoute, values)
		if err != nil {
			return nil, fmt.Errorf("origin_route: %w", err)
		}
		files[OriginRoutePath] = compact(route)
	}
	result := &Release{Document: canonical.Bytes()}
	if scenario.Facts.Telemetry != nil {
		manifest, err := telemetryManifest(parsed, *scenario.Facts.Telemetry, deploymentRoot)
		if err != nil {
			return nil, err
		}
		files[edgeconfig.TelemetryIdentityManifestPath] = manifest
		result.TenantID = scenario.Facts.Telemetry.TenantID
	}
	if scenario.Facts.CRS {
		if err := addCRS(parsed, files); err != nil {
			return nil, err
		}
	}
	if result.Bundle, err = contentAddressed(files); err != nil {
		return nil, err
	}
	return result, nil
}

// DecodeNumbers decodes raw keeping numbers as json.Number.
func DecodeNumbers(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(value)
}

func compact(raw []byte) []byte {
	var buffer bytes.Buffer
	if json.Compact(&buffer, raw) != nil {
		return raw
	}
	return buffer.Bytes()
}

// fillSecurity derives what the control plane computes on every listener's
// security: the CC v2 policy's canonical digest (CompiledSHA256 "" or
// "auto") and the canonical managed WAF.
func fillSecurity(document map[string]any) error {
	sites, _ := document["sites"].([]any)
	for siteIndex, rawSite := range sites {
		site, _ := rawSite.(map[string]any)
		listeners, _ := site["listeners"].([]any)
		for listenerIndex, rawListener := range listeners {
			listener, _ := rawListener.(map[string]any)
			security, _ := listener["security"].(map[string]any)
			if security == nil {
				continue
			}
			where := fmt.Sprintf("sites[%d].listeners[%d].security", siteIndex, listenerIndex)
			if cc, ok := security["cc"].(map[string]any); ok {
				encoded, _ := json.Marshal(cc["Policy"])
				var policy edgeconfig.CCV2Policy
				if err := DecodeNumbers(encoded, &policy); err != nil {
					return fmt.Errorf("%s.cc.Policy: %w", where, err)
				}
				canonical, err := edgeconfig.CanonicalCCV2Policy(policy)
				if err != nil {
					return fmt.Errorf("%s.cc.Policy: %w", where, err)
				}
				if value, _ := cc["CompiledSHA256"].(string); value == "" || value == "auto" {
					digest := sha256.Sum256(canonical)
					cc["CompiledSHA256"] = hex.EncodeToString(digest[:])
				}
				if value, _ := cc["SourceSHA256"].(string); value == "" || value == "auto" {
					digest := sha256.Sum256(append([]byte("source\x00"), canonical...))
					cc["SourceSHA256"] = hex.EncodeToString(digest[:])
				}
			}
			if waf, ok := security["managed_waf"].(map[string]any); ok {
				encoded, _ := json.Marshal(waf)
				var value edgeconfig.ManagedWAF
				if err := DecodeNumbers(encoded, &value); err != nil {
					return fmt.Errorf("%s.managed_waf: %w", where, err)
				}
				canonical, err := edgeconfig.CanonicalListenerManagedWAF(value)
				if err != nil {
					return fmt.Errorf("%s.managed_waf: %w", where, err)
				}
				var generic any
				encoded, _ = json.Marshal(canonical)
				if err := DecodeNumbers(encoded, &generic); err != nil {
					return err
				}
				security["managed_waf"] = generic
			}
		}
	}
	return nil
}

// telemetryManifest is the signed telemetry identity of every listener, as
// the control plane derives it from the same facts.
func telemetryManifest(value document, telemetry edgegolden.Telemetry, deploymentRoot string) ([]byte, error) {
	manifest := edgeconfig.TelemetryIdentityManifest{
		SchemaVersion: 1, ConfigVersionID: value.ConfigVersionID, ConfigRevision: value.SourceRevision,
		TenantID: telemetry.TenantID, InstallationID: telemetry.InstallationID,
		CapturePolicy:      edgeconfig.TelemetryCapturePolicyManifest{SchemaVersion: 1},
		SourceCapabilities: edgeconfig.TelemetrySourceCapabilities{SchemaVersion: 1},
	}
	for _, site := range value.Sites {
		seen := map[uint16]bool{}
		for _, listener := range site.Listeners {
			if seen[listener.Port] {
				continue
			}
			seen[listener.Port] = true
			access, security := edgeconfig.TelemetryLogPaths(deploymentRoot, value.ConfigVersionID, site.ID, listener.Port)
			manifest.Sites = append(manifest.Sites, edgeconfig.TelemetrySiteIdentity{
				SiteID: site.ID, PackageSubscriptionID: telemetry.Subscriptions[site.ID], Domain: site.Domains[0], ListenPort: listener.Port,
				NamespaceID:   edgeconfig.CacheSiteNamespaceID(telemetry.TenantID, site.ID),
				AccessLogPath: access, SecurityLogPath: security,
			})
			policy := edgeconfig.TelemetrySiteCapturePolicy{Methods: []string{}, URIPrefixes: []string{}, RequestHeaderAllowlist: []string{},
				ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{},
				MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20}
			if raw, ok := telemetry.Capture[site.ID]; ok {
				if err := json.Unmarshal(raw, &policy); err != nil {
					return nil, fmt.Errorf("telemetry capture %s: %w", site.ID, err)
				}
			}
			policy.SiteID, policy.Domain, policy.ListenPort = site.ID, site.Domains[0], listener.Port
			manifest.CapturePolicy.Sites = append(manifest.CapturePolicy.Sites, policy)
		}
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	content = append(content, '\n')
	if _, err := edgeconfig.ParseTelemetryIdentityManifest(content); err != nil {
		return nil, fmt.Errorf("telemetry identity: %w", err)
	}
	return content, nil
}

// addCRS adds exactly the catalog's CRS rule files the managed WAF loads.
func addCRS(value document, files map[string][]byte) error {
	var listeners []edgeconfig.SecurityListener
	for _, site := range value.Sites {
		for _, listener := range site.Listeners {
			protocol := edgeconfig.ProtocolHTTP
			if len(listener.TLS) != 0 && string(listener.TLS) != "null" {
				protocol = edgeconfig.ProtocolHTTPS
			}
			entry := edgeconfig.SecurityListener{SiteID: site.ID, Domain: site.Domains[0], Port: listener.Port, Protocol: protocol}
			if listener.Security != nil {
				entry.Security = *listener.Security
			}
			listeners = append(listeners, entry)
		}
	}
	refs, err := edgeconfig.ListenerCRSProfiles(listeners)
	if err != nil {
		return err
	}
	catalog, err := rulecatalog.DecodeWAFEngineBundle(*rulecatalog.CRSRulesBundle())
	if err != nil {
		return err
	}
	// The CRS profile packs are libs/rulepack's goldens (what license
	// migration 087 seeds), looked up by digest (PA-12).
	var profiles []edgeconfig.CRSProfile
	packs := map[string][]byte{}
	for _, ref := range refs {
		content, err := crsProfilePack(ref.SHA256)
		if err != nil {
			return err
		}
		_, profile, err := rulepack.LoadCRSProfile(content, ref.SHA256)
		if err != nil {
			return err
		}
		profiles = append(profiles, profile)
		packs[edgeconfig.ListenerCRSProfilePath(ref.SHA256)] = content
	}
	text := &edgeconfig.CRSRuleText{Version: rulecatalog.CRSRulesBundle().Version, Files: catalog}
	release, err := edgeconfig.ListenerCRSReleaseFiles(listeners, text, profiles)
	if err != nil {
		return err
	}
	for path, content := range release {
		files[path] = content
	}
	for path, content := range packs {
		files[path] = content
	}
	return nil
}

func contentAddressed(files map[string][]byte) (edgeconfig.Bundle, error) {
	manifest := edgeconfig.Manifest{Files: make([]edgeconfig.FileManifest, 0, len(files))}
	for path, content := range files {
		digest := sha256.Sum256(content)
		manifest.Files = append(manifest.Files, edgeconfig.FileManifest{Path: path, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])})
	}
	manifest, err := edgeconfig.NormalizeManifest(manifest)
	if err != nil {
		return edgeconfig.Bundle{}, err
	}
	digest, err := edgeconfig.ManifestDigest(manifest)
	if err != nil {
		return edgeconfig.Bundle{}, err
	}
	return edgeconfig.Bundle{Manifest: manifest, ManifestSHA256: digest, Files: files}, nil
}

// PublishChallenge installs a fresh key and publishes the policy where the
// challenge rollout does (<deployment root>/challenge/{keys,policies}/<id>).
func PublishChallenge(deploymentRoot string, value edgegolden.Challenge) error {
	keys := filepath.Join(deploymentRoot, "challenge", "keys", value.PolicyID)
	if err := os.MkdirAll(keys, 0o700); err != nil {
		return err
	}
	secret := make([]byte, 48)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	keyFile := filepath.Join(keys, "key-1.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(secret)), 0o600); err != nil {
		return err
	}
	var policy map[string]any
	if err := DecodeNumbers(value.Policy, &policy); err != nil {
		return err
	}
	policy["current_key"] = map[string]string{"key_id": "key-1", "key_file": keyFile}
	raw, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	publisher, err := challenge.NewPublisher(filepath.Join(deploymentRoot, "challenge", "policies", value.PolicyID))
	if err != nil {
		return err
	}
	_, err = publisher.PublishJSON(raw)
	return err
}

// maxSafeInteger bounds canonical numbers (the v2 document's integers).
const maxSafeInteger = int64(1<<53 - 1)

// writeCanonical is the site runtime v2 canonical encoding (keys in UTF-16
// order, safe integers, minimal string escapes): the bytes the node's
// document check and the control plane produce for the same value.
func writeCanonical(output *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(value))
	case string:
		writeCanonicalString(output, value)
	case json.Number:
		number, err := strconv.ParseFloat(string(value), 64)
		if err != nil || math.IsInf(number, 0) || math.IsNaN(number) || math.Trunc(number) != number ||
			math.Abs(number) > float64(maxSafeInteger) {
			return fmt.Errorf("number %q is not a safe integer", value)
		}
		output.WriteString(strconv.FormatInt(int64(number), 10))
	case []any:
		output.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonical(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			writeCanonicalString(output, key)
			output.WriteByte(':')
			if err := writeCanonical(output, value[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON type %T", value)
	}
	return nil
}

func writeCanonicalString(output *bytes.Buffer, value string) {
	const hex = "0123456789abcdef"
	output.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(character)
		case '\b':
			output.WriteString(`\b`)
		case '\t':
			output.WriteString(`\t`)
		case '\n':
			output.WriteString(`\n`)
		case '\f':
			output.WriteString(`\f`)
		case '\r':
			output.WriteString(`\r`)
		default:
			if character < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(hex[byte(character)>>4])
				output.WriteByte(hex[byte(character)&0xf])
			} else {
				output.WriteRune(character)
			}
		}
	}
	output.WriteByte('"')
}

func utf16Less(left, right string) bool {
	leftUnits, rightUnits := utf16.Encode([]rune(left)), utf16.Encode([]rune(right))
	for index := 0; index < len(leftUnits) && index < len(rightUnits); index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}
