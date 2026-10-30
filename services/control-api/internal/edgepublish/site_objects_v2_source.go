package edgepublish

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// siteObjectsV2Source is a compiled site runtime v2 release read directly
// for dynamic routing (D13-c③): the document's sites, each with its entries
// of the per-site release files, and the release's other files. It is what
// the v8 split (siteobject.Build) used to carry into buildSiteObjectsV2.
type siteObjectsV2Source struct {
	ScopeID         string
	ConfigVersionID string
	SourceRevision  int64
	// DocumentSHA256 is the digest of the canonical v2 document.
	DocumentSHA256 string
	// Capabilities are the document's required capabilities (name order).
	Capabilities   []siteobject.Capability
	System         *edgeconfig.SiteRuntimeSystem
	Streams        *edgeconfig.StreamRuntime
	InstallationID string
	// Files: release path -> content of every file but the document, the
	// HTTP policy, origin route and telemetry identity files (whose entries
	// are on the sites).
	Files map[string][]byte
	// Sites in site ID order.
	Sites []siteObjectsV2SourceSite
}

type siteObjectsV2SourceSite struct {
	Runtime siteRuntimeV2Site
	// HTTPPolicy: the site's binding and its http-policy.v1.json entry.
	HTTPPolicy *siteObjectsV2HTTPPolicy
	// OriginRoute: the site's origin-route.v1.json document (nil = none).
	OriginRoute json.RawMessage
	// Telemetry: the site's telemetry identity entries (the same on every
	// listener), capture lists as the manifest has them.
	Telemetry *edgesite.Telemetry
}

type siteObjectsV2HTTPPolicy struct {
	PolicyID       string
	PolicyRevision int64
	Edge           json.RawMessage
}

// siteObjectsV2SourceFromBundle reads bundle (buildSiteRuntimeV2Bundle).
func siteObjectsV2SourceFromBundle(bundle edgeconfig.Bundle) (siteObjectsV2Source, error) {
	invalid := func(what string, args ...any) (siteObjectsV2Source, error) {
		return siteObjectsV2Source{}, fmt.Errorf("%w: site objects v2 source: %s", ErrInvalidInput, fmt.Sprintf(what, args...))
	}
	raw, ok := bundle.Files[siteobject.DocumentPath]
	if !ok {
		return invalid("%s is missing", siteobject.DocumentPath)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document siteRuntimeV2Document
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return invalid("document: %v", err)
	}
	source := siteObjectsV2Source{ScopeID: document.ConfigurationScopeID, ConfigVersionID: document.ConfigVersionID,
		SourceRevision: document.SourceRevision, DocumentSHA256: siteobject.Digest(raw),
		System: document.System, Streams: document.Streams, Files: map[string][]byte{}}
	// Removing a scope's last listener keeps a streamless runtime in the
	// document for its tcp/udp lifecycle requirements (already in
	// RequiredCapabilities); the scope object then carries no streams.
	if source.Streams != nil && len(source.Streams.StreamsV2) == 0 {
		source.Streams = nil
	}
	for _, capability := range document.RequiredCapabilities {
		source.Capabilities = append(source.Capabilities, siteobject.Capability{Name: capability.Name, APIVersion: capability.APIVersion})
	}
	sites := make(map[string]*siteObjectsV2SourceSite, len(document.Sites))
	for _, runtime := range document.Sites {
		if sites[runtime.ID] != nil {
			return invalid("site %s appears twice", runtime.ID)
		}
		site := &siteObjectsV2SourceSite{Runtime: runtime}
		if binding := runtime.HTTPPolicy; binding != nil {
			site.HTTPPolicy = &siteObjectsV2HTTPPolicy{PolicyID: binding.PolicyID, PolicyRevision: binding.PolicyRevision}
		}
		sites[runtime.ID] = site
	}
	for path, content := range bundle.Files {
		switch path {
		case siteobject.DocumentPath:
		case siteRuntimeV2HTTPPolicyArtifactPath:
			var file struct {
				Sites []json.RawMessage `json:"sites"`
			}
			if err := json.Unmarshal(content, &file); err != nil {
				return invalid("%s: %v", path, err)
			}
			for _, entry := range file.Sites {
				var identity struct {
					SiteID string `json:"site_id"`
				}
				site := (*siteObjectsV2SourceSite)(nil)
				if json.Unmarshal(entry, &identity) == nil {
					site = sites[identity.SiteID]
				}
				if site == nil || site.HTTPPolicy == nil || site.HTTPPolicy.Edge != nil {
					return invalid("%s site", path)
				}
				site.HTTPPolicy.Edge = bytes.Clone(entry)
			}
		case siteOriginRouteBundlePath:
			var file struct {
				Sites []struct {
					SiteID   string          `json:"site_id"`
					Document json.RawMessage `json:"document"`
				} `json:"sites"`
			}
			if err := json.Unmarshal(content, &file); err != nil {
				return invalid("%s: %v", path, err)
			}
			for _, route := range file.Sites {
				site := sites[route.SiteID]
				if site == nil || site.OriginRoute != nil {
					return invalid("%s site", path)
				}
				site.OriginRoute = bytes.Clone(route.Document)
			}
		case edgeconfig.TelemetryIdentityManifestPath:
			manifest, err := edgeconfig.ParseTelemetryIdentityManifest(content)
			if err != nil {
				return invalid("%s: %v", path, err)
			}
			source.InstallationID = manifest.InstallationID
			for index, identity := range manifest.Sites {
				site := sites[identity.SiteID]
				if site == nil {
					return invalid("%s site", path)
				}
				telemetry := &edgesite.Telemetry{PackageSubscriptionID: identity.PackageSubscriptionID,
					Capture: telemetryCapture(manifest.CapturePolicy.Sites[index])}
				if site.Telemetry == nil {
					site.Telemetry = telemetry
				} else if !reflect.DeepEqual(site.Telemetry, telemetry) {
					return invalid("%s: listeners of site %s differ", path, identity.SiteID)
				}
			}
		default:
			source.Files[path] = content
		}
	}
	for _, site := range sites {
		if site.HTTPPolicy != nil && site.HTTPPolicy.Edge == nil {
			return invalid("site %s binds an HTTP policy absent from %s", site.Runtime.ID, siteRuntimeV2HTTPPolicyArtifactPath)
		}
		source.Sites = append(source.Sites, *site)
	}
	sort.Slice(source.Sites, func(i, j int) bool { return source.Sites[i].Runtime.ID < source.Sites[j].Runtime.ID })
	return source, nil
}

func telemetryCapture(policy edgeconfig.TelemetrySiteCapturePolicy) siteobject.TelemetryCapture {
	return siteobject.TelemetryCapture{
		Revision: policy.Revision, EvidenceDigest: policy.EvidenceDigest, Enabled: policy.Enabled,
		Methods: policy.Methods, URIPrefixes: policy.URIPrefixes,
		RequestHeaderAllowlist: policy.RequestHeaderAllowlist, ResponseHeaderAllowlist: policy.ResponseHeaderAllowlist,
		RequestBodyFieldAllowlist:  policy.RequestBodyFieldAllowlist,
		ResponseBodyFieldAllowlist: policy.ResponseBodyFieldAllowlist,
		MaxValueBytes:              policy.MaxValueBytes, MaxBodyBytes: policy.MaxBodyBytes, MaxEventBytes: policy.MaxEventBytes,
	}
}

// fileObjects is the release's files by content digest.
func (source siteObjectsV2Source) fileObjects() map[string][]byte {
	objects := make(map[string][]byte, len(source.Files))
	for _, content := range source.Files {
		objects[siteobject.Digest(content)] = content
	}
	return objects
}

// runtimes is every site's runtime by site ID.
func (source siteObjectsV2Source) runtimes() map[string]siteRuntimeV2Site {
	result := make(map[string]siteRuntimeV2Site, len(source.Sites))
	for _, site := range source.Sites {
		result[site.Runtime.ID] = site.Runtime
	}
	return result
}
