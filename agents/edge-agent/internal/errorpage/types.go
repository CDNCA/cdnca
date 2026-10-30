package errorpage

import (
	"errors"
)

const (
	SchemaV1               = "cdnca.error-pages/v1"
	MaxResourceBytes       = 1 << 20
	MaxPolicyResourceBytes = 8 << 20
	MaxArtifactBytes       = 16 << 20
	MaxSites               = 256
	MaxRulesPerScope       = 128
	MaxBindingsPerPolicy   = 32_768
)

var (
	ErrInvalidPolicy  = errors.New("invalid error page policy")
	ErrUnsafeResource = errors.New("unsafe error page resource")
	ErrRevision       = errors.New("error page policy revision conflict")
	ErrPrecheck       = errors.New("error page runtime precheck failed")
	ErrActivate       = errors.New("error page runtime activation failed")
	ErrHealth         = errors.New("error page runtime health check failed")
	ErrRollback       = errors.New("error page runtime rollback failed")
)

type Category string

const (
	CategoryOriginResponse Category = "origin_response"
	CategoryEdgeRoute      Category = "edge_route"
	CategoryEdgeConnect    Category = "edge_connect"
	CategoryNoHost         Category = "no_host"
	CategoryUnknownSite    Category = "unknown_site"
)

type StatusRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

type StatusMatch struct {
	Codes  []int         `json:"codes,omitempty"`
	Ranges []StatusRange `json:"ranges,omitempty"`
}

type Resource struct {
	MIMEType string  `json:"mime_type"`
	Size     int64   `json:"size_bytes"`
	SHA256   string  `json:"sha256"`
	Inline   *string `json:"inline,omitempty"`
	File     string  `json:"file,omitempty"`
}

type Rule struct {
	ID       string      `json:"id"`
	Category Category    `json:"category"`
	Match    StatusMatch `json:"match"`
	Resource Resource    `json:"resource"`
}

type Scope struct {
	Rules []Rule `json:"rules"`
}

type SiteScope struct {
	SiteKey string `json:"site_key"`
	Rules   []Rule `json:"rules"`
}

// Policy is the node-local versioned contract. Revision is strictly monotonic
// at publication time; Version identifies the control-plane release.
type Policy struct {
	Schema   string      `json:"schema"`
	Version  string      `json:"version"`
	Revision uint64      `json:"revision"`
	Global   Scope       `json:"global"`
	Sites    []SiteScope `json:"sites,omitempty"`
}

type Artifact struct {
	Version       string
	Revision      uint64
	Digest        string
	RuntimeSHA256 string
	CanonicalJSON []byte
	RuntimeLua    []byte
	BindingCount  int
	ResourceCount int

	bindings  map[string]string
	resources map[string]CompiledResource
}

type CompiledResource struct {
	MIMEType string
	Size     int64
	SHA256   string
	Body     []byte
	// StyleHash is the CSP source of the page's theme <style>, or "".
	StyleHash string
}

func (artifact Artifact) Lookup(siteKey string, category Category, status int) (CompiledResource, bool) {
	resourceKey, found := artifact.bindings[bindingKey(siteKey, category, status)]
	if !found && siteKey != "" {
		resourceKey, found = artifact.bindings[bindingKey("", category, status)]
	}
	if !found {
		return CompiledResource{}, false
	}
	resource, found := artifact.resources[resourceKey]
	if !found {
		return CompiledResource{}, false
	}
	resource.Body = append([]byte(nil), resource.Body...)
	return resource, true
}
