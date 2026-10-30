package edgepublish

import (
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/google/uuid"
)

// SiteObjectsV2 is the exported result of buildSiteObjectsV2 for tools that
// run the production conversion outside a publication (the dynamic routing
// golden renderer and scale benchmarks, cmd/cdnca-site-objects-v2).
type SiteObjectsV2 struct {
	// Sites: plaintext object encoding by digest, sorted by site ID.
	Sites []SiteObjectV2
	// Referenced: CC policies, HTTP policy entries, firewall actions by digest.
	Referenced map[string][]byte
	Ports      []edgesite.PortProfile
}

type SiteObjectV2 struct {
	SiteID    string
	SHA256    string
	Plaintext []byte
}

// BuildSiteObjectsV2FromBundle converts a compiled site runtime v2 release
// into cdnca.edge.site/v2 objects as the control plane publishes them (no
// error page or origin authentication facts).
func BuildSiteObjectsV2FromBundle(bundle edgeconfig.Bundle, tenantID uuid.UUID) (SiteObjectsV2, error) {
	source, err := siteObjectsV2SourceFromBundle(bundle)
	if err != nil {
		return SiteObjectsV2{}, err
	}
	built, err := buildSiteObjectsV2(source, tenantID, nil)
	if err != nil {
		return SiteObjectsV2{}, err
	}
	result := SiteObjectsV2{Referenced: built.Referenced, Ports: built.Ports}
	for _, site := range built.Sites {
		result.Sites = append(result.Sites, SiteObjectV2{SiteID: site.SiteID, SHA256: site.SHA256, Plaintext: site.Plaintext})
	}
	return result, nil
}
