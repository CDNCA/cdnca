package edgepublish

import "github.com/cdnca/cdnca/libs/edgeconfig"

// applySiteRuntimeV2LazyCertificates turns lazy certificates (site runtime
// v7) on whenever the document serves TLS. There is no per-site certificate
// form: a target node below v7 is refused by the capability check
// (validateSiteRuntimeV2TargetCapabilities names every such node). The node
// still decides per listener (TLS settings other than the port default,
// dispatched sockets keep their own certificate).
func applySiteRuntimeV2LazyCertificates(document *siteRuntimeV2Document, cacheMax int64) error {
	if document.LazyCertificates != nil {
		return ErrInvalidInput // compiled once, by this function only
	}
	if !siteRuntimeV2ServesTLS(*document) {
		return nil
	}
	lazy := edgeconfig.SiteRuntimeLazyCertificates{CacheMax: cacheMax}
	if lazy.Validate() != nil {
		return ErrInvalidInput
	}
	if !setSiteRuntimeV2Capability(document.RequiredCapabilities, "site_runtime", edgeconfig.LazyCertificateSiteRuntimeVersion) {
		return ErrInvalidInput
	}
	document.LazyCertificates = &lazy
	return nil
}

func siteRuntimeV2ServesTLS(document siteRuntimeV2Document) bool {
	for _, site := range document.Sites {
		for _, listener := range site.Listeners {
			if listener.TLS != nil {
				return true
			}
		}
	}
	return false
}
