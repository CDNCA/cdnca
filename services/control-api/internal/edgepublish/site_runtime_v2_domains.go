package edgepublish

import "slices"

// siteRuntimeV2Domains is a site's live domains with its primary domain
// (sites.domain) first. Every reader of a v2 document that needs one domain
// per site (the signed telemetry identity, node authorization, the realtime
// roster) takes the first, so it is the domain the legacy renderer keys a
// site's telemetry on (edgeconfig Site.Domain). A primary no longer live
// keeps the stored order.
func siteRuntimeV2Domains(fact siteFact) []string {
	if len(fact.domains) == 0 {
		return []string{fact.domain}
	}
	domains := slices.Clone(fact.domains)
	if index := slices.Index(domains, fact.domain); index > 0 {
		domains = append(append([]string{fact.domain}, domains[:index]...), domains[index+1:]...)
	}
	return domains
}
