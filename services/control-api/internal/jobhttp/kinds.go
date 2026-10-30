package jobhttp

import "context"

type KindInfo struct {
	Kind          string `json:"kind"`
	NameKey       string `json:"name_key"`
	Integration   string `json:"integration"`
	RuntimeStatus string `json:"runtime_status"`
}

type KindCatalog struct {
	Data []KindInfo `json:"data"`
}

// These are producer integrations, not a claim that their runtime is enabled.
// The producer contract test binds every entry to its production creation path.
var integratedKinds = []KindInfo{
	{Kind: "analytics.log_export", NameKey: "jobs.kindNames.analyticsLogExport"},
	{Kind: "cache.operation", NameKey: "jobs.kindNames.cacheOperation"},
	{Kind: "dns.cleanup.v1", NameKey: "jobs.kindNames.dnsCleanup"},
	{Kind: "dns.cname.allocation", NameKey: "jobs.kindNames.cnameAllocation"},
	{Kind: "dns.cname.intent", NameKey: "jobs.kindNames.cnameIntent"},
	{Kind: "dns.cname.stream_intent", NameKey: "jobs.kindNames.cnameStreamIntent"},
	{Kind: "dns.repair.v1", NameKey: "jobs.kindNames.dnsRepair"},
	{Kind: "dns_reconcile", NameKey: "jobs.kindNames.dnsReconcile"},
	{Kind: "edge.publication", NameKey: "jobs.kindNames.edgePublication"},
	{Kind: "site.status_recovery", NameKey: "jobs.kindNames.siteStatusRecovery"},
}

func (service *Service) Kinds(ctx context.Context, principal Principal, audience Audience) (KindCatalog, error) {
	if ctx == nil {
		return KindCatalog{}, ErrInvalidRequest
	}
	if _, err := authorize(principal, audience); err != nil {
		return KindCatalog{}, err
	}
	if err := ctx.Err(); err != nil {
		return KindCatalog{}, err
	}
	result := KindCatalog{Data: make([]KindInfo, len(integratedKinds))}
	for index, kind := range integratedKinds {
		kind.Integration = "integrated"
		kind.RuntimeStatus = "unknown"
		result.Data[index] = kind
	}
	return result, nil
}
