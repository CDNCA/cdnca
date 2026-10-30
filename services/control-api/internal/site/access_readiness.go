package site

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// 接入状态 access_readiness：站点能否真正接入流量，
// 逐项给出 package / line_group / cname_generated / dns_resolved / https_cert / published。
// 原则：显示“已就绪”必须是真的就绪；package 与
// package_unavailable_reason 同一口径（无有效套餐不下发）；line_group 的在线节点与
// dns_resolved 的 A/AAAA 只认已对外发布的端点；published 要求最近一次发布确实含本站。
// 列表与详情只读库：dns_resolved 取后台检查（site_dns_resolution_checks，迁移 565）
// 的结果，其余四项读现有事实；请求里不做 DNS 解析（详情的“立即检查”除外）。

const (
	AccessReady   = "ready"
	AccessPending = "pending"
	AccessBlocked = "blocked"

	AccessCheckPackage   = "package"
	AccessCheckLineGroup = "line_group"
	AccessCheckCNAME     = "cname_generated"
	AccessCheckDNS       = "dns_resolved"
	AccessCheckHTTPS     = "https_cert"
	AccessCheckPublished = "published"

	// dns_resolved 失败原因（每个域名一项，站点取第一个未通过的）。
	DNSPointsElsewhere = "dns_points_elsewhere"
	DNSNotFound        = "dns_not_found"
	DNSLookupFailed    = "dns_lookup_failed"
	DNSNoDomains       = "no_domains"
	dnsWaitingCNAME    = "waiting_cname"

	// publishExcluded: the scope's latest publication does not carry the site.
	publishExcluded = "excluded"

	// 后台检查按站点限频：通过后 10 分钟再查，未通过按 10m·2^(n-1) 退避，上限 1 小时。
	dnsCheckInterval   = 10 * time.Minute
	dnsCheckMaxBackoff = time.Hour
	// 详情“立即检查”同站点 1 分钟一次。
	manualAccessCheckInterval = time.Minute
	// 通配域名用这个子域名代表探测（*.example.com → cdnca-access-check.example.com）。
	wildcardProbeLabel = "cdnca-access-check"
)

// AccessReadiness is the site's 接入状态: ready when every check passes,
// blocked when one needs the platform or the owner to change something
// before it can pass, else pending (waiting on generation, DNS or rollout).
type AccessReadiness struct {
	State  string        `json:"state"`
	Checks []AccessCheck `json:"checks"`
}

// AccessCheck: Detail is a stable reason code (empty or an informational code
// when OK); CheckedAt is when the fact was read or, for dns_resolved, when
// the stored resolution check ran (nil: not checked yet).
type AccessCheck struct {
	Code      string     `json:"code"`
	OK        bool       `json:"ok"`
	Detail    string     `json:"detail"`
	CheckedAt *time.Time `json:"checked_at"`
}

var ErrAccessCheckThrottled = errors.New("site access check was run less than a minute ago")

// AccessCheckThrottledError carries how long until the next 立即检查.
type AccessCheckThrottledError struct{ Wait time.Duration }

func (e *AccessCheckThrottledError) Error() string { return ErrAccessCheckThrottled.Error() }
func (e *AccessCheckThrottledError) Unwrap() error { return ErrAccessCheckThrottled }

// dnsCheckRow is the stored resolution check of one site.
type dnsCheckRow struct {
	OK                bool
	Detail            string
	CNAME             string
	Domains           []string
	CheckedAt         *time.Time
	ManualRequestedAt *time.Time
}

// accessFacts are the per-site inputs of buildAccessReadiness.
type accessFacts struct {
	// PackageUnavailable: the site's package_unavailable_reason (nil: valid).
	PackageUnavailable *string
	Enabled            bool
	CNAME            string
	CNAMEState       *string
	CNAMEFailureCode *string
	Domains          []string
	HTTPSEnabled     bool

	LineGroupFound bool
	OnlineNodes    int

	CertBound, CertActive, CertRevoked bool
	CertNotBefore, CertNotAfter        *time.Time

	// PublishState: succeeded / failed / pending (publishing) / excluded (the
	// latest publication does not carry the site), "" never published.
	PublishState string
	// the scope publication read by loadAccessFacts, folded into PublishState.
	publication, includesSite    bool
	deployments, healthy, failed int

	DNS *dnsCheckRow
}

func buildAccessReadiness(facts accessFacts, now time.Time) AccessReadiness {
	read := now.UTC()
	check := func(code string, ok bool, detail string) AccessCheck {
		return AccessCheck{Code: code, OK: ok, Detail: detail, CheckedAt: &read}
	}
	pkg := check(AccessCheckPackage, true, "")
	if facts.PackageUnavailable != nil {
		pkg = check(AccessCheckPackage, false, *facts.PackageUnavailable)
	}

	var line AccessCheck
	switch {
	case !facts.LineGroupFound:
		line = check(AccessCheckLineGroup, false, "no_line_group")
	case facts.OnlineNodes == 0:
		line = check(AccessCheckLineGroup, false, "no_online_nodes")
	default:
		line = check(AccessCheckLineGroup, true, "")
	}

	var cname AccessCheck
	switch {
	case facts.CNAMEState != nil && *facts.CNAMEState == "failed":
		detail := "cname_failed"
		if facts.CNAMEFailureCode != nil && *facts.CNAMEFailureCode != "" {
			detail = *facts.CNAMEFailureCode
		}
		cname = check(AccessCheckCNAME, false, detail)
	case facts.CNAME == "" || facts.CNAMEState != nil && *facts.CNAMEState == "pending":
		cname = check(AccessCheckCNAME, false, "cname_pending")
	default:
		cname = check(AccessCheckCNAME, true, "")
	}

	dns := AccessCheck{Code: AccessCheckDNS}
	switch {
	case facts.CNAME == "":
		dns.Detail = dnsWaitingCNAME
	case facts.DNS == nil || facts.DNS.CheckedAt == nil || !strings.EqualFold(facts.DNS.CNAME, facts.CNAME) ||
		!sameDomains(facts.DNS.Domains, facts.Domains):
		// The stored check is of another CNAME or domain set (or none ran yet).
		dns.Detail = "not_checked"
	default:
		at := facts.DNS.CheckedAt.UTC()
		dns.OK, dns.Detail, dns.CheckedAt = facts.DNS.OK, facts.DNS.Detail, &at
		if dns.OK {
			dns.Detail = ""
		}
	}

	var https AccessCheck
	switch {
	case !facts.HTTPSEnabled:
		https = check(AccessCheckHTTPS, true, "https_disabled")
	case !facts.CertBound:
		https = check(AccessCheckHTTPS, false, "certificate_missing")
	case facts.CertRevoked:
		https = check(AccessCheckHTTPS, false, "certificate_revoked")
	case facts.CertNotAfter == nil || !facts.CertNotAfter.After(now):
		https = check(AccessCheckHTTPS, false, "certificate_expired")
	case facts.CertNotBefore != nil && facts.CertNotBefore.After(now):
		https = check(AccessCheckHTTPS, false, "certificate_not_yet_valid")
	case !facts.CertActive:
		https = check(AccessCheckHTTPS, false, "certificate_not_active")
	default:
		https = check(AccessCheckHTTPS, true, "")
	}

	var published AccessCheck
	switch {
	case !facts.Enabled:
		published = check(AccessCheckPublished, false, "site_disabled")
	case facts.PublishState == "failed":
		published = check(AccessCheckPublished, false, "publish_failed")
	case facts.PublishState == "pending":
		published = check(AccessCheckPublished, false, "publishing")
	case facts.PublishState == "succeeded":
		published = check(AccessCheckPublished, true, "")
	case facts.PublishState == publishExcluded:
		published = check(AccessCheckPublished, false, "site_not_in_publication")
	default:
		published = check(AccessCheckPublished, false, "not_published")
	}

	result := AccessReadiness{State: AccessReady, Checks: []AccessCheck{pkg, line, cname, dns, https, published}}
	for _, item := range result.Checks {
		if item.OK {
			continue
		}
		if accessCheckBlocked(item) {
			result.State = AccessBlocked
			break
		}
		result.State = AccessPending
	}
	return result
}

// accessCheckBlocked: the failure needs someone to change something (a
// line group, the CNAME, a certificate, the site or a failed rollout);
// generation, DNS propagation and an in-flight rollout only need waiting.
func accessCheckBlocked(check AccessCheck) bool {
	switch check.Code {
	case AccessCheckPackage, AccessCheckLineGroup:
		return true
	case AccessCheckCNAME:
		return check.Detail != "cname_pending"
	case AccessCheckHTTPS:
		return check.Detail != "certificate_not_active"
	case AccessCheckPublished:
		return check.Detail == "site_disabled" || check.Detail == "publish_failed"
	}
	return false
}

// publishState: the site's own automatic publication request in flight
// reads publishing and a failed one publish failed. Otherwise the scope's
// latest publication decides: when its config version does not carry the
// site (config_version_telemetry_site_bindings, one row per site of a site
// runtime v2 version) the site is not live, whatever that rollout did;
// when it does, its node deployments' latest states decide. A succeeded
// request alone is not enough: a later publication may have dropped the
// site. With no publication the site was never published.
func publishState(requestState string, publication, includesSite bool, total, healthy, failed int) string {
	switch requestState {
	case "failed":
		return requestState
	case "", "superseded", "succeeded":
	default:
		return "pending"
	}
	switch {
	case !publication:
		return ""
	case !includesSite:
		return publishExcluded
	case failed > 0:
		return "failed"
	case total > 0 && healthy == total:
		return "succeeded"
	}
	return "pending"
}

func sameDomains(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a, b := slices.Clone(left), slices.Clone(right)
	for index := range a {
		a[index] = strings.ToLower(a[index])
	}
	for index := range b {
		b[index] = strings.ToLower(b[index])
	}
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// dnsCheckDelay: the wait before the next background check after
// `failures` consecutive failed checks (0: the last one passed).
func dnsCheckDelay(failures int, interval, ceiling time.Duration) time.Duration {
	ceiling = max(ceiling, interval)
	delay := interval
	for range max(failures-1, 0) {
		delay *= 2
		if delay >= ceiling {
			return ceiling
		}
	}
	return delay
}

// manualAccessCheckWait: 0 when 立即检查 may run now, else the whole seconds
// left of the per-site minute.
func manualAccessCheckWait(last *time.Time, now time.Time) time.Duration {
	if last == nil {
		return 0
	}
	left := manualAccessCheckInterval - now.Sub(*last)
	if left <= 0 {
		return 0
	}
	return ((left + time.Second - 1) / time.Second) * time.Second
}

// DNSResolver is the control plane host's resolver (net.DefaultResolver);
// no DNS provider or third-party API is asked.
type DNSResolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// dnsTarget is what one site's domains must resolve to: the CNAME, or only
// addresses of the site's line group (Expected).
type dnsTarget struct {
	CNAME    string
	Expected []string
	Domains  []string
}

// DNSDomainResult is one domain's outcome (Code empty: resolves to us).
type DNSDomainResult struct {
	Domain string `json:"domain"`
	Code   string `json:"code,omitempty"`
}

type dnsOutcome struct {
	OK      bool
	Detail  string
	Results []DNSDomainResult
}

const dnsLookupTimeout = 5 * time.Second

func resolveSiteDNS(ctx context.Context, resolver DNSResolver, target dnsTarget) dnsOutcome {
	switch {
	case target.CNAME == "":
		return dnsOutcome{Detail: dnsWaitingCNAME, Results: []DNSDomainResult{}}
	case len(target.Domains) == 0:
		return dnsOutcome{Detail: DNSNoDomains, Results: []DNSDomainResult{}}
	}
	outcome := dnsOutcome{OK: true, Results: make([]DNSDomainResult, 0, len(target.Domains))}
	for _, domain := range target.Domains {
		result := resolveDomain(ctx, resolver, domain, target)
		outcome.Results = append(outcome.Results, result)
		if result.Code != "" && outcome.OK {
			outcome.OK, outcome.Detail = false, result.Code
		}
	}
	return outcome
}

func resolveDomain(ctx context.Context, resolver DNSResolver, domain string, target dnsTarget) DNSDomainResult {
	result := DNSDomainResult{Domain: domain}
	host := strings.TrimSuffix(domain, ".")
	if rest, ok := strings.CutPrefix(host, "*."); ok {
		host = wildcardProbeLabel + "." + rest
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	canonical, err := resolver.LookupCNAME(lookupCtx, host)
	if err != nil {
		result.Code = dnsErrorCode(err)
		return result
	}
	if dnsNameEqual(canonical, target.CNAME) {
		return result
	}
	addresses, err := resolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil {
		result.Code = dnsErrorCode(err)
		return result
	}
	if len(addresses) == 0 {
		result.Code = DNSNotFound
		return result
	}
	for _, address := range addresses {
		if !slices.Contains(target.Expected, address.Unmap().String()) {
			result.Code = DNSPointsElsewhere
			return result
		}
	}
	return result
}

func dnsNameEqual(left, right string) bool {
	return strings.EqualFold(strings.TrimSuffix(left, "."), strings.TrimSuffix(right, "."))
}

func dnsErrorCode(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return DNSNotFound
	}
	return DNSLookupFailed
}
