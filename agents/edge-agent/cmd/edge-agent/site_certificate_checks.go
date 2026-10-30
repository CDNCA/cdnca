package main

import (
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

const siteCertificateCheckName = "edge_site_certificates"

type unavailableCertificateSource interface {
	UnavailableCertificates() []dyntls.Unavailable
}

// siteCertificateChecks reports, with every terminal deployment, the sites
// whose certificate version the node cannot serve (missing, expired or not
// yet valid): the release is healthy, but those sites serve no HTTPS until a
// valid certificate is published.
func siteCertificateChecks(source unavailableCertificateSource) func() []*agentv1.CheckResult {
	return func() []*agentv1.CheckResult {
		unavailable := source.UnavailableCertificates()
		summary := "every site certificate is within its validity window"
		if len(unavailable) != 0 {
			sites := make([]string, len(unavailable))
			for index, certificate := range unavailable {
				sites[index] = fmt.Sprintf("site %s certificate %s", certificate.SiteID, certificate.VersionID)
			}
			summary = fmt.Sprintf("%d site certificates unavailable (missing, expired or not yet valid), HTTPS off: %s",
				len(unavailable), strings.Join(sites, ", "))
			// Status summaries are bounded (gateway sanitizeSummary keeps 512).
			if len(summary) > 500 {
				summary = summary[:497] + "..."
			}
		}
		return []*agentv1.CheckResult{{Name: siteCertificateCheckName, Succeeded: len(unavailable) == 0,
			Summary: summary, LatencyDuration: durationpb.New(0)}}
	}
}
