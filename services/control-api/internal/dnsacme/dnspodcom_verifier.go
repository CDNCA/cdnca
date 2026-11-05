package dnsacme

import "net/http"

// DNSPod.com (international) answers the same legacy API as dnsapi.cn on
// api.dnspod.com: POST /User.Detail with login_token "ID,Token" returns
// info.user ("Get Account Information", https://docs.dnspod.com/api/untitled-2/,
// read 2026-11-05). Status codes -1/-7/-8/85 refuse, -2 is "API used too
// frequently" (https://docs.dnspod.com/api-legacy/info.html).
const (
	dnspodComVerifyEndpoint = "https://api.dnspod.com/User.Detail"
	dnspodComVerifyHost     = "api.dnspod.com"
)

func NewDNSPodComProviderVerifier() *DNSPodProviderVerifier {
	verifier := newDNSPodProviderVerifier("", http.DefaultClient, dnspodVerifyTimeout)
	verifier.endpoint, verifier.host = dnspodComVerifyEndpoint, dnspodComVerifyHost
	return verifier
}
