package dnsreconcilehttpmtls

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcilehttp"
	"github.com/google/uuid"
)

var ErrUnauthenticated = errors.New("DNS reconcile workload mTLS identity is unauthenticated")

type Identity struct {
	URI        string
	WorkloadID string
	TenantID   uuid.UUID
	SiteID     uuid.UUID
}

type Authenticator struct {
	identities map[string]dnsreconcilehttp.WorkloadPrincipal
}

func NewAuthenticator(identities []Identity) (*Authenticator, error) {
	if len(identities) == 0 || len(identities) > 1024 {
		return nil, invalidConfig("at least one workload identity is required")
	}
	result := &Authenticator{identities: make(map[string]dnsreconcilehttp.WorkloadPrincipal, len(identities))}
	for _, identity := range identities {
		uri, ok := canonicalWorkloadURI(identity.URI)
		if !ok || identity.WorkloadID == "" || strings.TrimSpace(identity.WorkloadID) != identity.WorkloadID ||
			identity.TenantID == uuid.Nil || identity.SiteID == uuid.Nil {
			return nil, invalidConfig("workload identity is invalid")
		}
		if _, duplicate := result.identities[uri]; duplicate {
			return nil, invalidConfig("workload URI identities must be unique")
		}
		result.identities[uri] = dnsreconcilehttp.WorkloadPrincipal{
			WorkloadID: identity.WorkloadID, TenantID: identity.TenantID, SiteID: identity.SiteID,
		}
	}
	return result, nil
}

func (authenticator *Authenticator) Authenticate(request *http.Request) (dnsreconcilehttp.WorkloadPrincipal, error) {
	if authenticator == nil || request == nil || len(request.Header.Values("Authorization")) != 0 ||
		request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return dnsreconcilehttp.WorkloadPrincipal{}, ErrUnauthenticated
	}
	leaf := request.TLS.VerifiedChains[0][0]
	if leaf == nil {
		return dnsreconcilehttp.WorkloadPrincipal{}, ErrUnauthenticated
	}
	for _, chain := range request.TLS.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil || !chain[0].Equal(leaf) {
			return dnsreconcilehttp.WorkloadPrincipal{}, ErrUnauthenticated
		}
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil || len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		return dnsreconcilehttp.WorkloadPrincipal{}, ErrUnauthenticated
	}
	uri, ok := canonicalWorkloadURI(leaf.URIs[0].String())
	if !ok || uri != leaf.URIs[0].String() {
		return dnsreconcilehttp.WorkloadPrincipal{}, ErrUnauthenticated
	}
	principal, ok := authenticator.identities[uri]
	if !ok {
		return dnsreconcilehttp.WorkloadPrincipal{}, ErrUnauthenticated
	}
	return principal, nil
}

func canonicalWorkloadURI(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(raw, "spiffe://") || parsed.Scheme != "spiffe" || parsed.User != nil ||
		parsed.Host == "" || parsed.Host != parsed.Hostname() || !validTrustDomain(parsed.Hostname()) ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") ||
		parsed.Opaque != "" || parsed.RawPath != "" || strings.Contains(parsed.EscapedPath(), "%") ||
		!validWorkloadPath(parsed.Path) {
		return "", false
	}
	canonical := parsed.String()
	if canonical != raw {
		return "", false
	}
	return canonical, true
}

func validTrustDomain(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			character := label[index]
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

func validWorkloadPath(value string) bool {
	if !strings.HasPrefix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
