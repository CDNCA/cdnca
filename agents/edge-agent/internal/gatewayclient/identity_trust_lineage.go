package gatewayclient

import (
	"bytes"
	"crypto/x509"
)

func validateAgentIdentityTrustLineage(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	for index, certificate := range chain {
		if certificate == nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return false
		}
		if index > 0 {
			issuer := chain[index-1]
			if !bytes.Equal(issuer.RawIssuer, certificate.RawSubject) ||
				issuer.CheckSignatureFrom(certificate) != nil ||
				issuer.NotBefore.Before(certificate.NotBefore) || issuer.NotAfter.After(certificate.NotAfter) {
				return false
			}
		}
	}
	root := chain[len(chain)-1]
	if !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil {
		return false
	}
	for index := 1; index < len(chain); index++ {
		issuer := chain[index]
		subordinateCAs := index
		if issuer.MaxPathLenZero && subordinateCAs > 0 || issuer.MaxPathLen >= 0 && subordinateCAs > issuer.MaxPathLen {
			return false
		}
	}
	return true
}
