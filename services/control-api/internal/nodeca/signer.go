package nodeca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
)

const (
	maxCSRBytes   = 64 << 10
	maxChainDepth = 8
	serialBytes   = 20
)

var (
	ErrInvalidConfiguration = errors.New("invalid node CA signer configuration")
	ErrInvalidChain         = errors.New("invalid node CA certificate chain")
	ErrKeyMismatch          = errors.New("node CA signing key does not match issuing certificate")
	ErrInvalidRequest       = errors.New("invalid node certificate signing request")
	ErrRandomSource         = errors.New("node certificate serial generation failed")
	ErrSigning              = errors.New("node certificate signing failed")
)

// Signer signs short-lived node workload certificates. orderedChain must start
// with issuingCA and end with a self-signed trust anchor.
type Signer struct {
	privateKey crypto.Signer
	issuer     *x509.Certificate
	chain      []*x509.Certificate
	chainPEM   [][]byte
	random     io.Reader
	clock      func() time.Time
	gate       chan struct{}
}

func NewSigner(privateKey crypto.Signer, issuingCA *x509.Certificate, orderedChain []*x509.Certificate) (*Signer, error) {
	return newSigner(privateKey, issuingCA, orderedChain, cryptorand.Reader, time.Now)
}

// NewSignerWithRandom is equivalent to NewSigner and permits an injected
// cryptographic random source for failure testing and managed runtimes.
func NewSignerWithRandom(privateKey crypto.Signer, issuingCA *x509.Certificate, orderedChain []*x509.Certificate, random io.Reader) (*Signer, error) {
	return newSigner(privateKey, issuingCA, orderedChain, random, time.Now)
}

func newSigner(
	privateKey crypto.Signer,
	issuingCA *x509.Certificate,
	orderedChain []*x509.Certificate,
	random io.Reader,
	clock func() time.Time,
) (*Signer, error) {
	if isNil(privateKey) || issuingCA == nil || random == nil || clock == nil ||
		len(orderedChain) == 0 || len(orderedChain) > maxChainDepth {
		return nil, ErrInvalidConfiguration
	}

	issuer, err := cloneCertificate(issuingCA)
	if err != nil {
		return nil, ErrInvalidChain
	}
	chain := make([]*x509.Certificate, len(orderedChain))
	chainPEM := make([][]byte, len(orderedChain))
	seen := make(map[string]struct{}, len(orderedChain))
	for index, certificate := range orderedChain {
		cloned, cloneErr := cloneCertificate(certificate)
		if cloneErr != nil {
			return nil, ErrInvalidChain
		}
		fingerprint := string(cloned.Raw)
		if _, exists := seen[fingerprint]; exists {
			return nil, ErrInvalidChain
		}
		seen[fingerprint] = struct{}{}
		chain[index] = cloned
		chainPEM[index] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cloned.Raw})
	}
	if !bytes.Equal(chain[0].Raw, issuer.Raw) {
		return nil, ErrInvalidChain
	}

	now := clock().UTC()
	for _, certificate := range chain {
		if !validCA(certificate) || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, ErrInvalidChain
		}
	}
	for index := 0; index < len(chain)-1; index++ {
		if !bytes.Equal(chain[index].RawIssuer, chain[index+1].RawSubject) ||
			chain[index].CheckSignatureFrom(chain[index+1]) != nil {
			return nil, ErrInvalidChain
		}
	}
	root := chain[len(chain)-1]
	if !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil {
		return nil, ErrInvalidChain
	}
	if err := verifyIssuerChain(chain, now); err != nil {
		return nil, ErrInvalidChain
	}

	privateKeyPublic := privateKey.Public()
	privatePublic, err := marshalPublicKey(privateKeyPublic)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	issuerPublic, err := marshalPublicKey(issuer.PublicKey)
	if err != nil || !bytes.Equal(privatePublic, issuerPublic) {
		return nil, ErrKeyMismatch
	}
	if !validSigningPublicKey(privateKeyPublic) {
		return nil, ErrInvalidConfiguration
	}

	return &Signer{
		privateKey: privateKey,
		issuer:     issuer,
		chain:      chain,
		chainPEM:   chainPEM,
		random:     random,
		clock:      clock,
		gate:       make(chan struct{}, 1),
	}, nil
}

func (s *Signer) SignNodeCertificate(ctx context.Context, request nodeidentity.SignRequest) (nodeidentity.SignedCertificate, error) {
	if s == nil || ctx == nil {
		return nodeidentity.SignedCertificate{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nodeidentity.SignedCertificate{}, err
	}
	csr, uri, err := validateRequest(request)
	if err != nil {
		return nodeidentity.SignedCertificate{}, err
	}
	if err := ctx.Err(); err != nil {
		return nodeidentity.SignedCertificate{}, err
	}

	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-ctx.Done():
		return nodeidentity.SignedCertificate{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nodeidentity.SignedCertificate{}, err
	}

	now := s.clock().UTC()
	if now.Before(request.NotBefore) || !now.Before(request.NotAfter) || !chainCovers(s.chain, request.NotBefore, request.NotAfter) {
		return nodeidentity.SignedCertificate{}, ErrInvalidRequest
	}

	serialData := make([]byte, serialBytes)
	if _, err := io.ReadFull(s.random, serialData); err != nil {
		return nodeidentity.SignedCertificate{}, ErrRandomSource
	}
	serialData[0] &= 0x7f
	if allZero(serialData) {
		return nodeidentity.SignedCertificate{}, ErrRandomSource
	}
	if err := ctx.Err(); err != nil {
		return nodeidentity.SignedCertificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serialData),
		NotBefore:             request.NotBefore,
		NotAfter:              request.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(s.random, template, s.issuer, csr.PublicKey, s.privateKey)
	if err != nil {
		return nodeidentity.SignedCertificate{}, ErrSigning
	}
	if err := ctx.Err(); err != nil {
		return nodeidentity.SignedCertificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || leaf.CheckSignatureFrom(s.issuer) != nil || verifyLeafChain(leaf, s.chain, request.NotBefore, request.NotAfter) != nil {
		return nodeidentity.SignedCertificate{}, ErrSigning
	}

	chainPEM := make([][]byte, len(s.chainPEM))
	for index := range s.chainPEM {
		chainPEM[index] = bytes.Clone(s.chainPEM[index])
	}
	return nodeidentity.SignedCertificate{
		LeafCertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		IssuingChainPEM:    chainPEM,
	}, nil
}

func validateRequest(request nodeidentity.SignRequest) (*x509.CertificateRequest, *url.URL, error) {
	if request.NodeID == uuid.Nil || len(request.CertificateSigningRequestDER) == 0 ||
		len(request.CertificateSigningRequestDER) > maxCSRBytes ||
		(request.IssuanceKind != "initial" && request.IssuanceKind != "renewal") ||
		request.NotBefore.IsZero() || request.NotAfter.IsZero() || !request.NotBefore.Before(request.NotAfter) ||
		request.NotBefore.Nanosecond() != 0 || request.NotAfter.Nanosecond() != 0 {
		return nil, nil, ErrInvalidRequest
	}
	expectedURI := nodeidentity.NodeSPIFFEPrefix + request.NodeID.String()
	if request.URISAN != expectedURI {
		return nil, nil, ErrInvalidRequest
	}
	uri, err := url.Parse(expectedURI)
	if err != nil || uri.String() != expectedURI {
		return nil, nil, ErrInvalidRequest
	}
	csr, err := x509.ParseCertificateRequest(request.CertificateSigningRequestDER)
	if err != nil || csr.CheckSignature() != nil || !validCSRPublicKey(csr) ||
		len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, nil, ErrInvalidRequest
	}
	return csr, uri, nil
}

func validCSRPublicKey(csr *x509.CertificateRequest) bool {
	switch key := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 {
			return false
		}
		return csr.SignatureAlgorithm == x509.SHA256WithRSA || csr.SignatureAlgorithm == x509.SHA384WithRSA ||
			csr.SignatureAlgorithm == x509.SHA512WithRSA || csr.SignatureAlgorithm == x509.SHA256WithRSAPSS ||
			csr.SignatureAlgorithm == x509.SHA384WithRSAPSS || csr.SignatureAlgorithm == x509.SHA512WithRSAPSS
	case *ecdsa.PublicKey:
		return key.Curve != nil && key.Curve.Params().Name == "P-256" && csr.SignatureAlgorithm == x509.ECDSAWithSHA256
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize && csr.SignatureAlgorithm == x509.PureEd25519
	default:
		return false
	}
}

func validCA(certificate *x509.Certificate) bool {
	return certificate.IsCA && certificate.BasicConstraintsValid &&
		certificate.KeyUsage&x509.KeyUsageCertSign != 0 && validSignatureAlgorithm(certificate.SignatureAlgorithm) &&
		validSigningPublicKey(certificate.PublicKey)
}

func validSignatureAlgorithm(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
		return true
	default:
		return false
	}
}

func validSigningPublicKey(publicKey crypto.PublicKey) bool {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key.N != nil && key.N.BitLen() >= 2048 && key.N.BitLen() <= 4096
	case *ecdsa.PublicKey:
		if key.Curve == nil {
			return false
		}
		switch key.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
			return true
		default:
			return false
		}
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	default:
		return false
	}
}

func verifyIssuerChain(chain []*x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	intermediates := x509.NewCertPool()
	if len(chain) > 2 {
		for _, certificate := range chain[1 : len(chain)-1] {
			intermediates.AddCert(certificate)
		}
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func verifyLeafChain(leaf *x509.Certificate, chain []*x509.Certificate, notBefore, notAfter time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(chain[len(chain)-1])
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[:len(chain)-1] {
		intermediates.AddCert(certificate)
	}
	for _, instant := range []time.Time{notBefore, notAfter} {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, CurrentTime: instant,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			return err
		}
	}
	return nil
}

func chainCovers(chain []*x509.Certificate, notBefore, notAfter time.Time) bool {
	for _, certificate := range chain {
		if certificate.NotBefore.After(notBefore) || certificate.NotAfter.Before(notAfter) {
			return false
		}
	}
	return true
}

func cloneCertificate(certificate *x509.Certificate) (*x509.Certificate, error) {
	if certificate == nil || len(certificate.Raw) == 0 {
		return nil, ErrInvalidChain
	}
	return x509.ParseCertificate(bytes.Clone(certificate.Raw))
}

func marshalPublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrInvalidConfiguration
	}
	return x509.MarshalPKIXPublicKey(publicKey)
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ nodeidentity.CertificateSigner = (*Signer)(nil)
