package certificateasset

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"
)

func prepareCertificate(
	certificatePEM []byte,
	privateKeyPEM []byte,
	opaquePrivateKey *OpaquePrivateKey,
	now time.Time,
) (preparedCertificate, error) {
	certificates, canonicalPEM, err := parseCertificateChain(certificatePEM, now)
	if err != nil {
		return preparedCertificate{}, err
	}

	leaf := certificates[0]
	publicKeyDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return preparedCertificate{}, ErrInvalidCertificatePEM
	}
	publicKeyDigest := sha256.Sum256(publicKeyDER)
	var canonicalPrivateKey []byte
	var opaqueCopy *OpaquePrivateKey
	privateKeyReference := "spki-sha256:" + hex.EncodeToString(publicKeyDigest[:])
	if opaquePrivateKey == nil {
		privateKey, canonical, parseErr := parsePrivateKey(privateKeyPEM)
		if parseErr != nil {
			return preparedCertificate{}, parseErr
		}
		if !publicKeysEqual(leaf.PublicKey, privateKey.Public()) {
			zeroBytes(canonical)
			return preparedCertificate{}, ErrKeyMismatch
		}
		canonicalPrivateKey = canonical
	} else {
		if len(privateKeyPEM) != 0 || !validOpaquePrivateKey(*opaquePrivateKey) {
			return preparedCertificate{}, ErrInvalidInput
		}
		opaquePublicKey, parseErr := x509.ParsePKIXPublicKey(opaquePrivateKey.PublicKeySPKIDER)
		if parseErr != nil || !publicKeysEqual(leaf.PublicKey, opaquePublicKey) {
			return preparedCertificate{}, ErrKeyMismatch
		}
		privateKeyReference = opaquePrivateKey.KeyReference
		opaqueCopy = &OpaquePrivateKey{
			KeyReference:       privateKeyReference,
			PublicKeySPKIDER:   append([]byte(nil), opaquePrivateKey.PublicKeySPKIDER...),
			WrappedKeyMaterial: append([]byte(nil), opaquePrivateKey.WrappedKeyMaterial...),
			Metadata:           append(json.RawMessage(nil), opaquePrivateKey.Metadata...),
		}
	}
	algorithm, keyBits := publicKeyFacts(leaf.PublicKey)
	return preparedCertificate{
		Fingerprint:         sha256.Sum256(leaf.Raw),
		PublicKeySHA256:     publicKeyDigest,
		CanonicalPEM:        canonicalPEM,
		SANs:                append([]string(nil), leaf.DNSNames...),
		Subject:             leaf.Subject.String(),
		SerialNumber:        strings.ToLower(leaf.SerialNumber.Text(16)),
		PublicKeyAlgorithm:  algorithm,
		PublicKeyBits:       keyBits,
		SignatureAlgorithm:  leaf.SignatureAlgorithm.String(),
		NotBefore:           leaf.NotBefore.UTC(),
		NotAfter:            leaf.NotAfter.UTC(),
		PrivateKeyReference: privateKeyReference,
		CanonicalPrivateKey: canonicalPrivateKey,
		OpaquePrivateKey:    opaqueCopy,
	}, nil
}

func validOpaquePrivateKey(value OpaquePrivateKey) bool {
	if !validOpaqueName(value.KeyReference, 256) || len(value.PublicKeySPKIDER) == 0 ||
		len(value.PublicKeySPKIDER) > 4096 || len(value.WrappedKeyMaterial) < 16 ||
		len(value.WrappedKeyMaterial) > 128*1024 || len(value.Metadata) == 0 || len(value.Metadata) > 4096 {
		return false
	}
	var metadata map[string]any
	return json.Unmarshal(value.Metadata, &metadata) == nil && metadata != nil
}

func parseCertificateChain(input []byte, now time.Time) ([]*x509.Certificate, []byte, error) {
	if len(input) == 0 || len(input) > MaxCertificatePEMBytes || hasIllegalPEMControl(input) {
		return nil, nil, ErrInvalidCertificatePEM
	}
	rest := input
	certificates := make([]*x509.Certificate, 0, 3)
	for {
		prefixEnd := bytes.Index(rest, []byte("-----BEGIN "))
		if prefixEnd < 0 {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, nil, ErrInvalidCertificatePEM
			}
			break
		}
		if len(bytes.TrimSpace(rest[:prefixEnd])) != 0 {
			return nil, nil, ErrInvalidCertificatePEM
		}
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, nil, ErrInvalidCertificatePEM
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(certificates) >= MaxCertificateChain {
			return nil, nil, ErrInvalidCertificatePEM
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, ErrInvalidCertificatePEM
		}
		for _, existing := range certificates {
			if bytes.Equal(existing.Raw, certificate.Raw) {
				return nil, nil, ErrInvalidCertificatePEM
			}
		}
		certificates = append(certificates, certificate)
		rest = remaining
	}
	if len(certificates) == 0 {
		return nil, nil, ErrInvalidCertificatePEM
	}
	if err := validateCertificateChain(certificates, now.UTC()); err != nil {
		return nil, nil, err
	}
	canonical := make([]byte, 0, len(input))
	for _, certificate := range certificates {
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return certificates, canonical, nil
}

func validateCertificateChain(certificates []*x509.Certificate, now time.Time) error {
	leaf := certificates[0]
	if leaf.IsCA {
		return ErrCertificateAuthority
	}
	if len(leaf.DNSNames) == 0 || len(leaf.DNSNames) > MaxCertificateSANs ||
		len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return ErrInvalidSAN
	}
	for index, name := range leaf.DNSNames {
		normalized, err := normalizeDNSName(name, true)
		if err != nil {
			return ErrInvalidSAN
		}
		leaf.DNSNames[index] = normalized
	}
	if !permitsServerAuth(leaf.ExtKeyUsage) {
		return ErrServerAuthRequired
	}
	for index, certificate := range certificates {
		if now.Before(certificate.NotBefore) {
			return ErrCertificateNotYetValid
		}
		if !now.Before(certificate.NotAfter) {
			return ErrCertificateExpired
		}
		if weakSignature(certificate.SignatureAlgorithm) {
			return ErrWeakSignature
		}
		if len(certificate.UnhandledCriticalExtensions) != 0 {
			return ErrInvalidCertificatePEM
		}
		if certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 ||
			certificate.SerialNumber.BitLen() > 512 || containsControl(certificate.Subject.String()) ||
			containsControl(certificate.Issuer.String()) || len(certificate.Subject.String()) > 2048 ||
			len(certificate.Issuer.String()) > 2048 {
			return ErrInvalidCertificatePEM
		}
		if index > 0 && !certificate.IsCA {
			return ErrChainIncomplete
		}
		if weakPublicKey(certificate.PublicKey) {
			return ErrWeakPublicKey
		}
	}
	if len(certificates) == 1 {
		if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignatureFrom(leaf) == nil {
			return nil
		}
		return ErrChainIncomplete
	}
	for childIndex := 0; childIndex < len(certificates)-1; childIndex++ {
		child := certificates[childIndex]
		parentIndex := -1
		for candidateIndex := childIndex + 1; candidateIndex < len(certificates); candidateIndex++ {
			if child.CheckSignatureFrom(certificates[candidateIndex]) == nil {
				parentIndex = candidateIndex
				break
			}
		}
		if parentIndex < 0 {
			return ErrChainIncomplete
		}
		if parentIndex != childIndex+1 {
			return ErrChainOrder
		}
	}
	return nil
}

func parsePrivateKey(input []byte) (crypto.Signer, []byte, error) {
	if len(input) == 0 || len(input) > MaxPrivateKeyPEMBytes || hasIllegalPEMControl(input) {
		return nil, nil, ErrInvalidPrivateKeyPEM
	}
	prefixEnd := bytes.Index(input, []byte("-----BEGIN "))
	if prefixEnd < 0 || len(bytes.TrimSpace(input[:prefixEnd])) != 0 {
		return nil, nil, ErrInvalidPrivateKeyPEM
	}
	block, rest := pem.Decode(input)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, ErrInvalidPrivateKeyPEM
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, nil, ErrInvalidPrivateKeyPEM
	}
	if err != nil {
		return nil, nil, ErrInvalidPrivateKeyPEM
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, ErrInvalidPrivateKeyPEM
	}
	canonicalDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, nil, ErrInvalidPrivateKeyPEM
	}
	canonical := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: canonicalDER})
	zeroBytes(canonicalDER)
	return signer, canonical, nil
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	if leftErr != nil || rightErr != nil || len(leftDER) != len(rightDER) {
		return false
	}
	return subtle.ConstantTimeCompare(leftDER, rightDER) == 1
}

func permitsServerAuth(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func weakSignature(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1,
		x509.UnknownSignatureAlgorithm:
		return true
	default:
		return false
	}
}

func weakPublicKey(publicKey any) bool {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen() < MinimumRSAKeyBits || key.E < 65537
	case *ecdsa.PublicKey:
		return key.Curve == nil || key.Params().BitSize < 256
	case ed25519.PublicKey:
		return len(key) != ed25519.PublicKeySize
	default:
		return true
	}
}

func publicKeyFacts(publicKey any) (string, int) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return "rsa", key.N.BitLen()
	case *ecdsa.PublicKey:
		return "ecdsa", key.Params().BitSize
	case ed25519.PublicKey:
		return "ed25519", len(key) * 8
	default:
		return "unknown", 0
	}
}

func validEnvelope(envelope PrivateKeyEnvelope) bool {
	if !validOpaqueName(envelope.KeyID, 128) || len(envelope.Ciphertext) < 16 ||
		len(envelope.Ciphertext) > 128*1024 || len(envelope.Nonce) < 8 || len(envelope.Nonce) > 64 ||
		len(envelope.Metadata) == 0 || len(envelope.Metadata) > 4096 {
		return false
	}
	var metadata map[string]any
	return json.Unmarshal(envelope.Metadata, &metadata) == nil && metadata != nil
}

func cloneEnvelope(envelope PrivateKeyEnvelope) PrivateKeyEnvelope {
	return PrivateKeyEnvelope{
		KeyID:      envelope.KeyID,
		Ciphertext: append([]byte(nil), envelope.Ciphertext...),
		Nonce:      append([]byte(nil), envelope.Nonce...),
		Metadata:   append(json.RawMessage(nil), envelope.Metadata...),
	}
}

func envelopeContainsPlaintext(envelope PrivateKeyEnvelope, plaintext []byte) bool {
	return bytes.Contains(envelope.Ciphertext, plaintext) || bytes.Contains(envelope.Nonce, plaintext) ||
		bytes.Contains(envelope.Metadata, plaintext) || bytes.Contains([]byte(envelope.KeyID), plaintext)
}

func hasIllegalPEMControl(value []byte) bool {
	for _, character := range value {
		if (character < 0x20 && character != '\n' && character != '\r' && character != '\t') || character == 0x7f {
			return true
		}
	}
	return false
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func fingerprintHex(fingerprint [32]byte) string {
	return hex.EncodeToString(fingerprint[:])
}
