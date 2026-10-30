package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// boundGatewayURIPrefix marks a standalone Gateway bound through the control
// plane's Gateway registry (ADR 0013 §3.2); the co-located Gateway uses
// .../gateway/control from the installer and is never renewed here.
const (
	boundGatewayURIPrefix = "spiffe://cdn-platform/gateway/"
	colocatedGatewayURI   = "spiffe://cdn-platform/gateway/control"
	renewalCheckInterval  = time.Hour
)

func boundGateway(c config) bool {
	return strings.HasPrefix(c.controlClientWorkloadURISAN, boundGatewayURIPrefix) && c.controlClientWorkloadURISAN != colocatedGatewayURI
}

// reloadableCertificate is a TLS certificate swapped in place after renewal.
type reloadableCertificate struct {
	current atomic.Pointer[tls.Certificate]
	file    string
	kind    string // "client" or "server"
}

func newReloadableCertificate(certificate tls.Certificate, file, kind string) *reloadableCertificate {
	r := &reloadableCertificate{file: file, kind: kind}
	r.current.Store(&certificate)
	return r
}

func (r *reloadableCertificate) serverCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current.Load(), nil
}

func (r *reloadableCertificate) clientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.current.Load(), nil
}

// due reports whether the certificate passed half of its lifetime.
func (r *reloadableCertificate) due(now time.Time) bool {
	leaf := r.current.Load().Leaf
	return !now.Before(leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2))
}

// renew asks ControlInternal for a new certificate of the same key, writes
// it over the certificate file (the private key never changes) and swaps it.
func (r *reloadableCertificate) renew(ctx context.Context, client controlv1.ControlInternalServiceClient, instanceID string) error {
	current := r.current.Load()
	signer, ok := current.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("%s certificate key cannot sign a CSR", r.kind)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: current.Leaf.Subject.CommonName}}, signer)
	if err != nil {
		return err
	}
	response, err := client.RenewGatewayCertificate(ctx, &controlv1.RenewGatewayCertificateRequest{
		Request:           &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		GatewayInstanceId: instanceID, Kind: r.kind, CertificateSigningRequestDer: csr,
	})
	if err != nil {
		return fmt.Errorf("renew %s certificate: %w", r.kind, err)
	}
	block, _ := pem.Decode(response.GetCertificatePem())
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("renewed %s certificate is not PEM", r.kind)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !publicKeyMatches(leaf.PublicKey, signer.Public()) || !sameIdentity(leaf, current.Leaf) {
		return fmt.Errorf("renewed %s certificate does not match the current key or identity", r.kind)
	}
	if err := writeFileAtomic(r.file, response.GetCertificatePem(), 0o444); err != nil {
		return err
	}
	next := tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: current.PrivateKey, Leaf: leaf}
	r.current.Store(&next)
	return nil
}

func publicKeyMatches(a, b crypto.PublicKey) bool {
	left, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	right, err := x509.MarshalPKIXPublicKey(b)
	return err == nil && string(left) == string(right)
}

// sameIdentity: the renewed certificate keeps the URI SANs (client) and the
// server names (server) of the current one.
func sameIdentity(next, current *x509.Certificate) bool {
	if len(next.URIs) != len(current.URIs) || strings.Join(next.DNSNames, ",") != strings.Join(current.DNSNames, ",") ||
		len(next.IPAddresses) != len(current.IPAddresses) {
		return false
	}
	for i := range next.URIs {
		if next.URIs[i].String() != current.URIs[i].String() {
			return false
		}
	}
	for i := range next.IPAddresses {
		if !next.IPAddresses[i].Equal(current.IPAddresses[i]) {
			return false
		}
	}
	return true
}

func writeFileAtomic(path string, contents []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// runCertificateRenewal checks both certificates every hour and renews the
// ones past half-life (client 30 d, server 90 d: ADR 0013 §3.2). A failure
// is retried at the next check; the current certificate stays in use.
func runCertificateRenewal(ctx context.Context, client controlv1.ControlInternalServiceClient, instanceID string,
	logf func(string, ...any), now func() time.Time, certificates ...*reloadableCertificate) {
	check := func() {
		for _, certificate := range certificates {
			if !certificate.due(now()) {
				continue
			}
			callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := certificate.renew(callCtx, client, instanceID)
			cancel()
			if err != nil {
				logf("Gateway %s certificate renewal failed (retry in %s): %v", certificate.kind, renewalCheckInterval, err)
				continue
			}
			logf("Gateway %s certificate renewed until %s", certificate.kind, certificate.current.Load().Leaf.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	check()
	ticker := time.NewTicker(renewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}
