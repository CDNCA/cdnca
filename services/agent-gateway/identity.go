package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const nodeSPIFFEPrefix = "spiffe://cdn-platform/node/"

type nodeIdentity struct {
	NodeID            string
	SerialNumber      string
	CertificateSHA256 [32]byte
}

func authenticatedNode(ctx context.Context) (nodeIdentity, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nodeIdentity{}, status.Error(codes.Unauthenticated, "verified client certificate required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nodeIdentity{}, status.Error(codes.Unauthenticated, "verified client certificate required")
	}
	leaf := tlsInfo.State.VerifiedChains[0][0]
	if leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return nodeIdentity{}, status.Error(codes.Unauthenticated, "client certificate serial number is invalid")
	}
	nodeID, err := nodeIDFromCertificate(leaf)
	if err != nil {
		return nodeIdentity{}, status.Error(codes.Unauthenticated, err.Error())
	}
	return nodeIdentity{
		NodeID:            nodeID,
		SerialNumber:      strings.ToLower(leaf.SerialNumber.Text(16)),
		CertificateSHA256: sha256.Sum256(leaf.Raw),
	}, nil
}

func nodeIDFromCertificate(cert *x509.Certificate) (string, error) {
	if cert == nil || len(cert.URIs) != 1 {
		return "", fmt.Errorf("client certificate must contain exactly one URI SAN")
	}
	uri := cert.URIs[0]
	if uri.String() == "" || !strings.HasPrefix(uri.String(), nodeSPIFFEPrefix) || uri.RawQuery != "" || uri.Fragment != "" {
		return "", fmt.Errorf("client certificate URI SAN is not a node identity")
	}
	if uri.Scheme != "spiffe" || uri.Host != "cdn-platform" || !strings.HasPrefix(uri.Path, "/node/") {
		return "", fmt.Errorf("client certificate URI SAN is not a node identity")
	}
	nodeID := strings.TrimPrefix(uri.Path, "/node/")
	parsed, err := uuid.Parse(nodeID)
	if err != nil || parsed.String() != nodeID {
		return "", fmt.Errorf("client certificate node identity is invalid")
	}
	return nodeID, nil
}
