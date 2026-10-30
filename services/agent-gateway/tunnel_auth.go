package gateway

// Tunnel upgrade gate (ADR 0013 §4.6). The inner mTLS session is the node
// identity; this token only keeps strangers from occupying tunnel resources.
//
//   Cdnca-Node-Cert: base64(DER node leaf certificate)
//   Cdnca-Node-Auth: v1.<iat unix seconds>.<nonce 32 hex>.<base64 Ed25519 signature>
//
// signed text = "cdnca-gw-auth-v1\n" + audience + "\n" + path + "\n" +
//               node_id + "\n" + serial_hex + "\n" + iat + "\n" + nonce
//
// The edge agent signs the same text (internal/gatewaytunnel); both sides
// pin one test vector.

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	TunnelNodeCertificateHeader = "Cdnca-Node-Cert"
	TunnelNodeAuthHeader        = "Cdnca-Node-Auth"
	TunnelPath                  = "/agent/v1/tunnel"
	EnrollmentTunnelPath        = "/agent/v1/enroll"

	tunnelTokenSkew   = 60 * time.Second
	tunnelNonceWindow = 120 * time.Second
	maxTunnelHeader   = 8 << 10
)

// TunnelNonceStore remembers nonces for the replay window. Accept reports
// false when the nonce was already seen. The Redis store is shared by every
// gateway of the installation, so a token is good for one upgrade anywhere.
type TunnelNonceStore interface {
	Accept(ctx context.Context, nonce string, window time.Duration) (bool, error)
}

type memoryTunnelNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

func NewMemoryTunnelNonceStore() TunnelNonceStore {
	return &memoryTunnelNonceStore{seen: map[string]time.Time{}, now: time.Now}
}

func (s *memoryTunnelNonceStore) Accept(_ context.Context, nonce string, window time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, at := range s.seen {
		if now.Sub(at) > window {
			delete(s.seen, key)
		}
	}
	if _, ok := s.seen[nonce]; ok {
		return false, nil
	}
	s.seen[nonce] = now
	return true, nil
}

type redisTunnelNonceStore struct {
	client redis.UniversalClient
	prefix string
}

func NewRedisTunnelNonceStore(client redis.UniversalClient, prefix string) (TunnelNonceStore, error) {
	if client == nil || prefix == "" {
		return nil, fmt.Errorf("tunnel nonce store requires a Redis client and key prefix")
	}
	return &redisTunnelNonceStore{client: client, prefix: prefix}, nil
}

func (s *redisTunnelNonceStore) Accept(ctx context.Context, nonce string, window time.Duration) (bool, error) {
	return s.client.SetNX(ctx, s.prefix+":tunnel-nonce:"+nonce, 1, window).Result()
}

func tunnelSignedText(audience, path, nodeID, serialHex string, iat int64, nonce string) []byte {
	return []byte(strings.Join([]string{"cdnca-gw-auth-v1", audience, path, nodeID, serialHex, strconv.FormatInt(iat, 10), nonce}, "\n"))
}

type tunnelTokenVerifier struct {
	audience string
	nodeCAs  *x509.CertPool
	nonces   TunnelNonceStore
	now      func() time.Time
}

var errTunnelUnauthenticated = errors.New("tunnel upgrade is not authenticated")

// verify returns the node ID or an error describing the first failed check.
// Callers answer 401 for every error so the reason never reaches the peer.
func (v *tunnelTokenVerifier) verify(ctx context.Context, certificateHeader, authHeader, path string) (string, error) {
	if len(certificateHeader) == 0 || len(certificateHeader) > maxTunnelHeader || len(authHeader) == 0 || len(authHeader) > 512 {
		return "", fmt.Errorf("%w: tunnel headers are missing or oversized", errTunnelUnauthenticated)
	}
	der, err := base64.StdEncoding.DecodeString(certificateHeader)
	if err != nil {
		return "", fmt.Errorf("%w: node certificate header is invalid", errTunnelUnauthenticated)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("%w: node certificate is invalid", errTunnelUnauthenticated)
	}
	now := v.now()
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: v.nodeCAs, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", fmt.Errorf("%w: node certificate does not chain to the node CA", errTunnelUnauthenticated)
	}
	if leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 {
		return "", fmt.Errorf("%w: node certificate serial is invalid", errTunnelUnauthenticated)
	}
	nodeID, err := nodeIDFromCertificate(leaf)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errTunnelUnauthenticated, err)
	}
	parts := strings.Split(authHeader, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return "", fmt.Errorf("%w: node auth header is malformed", errTunnelUnauthenticated)
	}
	iat, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: node auth iat is invalid", errTunnelUnauthenticated)
	}
	if delta := now.Sub(time.Unix(iat, 0)); delta > tunnelTokenSkew || delta < -tunnelTokenSkew {
		return "", fmt.Errorf("%w: node auth token is outside the clock window", errTunnelUnauthenticated)
	}
	if raw, err := hex.DecodeString(parts[2]); err != nil || len(raw) != 16 || hex.EncodeToString(raw) != parts[2] {
		return "", fmt.Errorf("%w: node auth nonce is invalid", errTunnelUnauthenticated)
	}
	signature, err := base64.StdEncoding.DecodeString(parts[3])
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if err != nil || !ok || !ed25519.Verify(public, tunnelSignedText(v.audience, path, nodeID, strings.ToLower(leaf.SerialNumber.Text(16)), iat, parts[2]), signature) {
		return "", fmt.Errorf("%w: node auth signature is invalid", errTunnelUnauthenticated)
	}
	accepted, err := v.nonces.Accept(ctx, parts[2], tunnelNonceWindow)
	if err != nil {
		return "", fmt.Errorf("%w: nonce store unavailable", errTunnelUnauthenticated)
	}
	if !accepted {
		return "", fmt.Errorf("%w: node auth nonce was replayed", errTunnelUnauthenticated)
	}
	return nodeID, nil
}
