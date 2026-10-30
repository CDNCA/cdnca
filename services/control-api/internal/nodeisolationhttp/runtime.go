package nodeisolationhttp

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	controlidentity "github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeisolation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProductionDependencies struct {
	Pool     *pgxpool.Pool
	Identity *controlidentity.Service
}

type ProductionConfig struct {
	Policy  nodeisolation.Policy
	Handler Config
}

func DefaultProductionConfig() ProductionConfig {
	return ProductionConfig{Policy: nodeisolation.Policy{
		FailureThreshold: 3, RecoveryThreshold: 3, MaxEvidenceAge: time.Minute,
	}}
}

func NewProductionHandler(dependencies ProductionDependencies, config ProductionConfig) (*Handler, error) {
	if dependencies.Pool == nil || dependencies.Identity == nil || !dependencies.Identity.Configured() {
		return nil, ErrInvalidConfig
	}
	store, err := nodeisolation.NewIsolationStore(dependencies.Pool, time.Now)
	if err != nil {
		return nil, err
	}
	service, err := nodeisolation.NewIsolationService(store, config.Policy, time.Now)
	if err != nil {
		return nil, err
	}
	return NewNodeIsolationHandler(Dependencies{
		Service:   service,
		Sessions:  &productionSessionAuthenticator{identity: dependencies.Identity},
		Workloads: &productionWorkloadAuthenticator{pool: dependencies.Pool},
	}, config.Handler)
}

type productionSessionAuthenticator struct {
	identity *controlidentity.Service
}

func (authenticator *productionSessionAuthenticator) Authenticate(request *http.Request) (Principal, error) {
	if authenticator == nil || authenticator.identity == nil || request == nil || hasIdentityHeaders(request) {
		return Principal{}, ErrUnauthenticated
	}
	token, ok := strictBearer(request)
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	authenticated, err := authenticator.identity.AuthenticateSession(request.Context(), token)
	if err != nil {
			if errors.Is(err, controlidentity.ErrInvalidSession) || errors.Is(err, controlidentity.ErrAccountDisabled) ||
				errors.Is(err, controlidentity.ErrMembershipDisabled) {
			return Principal{}, ErrUnauthenticated
		}
		return Principal{}, ErrAuthenticationUnavailable
	}
	return Principal{
		SubjectID: authenticated.Principal.UserID, ScopeID: authenticated.Principal.ScopeID,
		ScopeKind: authenticated.Principal.ScopeKind, SessionID: authenticated.SessionID,
		Permissions: append([]string(nil), authenticated.Principal.Permissions...),
	}, nil
}

type productionWorkloadAuthenticator struct {
	pool *pgxpool.Pool
}

func (authenticator *productionWorkloadAuthenticator) Authenticate(request *http.Request) (WorkloadPrincipal, error) {
	if authenticator == nil || authenticator.pool == nil || request == nil || len(request.Header.Values("Authorization")) != 0 {
		return WorkloadPrincipal{}, ErrUnauthenticated
	}
	nodeID, uriSAN, leafSHA256, ok := nodeCertificateIdentity(request)
	if !ok {
		return WorkloadPrincipal{}, ErrUnauthenticated
	}
	var scopeID uuid.UUID
	err := authenticator.pool.QueryRow(request.Context(), `
		SELECT certificate.owner_scope_id
		FROM node_certificates certificate
		JOIN nodes node ON node.id=certificate.node_id AND node.scope_id=certificate.owner_scope_id
		WHERE certificate.node_id=$1 AND certificate.uri_san=$2
		  AND certificate.leaf_der_sha256=$3 AND certificate.status='active'
		  AND certificate.rotation_status IN ('current','overlap')
		  AND statement_timestamp()>=certificate.not_before
		  AND statement_timestamp()<certificate.not_after
		  AND (certificate.rotation_status='current' OR certificate.overlap_until>statement_timestamp())`,
		nodeID, uriSAN, leafSHA256[:]).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return WorkloadPrincipal{}, ErrUnauthenticated
	}
	if err != nil {
		return WorkloadPrincipal{}, ErrAuthenticationUnavailable
	}
	return WorkloadPrincipal{
		WorkloadID: nodeidentity.NodeSPIFFEPrefix + nodeID.String(), ScopeID: scopeID, NodeID: nodeID,
		Permissions: []string{PermissionReport},
	}, nil
}

func nodeCertificateIdentity(request *http.Request) (uuid.UUID, string, [sha256.Size]byte, bool) {
	if request == nil || request.TLS == nil || len(request.TLS.PeerCertificates) == 0 ||
		len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return uuid.Nil, "", [sha256.Size]byte{}, false
	}
	leaf := request.TLS.VerifiedChains[0][0]
	if leaf == nil || !leaf.Equal(request.TLS.PeerCertificates[0]) || leaf.IsCA || len(leaf.Raw) == 0 ||
		len(leaf.URIs) != 1 || leaf.URIs[0] == nil || len(leaf.DNSNames) != 0 ||
		len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasClientAuth(leaf.ExtKeyUsage) {
		return uuid.Nil, "", [sha256.Size]byte{}, false
	}
	for _, chain := range request.TLS.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil || !chain[0].Equal(leaf) {
			return uuid.Nil, "", [sha256.Size]byte{}, false
		}
	}
	uriSAN := leaf.URIs[0].String()
	if !strings.HasPrefix(uriSAN, nodeidentity.NodeSPIFFEPrefix) {
		return uuid.Nil, "", [sha256.Size]byte{}, false
	}
	rawNodeID := strings.TrimPrefix(uriSAN, nodeidentity.NodeSPIFFEPrefix)
	nodeID, err := uuid.Parse(rawNodeID)
	if err != nil || nodeID == uuid.Nil || nodeID.String() != rawNodeID ||
		uriSAN != nodeidentity.NodeSPIFFEPrefix+nodeID.String() {
		return uuid.Nil, "", [sha256.Size]byte{}, false
	}
	return nodeID, uriSAN, sha256.Sum256(leaf.Raw), true
}

func strictBearer(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || strings.Contains(values[0], ",") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	return token, token != "" && len(token) < 8192 && !strings.ContainsFunc(token, unicode.IsSpace)
}

func hasIdentityHeaders(request *http.Request) bool {
	for _, name := range []string{
		"X-Actor-ID", "X-Actor-Scope", "X-User-ID", "X-Scope-ID", "X-Scope-Kind",
		"X-Tenant-ID", "X-Role", "X-Roles", "X-Permission", "X-Permissions",
	} {
		if len(request.Header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func hasClientAuth(values []x509.ExtKeyUsage) bool {
	for _, value := range values {
		if value == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

var (
	_ SessionAuthenticator  = (*productionSessionAuthenticator)(nil)
	_ WorkloadAuthenticator = (*productionWorkloadAuthenticator)(nil)
)
