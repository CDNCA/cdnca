package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

const (
	siteRuntimeV2Schema = "cdnca.edge.site-runtime/v2"

	maxSiteRuntimeV2DocumentBytes = edgeconfig.MaxSiteRuntimeDocumentBytes
	maxSiteRuntimeV2SafeInteger   = int64(1<<53 - 1)
	// maxSiteRuntimeV2Sites is the per-scope site bound of site object
	// delivery (siteobject.MaxSites); in practice the canonical document
	// bound (maxSiteRuntimeV2DocumentBytes) is reached first.
	maxSiteRuntimeV2Sites = siteobject.MaxSites
)

const (
	// SiteRuntimeV2Schema names the only site runtime (1.0.35):
	// PublishRequest.SiteRuntimeSchema and the security activation's
	// StartInput.SiteRuntimeSchema accept it or empty.
	SiteRuntimeV2Schema = siteRuntimeV2Schema
	// DefaultSiteRuntimeSchema is what every release uses when the caller
	// does not choose (since 1.0.35, the compatibility baseline): manual,
	// automatic, challenge, error page, system configuration and system
	// republications, sold-package sync and security activations. A target
	// node without the site runtime the document needs is refused by name.
	DefaultSiteRuntimeSchema = siteRuntimeV2Schema
)

// ResolveSiteRuntimeSchema is schema, or DefaultSiteRuntimeSchema when the
// caller did not choose. Other values are returned unchanged for the
// caller's validation to refuse.
func ResolveSiteRuntimeSchema(schema string) string {
	if schema == "" {
		return DefaultSiteRuntimeSchema
	}
	return schema
}

var (
	siteRuntimeV2IdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	siteRuntimeV2DomainPattern     = regexp.MustCompile(`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	siteRuntimeV2TrustPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	siteRuntimeV2SHA256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type siteRuntimeV2Document struct {
	Streams              *edgeconfig.StreamRuntime `json:"streams,omitempty"`
	Schema               string                    `json:"schema"`
	ConfigurationScopeID string                    `json:"configuration_scope_id"`
	SourceRevision       int64                     `json:"source_revision"`
	ConfigVersionID      string                    `json:"config_version_id"`
	Sites                []siteRuntimeV2Site       `json:"sites"`
	RequiredCapabilities []siteRuntimeV2Capability `json:"required_capabilities"`

	// System is the platform system configuration's nginx base (gap 6):
	// the activation's revision, else the active one; absent before any.
	System *edgeconfig.SiteRuntimeSystem `json:"system,omitempty"`

	// LazyCertificates (site runtime v7) is set by finishSiteRuntimeV2 only
	// when every target node declares v7 (site_runtime_lazy_certificates.go).
	LazyCertificates *edgeconfig.SiteRuntimeLazyCertificates `json:"lazy_certificates,omitempty"`
}

type siteRuntimeV2Capability struct {
	Name       string `json:"name"`
	APIVersion uint32 `json:"api_version"`
}

type siteRuntimeV2Site struct {
	PackageLimits *edgeconfig.PackageConnectionLimit `json:"package_limits,omitempty"`
	// TrafficLimit: the site is over its own traffic cap (ge-analytics,
	// site_traffic_limits); absent otherwise.
	TrafficLimit *edgeconfig.SiteTrafficLimit `json:"traffic_limit,omitempty"`
	// PackageExpired (errpage-3): the site's package ended; published so the
	// node answers the package_expired page without reaching the origin.
	PackageExpired bool                                `json:"package_expired,omitempty"`
	ID             string                              `json:"id"`
	Revision       int64                               `json:"revision"`
	Domains        []string                            `json:"domains"`
	Listeners      []siteRuntimeV2Listener             `json:"listeners"`
	OriginPools    []siteRuntimeV2OriginPool           `json:"origin_pools"`
	DefaultPoolID  string                              `json:"default_pool_id"`
	WebSocket      *bool                               `json:"websocket"`
	Range          *bool                               `json:"range"`
	L2             siteRuntimeV2L2Policy               `json:"l2"`
	HTTPPolicy     *siteRuntimeV2HTTPPolicyBinding     `json:"http_policy,omitempty"`
	FirewallAction *siteRuntimeV2FirewallActionBinding `json:"firewall_action,omitempty"`
	// ForceHTTPS redirects plain listeners to an HTTPS port (site runtime v5).
	ForceHTTPS *siteRuntimeV2ForceHTTPS `json:"force_https,omitempty"`
	// Cache is the site's cache policy (site runtime v6, site_runtime_cache.go).
	Cache *edgeconfig.SiteRuntimeCache `json:"cache,omitempty"`
	// Access is the site's request handling (site runtime v5).
	Access *edgeconfig.SiteAccess `json:"access,omitempty"`
	// Forwarding is how requests reach the origin (site_runtime_origin.go):
	// trusted proxies of the client address headers, the WebSocket Origin
	// allowlist, the TLS listeners' pool. Absent: the defaults.
	Forwarding *siteRuntimeV2Forwarding `json:"forwarding,omitempty"`
	// Schedule302 is the site's HTTP 302 scheduling (sched302 v1,
	// site_schedule302.go).
	Schedule302 *sched302.Site `json:"schedule302,omitempty"`
}

type siteRuntimeV2ForceHTTPS struct {
	RedirectPort int64 `json:"redirect_port"`
	// Status (301 omitted) and ExcludeHosts (none omitted).
	Status       int64    `json:"status,omitempty"`
	ExcludeHosts []string `json:"exclude_hosts,omitempty"`
}

type siteRuntimeV2Listener struct {
	Security      *edgeconfig.ListenerSecurity `json:"security,omitempty"`
	ID            string                       `json:"id"`
	Position      int64                        `json:"position"`
	AddressFamily string                       `json:"address_family"`
	Port          int64                        `json:"port"`
	Protocols     []string                     `json:"protocols"`
	TLS           *siteRuntimeV2ListenerTLS    `json:"tls,omitempty"`
}

type siteRuntimeV2ListenerTLS struct {
	CertificateVersionID string   `json:"certificate_version_id"`
	Protocols            []string `json:"protocols"`
	// TLS profile (edgeconfig.TLSProfile); absent fields are
	// the baseline. The client CA bundle travels as client-ca/<sha>.pem.
	CipherPreset string `json:"cipher_preset,omitempty"`
	// CipherSuites: the custom preset's whitelisted
	// TLS 1.2 list (SITE_TLS_CUSTOM_CIPHERS).
	CipherSuites []string `json:"cipher_suites,omitempty"`
	OCSPStapling bool     `json:"ocsp_stapling,omitempty"`
	ClientAuth   string   `json:"client_auth,omitempty"`
	ClientCARef  string   `json:"client_ca_ref,omitempty"`
	// PreferServerCiphers: absent follows the preset; only
	// a value that differs is written (SITE_TLS_OPTIONS).
	PreferServerCiphers *bool `json:"prefer_server_ciphers,omitempty"`
}

func (value siteRuntimeV2ListenerTLS) profile() edgeconfig.TLSProfile {
	return edgeconfig.TLSProfile{Protocols: value.Protocols, CipherPreset: value.CipherPreset, CipherSuites: value.CipherSuites,
		OCSPStapling: value.OCSPStapling, ClientAuth: value.ClientAuth, ClientCARef: value.ClientCARef,
		PreferServerCiphers: value.PreferServerCiphers}
}

// siteFactHTTPSProtocols: the site's HTTP/2 and HTTP/3 switches (migration
// 512); QUIC is TLS 1.3 only.
func siteFactHTTPSProtocols(fact siteFact, profile edgeconfig.TLSProfile) []string {
	protocols := []string{"http1"}
	if !fact.http2Off {
		protocols = append(protocols, "http2")
	}
	if !fact.http3Off && slices.Contains(profile.Protocols, "TLSv1.3") {
		protocols = append(protocols, "http3")
	}
	return protocols
}

// usesTLSCustomCiphers: the listener needs SITE_TLS_CUSTOM_CIPHERS (the
// custom cipher preset).
func (listener siteRuntimeV2Listener) usesTLSCustomCiphers() bool {
	return listener.TLS != nil && listener.TLS.CipherPreset == edgeconfig.TLSCipherCustom
}

// usesTLSOptions: the listener needs SITE_TLS_OPTIONS (HTTP/2 off on a TLS
// listener, native patch 27, or an explicit prefer_server_ciphers).
func (listener siteRuntimeV2Listener) usesTLSOptions() bool {
	return listener.TLS != nil && (!slices.Contains(listener.Protocols, "http2") || listener.TLS.PreferServerCiphers != nil)
}

type siteRuntimeV2OriginPool struct {
	ID        string                   `json:"id"`
	Position  int64                    `json:"position"`
	Kind      string                   `json:"kind"`
	Algorithm string                   `json:"algorithm"`
	Origins   []siteRuntimeV2Origin    `json:"origins"`
	Retry     siteRuntimeV2RetryPolicy `json:"retry"`
	// KeepaliveIdleTimeoutMS overrides the node's origin connection reuse
	// (site runtime v5): 0 is off; absent keeps nginx's default.
	KeepaliveIdleTimeoutMS *int64 `json:"keepalive_idle_timeout_ms,omitempty"`
	// HashKey (algorithm hash) and Sticky (algorithm sticky) select the
	// origin; RequestHost is the origin Host header (absent: the visitor's
	// $host; visitor_port: with the visited port, migration 490); FollowPort
	// sends to the listener's public port.
	HashKey     *string                   `json:"hash_key,omitempty"`
	Sticky      *siteRuntimeV2Sticky      `json:"sticky,omitempty"`
	RequestHost *siteRuntimeV2RequestHost `json:"request_host,omitempty"`
	FollowPort  *bool                     `json:"follow_port,omitempty"`
	// ActiveLevel is the lowest origin level the edge may use (origin
	// failover moved the pool down, or manual failback holds it); absent is 0.
	ActiveLevel *int64 `json:"active_level,omitempty"`
}

type siteRuntimeV2Origin struct {
	ID       string  `json:"id"`
	Position int64   `json:"position"`
	Tier     string  `json:"tier"`
	Scheme   string  `json:"scheme"`
	Host     string  `json:"host"`
	Port     int64   `json:"port"`
	Weight   int64   `json:"weight"`
	NodeID   *string `json:"node_id,omitempty"`
	// SNI of an HTTPS origin; absent sends the origin request Host.
	SNI *string `json:"sni,omitempty"`
	// TrustRef of an HTTPS origin: "system" (the node's CA store) or
	// sha256:<hex> of a signed origin-trust/<hex>.pem bundle.
	TrustRef *string `json:"trust_ref,omitempty"`
	// Level orders the origins (0 primary, 1 backup 1, ...); absent is 0.
	Level    *int64 `json:"level,omitempty"`
	MaxConns *int64 `json:"max_conns,omitempty"`
}

type siteRuntimeV2RetryPolicy struct {
	Methods            []string `json:"methods"`
	BodylessOnly       *bool    `json:"bodyless_only"`
	ResponseNotStarted *bool    `json:"response_not_started"`
	RetryOn            []string `json:"retry_on"`
	MaxAttempts        int64    `json:"max_attempts"`
	ConnectTimeoutMS   int64    `json:"connect_timeout_ms"`
	ReadTimeoutMS      int64    `json:"read_timeout_ms"`
	TotalBudgetMS      int64    `json:"total_budget_ms"`
}

type siteRuntimeV2L2Policy struct {
	Enabled              *bool   `json:"enabled"`
	DirectFallbackPoolID *string `json:"direct_fallback_pool_id,omitempty"`
	ProbeIntervalMS      int64   `json:"probe_interval_ms"`
	FailureThreshold     int64   `json:"failure_threshold"`
	RecoveryThreshold    int64   `json:"recovery_threshold"`
	SingleHalfOpenProbe  *bool   `json:"single_half_open_probe"`
	MaxHops              int64   `json:"max_hops"`
	// A19-b (L2_ROUTING): the L2 configuration's cache mode and its L2
	// conditions (edgesite.L2 CacheOnly / Conditions)
	CacheOnly  bool                       `json:"cache_only,omitempty"`
	Conditions []siteRuntimeV2L2Condition `json:"conditions,omitempty"`
	// Passthrough (L2_ROUTING v2): edgesite.L2 Passthrough
	Passthrough bool `json:"passthrough,omitempty"`
}

type siteRuntimeV2L2Condition struct {
	ID          string            `json:"id"`
	Rules       []edgesite.L2Rule `json:"rules,omitempty"`
	NodeIDs     []string          `json:"node_ids,omitempty"`
	EndpointIDs []string          `json:"endpoint_ids"`
}

// usesL2Routing: the site needs L2_ROUTING.
func (policy siteRuntimeV2L2Policy) usesL2Routing() bool {
	return policy.CacheOnly || len(policy.Conditions) != 0 || policy.Passthrough
}

func compileSiteRuntimeV2Document(raw []byte) ([]byte, [sha256.Size]byte, []*agentv1.Capability, bool, error) {
	if len(raw) == 0 || len(raw) > maxSiteRuntimeV2DocumentBytes || !utf8.Valid(raw) {
		return nil, [sha256.Size]byte{}, nil, false, ErrInvalidInput
	}
	value, err := parseSiteRuntimeV2JSON(raw)
	if err != nil {
		return nil, [sha256.Size]byte{}, nil, false, ErrInvalidInput
	}
	if rejectSiteRuntimeV2ExplicitNulls(value) {
		return nil, [sha256.Size]byte{}, nil, false, ErrInvalidInput
	}
	var canonical bytes.Buffer
	if err := writeSiteRuntimeV2CanonicalJSON(&canonical, value); err != nil {
		return nil, [sha256.Size]byte{}, nil, false, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical.Bytes()))
	decoder.DisallowUnknownFields()
	var document siteRuntimeV2Document
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, [sha256.Size]byte{}, nil, false, ErrInvalidInput
	}
	capabilities, requiresTLS, err := validateSiteRuntimeV2Document(document)
	if err != nil {
		return nil, [sha256.Size]byte{}, nil, false, err
	}
	canonicalBytes := bytes.Clone(canonical.Bytes())
	return canonicalBytes, sha256.Sum256(canonicalBytes), capabilities, requiresTLS, nil
}

func siteRuntimeV2ArtifactIdentity(configVersionID uuid.UUID, canonical []byte) (uuid.UUID, [sha256.Size]byte, error) {
	if configVersionID == uuid.Nil || len(canonical) == 0 || len(canonical) > maxSiteRuntimeV2DocumentBytes {
		return uuid.Nil, [sha256.Size]byte{}, ErrInvalidInput
	}
	return uuid.NewSHA1(configVersionID, []byte("site-runtime-v2")), sha256.Sum256(canonical), nil
}

func validateSiteRuntimeV2TargetCapabilities(
	required []*agentv1.Capability,
	requiresTLS bool,
	advertised map[uuid.UUID][]*agentv1.Capability,
	advertisedTLS map[uuid.UUID]bool,
) error {
	if len(required) == 0 || len(advertised) == 0 {
		return ErrTargetIneligible
	}
	wanted := make(map[agentv1.CapabilityName]uint32, len(required))
	for _, capability := range required {
		if capability == nil || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED ||
			capability.ApiVersion == 0 {
			return ErrInvalidInput
		}
		if _, duplicate := wanted[capability.Name]; duplicate {
			return ErrInvalidInput
		}
		wanted[capability.Name] = capability.ApiVersion
	}
	for nodeID, capabilities := range advertised {
		if nodeID == uuid.Nil || len(capabilities) == 0 || requiresTLS && !advertisedTLS[nodeID] {
			return ErrTargetIneligible
		}
		have := make(map[agentv1.CapabilityName]uint32, len(capabilities))
		for _, capability := range capabilities {
			if capability == nil || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED ||
				capability.ApiVersion == 0 {
				return ErrTargetIneligible
			}
			if _, duplicate := have[capability.Name]; duplicate {
				return ErrTargetIneligible
			}
			have[capability.Name] = capability.ApiVersion
		}
		for name, version := range wanted {
			if have[name] < version {
				return ErrTargetIneligible
			}
		}
	}
	return nil
}

func (s *Service) compileSiteRuntimeV2Facts(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, configID uuid.UUID,
	sourceRevision int64,
	target TargetSnapshot,
	now time.Time,
	systemSource *SystemConfigurationSource,
) ([]byte, [sha256.Size]byte, edgeconfig.Bundle, [sha256.Size]byte, []*agentv1.Capability, map[uuid.UUID]uuid.UUID, error) {
	return s.compileSiteRuntimeV2FactsCapture(ctx, tx, scopeID, configID, sourceRevision, target, now, systemSource, nil)
}

// compileSiteRuntimeV2FactsCapture compiles the scope's rows; capture, when
// set, receives the publication's compiled source (stop overlay base).
func (s *Service) compileSiteRuntimeV2FactsCapture(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, configID uuid.UUID,
	sourceRevision int64,
	target TargetSnapshot,
	now time.Time,
	systemSource *SystemConfigurationSource,
	capture *siteRuntimeV2Inputs,
) ([]byte, [sha256.Size]byte, edgeconfig.Bundle, [sha256.Size]byte, []*agentv1.Capability, map[uuid.UUID]uuid.UUID, error) {
	return s.compileSiteRuntimeV2FactsWith(ctx, tx, scopeID, configID, sourceRevision, target, now, systemSource, capture, nil)
}

// compileSiteRuntimeV2FactsWith compiles the scope's rows. security, when set,
// is a security activation candidate's binding (security_candidate.go): it
// replaces the site's active binding of its kind, the scope stays locked at
// the active revision sourceRevision-1, and site status recovery is not
// applied (as the v1 candidate).
func (s *Service) compileSiteRuntimeV2FactsWith(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, configID uuid.UUID,
	sourceRevision int64,
	target TargetSnapshot,
	now time.Time,
	systemSource *SystemConfigurationSource,
	capture *siteRuntimeV2Inputs,
	security *securityBindingFact,
) ([]byte, [sha256.Size]byte, edgeconfig.Bundle, [sha256.Size]byte, []*agentv1.Capability, map[uuid.UUID]uuid.UUID, error) {
	nodeIDs := target.NodeIDs
	lockedRevision := sourceRevision
	recoverySiteIDs := []uuid.UUID{}
	if security != nil {
		lockedRevision = sourceRevision - 1
	} else {
		recoveryCandidates, err := loadSiteStatusRecoveryCandidates(ctx, tx, scopeID, sourceRevision)
		if err != nil {
			return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
		}
		recoverySiteIDs = siteStatusRecoveryCandidateIDs(recoveryCandidates)
	}
	sites, err := loadSiteFacts(ctx, tx, scopeID, recoverySiteIDs)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	streams, err := loadStreamFacts(ctx, tx, scopeID)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	// No sites is valid, as in v1 (edgeconfig.Spec.AllowEmpty): without streams
	// it is the health-only withdrawal; with streams an L4-only scope.
	l4V2Protocols, err := loadL4V2LifecycleProtocols(ctx, tx, scopeID, sourceRevision)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	if target.Topology == nil {
		// a node-list publication (automatic, system, explicit nodes): each
		// site's L2 from its line group (fix-autol2b, L2_ROUTING v2)
		var skipped []siteL2PublicationSkip
		if target.Topology, skipped, err = siteL2PublicationTopology(ctx, tx, scopeID, sourceRevision, sites,
			nodeIDs, now); err != nil {
			return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
		}
		if capture != nil {
			capture.L2Skipped = skipped
		}
	}
	document, requiresTLS, err := compileSiteRuntimeV2Source(ctx, tx, scopeID, configID, sourceRevision, sites, target.Topology, now)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	// The scope's published error pages carry slot node pages (errpage-3):
	// the site objects deliver them as node pages, which need the capability.
	if slots, err := scopeErrorPagesNeedSlots(ctx, tx, scopeID); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	} else if slots {
		requireSiteRuntimeV2Capability(&document, siteobject.ErrorPageSlotsCapability, siteobject.ErrorPageSlotsAPIVersion)
	}
	httpPolicyRevision, httpPolicyFacts, err := loadHTTPPolicyFactsAt(ctx, tx, scopeID, lockedRevision, sourceRevision, document.Sites)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	httpPolicyArtifact, _, err := compileHTTPPolicyArtifact(scopeID, sourceRevision, httpPolicyRevision, &document, httpPolicyFacts)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	firewallActions, err := loadFirewallActionFacts(ctx, tx, scopeID, document.Sites)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	firewallActionArtifacts, err := compileFirewallActionArtifacts(scopeID, &document, firewallActions)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1 AND kind=$2`, scopeID, ScopeKindTenant).Scan(&tenantID); err != nil || tenantID == uuid.Nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, fmt.Errorf("%w: load tenant scope", ErrPersistence)
	}
	bindSiteRuntimeV2Streams(&document, tenantID, streams, l4V2Protocols)
	// The node renders its health server on HealthPort: an L4 listener there
	// would fail the node's reload, so refuse it before the rollout.
	if _, _, err := siteRuntimeStreamFragment(document, s.config.HealthPort); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, ErrInvalidInput
	}
	if document.System, err = loadSiteRuntimeV2System(ctx, tx, systemSource, nodeIDs); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	installationID, err := loadTelemetryInstallationID(ctx, tx)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	packageSubscriptions, err := loadPackageSubscriptionFacts(ctx, tx, scopeID, recoverySiteIDs)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	soldLimits, err := loadSoldPackageLimits(ctx, tx, scopeID)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	applySoldPackageRuntimeV2Limits(&document, soldLimits)
	if err := applySiteTrafficLimits(ctx, tx, scopeID, &document); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	if err := markSiteRuntimeV2PackageExpiry(ctx, tx, scopeID, &document, recoverySiteIDs, now); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	challengeBindings, err := loadChallengeBindingFacts(ctx, tx, scopeID, recoverySiteIDs)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	for index := range sites {
		sites[index].challenge = challengeBindings[sites[index].id]
	}
	if err := bindSoldPackageRuntimeSecurity(ctx, tx, scopeID, tenantID, sites, soldLimits, &document, security); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	capturePolicies, err := loadSiteCapturePolicyFacts(ctx, tx, scopeID)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	accessLogFields, err := loadAccessLogFields(ctx, tx, systemSource)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	// A scope without sites has no website telemetry (v1 writes no manifest either).
	var telemetryManifest [][]byte
	if len(document.Sites) != 0 {
		manifest, err := buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, installationID, configID, sourceRevision,
			document, packageSubscriptions, capturePolicies, accessLogFields, s.config.StateRoot)
		if err != nil {
			return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
		}
		telemetryManifest = [][]byte{manifest}
	}
	originRouteFacts, err := loadSiteOriginRouteFacts(ctx, tx, scopeID, document.Sites, target.Topology)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	cachePolicies, err := loadCachePolicyFacts(ctx, tx, scopeID, lockedRevision)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	if err := bindSiteRuntimeV2Cache(&document, tenantID, sites, cachePolicies); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	if err := bindSiteRuntimeV2Schedule302(ctx, tx, scopeID, &document); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	var originRouteBundle []byte
	if len(originRouteFacts) != 0 {
		originRouteBundle, err = compileSiteOriginRouteBundleWithTopology(scopeID, configID, sourceRevision, originRouteFacts, target.Topology)
		if err != nil {
			return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
		}
	}
	if capture != nil {
		*capture = captureSiteRuntimeV2Inputs(document, httpPolicyRevision, httpPolicyFacts, firewallActions,
			capturePolicies, originRouteFacts, packageSubscriptions, target.Topology)
	}
	return finishSiteRuntimeV2(ctx, tx, scopeID, nodeIDs, now, document, &requiresTLS, originRouteBundle,
		httpPolicyArtifact, firewallActionArtifacts, telemetryManifest, packageSubscriptions, s.config.LazyCertificateCacheMax)
}

// finishSiteRuntimeV2 canonicalizes a compiled document, checks it against
// the target nodes' capabilities and builds the plaintext bundle (split into
// site objects by the caller, buildSiteObjectRelease) and its manifest
// digest. The capabilities returned are the release's: the document's with
// site_runtime 9. requiresTLS, when set, must match the document.
func finishSiteRuntimeV2(
	ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, nodeIDs []uuid.UUID, now time.Time,
	document siteRuntimeV2Document, requiresTLS *bool, originRouteBundle, httpPolicyArtifact []byte,
	firewallActionArtifacts map[string][]byte, telemetryManifest [][]byte, packageSubscriptions map[uuid.UUID]uuid.UUID,
	lazyCacheMax int64,
) ([]byte, [sha256.Size]byte, edgeconfig.Bundle, [sha256.Size]byte, []*agentv1.Capability, map[uuid.UUID]uuid.UUID, error) {
	advertised, err := loadSiteRuntimeV2TargetCapabilities(ctx, tx, scopeID, nodeIDs, now)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	if err := applySiteRuntimeV2LazyCertificates(&document, lazyCacheMax); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, ErrInvalidInput
	}
	canonical, canonicalDigest, capabilities, compiledRequiresTLS, err := compileSiteRuntimeV2Document(raw)
	if err != nil || requiresTLS != nil && compiledRequiresTLS != *requiresTLS {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, ErrInvalidInput
	}
	advertisedTLS := make(map[uuid.UUID]bool, len(nodeIDs))
	if compiledRequiresTLS {
		for _, nodeID := range nodeIDs {
			advertisedTLS[nodeID] = true
		}
	}
	// Every v2 release is delivered as dynamic routing site objects (a v2
	// root): the target nodes must run site_runtime 9.
	if capabilities, err = dynamicRoutingDeliveryCapabilities(capabilities); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	if err := validateSiteRuntimeV2TargetCapabilities(capabilities, compiledRequiresTLS, advertised, advertisedTLS); err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, readableTargetCapabilityError(ctx, tx, nodeIDs, capabilities, advertised, err)
	}
	crsFiles, err := loadSiteRuntimeV2CRSFiles(ctx, tx, canonical)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	trustFiles, err := loadSiteRuntimeV2TrustFiles(ctx, tx, document)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	clientCAs, err := loadSiteRuntimeV2ClientCAFiles(ctx, tx, scopeID, document)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	for path, content := range clientCAs {
		if trustFiles == nil {
			trustFiles = map[string][]byte{}
		}
		trustFiles[path] = content
	}
	bundle, err := buildSiteRuntimeV2Bundle(
		canonical, trustFiles, originRouteBundle, httpPolicyArtifact, firewallActionArtifacts, crsFiles, telemetryManifest...,
	)
	if err != nil {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, err
	}
	manifestDigest, err := hex.DecodeString(bundle.ManifestSHA256)
	if err != nil || len(manifestDigest) != sha256.Size {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, ErrInvalidInput
	}
	// Each site's package subscription, as the telemetry manifest states it.
	siteSubscriptions := make(map[uuid.UUID]uuid.UUID, len(document.Sites))
	for _, site := range document.Sites {
		siteID := uuid.MustParse(site.ID)
		siteSubscriptions[siteID] = packageSubscriptions[siteID]
	}
	return canonical, canonicalDigest, bundle, [sha256.Size]byte(manifestDigest), capabilities, siteSubscriptions, nil
}

func compileSiteRuntimeV2Source(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, configID uuid.UUID,
	sourceRevision int64,
	facts []siteFact,
	topology *L2TopologySnapshot,
	now time.Time,
) (siteRuntimeV2Document, bool, error) {
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: scopeID.String(), SourceRevision: sourceRevision,
		ConfigVersionID: configID.String(), Sites: make([]siteRuntimeV2Site, 0, len(facts)),
	}
	// Every document needs the 1.0.35 baseline; only lazy certificates go above it.
	required := map[string]uint32{"http1": 1, "ipv4": 1, "site_runtime": edgeconfig.MinSiteRuntimeVersion, "websocket": 1}
	requiresTLS := false
	// One batched read of every HTTPS site's certificate binding.
	var httpsSites []uuid.UUID
	for _, fact := range facts {
		if fact.httpsEnabled {
			httpsSites = append(httpsSites, fact.id)
		}
	}
	tlsBindings, err := loadSiteRuntimeV2TLSBindings(ctx, tx, scopeID, httpsSites)
	if err != nil {
		return siteRuntimeV2Document{}, false, err
	}
	for _, fact := range facts {
		site, siteRequiresTLS, err := compileSiteRuntimeV2SiteFactWith(ctx, tx, scopeID, fact, topology, now, tlsBindings)
		if err != nil {
			return siteRuntimeV2Document{}, false, err
		}
		document.Sites = append(document.Sites, site)
		for name, version := range siteAccessCapabilities(site.Access) {
			required[name] = max(required[name], version)
		}
		if site.Forwarding != nil && site.Forwarding.FollowRedirect != nil {
			required[edgeconfig.OriginFollowRedirectCapability] = edgeconfig.OriginFollowRedirectAPIVersion
		}
		if siteRuntimeV2UsesOriginTLSNoVerify(site) {
			required[edgeconfig.OriginTLSNoVerifyCapability] = edgeconfig.OriginTLSNoVerifyAPIVersion
		}
		if site.Forwarding.usesEdgeOptions() {
			required[edgeconfig.SiteEdgeOptionsCapability] = edgeconfig.SiteEdgeOptionsAPIVersion
		}
		if site.L2.usesL2Routing() {
			required[edgeconfig.L2RoutingCapability] = edgeconfig.L2RoutingAPIVersion
		}
		if slices.ContainsFunc(site.Listeners, siteRuntimeV2Listener.usesTLSOptions) {
			required[edgeconfig.SiteTLSOptionsCapability] = edgeconfig.SiteTLSOptionsAPIVersion
		}
		if slices.ContainsFunc(site.Listeners, siteRuntimeV2Listener.usesTLSCustomCiphers) {
			required[edgeconfig.SiteTLSCustomCiphersCapability] = edgeconfig.SiteTLSCustomCiphersAPIVersion
		}
		if siteFactIPv6Enabled(fact) {
			required["ipv6"] = 1
		}
		if site.PackageExpired {
			required[siteobject.ErrorPageSlotsCapability] = siteobject.ErrorPageSlotsAPIVersion
		}
		if siteRequiresTLS {
			addSiteRuntimeV2ProtocolCapabilities(required, site)
			requiresTLS = true
		}
	}
	names := make([]string, 0, len(required))
	for name := range required {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		document.RequiredCapabilities = append(document.RequiredCapabilities,
			siteRuntimeV2Capability{Name: name, APIVersion: required[name]})
	}
	return document, requiresTLS, nil
}

// addSiteRuntimeV2ProtocolCapabilities: an HTTPS site needs http2 (it
// follows TLS); http3 (SITE_QUIC) only when a listener serves HTTP/3, so a
// site with HTTP/3 off or downgraded publishes to nodes without QUIC (the
// node renders "listen ... quic" only for ports with an http3 listener).
func addSiteRuntimeV2ProtocolCapabilities(required map[string]uint32, site siteRuntimeV2Site) {
	required["http2"] = 1
	for _, listener := range site.Listeners {
		if slices.Contains(listener.Protocols, "http3") {
			required["http3"] = 1
		}
	}
}

func compileSiteRuntimeV2SiteFact(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	fact siteFact,
	now time.Time,
) (siteRuntimeV2Site, bool, error) {
	return compileSiteRuntimeV2SiteFactWithTopology(ctx, tx, scopeID, fact, nil, now)
}

func compileSiteRuntimeV2SiteFactWithTopology(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	fact siteFact,
	topology *L2TopologySnapshot,
	now time.Time,
) (siteRuntimeV2Site, bool, error) {
	return compileSiteRuntimeV2SiteFactWith(ctx, tx, scopeID, fact, topology, now, nil)
}

// compileSiteRuntimeV2SiteFactWith compiles one site; tlsBindings, when set,
// holds the prefetched certificate bindings (loadSiteRuntimeV2TLSBindings),
// otherwise the site's binding is read alone.
func compileSiteRuntimeV2SiteFactWith(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	fact siteFact,
	topology *L2TopologySnapshot,
	now time.Time,
	tlsBindings map[uuid.UUID]*siteRuntimeV2TLSBindingRow,
) (siteRuntimeV2Site, bool, error) {
	domains := siteRuntimeV2Domains(fact)
	httpPorts, err := parseSiteRuntimeV2Ports(fact.httpPorts)
	if err != nil {
		return siteRuntimeV2Site{}, false, err
	}
	httpsPorts, err := parseSiteRuntimeV2Ports(fact.httpsPorts)
	if err != nil || fact.httpsEnabled != (len(httpsPorts) != 0) || len(httpPorts)+len(httpsPorts) == 0 ||
		fact.failoverTries < 1 || fact.failoverTries >= 8 {
		return siteRuntimeV2Site{}, false, ErrInvalidInput
	}
	trueValue, falseValue := true, false
	addressFamily := "ipv4"
	if siteFactIPv6Enabled(fact) {
		addressFamily = "dual_stack"
	}
	site := siteRuntimeV2Site{
		ID: fact.id.String(), Revision: fact.revision, Domains: append([]string(nil), domains...),
		DefaultPoolID: "primary", WebSocket: &trueValue, Range: &trueValue,
		L2: siteRuntimeV2L2Policy{
			Enabled: &falseValue, ProbeIntervalMS: 10000, FailureThreshold: 3,
			RecoveryThreshold: 3, SingleHalfOpenProbe: &trueValue, MaxHops: 1,
		},
	}
	position := int64(0)
	for _, port := range httpPorts {
		site.Listeners = append(site.Listeners, siteRuntimeV2Listener{
			ID: "public-" + strconv.Itoa(port), Position: position, AddressFamily: addressFamily,
			Port: int64(port), Protocols: []string{"http1"},
		})
		position++
	}
	var certificateVersionID uuid.UUID
	if len(httpsPorts) != 0 {
		if tlsBindings != nil {
			certificateVersionID, err = tlsBindings[fact.id].versionFor(domains, now)
		} else {
			certificateVersionID, err = loadSiteRuntimeV2TLSBinding(ctx, tx, scopeID, fact.id, domains, now)
		}
		if err != nil {
			return siteRuntimeV2Site{}, false, err
		}
	}
	var tlsProfile edgeconfig.TLSProfile
	if len(httpsPorts) != 0 {
		if tlsProfile, err = siteFactTLSProfile(fact); err != nil {
			return siteRuntimeV2Site{}, false, err
		}
	}
	httpsProtocols := siteFactHTTPSProtocols(fact, tlsProfile)
	for _, port := range httpsPorts {
		site.Listeners = append(site.Listeners, siteRuntimeV2Listener{
			ID: "public-" + strconv.Itoa(port), Position: position, AddressFamily: addressFamily,
			Port: int64(port), Protocols: slices.Clone(httpsProtocols),
			TLS: &siteRuntimeV2ListenerTLS{CertificateVersionID: certificateVersionID.String(),
				Protocols: slices.Clone(tlsProfile.Protocols), CipherPreset: tlsProfile.CipherPreset,
				CipherSuites: slices.Clone(tlsProfile.CipherSuites),
				OCSPStapling: tlsProfile.OCSPStapling, ClientAuth: tlsProfile.ClientAuth, ClientCARef: tlsProfile.ClientCARef,
				PreferServerCiphers: tlsProfile.PreferServerCiphers},
		})
		position++
	}
	retry := siteRuntimeV2RetryPolicy{
		Methods: []string{"GET", "HEAD"}, BodylessOnly: &trueValue, ResponseNotStarted: &trueValue,
		RetryOn:     []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
		MaxAttempts: int64(fact.failoverTries + 1), ConnectTimeoutMS: int64(fact.connectTimeoutMS),
		ReadTimeoutMS: int64(fact.readTimeoutMS), TotalBudgetMS: 60000,
	}
	pool := siteRuntimeV2OriginPool{
		ID: "primary", Position: 0, Kind: "origin", Algorithm: fact.balance, Retry: retry,
		Origins: make([]siteRuntimeV2Origin, len(fact.origins)),
	}
	if fact.keepaliveIdleTimeoutMS != nil {
		idle := int64(*fact.keepaliveIdleTimeoutMS)
		pool.KeepaliveIdleTimeoutMS = &idle
	}
	for index, origin := range fact.origins {
		pool.Origins[index] = siteRuntimeV2Origin{
			ID: "origin-" + strconv.Itoa(index), Position: int64(index), Tier: "origin", Scheme: "http",
			Host: origin.Host, Port: int64(origin.Port), Weight: int64(origin.Weight),
		}
	}
	site.OriginPools = []siteRuntimeV2OriginPool{pool}
	topology, err = siteL2Topology(topology, fact)
	if err != nil {
		return siteRuntimeV2Site{}, false, err
	}
	if topology != nil {
		if topology.Revision < 1 || topology.SourceLineGroupID == uuid.Nil && !topology.Passthrough || topology.SourceRevision < 1 ||
			len(topology.TargetIdentities) == 0 || len(topology.Endpoints) == 0 ||
			topology.ProbeIntervalMS < 1000 || topology.ProbeIntervalMS > 300000 ||
			topology.FailureThreshold < 1 || topology.FailureThreshold > 20 ||
			topology.RecoveryThreshold < 1 || topology.RecoveryThreshold > 20 {
			return siteRuntimeV2Site{}, false, ErrTargetSnapshotConflict
		}
		pool.Position = 1
		// A19: the L2 configuration's load method; endpoints in member sort
		// order with the member weights (siteL2Topology)
		l2Pool := siteRuntimeV2OriginPool{
			ID: "l2-topology", Position: 0, Kind: "l2", Algorithm: l2PoolAlgorithm(topology.Config), Retry: retry,
			Origins: make([]siteRuntimeV2Origin, len(topology.Endpoints)),
		}
		for index, endpoint := range topology.Endpoints {
			if endpoint.EndpointID == uuid.Nil || endpoint.NodeID == uuid.Nil || len(endpoint.Address) == 0 ||
				endpoint.Port < 1 || endpoint.Port > 65535 || endpoint.Weight < 1 || endpoint.Weight > 100 ||
				endpoint.MTLSIdentitySHA256 == ([sha256.Size]byte{}) {
				return siteRuntimeV2Site{}, false, ErrTargetSnapshotConflict
			}
			nodeID := endpoint.NodeID.String()
			l2Pool.Origins[index] = siteRuntimeV2Origin{
				ID: endpoint.EndpointID.String(), Position: int64(index), Tier: "l2", Scheme: "http",
				Host: endpoint.Address, Port: int64(endpoint.Port), Weight: int64(endpoint.Weight), NodeID: &nodeID,
			}
		}
		directPoolID := pool.ID
		site.DefaultPoolID = l2Pool.ID
		site.OriginPools = []siteRuntimeV2OriginPool{l2Pool, pool}
		site.L2 = siteRuntimeV2L2Policy{
			Enabled: &trueValue, DirectFallbackPoolID: &directPoolID,
			ProbeIntervalMS: int64(topology.ProbeIntervalMS), FailureThreshold: int64(topology.FailureThreshold),
			RecoveryThreshold: int64(topology.RecoveryThreshold), SingleHalfOpenProbe: &trueValue, MaxHops: 1,
			// 模式=缓存: only a URL a cache rule caches goes through L2 (A19-b)
			CacheOnly: topology.Config != nil && topology.Config.Mode == "cache",
			// L1 -> L2 on the visitor's protocol and port (L2_ROUTING v2)
			Passthrough: topology.Passthrough,
		}
		for _, condition := range topology.Conditions {
			converted := siteRuntimeV2L2Condition{ID: condition.ID.String(), Rules: slices.Clone(condition.Rules)}
			for _, nodeID := range condition.NodeIDs {
				converted.NodeIDs = append(converted.NodeIDs, nodeID.String())
			}
			for _, endpointID := range condition.EndpointIDs {
				converted.EndpointIDs = append(converted.EndpointIDs, endpointID.String())
			}
			site.L2.Conditions = append(site.L2.Conditions, converted)
		}
	}
	direct := 0
	if topology != nil {
		direct = 1
	}
	if fact.forwarding != nil && len(fact.originExtras) != len(fact.origins) {
		return siteRuntimeV2Site{}, false, ErrInvalidInput
	}
	if err := applySiteRuntimeV2OriginForwarding(&site, direct, fact); err != nil {
		return siteRuntimeV2Site{}, false, err
	}
	forced, err := siteRuntimeV2ForcedHTTPS(fact, httpsPorts)
	if err != nil {
		return siteRuntimeV2Site{}, false, err
	}
	site.ForceHTTPS = forced
	if fact.access != nil {
		access := *fact.access
		site.Access = &access
	}
	return site, len(httpsPorts) != 0, nil
}

// siteRuntimeV2ForcedHTTPS is the site's forced HTTPS redirect; port 0 is its
// lowest HTTPS port (httpsPorts is sorted).
func siteRuntimeV2ForcedHTTPS(fact siteFact, httpsPorts []int) (*siteRuntimeV2ForceHTTPS, error) {
	if !fact.forceHTTPS || len(httpsPorts) == 0 {
		return nil, nil
	}
	port := httpsPorts[0]
	if fact.httpsRedirectPort != 0 {
		port = fact.httpsRedirectPort
	}
	if !slices.Contains(httpsPorts, port) {
		return nil, ErrInvalidInput
	}
	forced := &siteRuntimeV2ForceHTTPS{RedirectPort: int64(port)}
	if fact.httpsRedirectStatus != 0 && fact.httpsRedirectStatus != 301 {
		forced.Status = int64(fact.httpsRedirectStatus)
	}
	// An excluded domain the site no longer serves is dropped, not refused:
	// removing a domain must not stop the site's publication.
	domains := siteRuntimeV2Domains(fact)
	for _, host := range fact.httpsRedirectExclude {
		if slices.Contains(domains, host) {
			forced.ExcludeHosts = append(forced.ExcludeHosts, host)
		}
	}
	slices.Sort(forced.ExcludeHosts)
	if len(forced.ExcludeHosts) == len(domains) {
		return nil, nil
	}
	return forced, nil
}

func parseSiteRuntimeV2Ports(values []string) ([]int, error) {
	result := make([]int, len(values))
	for index, raw := range values {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 65535 {
			return nil, ErrInvalidInput
		}
		result[index] = value
	}
	sort.Ints(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func loadSiteRuntimeV2TargetCapabilities(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	nodeIDs []uuid.UUID,
	now time.Time,
) (map[uuid.UUID][]*agentv1.Capability, error) {
	rows, err := tx.Query(ctx, `SELECT target.node_id
		FROM unnest($2::uuid[]) AS target(node_id)
		JOIN nodes node ON node.id=target.node_id AND node.admin_state='active'
		JOIN access_scopes node_scope ON node_scope.id=node.scope_id
		  AND (node_scope.kind='platform' OR node.scope_id=$1)
		JOIN node_config_state state ON state.node_id=node.id
		  AND state.configuration_scope_id=$1 AND NOT state.reconciliation_required
		ORDER BY target.node_id FOR SHARE OF node,state`, scopeID, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: read target capability facts", ErrPersistence)
	}
	seen := 0
	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil || nodeID == uuid.Nil {
			rows.Close()
			return nil, fmt.Errorf("%w: validate target capability facts", ErrPersistence)
		}
		seen++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, fmt.Errorf("%w: iterate target capability facts", ErrPersistence)
	}
	if seen != len(nodeIDs) {
		return nil, ErrTargetIneligible
	}
	capabilities, err := LoadNodePublicationCapabilities(ctx, tx, nodeIDs, now)
	if err != nil {
		return nil, err
	}
	result := make(map[uuid.UUID][]*agentv1.Capability, len(nodeIDs))
	for nodeID, capability := range capabilities {
		result[nodeID] = cloneSiteRuntimeV2AdvertisedCapabilities(capability.Features)
	}
	// The enrollment snapshot above still proves the node's identity; what
	// it runs now is what its latest session declared.
	return preferSessionCapabilities(ctx, tx, nodeIDs, result)
}

func cloneSiteRuntimeV2AdvertisedCapabilities(values []*agentv1.Capability) []*agentv1.Capability {
	result := make([]*agentv1.Capability, len(values))
	for index, value := range values {
		if value != nil {
			result[index] = proto.Clone(value).(*agentv1.Capability)
		}
	}
	return result
}

func loadSiteRuntimeV2TLSBinding(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, siteID uuid.UUID,
	domains []string,
	now time.Time,
) (uuid.UUID, error) {
	bindings, err := loadSiteRuntimeV2TLSBindings(ctx, tx, scopeID, []uuid.UUID{siteID})
	if err != nil {
		return uuid.Nil, err
	}
	return bindings[siteID].versionFor(domains, now)
}

// siteRuntimeV2TLSBindingRow is one site's default certificate binding with
// its active version and key envelope facts, as one batched read returns it.
type siteRuntimeV2TLSBindingRow struct {
	assetID, versionID, activeVersionID uuid.UUID
	version                             int64
	sans                                []string
	fingerprint, publicKey, aad         []byte
	envelopeFingerprint                 []byte
	envelopePublicKey, envelopeAAD      []byte
	privateKeyReference                 string
	envelopePrivateKeyReference         string
	ciphertext, nonce                   []byte
	keyID                               string
	metadata                            []byte
	notBefore, notAfter                 time.Time
	revoked                             bool
}

// versionFor is the binding's certificate version when it can serve domains
// now; a missing binding (nil) is unavailable material.
func (row *siteRuntimeV2TLSBindingRow) versionFor(domains []string, now time.Time) (uuid.UUID, error) {
	if row == nil || row.assetID == uuid.Nil || row.versionID == uuid.Nil || row.activeVersionID != row.versionID ||
		row.version < 1 || row.revoked ||
		now.Before(row.notBefore) || !now.Before(row.notAfter) || certificateasset.RequireCoverage(row.sans, domains) != nil ||
		len(row.fingerprint) != sha256.Size || len(row.publicKey) != sha256.Size || len(row.aad) != sha256.Size ||
		!bytes.Equal(row.fingerprint, row.envelopeFingerprint) || !bytes.Equal(row.publicKey, row.envelopePublicKey) ||
		row.privateKeyReference != row.envelopePrivateKeyReference || !bytes.Equal(row.aad, row.envelopeAAD) ||
		len(row.ciphertext) < 16 || len(row.ciphertext) > 131072 || len(row.nonce) < 8 || len(row.nonce) > 64 ||
		row.keyID == "" || strings.TrimSpace(row.keyID) != row.keyID || len(row.metadata) == 0 {
		return uuid.Nil, ErrTLSMaterialUnavailable
	}
	return row.versionID, nil
}

// siteRuntimeV2TLSBindingBatch bounds one batched TLS binding read.
const siteRuntimeV2TLSBindingBatch = 1000

// loadSiteRuntimeV2TLSBindings reads the default certificate binding facts
// of siteIDs in batches (one query per siteRuntimeV2TLSBindingBatch sites,
// not one per site). Sites without a usable binding row are absent.
func loadSiteRuntimeV2TLSBindings(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	siteIDs []uuid.UUID,
) (map[uuid.UUID]*siteRuntimeV2TLSBindingRow, error) {
	result := make(map[uuid.UUID]*siteRuntimeV2TLSBindingRow, len(siteIDs))
	for start := 0; start < len(siteIDs); start += siteRuntimeV2TLSBindingBatch {
		batch := siteIDs[start:min(start+siteRuntimeV2TLSBindingBatch, len(siteIDs))]
		rows, err := tx.Query(ctx, `SELECT target.site_id,binding.asset_id,binding.version_id,activation.version_id,
			version.version,version.sans,version.fingerprint_sha256,version.public_key_sha256,version.private_key_reference,
			version.private_key_aad_sha256,version.not_before,version.not_after,
			EXISTS(SELECT 1 FROM certificate_asset_revocation_facts revoked
			  WHERE revoked.tenant_scope_id=$1 AND revoked.asset_id=binding.asset_id
			    AND revoked.version_id=binding.version_id),
			envelope.certificate_fingerprint_sha256,envelope.certificate_public_key_sha256,
			envelope.private_key_reference,envelope.aad_sha256,envelope.private_key_ciphertext,
			envelope.private_key_key_id,envelope.private_key_nonce,envelope.private_key_metadata
		FROM unnest($2::uuid[]) AS target(site_id)
		CROSS JOIN LATERAL (
			SELECT action,asset_id,version_id,is_default FROM certificate_site_binding_facts
			WHERE tenant_scope_id=$1 AND site_id=target.site_id
			ORDER BY sequence DESC LIMIT 1
		) binding
		CROSS JOIN LATERAL (
			SELECT version_id FROM certificate_asset_activation_facts
			WHERE tenant_scope_id=$1 AND asset_id=binding.asset_id
			ORDER BY sequence DESC LIMIT 1
		) activation
		CROSS JOIN LATERAL (
			SELECT certificate_fingerprint_sha256,certificate_public_key_sha256,private_key_reference,
			       aad_sha256,private_key_ciphertext,private_key_key_id,private_key_nonce,private_key_metadata
			FROM certificate_asset_private_key_envelope_facts
			WHERE tenant_scope_id=$1 AND asset_id=binding.asset_id AND version_id=binding.version_id
			ORDER BY sequence DESC LIMIT 1
		) envelope
		JOIN certificate_assets asset ON asset.tenant_scope_id=$1 AND asset.id=binding.asset_id AND asset.deleted_at IS NULL
		JOIN certificate_asset_versions version ON version.tenant_scope_id=$1 AND version.asset_id=binding.asset_id
		 AND version.id=binding.version_id
		WHERE binding.action='bind' AND binding.is_default`, scopeID, batch)
		if err != nil {
			return nil, fmt.Errorf("%w: read TLS bindings", ErrPersistence)
		}
		for rows.Next() {
			var siteID uuid.UUID
			row := new(siteRuntimeV2TLSBindingRow)
			if err := rows.Scan(&siteID, &row.assetID, &row.versionID, &row.activeVersionID, &row.version, &row.sans,
				&row.fingerprint, &row.publicKey, &row.privateKeyReference, &row.aad, &row.notBefore, &row.notAfter,
				&row.revoked, &row.envelopeFingerprint, &row.envelopePublicKey, &row.envelopePrivateKeyReference,
				&row.envelopeAAD, &row.ciphertext, &row.keyID, &row.nonce, &row.metadata); err != nil {
				rows.Close()
				return nil, fmt.Errorf("%w: read TLS binding", ErrPersistence)
			}
			result[siteID] = row
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("%w: read TLS bindings", ErrPersistence)
		}
	}
	return result, nil
}

func marshalSiteRuntimeV2Bundle(canonical []byte, trustFiles map[string][]byte, telemetryManifest ...[]byte) ([]byte, error) {
	return marshalSiteRuntimeV2BundleWithOriginRoutes(canonical, trustFiles, nil, telemetryManifest...)
}

func marshalSiteRuntimeV2BundleWithOriginRoutes(
	canonical []byte,
	trustFiles map[string][]byte,
	originRoutes []byte,
	telemetryManifest ...[]byte,
) ([]byte, error) {
	return marshalSiteRuntimeV2BundleWithHTTPPolicy(canonical, trustFiles, originRoutes, nil, telemetryManifest...)
}

func marshalSiteRuntimeV2BundleWithHTTPPolicy(
	canonical []byte,
	trustFiles map[string][]byte,
	originRoutes []byte,
	httpPolicy []byte,
	telemetryManifest ...[]byte,
) ([]byte, error) {
	return marshalSiteRuntimeV2BundleWithPolicies(canonical, trustFiles, originRoutes, httpPolicy, nil, telemetryManifest...)
}

func marshalSiteRuntimeV2BundleWithPolicies(
	canonical []byte,
	trustFiles map[string][]byte,
	originRoutes []byte,
	httpPolicy []byte,
	firewallActions map[string][]byte,
	telemetryManifest ...[]byte,
) ([]byte, error) {
	return marshalSiteRuntimeV2BundleWithSecurity(canonical, trustFiles, originRoutes, httpPolicy, firewallActions, nil, telemetryManifest...)
}

// marshalSiteRuntimeV2BundleWithSecurity also carries the CRS rule text the
// document's managed WAF loads (crs: release path -> content, exactly those
// files; site_runtime_security.go).
func marshalSiteRuntimeV2BundleWithSecurity(
	canonical []byte,
	trustFiles map[string][]byte,
	originRoutes []byte,
	httpPolicy []byte,
	firewallActions map[string][]byte,
	crs map[string][]byte,
	telemetryManifest ...[]byte,
) ([]byte, error) {
	bundle, err := buildSiteRuntimeV2Bundle(canonical, trustFiles, originRoutes, httpPolicy, firewallActions, crs, telemetryManifest...)
	if err != nil {
		return nil, err
	}
	wire, err := edgeconfig.MarshalBundle(bundle)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal site runtime v2 bundle", ErrInvalidInput)
	}
	return wire, nil
}

// buildSiteRuntimeV2Bundle is the release bundle (site runtime v8 splits it
// into site objects, site_objects.go); marshalSiteRuntimeV2BundleWithSecurity
// is its one-document wire form, bounded by the 4 MiB bundle wire limit.
func buildSiteRuntimeV2Bundle(
	canonical []byte,
	trustFiles map[string][]byte,
	originRoutes []byte,
	httpPolicy []byte,
	firewallActions map[string][]byte,
	crs map[string][]byte,
	telemetryManifest ...[]byte,
) (edgeconfig.Bundle, error) {
	if err := validateSiteRuntimeV2OriginRouteTopology(canonical, originRoutes); err != nil {
		return edgeconfig.Bundle{}, err
	}
	if err := validateSiteRuntimeV2CRSFiles(canonical, crs); err != nil {
		return edgeconfig.Bundle{}, err
	}
	if err := validateSiteRuntimeV2HTTPPolicyArtifact(canonical, httpPolicy); err != nil {
		return edgeconfig.Bundle{}, err
	}
	if err := validateSiteRuntimeV2FirewallActionArtifacts(canonical, firewallActions); err != nil {
		return edgeconfig.Bundle{}, err
	}
	files := map[string][]byte{"site-runtime.v2.json": bytes.Clone(canonical)}
	var runtime siteRuntimeV2Document
	if err := json.Unmarshal(canonical, &runtime); err == nil && runtime.Streams != nil {
		_, streamFiles, err := siteRuntimeStreamFragment(runtime, 0)
		if err != nil {
			return edgeconfig.Bundle{}, ErrInvalidInput
		}
		for path, content := range streamFiles {
			if _, duplicate := files[path]; duplicate {
				return edgeconfig.Bundle{}, ErrInvalidInput
			}
			files[path] = bytes.Clone(content)
		}
	}
	if len(telemetryManifest) > 1 || len(telemetryManifest) == 1 && len(telemetryManifest[0]) == 0 {
		return edgeconfig.Bundle{}, ErrInvalidInput
	}
	if len(telemetryManifest) == 1 {
		files[edgeconfig.TelemetryIdentityManifestPath] = bytes.Clone(telemetryManifest[0])
	}
	if len(originRoutes) != 0 {
		files[siteOriginRouteBundlePath] = bytes.Clone(originRoutes)
	}
	if len(httpPolicy) != 0 {
		files[siteRuntimeV2HTTPPolicyArtifactPath] = bytes.Clone(httpPolicy)
	}
	for path, content := range firewallActions {
		if _, duplicate := files[path]; duplicate {
			return edgeconfig.Bundle{}, ErrInvalidInput
		}
		files[path] = bytes.Clone(content)
	}
	for path, content := range crs {
		if _, duplicate := files[path]; duplicate {
			return edgeconfig.Bundle{}, ErrInvalidInput
		}
		files[path] = bytes.Clone(content)
	}
	for path, content := range trustFiles {
		if !strings.HasPrefix(path, "origin-trust/") && !strings.HasPrefix(path, edgeconfig.ClientCAPrefix) ||
			!strings.HasSuffix(path, ".pem") {
			return edgeconfig.Bundle{}, ErrInvalidInput
		}
		files[path] = bytes.Clone(content)
	}
	bundle, err := edgeconfig.NewBundle(files)
	if err != nil {
		return edgeconfig.Bundle{}, fmt.Errorf("%w: site runtime v2 bundle", ErrInvalidInput)
	}
	return bundle, nil
}

// loadSiteRuntimeV2ClientCAFiles is the client CA bundle of every listener
// that verifies client certificates, read from the sites' current rows and
// checked against the document's references.
func loadSiteRuntimeV2ClientCAFiles(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	document siteRuntimeV2Document) (map[string][]byte, error) {
	wanted := map[string]string{} // site ID -> reference
	for _, site := range document.Sites {
		for _, listener := range site.Listeners {
			if listener.TLS != nil && listener.TLS.ClientCARef != "" {
				if previous, exists := wanted[site.ID]; exists && previous != listener.TLS.ClientCARef {
					return nil, ErrInvalidInput
				}
				wanted[site.ID] = listener.TLS.ClientCARef
			}
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	ids := make([]uuid.UUID, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, uuid.MustParse(id))
	}
	rows, err := tx.Query(ctx, `SELECT id,tls_client_ca_pem FROM sites
		WHERE scope_id=$1 AND id=ANY($2::uuid[]) AND tls_client_ca_pem IS NOT NULL`, scopeID, ids)
	if err != nil {
		return nil, fmt.Errorf("%w: read client CA bundles", ErrPersistence)
	}
	defer rows.Close()
	files := map[string][]byte{}
	for rows.Next() {
		var id uuid.UUID
		var bundle string
		if err := rows.Scan(&id, &bundle); err != nil {
			return nil, fmt.Errorf("%w: scan client CA bundle", ErrPersistence)
		}
		ref := wanted[id.String()]
		if edgeconfig.ClientCARefFor([]byte(bundle)) != ref {
			return nil, ErrInvalidInput // the row changed after the document was compiled
		}
		files[edgeconfig.ClientCAPath(ref)] = []byte(bundle)
		delete(wanted, id.String())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate client CA bundles", ErrPersistence)
	}
	if len(wanted) != 0 {
		return nil, ErrInvalidInput
	}
	return files, nil
}

func validateSiteRuntimeV2OriginRouteTopology(canonical, originRoutes []byte) error {
	var runtime siteRuntimeV2Document
	if err := json.Unmarshal(canonical, &runtime); err != nil {
		if len(originRoutes) == 0 {
			return nil
		}
		return ErrInvalidInput
	}
	requiresL2 := false
	for _, site := range runtime.Sites {
		if site.L2.Enabled == nil {
			return ErrInvalidInput
		}
		requiresL2 = requiresL2 || *site.L2.Enabled
	}
	if len(originRoutes) == 0 {
		if requiresL2 {
			return ErrInvalidInput
		}
		return nil
	}
	if edgeconfig.RejectDuplicateJSONKeys(originRoutes) != nil {
		return ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(originRoutes))
	decoder.DisallowUnknownFields()
	var routes siteOriginRouteBundleDocument
	if err := decoder.Decode(&routes); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		routes.Schema != siteOriginRouteBundleSchema || routes.ConfigurationScopeID != runtime.ConfigurationScopeID ||
		routes.SourceRevision != runtime.SourceRevision || routes.ConfigVersionID != runtime.ConfigVersionID {
		return ErrInvalidInput
	}
	routeSites := make(map[string]siteOriginRouteBundleSite, len(routes.Sites))
	for _, site := range routes.Sites {
		if _, duplicate := routeSites[site.SiteID]; duplicate {
			return ErrInvalidInput
		}
		normalized, err := normalizeSiteOriginRouteDocument(site.Document)
		if err != nil {
			return ErrInvalidInput
		}
		site.Document = normalized
		routeSites[site.SiteID] = site
	}
	for _, site := range runtime.Sites {
		routeSite, present := routeSites[site.ID]
		if !present || routeSite.SiteRevision != site.Revision {
			return ErrInvalidInput
		}
		runtimePools := make(map[string]siteRuntimeV2OriginPool, len(site.OriginPools))
		for _, pool := range site.OriginPools {
			runtimePools[pool.ID] = pool
		}
		topologyRevision := int64(0)
		l2Pools := 0
		for _, pool := range routeSite.Document.Pools {
			if pool.Kind != "l2" {
				continue
			}
			l2Pools++
			if !*site.L2.Enabled {
				return ErrInvalidInput
			}
			signed, ok := runtimePools[pool.ID]
			if !ok || signed.Kind != "l2" || len(signed.Origins) != len(pool.Endpoints) {
				return ErrInvalidInput
			}
			signedEndpoints := make(map[string]siteRuntimeV2Origin, len(signed.Origins))
			for _, endpoint := range signed.Origins {
				signedEndpoints[endpoint.ID] = endpoint
			}
			for _, endpoint := range pool.Endpoints {
				signedEndpoint, ok := signedEndpoints[endpoint.ID]
				if !ok || signedEndpoint.Tier != "l2" || signedEndpoint.NodeID == nil ||
					*signedEndpoint.NodeID != endpoint.NodeID || signedEndpoint.Host != endpoint.Host ||
					signedEndpoint.Port != int64(endpoint.Port) || signedEndpoint.Weight != int64(endpoint.Weight) {
					return ErrInvalidInput
				}
				if topologyRevision == 0 {
					topologyRevision = endpoint.TopologyRevision
				} else if topologyRevision != endpoint.TopologyRevision {
					return ErrInvalidInput
				}
			}
		}
		if *site.L2.Enabled && (l2Pools == 0 || site.L2.DirectFallbackPoolID == nil ||
			routeSite.Document.DefaultPoolID != site.DefaultPoolID ||
			routeSite.Document.DefaultFallbackPoolID != *site.L2.DirectFallbackPoolID) {
			return ErrInvalidInput
		}
	}
	return nil
}

func validateSiteRuntimeV2Document(document siteRuntimeV2Document) ([]*agentv1.Capability, bool, error) {
	if document.Schema != siteRuntimeV2Schema || !canonicalSiteRuntimeV2UUID(document.ConfigurationScopeID) ||
		!canonicalSiteRuntimeV2UUID(document.ConfigVersionID) || document.SourceRevision < 1 ||
		document.SourceRevision > maxSiteRuntimeV2SafeInteger || document.Sites == nil || len(document.Sites) > maxSiteRuntimeV2Sites ||
		len(document.RequiredCapabilities) == 0 || len(document.RequiredCapabilities) > 64 ||
		document.System != nil && document.System.Validate() != nil {
		return nil, false, ErrInvalidInput
	}
	required := make(map[string]uint32, len(document.RequiredCapabilities))
	capabilities := make([]*agentv1.Capability, len(document.RequiredCapabilities))
	for index, capability := range document.RequiredCapabilities {
		name, ok := siteruntimecap.Name(capability.Name)
		if !ok || capability.APIVersion == 0 || capability.Name == "site_runtime" &&
			(capability.APIVersion < edgeconfig.MinSiteRuntimeVersion || capability.APIVersion > edgeconfig.MaxDocumentSiteRuntimeVersion) ||
			index > 0 && document.RequiredCapabilities[index-1].Name >= capability.Name {
			return nil, false, ErrInvalidInput
		}
		required[capability.Name] = capability.APIVersion
		capabilities[index] = &agentv1.Capability{Name: name, ApiVersion: capability.APIVersion}
	}
	inferred := map[string]uint32{"site_runtime": edgeconfig.MinSiteRuntimeVersion}
	if document.LazyCertificates != nil {
		if document.LazyCertificates.Validate() != nil {
			return nil, false, ErrInvalidInput
		}
		inferred["site_runtime"] = edgeconfig.LazyCertificateSiteRuntimeVersion
	}
	requiresTLS := false
	for index, site := range document.Sites {
		if index > 0 && document.Sites[index-1].ID >= site.ID {
			return nil, false, ErrInvalidInput
		}
		tls, err := validateSiteRuntimeV2Site(site, inferred)
		if err != nil {
			return nil, false, err
		}
		requiresTLS = requiresTLS || tls
	}
	if _, _, err := siteRuntimeStreamFragment(document, 0); err != nil {
		return nil, false, ErrInvalidInput
	}
	if _, err := siteRuntimeSecurityFragments(document); err != nil {
		return nil, false, ErrInvalidInput
	}
	for name, version := range inferred {
		if required[name] < version {
			return nil, false, ErrInvalidInput
		}
	}
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i].Name < capabilities[j].Name })
	return capabilities, requiresTLS, nil
}

func validateSiteRuntimeV2Site(site siteRuntimeV2Site, inferred map[string]uint32) (bool, error) {
	if !canonicalSiteRuntimeV2UUID(site.ID) || site.Revision < 1 || site.Revision > maxSiteRuntimeV2SafeInteger ||
		len(site.Domains) == 0 || len(site.Domains) > 100 || len(site.Listeners) == 0 || len(site.Listeners) > 32 ||
		len(site.OriginPools) == 0 || len(site.OriginPools) > 64 || site.WebSocket == nil || site.Range == nil ||
		site.L2.Enabled == nil || site.L2.SingleHalfOpenProbe == nil || !*site.L2.SingleHalfOpenProbe {
		return false, ErrInvalidInput
	}
	seenDomains := make(map[string]struct{}, len(site.Domains))
	for _, domain := range site.Domains {
		if len(domain) > 253 || !siteRuntimeV2DomainPattern.MatchString(domain) {
			return false, ErrInvalidInput
		}
		if _, duplicate := seenDomains[domain]; duplicate {
			return false, ErrInvalidInput
		}
		seenDomains[domain] = struct{}{}
	}
	if *site.WebSocket {
		inferred["websocket"] = 1
	}
	if site.ForceHTTPS != nil {
		tlsPort := false
		for _, listener := range site.Listeners {
			tlsPort = tlsPort || listener.Port == site.ForceHTTPS.RedirectPort && listener.TLS != nil
		}
		if !tlsPort {
			return false, ErrInvalidInput
		}
		if status := site.ForceHTTPS.Status; status != 0 && status != 302 && status != 307 && status != 308 {
			return false, ErrInvalidInput
		}
		for index, host := range site.ForceHTTPS.ExcludeHosts {
			if !slices.Contains(site.Domains, host) || strings.HasPrefix(host, "*.") ||
				index > 0 && site.ForceHTTPS.ExcludeHosts[index-1] >= host {
				return false, ErrInvalidInput
			}
		}
	}
	if site.Access != nil {
		hasTLS := false
		for _, listener := range site.Listeners {
			hasTLS = hasTLS || listener.TLS != nil
		}
		if edgeconfig.ValidateSiteAccess(*site.Access, site.Domains, hasTLS) != nil {
			return false, ErrInvalidInput
		}
		for name, version := range siteAccessCapabilities(site.Access) {
			inferred[name] = max(inferred[name], version)
		}
	}
	if site.HTTPPolicy != nil {
		if !canonicalSiteRuntimeV2UUID(site.HTTPPolicy.PolicyID) || site.HTTPPolicy.PolicyRevision < 1 ||
			site.HTTPPolicy.PolicyRevision > maxSiteRuntimeV2SafeInteger ||
			!siteRuntimeV2SHA256Pattern.MatchString(site.HTTPPolicy.ArtifactSHA256) {
			return false, ErrInvalidInput
		}
	}
	if site.FirewallAction != nil {
		if !canonicalSiteRuntimeV2UUID(site.FirewallAction.PolicyID) || site.FirewallAction.PolicyRevision < 1 ||
			site.FirewallAction.PolicyRevision > maxSiteRuntimeV2SafeInteger ||
			!siteRuntimeV2SHA256Pattern.MatchString(site.FirewallAction.DocumentSHA256) ||
			!validFirewallActionArtifactPath(site.ID, site.FirewallAction.ArtifactPath) {
			return false, ErrInvalidInput
		}
	}
	if site.PackageLimits != nil {
		if site.PackageLimits.Validate() != nil {
			return false, ErrInvalidInput
		}
		if site.PackageLimits.SubscriptionLimitsUsed() {
			inferred[edgeconfig.SubscriptionLimitsCapability] = edgeconfig.SubscriptionLimitsAPIVersion
		}
	}
	if err := validateSiteRuntimeV2Cache(site, inferred); err != nil {
		return false, err
	}
	if err := validateSiteRuntimeV2Schedule302(site, inferred); err != nil {
		return false, err
	}
	requiresTLS := false
	listenerIDs := make(map[string]struct{}, len(site.Listeners))
	for index, listener := range site.Listeners {
		if !siteRuntimeV2IdentifierPattern.MatchString(listener.ID) || listener.Position < 0 || listener.Position > 65535 ||
			index > 0 && site.Listeners[index-1].Position >= listener.Position || listener.Port < 1 || listener.Port > 65535 ||
			len(listener.Protocols) == 0 || len(listener.Protocols) > 3 {
			return false, ErrInvalidInput
		}
		if _, duplicate := listenerIDs[listener.ID]; duplicate {
			return false, ErrInvalidInput
		}
		listenerIDs[listener.ID] = struct{}{}
		if listener.Security != nil {
			if listener.Security.CC != nil {
				inferred["cc"] = max(inferred["cc"], listenerCCAPIVersion(listener.Security))
			}
			if version := edgeconfig.ListenerSecurityWAFAPIVersion(listener.Security); version > 0 {
				inferred["waf"] = max(inferred["waf"], version)
			}
			if edgeconfig.ListenerSecurityUsesJA4(listener.Security) {
				inferred["ja4"] = ja4APIVersion
			}
			if edgeconfig.ListenerSecurityUsesCCMatchKeys(listener.Security) {
				inferred[edgeconfig.CCMatchKeysCapability] = edgeconfig.CCMatchKeysAPIVersion
			}
			if edgeconfig.ListenerSecurityUsesJA4Negation(listener.Security) {
				inferred[edgeconfig.WAFJA4NegationCapability] = edgeconfig.JA4NegationAPIVersion
			}
			if edgeconfig.SecurityPoliciesUseIPIntel(listener.Security.Policies) {
				inferred["ip_intel"] = edgeconfig.IPIntelCapabilityVersion
			}
		}
		switch listener.AddressFamily {
		case "ipv4":
			inferred["ipv4"] = 1
		case "ipv6":
			inferred["ipv6"] = 1
		case "dual_stack":
			inferred["ipv4"], inferred["ipv6"] = 1, 1
		default:
			return false, ErrInvalidInput
		}
		seenProtocols := make(map[string]struct{}, len(listener.Protocols))
		needsTLS := false
		for _, protocol := range listener.Protocols {
			if _, duplicate := seenProtocols[protocol]; duplicate {
				return false, ErrInvalidInput
			}
			seenProtocols[protocol] = struct{}{}
			switch protocol {
			case "http1":
				inferred["http1"] = 1
			case "http2":
				inferred["http2"] = 1
			case "http3":
				inferred["http3"], needsTLS = 1, true
			default:
				return false, ErrInvalidInput
			}
		}
		if needsTLS && listener.TLS == nil || listener.TLS != nil &&
			(!canonicalSiteRuntimeV2UUID(listener.TLS.CertificateVersionID) || listener.TLS.profile().Validate() != nil ||
				needsTLS && listener.TLS.Protocols != nil && !slices.Contains(listener.TLS.Protocols, "TLSv1.3")) {
			return false, ErrInvalidInput
		}
		requiresTLS = requiresTLS || listener.TLS != nil
		// An explicit prefer_server_ciphers is only understood by a node
		// with SITE_TLS_OPTIONS. HTTP/2 off is not inferred here: documents
		// with an http1-only TLS listener predate it (the publisher adds the
		// capability, compileSiteRuntimeV2Source).
		if listener.TLS != nil && listener.TLS.PreferServerCiphers != nil {
			inferred[edgeconfig.SiteTLSOptionsCapability] = edgeconfig.SiteTLSOptionsAPIVersion
		}
		if listener.usesTLSCustomCiphers() {
			inferred[edgeconfig.SiteTLSCustomCiphersCapability] = edgeconfig.SiteTLSCustomCiphersAPIVersion
		}
	}
	pools := make(map[string]siteRuntimeV2OriginPool, len(site.OriginPools))
	for index, pool := range site.OriginPools {
		if err := validateSiteRuntimeV2Pool(pool, index, site.OriginPools, inferred); err != nil {
			return false, err
		}
		if _, duplicate := pools[pool.ID]; duplicate {
			return false, ErrInvalidInput
		}
		pools[pool.ID] = pool
	}
	defaultPool, ok := pools[site.DefaultPoolID]
	if !ok || site.L2.ProbeIntervalMS < 100 || site.L2.ProbeIntervalMS > 300000 ||
		site.L2.FailureThreshold < 1 || site.L2.FailureThreshold > 20 ||
		site.L2.RecoveryThreshold < 1 || site.L2.RecoveryThreshold > 20 || site.L2.MaxHops != 1 {
		return false, ErrInvalidInput
	}
	if *site.L2.Enabled {
		if defaultPool.Kind != "l2" || site.L2.DirectFallbackPoolID == nil {
			return false, ErrInvalidInput
		}
		fallback, ok := pools[*site.L2.DirectFallbackPoolID]
		if !ok || fallback.ID == defaultPool.ID || fallback.Kind != "origin" || len(fallback.Origins) == 0 {
			return false, ErrInvalidInput
		}
		if err := validateSiteRuntimeV2L2Conditions(site.L2.Conditions, defaultPool); err != nil {
			return false, err
		}
	} else if site.L2.usesL2Routing() {
		return false, ErrInvalidInput
	}
	if site.L2.usesL2Routing() {
		inferred[edgeconfig.L2RoutingCapability] = edgeconfig.L2RoutingAPIVersion
	}
	if site.Forwarding != nil && site.Forwarding.FollowRedirect != nil {
		inferred[edgeconfig.OriginFollowRedirectCapability] = edgeconfig.OriginFollowRedirectAPIVersion
	}
	if siteRuntimeV2UsesOriginTLSNoVerify(site) {
		inferred[edgeconfig.OriginTLSNoVerifyCapability] = edgeconfig.OriginTLSNoVerifyAPIVersion
	}
	if site.Forwarding.usesEdgeOptions() {
		inferred[edgeconfig.SiteEdgeOptionsCapability] = edgeconfig.SiteEdgeOptionsAPIVersion
	}
	if site.PackageExpired {
		inferred[siteobject.ErrorPageSlotsCapability] = siteobject.ErrorPageSlotsAPIVersion
	}
	if err := validateSiteRuntimeV2Forwarding(site, pools); err != nil {
		return false, err
	}
	return requiresTLS, nil
}

// validateSiteRuntimeV2L2Conditions: edgesite.ValidateL2Conditions on the
// runtime document's L2 pool, condition ids canonical UUIDs.
func validateSiteRuntimeV2L2Conditions(conditions []siteRuntimeV2L2Condition, pool siteRuntimeV2OriginPool) error {
	l2Pool := edgesite.Pool{ID: pool.ID, Kind: edgesite.PoolL2}
	for _, origin := range pool.Origins {
		l2Pool.Endpoints = append(l2Pool.Endpoints, edgesite.Endpoint{ID: origin.ID})
	}
	converted := make([]edgesite.L2Condition, len(conditions))
	for index, condition := range conditions {
		if !canonicalSiteRuntimeV2UUID(condition.ID) {
			return ErrInvalidInput
		}
		converted[index] = edgesite.L2Condition{ID: condition.ID, Rules: condition.Rules,
			NodeIDs: condition.NodeIDs, EndpointIDs: condition.EndpointIDs}
	}
	if edgesite.ValidateL2Conditions(converted, l2Pool) != nil {
		return ErrInvalidInput
	}
	return nil
}

func validateSiteRuntimeV2Pool(
	pool siteRuntimeV2OriginPool,
	index int,
	pools []siteRuntimeV2OriginPool,
	inferred map[string]uint32,
) error {
	if !siteRuntimeV2IdentifierPattern.MatchString(pool.ID) || pool.Position < 0 || pool.Position > 65535 ||
		index > 0 && pools[index-1].Position >= pool.Position || len(pool.Origins) == 0 || len(pool.Origins) > 32 ||
		(pool.Kind != "origin" && pool.Kind != "l2") {
		return ErrInvalidInput
	}
	switch pool.Algorithm {
	case "round_robin", "ip_hash", "url_hash", "least_conn", "random", "hash", "sticky":
	default:
		return ErrInvalidInput
	}
	if err := validateSiteRuntimeV2PoolForwarding(pool); err != nil {
		return err
	}
	seenOrigins := make(map[string]struct{}, len(pool.Origins))
	for originIndex, origin := range pool.Origins {
		if !siteRuntimeV2IdentifierPattern.MatchString(origin.ID) || origin.Position < 0 || origin.Position > 65535 ||
			originIndex > 0 && pool.Origins[originIndex-1].Position >= origin.Position || origin.Port < 1 || origin.Port > 65535 ||
			origin.Weight < 1 || origin.Weight > 100 || origin.Tier != pool.Kind ||
			(origin.Scheme != "http" && origin.Scheme != "https") || !validSiteRuntimeV2Host(origin.Host) {
			return ErrInvalidInput
		}
		if _, duplicate := seenOrigins[origin.ID]; duplicate {
			return ErrInvalidInput
		}
		seenOrigins[origin.ID] = struct{}{}
		if address, parseErr := netip.ParseAddr(origin.Host); parseErr == nil {
			if address.Is4() {
				inferred["ipv4"] = 1
			} else {
				inferred["ipv6"] = 1
			}
		}
		if pool.Kind == "l2" && (origin.NodeID == nil || !canonicalSiteRuntimeV2UUID(*origin.NodeID)) ||
			pool.Kind == "origin" && origin.NodeID != nil && !canonicalSiteRuntimeV2UUID(*origin.NodeID) {
			return ErrInvalidInput
		}
		// An HTTPS origin verifies its certificate against the node's CA
		// store ("system") or a signed bundle, unless the pool chose not to
		// ("none", ORIGIN_TLS_NO_VERIFY). SNI absent sends the origin
		// request Host.
		validTrust := origin.TrustRef != nil &&
			(*origin.TrustRef == siteRuntimeV2SystemTrust || *origin.TrustRef == siteRuntimeV2NoVerifyTrust ||
				siteRuntimeV2TrustPattern.MatchString(*origin.TrustRef))
		if origin.Scheme == "https" && (!validTrust || pool.Kind != "origin") ||
			origin.Scheme == "http" && (origin.SNI != nil || origin.TrustRef != nil) ||
			origin.SNI != nil && !validSiteRuntimeV2Host(*origin.SNI) {
			return ErrInvalidInput
		}
	}
	if pool.KeepaliveIdleTimeoutMS != nil {
		idle := *pool.KeepaliveIdleTimeoutMS
		if pool.Kind != "origin" || idle != 0 && (idle < 1000 || idle > 300000) {
			return ErrInvalidInput
		}
	}
	wantRetry := []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"}
	if len(pool.Retry.Methods) != 2 || pool.Retry.Methods[0] != "GET" || pool.Retry.Methods[1] != "HEAD" ||
		pool.Retry.BodylessOnly == nil || !*pool.Retry.BodylessOnly ||
		pool.Retry.ResponseNotStarted == nil || !*pool.Retry.ResponseNotStarted ||
		len(pool.Retry.RetryOn) != len(wantRetry) || pool.Retry.MaxAttempts < 1 || pool.Retry.MaxAttempts > 8 ||
		pool.Retry.ConnectTimeoutMS < 10 || pool.Retry.ConnectTimeoutMS > 60000 ||
		pool.Retry.ReadTimeoutMS < 10 || pool.Retry.ReadTimeoutMS > 60000 ||
		pool.Retry.TotalBudgetMS < 10 || pool.Retry.TotalBudgetMS > 120000 {
		return ErrInvalidInput
	}
	for index := range wantRetry {
		if pool.Retry.RetryOn[index] != wantRetry[index] {
			return ErrInvalidInput
		}
	}
	return nil
}

func canonicalSiteRuntimeV2UUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validSiteRuntimeV2Host(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == ""
	}
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func rejectSiteRuntimeV2ExplicitNulls(value any) bool {
	root, ok := value.(map[string]any)
	if !ok {
		return false
	}
	sites, _ := root["sites"].([]any)
	for _, rawSite := range sites {
		site, _ := rawSite.(map[string]any)
		listeners, _ := site["listeners"].([]any)
		for _, rawListener := range listeners {
			listener, _ := rawListener.(map[string]any)
			if tls, exists := listener["tls"]; exists && tls == nil {
				return true
			}
		}
		pools, _ := site["origin_pools"].([]any)
		for _, rawPool := range pools {
			pool, _ := rawPool.(map[string]any)
			origins, _ := pool["origins"].([]any)
			for _, rawOrigin := range origins {
				origin, _ := rawOrigin.(map[string]any)
				for _, key := range []string{"node_id", "sni", "trust_ref"} {
					if field, exists := origin[key]; exists && field == nil {
						return true
					}
				}
			}
		}
		l2, _ := site["l2"].(map[string]any)
		if fallback, exists := l2["direct_fallback_pool_id"]; exists && fallback == nil {
			return true
		}
	}
	return false
}

func parseSiteRuntimeV2JSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := parseSiteRuntimeV2JSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidInput
	}
	return value, nil
}

func parseSiteRuntimeV2JSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delimiter {
	case '{':
		result := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, ErrInvalidInput
			}
			if _, duplicate := result[key]; duplicate {
				return nil, ErrInvalidInput
			}
			value, err := parseSiteRuntimeV2JSONValue(decoder)
			if err != nil {
				return nil, err
			}
			result[key] = value
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, ErrInvalidInput
		}
		return result, nil
	case '[':
		result := make([]any, 0)
		for decoder.More() {
			value, err := parseSiteRuntimeV2JSONValue(decoder)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, ErrInvalidInput
		}
		return result, nil
	default:
		return nil, ErrInvalidInput
	}
}

func writeSiteRuntimeV2CanonicalJSON(output *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(value))
	case string:
		writeSiteRuntimeV2CanonicalString(output, value)
	case json.Number:
		number, ok := parseSiteRuntimeV2SafeInteger(value)
		if !ok {
			return ErrInvalidInput
		}
		output.WriteString(strconv.FormatInt(number, 10))
	case []any:
		output.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeSiteRuntimeV2CanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return siteRuntimeV2UTF16Less(keys[i], keys[j]) })
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			writeSiteRuntimeV2CanonicalString(output, key)
			output.WriteByte(':')
			if err := writeSiteRuntimeV2CanonicalJSON(output, value[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported JSON value %T", ErrInvalidInput, value)
	}
	return nil
}

func parseSiteRuntimeV2SafeInteger(value json.Number) (int64, bool) {
	number, err := strconv.ParseFloat(string(value), 64)
	if err != nil || math.IsInf(number, 0) || math.IsNaN(number) || math.Trunc(number) != number ||
		math.Abs(number) > float64(maxSiteRuntimeV2SafeInteger) {
		return 0, false
	}
	return int64(number), true
}

func writeSiteRuntimeV2CanonicalString(output *bytes.Buffer, value string) {
	const hex = "0123456789abcdef"
	output.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(character)
		case '\b':
			output.WriteString(`\b`)
		case '\t':
			output.WriteString(`\t`)
		case '\n':
			output.WriteString(`\n`)
		case '\f':
			output.WriteString(`\f`)
		case '\r':
			output.WriteString(`\r`)
		default:
			if character < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(hex[byte(character)>>4])
				output.WriteByte(hex[byte(character)&0xf])
			} else {
				output.WriteRune(character)
			}
		}
	}
	output.WriteByte('"')
}

func siteRuntimeV2UTF16Less(left, right string) bool {
	leftUnits, rightUnits := utf16.Encode([]rune(left)), utf16.Encode([]rune(right))
	for index := 0; index < len(leftUnits) && index < len(rightUnits); index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}

// siteAccessCapabilities are the node capabilities a site's access settings
// need: Brotli or a compression level of the site's own
// (EDGE_BROTLI), WebP conversion (EDGE_WEBP); response rules
// (EDGE_RESPONSE_RULES).
func siteAccessCapabilities(access *edgeconfig.SiteAccess) map[string]uint32 {
	if access == nil {
		return nil
	}
	result := map[string]uint32{}
	if access.Compression.NeedsEdgeBrotli() {
		result["edge_brotli"] = 1
	}
	if access.WebP != nil {
		result["edge_webp"] = 1
	}
	if len(access.ResponseRules) != 0 {
		result[edgeconfig.EdgeResponseRulesCapability] = 1
	}
	return result
}
