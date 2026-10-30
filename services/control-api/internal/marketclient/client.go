// Package marketclient connects this controller to the node marketplace
// (docs/marketplace/01-architecture.md). All traffic is outbound mTLS using the
// installation client certificate; peers' keys are taken only from
// market-signed member cards; supply grants are verified before use.
package marketclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/card"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/nodeaction"
	"github.com/cdnca/cdnca/libs/marketproto/nodeload"
	"github.com/cdnca/cdnca/libs/marketproto/usage"
	"github.com/google/uuid"
)

const (
	responseLimit   = 8 << 20
	requestTimeout  = 30 * time.Second
	longPollSeconds = 25
	cardTTL         = 10 * time.Minute
)

var (
	ErrConfig   = errors.New("market client configuration invalid")
	ErrRejected = errors.New("market rejected the request")
	ErrProtocol = errors.New("market response invalid")
)

// RejectedError is a non-2xx market answer; errors.Is(err, ErrRejected) holds.
// Callers use Status/Code to fall back for an older market (404 on a route it
// lacks, 400 invalid_json on a field it does not know).
type RejectedError struct {
	Status int
	Code   string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("%v: %d %s", ErrRejected, e.Status, e.Code)
}
func (e *RejectedError) Is(target error) bool { return target == ErrRejected }

// Rejected returns the market's status and error code when err is a rejection.
func Rejected(err error) (status int, code string, ok bool) {
	var r *RejectedError
	if errors.As(err, &r) {
		return r.Status, r.Code, true
	}
	return 0, "", false
}

// Identity is this member's market key material. Persist it: rotating keys
// re-registers and invalidates peers' cached cards.
type Identity struct {
	MemberID   uuid.UUID
	SigningKey ed25519.PrivateKey
	BoxPrivate []byte
	BoxPublic  []byte
}

type Config struct {
	BaseURL string
	// RootCAs verifies the market server certificate.
	RootCAs *x509.CertPool
	// ClientCertificate supplies the installation client certificate, e.g.
	// pluginruntimecomposition.CertificateManager.GetClientCertificate.
	ClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	// MarketKeys verifies grants and member cards (current + previous).
	MarketKeys map[string]ed25519.PublicKey
	// DialContext opens the connection the inner mTLS runs over (libs/mtlstunnel
	// tunnel through the CDN); nil dials directly.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

type Client struct {
	base   *url.URL
	http   *http.Client
	keys   map[string]ed25519.PublicKey
	grants grant.Keyring

	mu    sync.Mutex
	cards map[uuid.UUID]cachedCard
	now   func() time.Time
}

type cachedCard struct {
	card    card.Card
	fetched time.Time
}

func New(cfg Config) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || cfg.RootCAs == nil ||
		cfg.ClientCertificate == nil || len(cfg.MarketKeys) == 0 {
		return nil, ErrConfig
	}
	transport := &http.Transport{DialContext: cfg.DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: cfg.RootCAs, GetClientCertificate: cfg.ClientCertificate},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: (longPollSeconds + 10) * time.Second, MaxIdleConnsPerHost: 4,
	}
	keyring := grant.Keyring{}
	for id, key := range cfg.MarketKeys {
		keyring[id] = key
	}
	return &Client{base: base, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, keys: cfg.MarketKeys, grants: keyring, cards: map[uuid.UUID]cachedCard{}, now: time.Now}, nil
}

// Register publishes this installation's keys with its current signed lease
// and returns the market member ID. cdncaCE: a community installation has no
// lease; Register then sends its community identity (license service
// community-register), which the market accepts instead (buy only).
func (c *Client) Register(ctx context.Context, id Identity, signedLease []byte, displayName string) (uuid.UUID, error) {
	return c.register(ctx, id, "signed_lease", signedLease, displayName)
}

// RegisterCommunity is Register with a community installation identity (the
// encoded signed document, sent as bytes like signed_lease).
func (c *Client) RegisterCommunity(ctx context.Context, id Identity, communityIdentity []byte, displayName string) (uuid.UUID, error) {
	return c.register(ctx, id, "community_identity", communityIdentity, displayName)
}

func (c *Client) register(ctx context.Context, id Identity, proofField string, proof []byte, displayName string) (uuid.UUID, error) {
	if len(id.SigningKey) != ed25519.PrivateKeySize || len(id.BoxPublic) != 32 {
		return uuid.Nil, ErrConfig
	}
	var member struct {
		ID uuid.UUID `json:"id"`
	}
	body := map[string]any{"display_name": displayName, "signing_public_key": []byte(id.SigningKey.Public().(ed25519.PublicKey)),
		"box_public_key": id.BoxPublic, proofField: proof}
	if err := c.do(ctx, http.MethodPost, "/v1/members/register", body, &member, requestTimeout); err != nil {
		return uuid.Nil, err
	}
	if member.ID == uuid.Nil {
		return uuid.Nil, ErrProtocol
	}
	return member.ID, nil
}

// Grants returns verified grants this member must serve as a leaf supplier,
// and the root subscriber member of each (by grant ID, only for grants in
// the result) so attack digests have a recipient before any subscriber
// request arrives. Grants that fail verification or name another leaf are
// dropped, not trusted.
func (c *Client) Grants(ctx context.Context, self uuid.UUID) ([]grant.Grant, map[uuid.UUID]uuid.UUID, error) {
	var response struct {
		Items       []grant.Signed          `json:"items"`
		Subscribers map[uuid.UUID]uuid.UUID `json:"subscribers"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/grants", nil, &response, requestTimeout); err != nil {
		return nil, nil, err
	}
	out := make([]grant.Grant, 0, len(response.Items))
	subscribers := map[uuid.UUID]uuid.UUID{}
	for _, signed := range response.Items {
		g, err := c.grants.Verify(signed)
		if err != nil || g.LeafMemberID != self {
			continue
		}
		out = append(out, g)
		if member := response.Subscribers[g.GrantID]; member != uuid.Nil {
			subscribers[g.GrantID] = member
		}
	}
	return out, subscribers, nil
}

// SupplyTarget is one row of GET /v1/supply-targets: the aggregate name of a
// subscription (Aggregate) or one of its leaves.
type SupplyTarget struct {
	SubscriptionID uuid.UUID  `json:"subscription_id"`
	Aggregate      bool       `json:"aggregate"`
	LeafMemberID   uuid.UUID  `json:"leaf_member_id"`
	NodePoolRef    string     `json:"node_pool_ref"`
	GrantID        *uuid.UUID `json:"grant_id,omitempty"`
	FQDN           string     `json:"fqdn"`
	Previous       []string   `json:"previous"`
	// State is the slot's service state (ADR 0012 §7, ML-06): serving,
	// paused, stopped or overloaded; an aggregate row has its leaves' best.
	State string `json:"state"`
}

// Supply target states (GET /v1/supply-targets state).
const (
	SupplyServing    = "serving"
	SupplyPaused     = "paused"
	SupplyStopped    = "stopped"
	SupplyOverloaded = "overloaded"
)

// SupplyHold is the strictest open hold on one of this leaf's supply slots.
type SupplyHold struct {
	SubscriptionPath []uuid.UUID `json:"subscription_path"`
	NodePoolRef      string      `json:"node_pool_ref"`
	Action           string      `json:"action"`
	ThrottleBPS      int64       `json:"throttle_bps"`
	Revision         int64       `json:"revision"`
}

// SupplyHolds is GET /v1/supply-holds: this leaf's hold snapshot (ADR 0012
// §6.2 supply.hold); Revision moves on every hold opened or released.
type SupplyHolds struct {
	Revision int64        `json:"revision"`
	Items    []SupplyHold `json:"items"`
}

func (c *Client) SupplyHolds(ctx context.Context) (SupplyHolds, error) {
	var holds SupplyHolds
	if err := c.do(ctx, http.MethodGet, "/v1/supply-holds", nil, &holds, requestTimeout); err != nil {
		return SupplyHolds{}, err
	}
	if holds.Revision < 0 {
		return SupplyHolds{}, ErrProtocol
	}
	for _, h := range holds.Items {
		if len(h.SubscriptionPath) == 0 || h.NodePoolRef == "" || h.Revision < 0 || h.ThrottleBPS < 0 ||
			(h.Action != "stop" && h.Action != "pause" && h.Action != "throttle") {
			return SupplyHolds{}, ErrProtocol
		}
	}
	return holds, nil
}

// SupplyTargets lists the CNAME targets and leaves of this member's own
// subscriptions.
func (c *Client) SupplyTargets(ctx context.Context) ([]SupplyTarget, error) {
	var response struct {
		Items []SupplyTarget `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/supply-targets", nil, &response, requestTimeout); err != nil {
		return nil, err
	}
	return response.Items, nil
}

// SlotState is one row of GET /v1/leaf/subscription-states: whether a slot
// this leaf serves is normal, stopped (unpaid or a platform ticket) or
// cancelled (ADR 0012 ML-18).
type SlotState struct {
	SubscriptionPath []uuid.UUID `json:"subscription_path"`
	NodePoolRef      string      `json:"node_pool_ref"`
	State            string      `json:"state"`
}

// SlotStates lists this leaf's slot states and the market time they hold for.
func (c *Client) SlotStates(ctx context.Context) ([]SlotState, time.Time, error) {
	var response struct {
		AsOf  time.Time   `json:"as_of"`
		Items []SlotState `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/leaf/subscription-states", nil, &response, requestTimeout); err != nil {
		return nil, time.Time{}, err
	}
	if response.AsOf.IsZero() || response.Items == nil {
		return nil, time.Time{}, ErrProtocol
	}
	return response.Items, response.AsOf, nil
}

// idempotencyKeyPattern is the market's Idempotency-Key grammar
// (marketplace-openapi components/parameters.yaml).
var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Forward sends one member API request and returns the market's status and
// JSON body unchanged, for the controller's own admin console. path must be
// absolute under /v1/; callers allowlist what they forward. A non-empty
// idempotencyKey is sent as the Idempotency-Key header (marketplace writes).
func (c *Client) Forward(ctx context.Context, method, path, idempotencyKey string, body []byte) (int, []byte, error) {
	if !strings.HasPrefix(path, "/v1/") || strings.Contains(path, "..") ||
		idempotencyKey != "" && !idempotencyKeyPattern.MatchString(idempotencyKey) {
		return 0, nil, ErrConfig
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, reader)
	if err != nil {
		return 0, nil, ErrConfig
	}
	request.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("market unreachable: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil || len(raw) > responseLimit {
		return 0, nil, ErrProtocol
	}
	return response.StatusCode, raw, nil
}

// OwnOffer is one of this member's offers, as GET /v1/offers?mine=1 returns it.
type OwnOffer struct {
	ID         uuid.UUID `json:"id"`
	Status     string    `json:"status"`
	Components []struct {
		Kind        string `json:"kind"`
		NodePoolRef string `json:"node_pool_ref"`
	} `json:"components"`
}

func (c *Client) OwnOffers(ctx context.Context) ([]OwnOffer, error) {
	var response struct {
		Items []OwnOffer `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/offers?mine=1", nil, &response, requestTimeout); err != nil {
		return nil, err
	}
	return response.Items, nil
}

// PoolNode is one probe-ready edge node of a pool, as the market expects it.
type PoolNode struct {
	NodeID  string `json:"node_id"`
	IP      string `json:"ip"`
	Region  string `json:"region"`
	Carrier string `json:"carrier"`
	// Benchmark: the node's session advertises CAPABILITY_NAME_MARKET_BENCHMARK
	// v1 (omitted otherwise, so markets without M4 still accept the report).
	Benchmark bool `json:"benchmark,omitempty"`
	// Plugins: the node plugin feature codes (module.* / pack.*) this
	// installation is licensed for and the node has installed; the market
	// lets an offer include only those every node of its supply has.
	Plugins []string `json:"plugins,omitempty"`
}

// ReportPoolNodes replaces the market's inventory of one node pool. online,
// when set, is this controller's count of the pool's online available nodes
// (marketsupplyguard.OnlineAvailable); the market judges zero-online
// outages from it (ADR 0012 §24).
func (c *Client) ReportPoolNodes(ctx context.Context, pool string, nodes []PoolNode, online *int) error {
	if nodes == nil {
		nodes = []PoolNode{}
	}
	body := map[string]any{"nodes": nodes}
	if online != nil {
		body["online_available"] = *online
	}
	return c.do(ctx, http.MethodPut, "/v1/pools/"+url.PathEscape(pool)+"/nodes", body, nil, requestTimeout)
}

// ProbeTask is one probe the market asks one of this member's nodes to run.
type ProbeTask struct {
	RoundID       uuid.UUID `json:"round_id"`
	ProberNodeID  string    `json:"prober_node_id"`
	TargetIP      string    `json:"target_ip"`
	Port          int       `json:"port"`
	Path          string    `json:"path"`
	TimeoutMillis int       `json:"timeout_millis"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (c *Client) ProbeTasks(ctx context.Context) ([]ProbeTask, error) {
	var response struct {
		Items []ProbeTask `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/probe/tasks", nil, &response, requestTimeout); err != nil {
		return nil, err
	}
	return response.Items, nil
}

// ProbeResult is one executed probe; skipped probes are never submitted.
type ProbeResult struct {
	RoundID      uuid.UUID `json:"round_id"`
	ProberNodeID string    `json:"prober_node_id"`
	OK           bool      `json:"ok"`
	LatencyMs    int       `json:"latency_ms"`
}

func (c *Client) SubmitProbeResults(ctx context.Context, results []ProbeResult) (int, error) {
	var response struct {
		Accepted int `json:"accepted"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/probe/results", map[string]any{"results": results}, &response, requestTimeout)
	return response.Accepted, err
}

// UsageResult is the market's verdict on one signed usage report.
type UsageResult struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Conflicts  int `json:"conflicts"`
	Rejected   int `json:"rejected"`
}

// ReportUsage signs and submits one leaf usage report.
func (c *Client) ReportUsage(ctx context.Context, self Identity, report usage.Report) (UsageResult, error) {
	report.LeafMemberID = self.MemberID
	signed, err := usage.Sign(report, self.SigningKey)
	if err != nil {
		return UsageResult{}, err
	}
	var result UsageResult
	err = c.do(ctx, http.MethodPost, "/v1/usage/reports", signed, &result, requestTimeout)
	return result, err
}

// NodeLoadResult is the market's verdict on one signed node load report.
type NodeLoadResult struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
}

// ReportNodeLoad signs and submits one per-minute node load report
// (ADR 0012 §6.1).
func (c *Client) ReportNodeLoad(ctx context.Context, self Identity, report nodeload.Report) (NodeLoadResult, error) {
	report.LeafMemberID = self.MemberID
	signed, err := nodeload.Sign(report, self.SigningKey)
	if err != nil {
		return NodeLoadResult{}, err
	}
	var result NodeLoadResult
	err = c.do(ctx, http.MethodPost, "/v1/node-load/reports", signed, &result, requestTimeout)
	return result, err
}

// NodeActionResult is the market's answer to a node action report.
type NodeActionResult struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
	Paused     int `json:"paused"`
}

// ReportNodeActions signs a whole-node action report as this member (ADR
// 0012 §19.3) and posts it to the market.
func (c *Client) ReportNodeActions(ctx context.Context, self Identity, report nodeaction.Report) (NodeActionResult, error) {
	report.LeafMemberID = self.MemberID
	signed, err := nodeaction.Sign(report, self.SigningKey)
	if err != nil {
		return NodeActionResult{}, err
	}
	var result NodeActionResult
	err = c.do(ctx, http.MethodPost, "/v1/node-actions/reports", signed, &result, requestTimeout)
	return result, err
}

// Card returns a peer's verified keys, cached briefly.
func (c *Client) Card(ctx context.Context, member uuid.UUID) (card.Card, error) {
	c.mu.Lock()
	cached, ok := c.cards[member]
	c.mu.Unlock()
	if ok && c.now().Sub(cached.fetched) < cardTTL {
		return cached.card, nil
	}
	var signed card.Signed
	if err := c.do(ctx, http.MethodGet, "/v1/members/"+member.String()+"/card", nil, &signed, requestTimeout); err != nil {
		return card.Card{}, err
	}
	verified, err := card.Verify(c.keys, signed)
	if err != nil || verified.MemberID != member {
		return card.Card{}, ErrProtocol
	}
	c.mu.Lock()
	c.cards[member] = cachedCard{card: verified, fetched: c.now()}
	c.mu.Unlock()
	return verified, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, reader)
	if err != nil {
		return ErrConfig
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("market unreachable: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil || len(raw) > responseLimit {
		return ErrProtocol
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		var problem struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &problem)
		return &RejectedError{Status: response.StatusCode, Code: problem.Error}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return ErrProtocol
	}
	return nil
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
