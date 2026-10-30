// Package marketruntime connects this controller to the node market as a
// leaf supplier: it registers with the current signed lease, keeps supply
// grants in sync, and answers relay requests through marketsupply.
//
// The installation client certificate is the one the plugin runtime already
// bootstraps from the license service; this package only reads its files, so
// the two never race on renewal.
package marketruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsubscribe"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/curve25519"
)

const identityFile = "market-identity.json"

var (
	ErrNoLease     = errors.New("market runtime: no current signed lease installed")
	ErrCallTimeout = errors.New("market runtime: leaf did not reply in time")
)

type Config struct {
	DisplayName string
	// CertFile / KeyFile are the installation client certificate files.
	CertFile, KeyFile string
	// StateDir holds this member's market key material (mode 0700).
	StateDir      string
	GrantEvery    time.Duration
	RegisterEvery time.Duration
	// CallTimeout bounds one relay round trip to a leaf.
	CallTimeout time.Duration
	// CommunityIdentity (cdncaCE) returns the stored community installation
	// identity the market accepts instead of a lease; nil uses the lease.
	CommunityIdentity func() ([]byte, error)
}

// ErrNotRegistered: a community installation has not run community-register yet.
var ErrNotRegistered = errors.New("community installation is not registered with the official service")

// Market is the subset of marketclient.Client the runtime drives.
type Market interface {
	Register(ctx context.Context, id marketclient.Identity, signedLease []byte, displayName string) (uuid.UUID, error)
	RegisterCommunity(ctx context.Context, id marketclient.Identity, communityIdentity []byte, displayName string) (uuid.UUID, error)
	// Grants also returns each grant's root subscriber member by grant ID.
	Grants(ctx context.Context, self uuid.UUID) ([]grant.Grant, map[uuid.UUID]uuid.UUID, error)
	Receive(ctx context.Context, self marketclient.Identity, cursor int64) ([]marketclient.Inbound, int64, []error)
	Send(ctx context.Context, self marketclient.Identity, out marketclient.Outbound) (int64, error)
	Ack(ctx context.Context, seq int64) error
}

// Supply is the subset of marketsupply.Service the runtime drives.
type Supply interface {
	Sync(ctx context.Context, grants []grant.Grant) ([]marketsupply.Outcome, error)
	Handle(ctx context.Context, header envelope.Header, payload []byte) (siteconf.Reply, error)
}

// Subscriptions is the subscriber side (marketsubscribe.Service).
type Subscriptions interface {
	SyncTargets(ctx context.Context, platform uuid.UUID) (int, error)
}

type Runtime struct {
	cfg    Config
	subs   Subscriptions
	pool   *pgxpool.Pool
	market Market
	supply Supply
	log    *slog.Logger

	usageSource   UsageSource
	usageReporter UsageReporter
	usageEvery    time.Duration

	// Attack digests (secdigest.go): leaf source and subscriber receiver.
	digestSource   DigestSource
	digestReceiver DigestReceiver

	holdSource   HoldSource
	limitApplier LimitApplier
	holdEvery    time.Duration

	probe interface{ Run(context.Context) error }
	// notices turns market notices into notification center events (notices.go).
	notices NoticeEnqueuer
	// direct top-ups (directpay.go, ADR 0015).
	directPay    DirectPay
	directMarket DirectCheckouts
	// background loops that run once the member is registered.
	background []func(context.Context) error

	mu      sync.Mutex
	id      marketclient.Identity
	pending map[string]chan siteconf.Reply
}

func New(cfg Config, pool *pgxpool.Pool, market Market, supply Supply, log *slog.Logger) *Runtime {
	if cfg.GrantEvery <= 0 {
		cfg.GrantEvery = 5 * time.Minute
	}
	if cfg.RegisterEvery <= 0 {
		cfg.RegisterEvery = time.Hour
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 2 * time.Minute
	}
	return &Runtime{cfg: cfg, pool: pool, market: market, supply: supply, log: log}
}

// WithSubscriptions also keeps this controller's own market subscriptions
// (as a buyer) in sync on every grant round.
func (r *Runtime) WithSubscriptions(subs Subscriptions) *Runtime {
	r.subs = subs
	return r
}

// WithProbe also runs leaf-side market probing (marketprobe.Service) once the
// member is registered.
func (r *Runtime) WithProbe(probe interface{ Run(context.Context) error }) *Runtime {
	r.probe = probe
	return r
}

// Supply returns the leaf the runtime drives.
func (r *Runtime) Supply() Supply { return r.supply }

// WithBackground also runs loop once the member is registered, e.g. the
// leaf security reconciler, which needs runtimes built after this one.
func (r *Runtime) WithBackground(loop func(context.Context) error) *Runtime {
	r.background = append(r.background, loop)
	return r
}

// ClientCertificate reloads the installation certificate on every handshake,
// so renewals by the plugin runtime are picked up without a restart.
func ClientCertificate(certFile, keyFile string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load installation client certificate: %w", err)
		}
		return &cert, nil
	}
}

// Run blocks until ctx ends. Failures are logged and retried; the market is
// optional for the rest of the controller.
func (r *Runtime) Run(ctx context.Context) error {
	for {
		if err := r.register(ctx); err == nil {
			break
		} else {
			r.log.Warn("market registration failed", "err", err)
		}
		if !sleep(ctx, time.Minute) {
			return ctx.Err()
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.grantLoop(ctx) }()
	go func() { defer wg.Done(); r.relayLoop(ctx) }()
	if r.usageSource != nil && r.usageReporter != nil {
		wg.Add(1)
		go func() { defer wg.Done(); r.usageLoop(ctx) }()
	}
	if r.digestSource != nil {
		wg.Add(1)
		go func() { defer wg.Done(); r.digestLoop(ctx) }()
	}
	if r.holdSource != nil && r.limitApplier != nil {
		wg.Add(1)
		go func() { defer wg.Done(); r.holdLoop(ctx) }()
	}
	if r.probe != nil {
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.probe.Run(ctx) }()
	}
	for _, loop := range r.background {
		wg.Add(1)
		go func() { defer wg.Done(); _ = loop(ctx) }()
	}
	wg.Wait()
	return ctx.Err()
}

func (r *Runtime) register(ctx context.Context) error {
	id, err := r.loadIdentity()
	if err != nil {
		return err
	}
	var member uuid.UUID
	if r.cfg.CommunityIdentity != nil {
		// cdncaCE: no lease; the stored community identity (community-register).
		document, err := r.cfg.CommunityIdentity()
		if err != nil {
			return err
		}
		if len(document) == 0 {
			return ErrNotRegistered
		}
		if member, err = r.market.RegisterCommunity(ctx, id, document, r.cfg.DisplayName); err != nil {
			return err
		}
	} else {
		lease, err := r.currentLease(ctx)
		if err != nil {
			return err
		}
		if member, err = r.market.Register(ctx, id, lease, r.cfg.DisplayName); err != nil {
			return err
		}
	}
	if id.MemberID != member {
		id.MemberID = member
		if err := r.saveIdentity(id); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.id = id
	r.mu.Unlock()
	r.log.Info("market member registered", "member_id", member)
	return nil
}

// Identity is the registered member identity (zero MemberID until the
// first registration succeeded), for leaf loops built outside the runtime.
func (r *Runtime) Identity() marketclient.Identity { return r.identity() }

func (r *Runtime) identity() marketclient.Identity {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.id
}

func (r *Runtime) grantLoop(ctx context.Context) {
	lastRegister := time.Now()
	for {
		if time.Since(lastRegister) >= r.cfg.RegisterEvery {
			// Re-register so the market sees the renewed lease (features may change).
			if err := r.register(ctx); err != nil {
				r.log.Warn("market re-registration failed", "err", err)
			} else {
				lastRegister = time.Now()
			}
		}
		grants, subscribers, err := r.market.Grants(ctx, r.identity().MemberID)
		if err != nil {
			r.log.Warn("market grant fetch failed", "err", err)
		} else {
			r.rememberSubscribers(grants, subscribers)
			if outcomes, err := r.supply.Sync(ctx, grants); err != nil {
				r.log.Warn("market grant sync failed", "err", err)
			} else {
				for _, o := range outcomes {
					if o.Action == "failed" {
						r.log.Warn("market grant not applied", "grant_id", o.GrantID, "key", o.Key, "err", o.Error)
					}
				}
			}
		}
		if r.subs != nil {
			var platform uuid.UUID
			if err := r.pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); err != nil {
				r.log.Warn("market subscription sync skipped", "err", err)
			} else if _, err := r.subs.SyncTargets(ctx, platform); err != nil {
				r.log.Warn("market subscription sync failed", "err", err)
			}
		}
		if !sleep(ctx, r.cfg.GrantEvery) {
			return
		}
	}
}

// relayLoop starts from cursor 0 on every boot: the relay keeps everything
// not yet acked, and every handler is idempotent, so a replay is harmless.
func (r *Runtime) relayLoop(ctx context.Context) {
	var cursor int64
	for ctx.Err() == nil {
		self := r.identity()
		messages, next, errs := r.market.Receive(ctx, self, cursor)
		for _, err := range errs {
			r.log.Warn("market relay message rejected", "err", err)
		}
		failed := false
		for _, m := range messages {
			if err := r.answer(ctx, self, m); err != nil {
				// Transient (database, market); stop here and redeliver from m.
				r.log.Warn("market relay handling failed", "op", m.Header.Operation, "err", err)
				next, failed = m.Seq-1, true
				break
			}
		}
		if next > cursor {
			if err := r.market.Ack(ctx, next); err != nil {
				r.log.Warn("market relay ack failed", "err", err)
			}
			cursor = next
		}
		// Back off on errors; a healthy long poll paces itself.
		if (failed || len(errs) > 0 && len(messages) == 0) && !sleep(ctx, 10*time.Second) {
			return
		}
	}
}

func (r *Runtime) answer(ctx context.Context, self marketclient.Identity, m marketclient.Inbound) error {
	if m.Notice != nil {
		if r.notices == nil {
			return nil
		}
		return enqueueNotice(ctx, r.pool, r.notices, *m.Notice)
	}
	if m.DirectTopup != nil {
		return r.answerDirectTopup(ctx, self, *m.DirectTopup)
	}
	if m.Header.Operation == secdigest.Operation {
		// A leaf's attack digest for one of our sites: no reply.
		if r.digestReceiver == nil {
			return nil
		}
		return r.digestReceiver.ReceiveDigest(ctx, m.Header, m.Payload)
	}
	if m.Header.Operation == siteconf.OpReply {
		// A leaf answering one of our own requests: hand it to the waiter.
		var reply siteconf.Reply
		if json.Unmarshal(m.Payload, &reply) == nil {
			r.mu.Lock()
			waiter := r.pending[m.Header.IdempotencyKey]
			delete(r.pending, m.Header.IdempotencyKey)
			r.mu.Unlock()
			if waiter != nil {
				waiter <- reply
			}
		}
		return nil
	}
	reply, err := r.supply.Handle(ctx, m.Header, m.Payload)
	if err != nil {
		return err
	}
	body, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	_, err = r.market.Send(ctx, self, marketclient.Outbound{To: m.Header.SenderMemberID,
		GrantID: m.Header.GrantID, Operation: siteconf.OpReply, Domains: m.Header.Domains,
		IdempotencyKey: "reply-" + m.Header.MessageID.String(), Payload: body})
	return err
}

// Call sends one request to a leaf through the relay and waits for its
// reply. The leaf replies with idempotency key "reply-<message id>".
func (r *Runtime) Call(ctx context.Context, leaf marketsubscribe.Leaf, op string, domains []string,
	idempotencyKey string, body any,
) (siteconf.Reply, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return siteconf.Reply{}, err
	}
	messageID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(idempotencyKey))
	waiter := make(chan siteconf.Reply, 1)
	key := "reply-" + messageID.String()
	r.mu.Lock()
	if r.pending == nil {
		r.pending = map[string]chan siteconf.Reply{}
	}
	r.pending[key] = waiter
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pending, key)
		r.mu.Unlock()
	}()
	if _, err := r.market.Send(ctx, r.identity(), marketclient.Outbound{To: leaf.LeafMemberID, GrantID: leaf.GrantID,
		MessageID: messageID, Operation: op, Domains: domains, IdempotencyKey: idempotencyKey, Payload: payload}); err != nil {
		return siteconf.Reply{}, err
	}
	timeout := time.NewTimer(r.cfg.CallTimeout)
	defer timeout.Stop()
	select {
	case reply := <-waiter:
		return reply, nil
	case <-timeout.C:
		return siteconf.Reply{}, ErrCallTimeout
	case <-ctx.Done():
		return siteconf.Reply{}, ctx.Err()
	}
}

func (r *Runtime) currentLease(ctx context.Context) ([]byte, error) {
	var lease []byte
	err := r.pool.QueryRow(ctx, `SELECT leases.signed_lease FROM entitlement_cached_leases leases
		JOIN control_installation_entitlement current ON current.current_serial = leases.serial
		WHERE current.singleton`).Scan(&lease)
	if err != nil {
		return nil, errors.Join(ErrNoLease, err)
	}
	return lease, nil
}

type storedIdentity struct {
	MemberID    uuid.UUID `json:"member_id"`
	SigningSeed []byte    `json:"signing_seed"`
	BoxPrivate  []byte    `json:"box_private"`
}

func (r *Runtime) loadIdentity() (marketclient.Identity, error) {
	path := filepath.Join(r.cfg.StateDir, identityFile)
	raw, err := os.ReadFile(path)
	var stored storedIdentity
	created := false
	switch {
	case err == nil:
		if json.Unmarshal(raw, &stored) != nil || len(stored.SigningSeed) != ed25519.SeedSize || len(stored.BoxPrivate) != 32 {
			return marketclient.Identity{}, fmt.Errorf("market identity %s is corrupt", path)
		}
	case errors.Is(err, os.ErrNotExist):
		stored.SigningSeed, stored.BoxPrivate, created = make([]byte, ed25519.SeedSize), make([]byte, 32), true
		if _, err := rand.Read(stored.SigningSeed); err != nil {
			return marketclient.Identity{}, err
		}
		if _, err := rand.Read(stored.BoxPrivate); err != nil {
			return marketclient.Identity{}, err
		}
	default:
		return marketclient.Identity{}, err
	}
	boxPublic, err := curve25519.X25519(stored.BoxPrivate, curve25519.Basepoint)
	if err != nil {
		return marketclient.Identity{}, err
	}
	id := marketclient.Identity{MemberID: stored.MemberID, SigningKey: ed25519.NewKeyFromSeed(stored.SigningSeed),
		BoxPrivate: stored.BoxPrivate, BoxPublic: boxPublic}
	// Persist new keys before registering, so a crash cannot orphan a member.
	if created {
		if err := r.saveIdentity(id); err != nil {
			return marketclient.Identity{}, err
		}
	}
	return id, nil
}

func (r *Runtime) saveIdentity(id marketclient.Identity) error {
	if err := os.MkdirAll(r.cfg.StateDir, 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(storedIdentity{MemberID: id.MemberID, SigningSeed: id.SigningKey.Seed(), BoxPrivate: id.BoxPrivate})
	tmp := filepath.Join(r.cfg.StateDir, identityFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(r.cfg.StateDir, identityFile))
}

// MarketCAFileEnv names a PEM CA bundle that replaces the system pool. Only
// the cross-process e2e harnesses set it (their market serves a test CA);
// production leaves it unset.
const MarketCAFileEnv = "CDNCA_MARKET_CA_FILE"

// RootCAs is the system pool: the market serves a public certificate.
func RootCAs() (*x509.CertPool, error) {
	path := os.Getenv(MarketCAFileEnv)
	if path == "" {
		return x509.SystemCertPool()
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s must be an absolute path", MarketCAFileEnv)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", MarketCAFileEnv, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s holds no PEM certificate", MarketCAFileEnv)
	}
	return pool, nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
